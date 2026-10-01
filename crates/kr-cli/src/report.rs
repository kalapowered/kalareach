//! What a command prints.
//!
//! Two audiences, one set of facts. Text for a person is short and says what changed; `--json` is
//! the same information in a shape a script can read, with the stable error code and the exit code
//! a failure carries.
//!
//! Nothing here invents a status. A `native_compat` session is labelled as one everywhere it is
//! reported, because that label is the difference between a session that implements empty-prompt
//! Ctrl-D and one that does not.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::attachment::{AttachMode, AttachmentSummary, TerminalPresentationMode};
use kr_protocol::desktop::{
    CapabilityRecord, DesktopCapabilityReport, DesktopContext, EnvironmentCapabilitiesResult,
    SleepInhibitionSetting, SleepInhibitionState,
};
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::session::{ClosureRecord, SessionState, SessionSummary};

use crate::doctor::content::Preview;
use crate::error::CliError;
use crate::output::{self, Asked, Document, Line, Request, left, right};
use crate::stdout_line;

/// How a command finished.
///
/// A command whose own result describes the failure reports it here rather than returning it, so
/// exactly one result reaches the caller and the exit status still says what happened.
#[derive(Debug)]
pub enum Completion {
    /// The command succeeded.
    Done,
    /// The command failed and has already written the result that says so.
    Reported(CliError),
}

/// Renders a failure as machine-readable output.
///
/// The message is what the failure says, which its type holds to a [`Shown`].
#[must_use]
pub fn failure(error: &CliError) -> Document {
    Document::new()
        .with("ok", false)
        .with("code", output::said(&error.code()))
        .with("message", error.machine_message())
        .with("exit_code", error.exit_code())
}

/// Renders a result that is also a failure: the result, with the failure's code, message and exit
/// status beside it and `ok` false.
#[must_use]
pub fn with_failure(mut document: Document, error: &CliError) -> Document {
    document.merge(failure(error));
    document
}

/// Writes one line on standard error.
///
/// Every failure, warning and notice this program writes there goes through here or through
/// [`failed`], and each is a [`Shown`]: this program's own words, values with nothing in them to
/// hide, and what a reducer or a door decided may be said. The one other thing written there is
/// the preview of a content export, by [`show_preview`].
pub fn say(line: &Shown) {
    eprintln!("{line}");
}

/// Prints the preview of a content export on standard error, and flushes it.
///
/// This is the one place content a person asked to read reaches the error stream. The export's
/// preview goes there so that `--json` keeps standard output for its document, and the command
/// prints it before it writes anything. It takes a [`Preview`], which only the export builds, and
/// a failure to write or flush it is the command's failure: nothing is written after a preview
/// the person could not be shown.
///
/// # Errors
///
/// Returns an error when the preview cannot be written or flushed.
pub fn show_preview(preview: &Preview) -> Result<(), CliError> {
    write_preview(&mut std::io::stderr().lock(), preview)
}

/// Writes a preview's lines on `writer` and flushes it: [`show_preview`] on the error stream, and
/// the crate's tests on writers that fail part of the way or when they are flushed.
///
/// # Errors
///
/// Returns an error when a line cannot be written or the writer cannot be flushed.
pub fn write_preview(writer: &mut impl std::io::Write, preview: &Preview) -> Result<(), CliError> {
    let unwritten = |error: std::io::Error| {
        CliError::Terminal(shown!(
            "the content could not be shown, so nothing was written: {}",
            Shown::io(&error)
        ))
    };
    for line in preview.lines() {
        output::write_line(writer, line).map_err(unwritten)?;
    }
    writer.flush().map_err(unwritten)
}

/// Whether standard error is a terminal: whether a person is there to be shown a preview.
#[must_use]
pub fn is_terminal() -> bool {
    use std::io::IsTerminal as _;

    std::io::stderr().is_terminal()
}

/// Reports a failure on standard error, as `kr: ` and what the failure says.
pub fn failed(error: &CliError) {
    say(&shown!("kr: {}", *error));
}

/// Writes the one byte that tells the process that started this one that it is ready, on standard
/// error, which that process reads as a pipe rather than as text.
///
/// # Errors
///
/// Returns the failure to write or flush the byte.
pub fn ready(byte: u8) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut pipe = std::io::stderr();
    pipe.write_all(&[byte])?;
    pipe.flush()
}

/// Renders one session.
#[must_use]
pub fn session(summary: &SessionSummary) -> Document {
    Document::new()
        .with("session_id", output::said(&summary.session_id))
        .with("display_number", summary.display_number.get())
        .with("environment_id", output::said(&summary.environment_id))
        .with("state", summary.state.as_str())
        .with("shell_mode", summary.shell_mode.as_str())
        .with("shell", Asked::text(Request::Sessions, &summary.shell_path))
        .with("cwd", Asked::text(Request::Sessions, &summary.cwd))
        .with("dimensions", dimensions(summary.dimensions))
        .with("attachments", summary.attachment_count.get())
        .with("worker_profile", summary.worker_profile.as_str())
        // The desktop this session's processes run on, which is not the terminal it is shown in.
        // A session with no desktop says so with nulls rather than with a placeholder.
        .with(
            "desktop",
            Document::new()
                .with(
                    "desktop_session_id",
                    summary
                        .desktop
                        .desktop_session_id
                        .as_ref()
                        .map(|desktop| Asked::text(Request::Sessions, &desktop.to_string())),
                )
                .with(
                    "login_generation",
                    summary
                        .desktop
                        .login_generation
                        .as_ref()
                        .map(|value| value.get()),
                ),
        )
        .with("created_at_ms", summary.created_at_ms.get())
        .with("closure", summary.closure.as_ref().map(closure))
}

/// Renders a size as its columns and rows.
#[must_use]
pub fn dimensions(dimensions: kr_protocol::session::Dimensions) -> Document {
    Document::new()
        .with("columns", dimensions.columns())
        .with("rows", dimensions.rows())
}

/// The kinds of resource a closure record says survived, as a worker and this host's daemon write
/// them. Any other kind is replaced.
const SURVIVING_KINDS: [&str; 3] = ["process", "unestablished", "unaccounted_worker"];

/// Renders a session's closure record, whole: how it closed, what it terminated and what survived
/// it.
///
/// A process's name is the session's own, shown to the person who asked about the session; what a
/// surviving resource's detail says is the host's sentence, said as its class and its length.
#[must_use]
pub fn closure(record: &ClosureRecord) -> Document {
    Document::new()
        .with("session_id", output::said(&record.session_id))
        .with("session_epoch", output::said(&record.session_epoch))
        .with(
            "terminated",
            record
                .terminated
                .iter()
                .map(|process| {
                    Document::new()
                        .with("pid", process.identity.pid.get())
                        .with(
                            "start",
                            Document::new()
                                .with("pid", output::said(&process.identity.pid))
                                .with("source", crate::shown::wire_word(process.identity.source))
                                .with("start_value", output::said(&process.identity.start_value)),
                        )
                        .with(
                            "name",
                            process
                                .name
                                .as_ref()
                                .map(|name| Asked::text(Request::Sessions, name)),
                        )
                        .with("forced", process.forced)
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "surviving",
            record
                .surviving
                .iter()
                .map(|resource| {
                    Document::new()
                        .with("kind", surviving_kind(&resource.kind))
                        .with(
                            "detail",
                            crate::shown::exported("SurvivingResource", "detail", &resource.detail),
                        )
                })
                .collect::<Vec<_>>(),
        )
        .with("reason", record.reason.as_str())
        .with(
            "exit_code",
            record.root_exit_code.as_ref().map(|code| code.get()),
        )
        .with("signal", Shown::signal(record))
        .with(
            "ownership_coverage",
            match record.ownership_coverage {
                kr_protocol::session::OwnershipCoverage::Complete => "complete",
                kr_protocol::session::OwnershipCoverage::Incomplete => "incomplete",
            },
        )
        .with("durability", durability_word(record.durability))
        .with("closed_at_ms", record.closed_at_ms.get())
}

/// What kind of resource survived a session: one of the kinds a worker and this host write, or a
/// placeholder.
fn surviving_kind(kind: &str) -> Shown {
    SURVIVING_KINDS
        .iter()
        .find(|known| **known == kind)
        .map_or_else(
            || Shown::said("[a resource kind]"),
            |known| Shown::said(known),
        )
}

/// The word a record's durability goes by.
#[must_use]
pub const fn durability_word(durability: kr_protocol::session::Durability) -> &'static str {
    match durability {
        kr_protocol::session::Durability::Durable => "durable",
        kr_protocol::session::Durability::Volatile => "volatile",
    }
}

/// Renders one session as a line for a person.
#[must_use]
pub fn session_line(summary: &SessionSummary) -> Line {
    let state = match summary.state {
        SessionState::Creating => "creating",
        SessionState::Live => "live",
        SessionState::Closing => "closing",
        SessionState::Closed => "closed",
    };
    stdout_line!(
        "{}  {} {} {}x{} {} attachment{}  {}",
        right(4, &summary.display_number.get()),
        left(8, &state),
        left(14, &summary.shell_mode.as_str()),
        right(4, &summary.dimensions.columns()),
        left(4, &summary.dimensions.rows()),
        summary.attachment_count.get(),
        if summary.attachment_count.get() == 1 {
            ""
        } else {
            "s"
        },
        Asked::text(Request::Sessions, &summary.shell_path),
    )
}

/// Renders the host's own state.
#[must_use]
pub fn host(info: &HostInfoResult) -> Document {
    Document::new()
        .with(
            "build_id",
            crate::shown::build_identity(&info.build_id.to_string()),
        )
        .with(
            "protocol_version",
            shown!(
                "{}.{}",
                info.protocol_version.major,
                info.protocol_version.minor
            ),
        )
        .with("environment_id", output::said(&info.environment_id))
        .with("generation", info.generation.get())
        .with("live_sessions", info.live_sessions.get())
        .with("session_limit", info.session_limit.get())
        .with("started_at_ms", info.started_at_ms.get())
        .with(
            "default_worker_profile",
            info.default_worker_profile.as_str(),
        )
        .with("power", power(&info.power))
}

/// Renders what the host's sleep inhibition is doing.
///
/// The assertion's name and why none is held are the host's text, said as their class and length.
#[must_use]
pub fn power(state: &SleepInhibitionState) -> Document {
    Document::new()
        .with("setting", state.setting.as_str())
        .with("active", state.active)
        .with(
            "reason",
            state.reason.as_ref().map(|reason| reason.as_str()),
        )
        .with("mechanism", state.mechanism.as_str())
        .with("power_source", state.power_source.as_str())
        .with("sessions_with_work", state.sessions_with_work.get())
        .with("pending_requests", state.pending_requests.get())
        .with("since_ms", state.since_ms.as_ref().map(|since| since.get()))
        .with(
            "holder",
            state
                .holder
                .as_ref()
                .map(|holder| crate::shown::exported("SleepInhibitionState", "holder", holder)),
        )
        .with(
            "withheld_reason",
            state.withheld_reason.as_ref().map(|reason| {
                crate::shown::exported("SleepInhibitionState", "withheld_reason", reason)
            }),
        )
        .with("description", power_line(state))
}

/// The line host status and `kr status` print about sleep, in the words the power state describes
/// itself with, the assertion's name and why none is held said as their class and length.
#[must_use]
pub fn power_line(state: &SleepInhibitionState) -> Shown {
    if state.active {
        let reason = state
            .reason
            .as_ref()
            .map_or("work the host has admitted", |reason| reason.describe());
        let holder = state.holder.as_ref().map_or_else(
            || Shown::said("an assertion"),
            |holder| crate::shown::exported("SleepInhibitionState", "holder", holder),
        );
        return shown!(
            "sleep inhibited ({}): {}, held as {} on {} power",
            state.setting.as_str(),
            reason,
            holder,
            state.power_source.as_str()
        );
    }
    match state.setting {
        SleepInhibitionSetting::Off => Shown::said("sleep policy unchanged (off)"),
        setting => shown!(
            "sleep policy unchanged ({}): {}",
            setting.as_str(),
            state.withheld_reason.as_ref().map_or_else(
                || Shown::said("nothing currently justifies an assertion"),
                |reason| crate::shown::exported("SleepInhibitionState", "withheld_reason", reason)
            )
        ),
    }
}

/// Renders one desktop execution context.
///
/// The desktop's identifier and the account it belongs to are the session's own, shown to the
/// person who asked; the platform's session name and the compositor's are the host's text, said as
/// their class and length.
#[must_use]
pub fn desktop(context: &DesktopContext) -> Document {
    Document::new()
        .with(
            "desktop_session_id",
            context
                .desktop_session_id
                .as_ref()
                .map(|desktop| Asked::text(Request::Sessions, &desktop.to_string())),
        )
        .with("kind", context.kind.as_str())
        .with(
            "platform_session",
            context.platform_session.as_ref().map(|session| {
                crate::shown::exported("DesktopContext", "platform_session", session)
            }),
        )
        .with(
            "login_generation",
            context.login_generation.as_ref().map(|value| value.get()),
        )
        .with("generation_source", context.generation_source.as_str())
        .with("os_user", Asked::text(Request::Sessions, &context.os_user))
        .with("uid", context.uid.as_ref().map(|uid| uid.get()))
        .with("graphic_access", context.graphic_access)
        .with("remote", context.remote)
        .with("availability", context.availability.as_str())
        .with("container", context.container.as_str())
        .with("display_server", context.display_server.as_str())
        .with(
            "compositor",
            context.compositor.as_ref().map(|compositor| {
                crate::shown::exported("DesktopContext", "compositor", compositor)
            }),
        )
        .with("worker_profile", context.worker_profile.as_str())
}

/// Renders one capability record.
///
/// The binary it was established about is said whole: it is what `kr doctor` was asked to
/// diagnose. The facility's identity and the reason a person is given are the host's text.
#[must_use]
pub fn capability(record: &CapabilityRecord) -> Document {
    Document::new()
        .with(
            "capability",
            crate::shown::exported(
                "CapabilityRecord",
                "capability",
                &record.capability.to_string(),
            ),
        )
        .with("version", record.version.get())
        .with("revision", record.revision.get())
        .with("state", record.state.as_str())
        .with("evidence_source", record.evidence_source.as_str())
        .with(
            "binary",
            record
                .identity
                .binary
                .as_ref()
                .map(|binary| Asked::text(Request::Diagnostics, binary)),
        )
        .with(
            "facility_identity",
            record
                .identity
                .version
                .as_ref()
                .map(crate::shown::host_text),
        )
        .with(
            "profile",
            record
                .identity
                .profile
                .as_ref()
                .map(|profile| profile.as_str()),
        )
        .with(
            "invalidation",
            record
                .invalidation
                .iter()
                .map(|trigger| trigger.as_str())
                .collect::<Vec<_>>(),
        )
        .with(
            "disabled_reason",
            record.disabled_reason.as_ref().map(crate::shown::host_text),
        )
        .with("observed_at_ms", record.observed_at_ms.get())
}

/// Renders a desktop and what may be done on it.
#[must_use]
pub fn desktop_capabilities(report: &DesktopCapabilityReport) -> Document {
    Document::new()
        .with("desktop", desktop(&report.desktop))
        .with(
            "capabilities",
            report.records.iter().map(capability).collect::<Vec<_>>(),
        )
}

/// Renders what one environment can currently do.
#[must_use]
pub fn environment_capabilities(result: &EnvironmentCapabilitiesResult) -> Document {
    Document::new()
        .with("environment_id", output::said(&result.environment_id))
        .with(
            "default_worker_profile",
            result.default_worker_profile.as_str(),
        )
        .with("desktop", desktop_capabilities(&result.desktop))
        .with(
            "persistence",
            result
                .persistence
                .iter()
                .map(|entry| {
                    Document::new()
                        .with("profile", entry.profile.as_str())
                        .with("persistence", entry.persistence.as_str())
                        .with("mechanism", crate::shown::host_text(entry.mechanism()))
                        .with("detail", crate::shown::host_text(entry.detail()))
                })
                .collect::<Vec<_>>(),
        )
        .with("power", power(&result.power))
}

/// Renders the execution context a session is about to be created in.
///
/// It is printed before the request is sent, because which desktop a command will be able to
/// reach is the kind of thing a person wants to know before a shell starts rather than after.
#[must_use]
pub fn execution_context_line(
    profile: kr_protocol::identity::WorkerProfile,
    chosen: bool,
) -> Shown {
    shown!(
        "execution context {} ({})",
        profile.as_str(),
        if chosen {
            "chosen"
        } else {
            "this host's default"
        }
    )
}

/// Renders the desktop this environment has as a line for a person.
#[must_use]
pub fn desktop_summary_line(report: &DesktopCapabilityReport) -> Line {
    let desktop = &report.desktop;
    let Some(name) = desktop.desktop_session_id.as_ref() else {
        return stdout_line!("no graphical login session, so no desktop to bind a session to");
    };
    let unavailable = report
        .records
        .iter()
        .filter(|record| !record.state.is_available())
        .count();
    stdout_line!(
        "desktop {} ({}, {}, {} of {} capabilities established)",
        Asked::text(Request::Sessions, &name.to_string()),
        desktop.display_server.as_str(),
        desktop.availability.as_str(),
        report.records.len() - unavailable,
        report.records.len()
    )
}

/// Renders what a logout does to each execution profile, one line each.
#[must_use]
pub fn persistence_lines(persistence: &[kr_protocol::desktop::ProfilePersistence]) -> Vec<Shown> {
    persistence
        .iter()
        .map(|entry| {
            shown!(
                "a {} session at logout: {} ({})",
                entry.profile.as_str(),
                entry.persistence.as_str(),
                crate::shown::host_text(entry.mechanism())
            )
        })
        .collect()
}

/// Renders each capability of one desktop as a line for a person: the reason a person is given
/// where there is one, and otherwise the binary it was established about.
#[must_use]
pub fn capability_lines(report: &DesktopCapabilityReport) -> Vec<Line> {
    report
        .records
        .iter()
        .map(|record| {
            let capability = crate::shown::exported(
                "CapabilityRecord",
                "capability",
                &record.capability.to_string(),
            );
            match (
                record.disabled_reason.as_ref(),
                record.identity.binary.as_ref(),
            ) {
                (Some(reason), _) => stdout_line!(
                    "  {} {} {}",
                    left(26, &capability),
                    left(24, &record.state.as_str()),
                    crate::shown::host_text(reason)
                ),
                (None, Some(binary)) => stdout_line!(
                    "  {} {} {}",
                    left(26, &capability),
                    left(24, &record.state.as_str()),
                    Asked::text(Request::Diagnostics, binary)
                ),
                (None, None) => stdout_line!(
                    "  {} {} no facility named",
                    left(26, &capability),
                    left(24, &record.state.as_str())
                ),
            }
        })
        .collect()
}

/// Renders the desktop a session runs on as a line for a person.
#[must_use]
pub fn desktop_line(summary: &SessionSummary) -> Line {
    match summary.desktop.desktop_session_id.as_ref() {
        Some(desktop) => stdout_line!(
            "execution context {}: desktop {}",
            summary.worker_profile.as_str(),
            Asked::text(Request::Sessions, &desktop.to_string())
        ),
        None => stdout_line!(
            "execution context {}: no desktop, and none of a desktop's handles",
            summary.worker_profile.as_str()
        ),
    }
}

/// Renders each terminal attachment's presentation and the reason for it.
///
/// Section 8 asks `kr status` to report each terminal attachment's mode and its reason. An
/// attachment that is not a terminal has neither and is left out. A viewport whose worker gave no
/// reason, which a worker built before reasons existed does, says so with a null. The terminal's
/// type is one of the terminfo names this build lists, or its placeholder.
#[must_use]
pub fn terminal_attachments(attachments: &[AttachmentSummary]) -> Vec<Document> {
    attachments
        .iter()
        .filter(|summary| summary.mode == AttachMode::Terminal)
        .map(|summary| {
            Document::new()
                .with("attachment_id", output::said(&summary.attachment_id))
                .with(
                    "presentation",
                    summary.presentation.as_ref().map(|mode| mode.as_str()),
                )
                .with(
                    "presentation_reason",
                    summary.presentation_reason.map(|reason| reason.as_str()),
                )
                .with(
                    "dimensions",
                    summary.dimensions.as_ref().copied().map(dimensions),
                )
                .with(
                    "terminal_profile_id",
                    summary
                        .terminal_profile_id
                        .as_ref()
                        .map(|name| Shown::terminfo(name)),
                )
        })
        .collect()
}

/// Renders each terminal attachment's presentation and its reason as a line for a person.
#[must_use]
pub fn terminal_attachment_lines(attachments: &[AttachmentSummary]) -> Vec<Shown> {
    attachments
        .iter()
        .filter(|summary| summary.mode == AttachMode::Terminal)
        .map(|summary| {
            let presented = match (
                summary.presentation.as_ref().copied(),
                summary.presentation_reason,
            ) {
                (Some(TerminalPresentationMode::Direct), _) => Shown::said("direct"),
                (Some(TerminalPresentationMode::Viewport), Some(reason)) => {
                    shown!("viewport ({}): {}", reason.as_str(), reason.describe())
                }
                (Some(TerminalPresentationMode::Viewport), None) => {
                    Shown::said("viewport, with no reason reported by this session's worker")
                }
                (None, _) => Shown::said("no presentation reported"),
            };
            shown!("attachment {}: {}", summary.attachment_id, presented)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use kr_client::shown::Said as _;
    use serde_json::{Value, json};

    use super::*;
    use crate::output::planted::{
        only_asked, only_asked_lines, only_asked_or_host_text, planted, planted_text,
    };
    use crate::shown::marker::MARKER;

    #[test]
    fn a_failure_carries_its_code_and_exit_status() {
        let error = CliError::AmbiguousSession(Shown::said("3"));
        let value = failure(&error).json();
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["code"], json!("AMBIGUOUS_SESSION"));
        assert_eq!(value["message"], json!(error.said().as_str()));
        assert_eq!(value["exit_code"], json!(5));
    }

    /// KR-REQ-23.57: what a person is told of a refusal leaves the code out, and a `--json` failure
    /// keeps it, in its own field and in the message it has always carried.
    #[test]
    fn a_refusal_keeps_its_code_and_its_message_in_a_json_failure() {
        let error = CliError::Refused(kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::PairingRejected,
            "that invitation has ended",
        ));
        let value = failure(&error).json();
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["code"], json!("PAIRING_REJECTED"));
        assert_eq!(
            value["message"],
            json!("PAIRING_REJECTED: that invitation has ended")
        );
        assert_eq!(value["exit_code"], json!(8));
        let said = error.said();
        assert!(!said.as_str().contains("PAIRING_REJECTED"), "{said}");
    }

    #[test]
    fn the_execution_context_is_named_before_a_session_is_created() {
        let chosen =
            execution_context_line(kr_protocol::identity::WorkerProfile::DesktopBound, true);
        assert_eq!(chosen.as_str(), "execution context desktop_bound (chosen)");
        let defaulted =
            execution_context_line(kr_protocol::identity::WorkerProfile::HeadlessUser, false);
        assert_eq!(
            defaulted.as_str(),
            "execution context headless_user (this host's default)"
        );
    }

    #[test]
    fn a_session_says_which_desktop_it_runs_on_or_that_it_has_none() {
        let mut summary = summary_for_tests();
        assert_eq!(
            desktop_line(&summary).text(),
            "execution context headless_user: no desktop, and none of a desktop's handles"
        );
        assert!(
            session(&summary).json()["desktop"]["desktop_session_id"].is_null(),
            "a session with no desktop says so with a null"
        );

        summary.worker_profile = kr_protocol::identity::WorkerProfile::DesktopBound;
        summary.desktop = kr_protocol::identity::DesktopBinding {
            desktop_session_id: kr_protocol::scalars::Nullable::some(
                kr_protocol::ids::DesktopSessionId::new(
                    "macos_security_session:uid=501:session=100019:generation=7:boot=ab",
                )
                .expect("a name"),
            ),
            login_generation: kr_protocol::scalars::Nullable::some(kr_protocol::scalars::U64::new(
                7,
            )),
        };
        assert_eq!(
            desktop_line(&summary).text(),
            "execution context desktop_bound: desktop \
             macos_security_session:uid=501:session=100019:generation=7:boot=ab"
        );
        assert_eq!(
            session(&summary).json()["desktop"]["login_generation"],
            json!(7),
            "the generation is reported beside the name"
        );
    }

    fn summary_for_tests() -> SessionSummary {
        SessionSummary {
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::NIL),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            environment_id: kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::NIL),
            display_number: kr_protocol::session::DisplayNumber::new(3),
            state: SessionState::Live,
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/tmp".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            dimensions: kr_protocol::session::Dimensions::new(120, 40),
            attachment_count: kr_protocol::scalars::U64::new(1),
            application_state: kr_protocol::scalars::Nullable::null(),
            root_process: kr_protocol::scalars::Nullable::null(),
            closure: kr_protocol::scalars::Nullable::null(),
        }
    }

    /// A terminal attachment of the kind the session's worker reports.
    fn attachment(
        byte: u8,
        mode: AttachMode,
        presentation: Option<TerminalPresentationMode>,
        reason: Option<kr_protocol::attachment::PresentationReason>,
    ) -> AttachmentSummary {
        AttachmentSummary {
            attachment_id: kr_protocol::ids::AttachmentId::new(
                kr_protocol::scalars::Uuid::from_bytes([byte; 16]),
            ),
            ordinal: kr_protocol::ids::AttachmentOrdinal::new(u64::from(byte)),
            mode,
            claim_geometry: false,
            dimensions: kr_protocol::scalars::Nullable::some(
                kr_protocol::session::Dimensions::new(100, 30),
            ),
            presentation: kr_protocol::scalars::Nullable(presentation),
            presentation_reason: reason,
            terminal_profile_id: kr_protocol::scalars::Nullable::some("xterm-256color".to_owned()),
            granted: kr_protocol::scalars::CanonicalSet::new(),
            attached_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        }
    }

    /// KR-REQ-08.02: each terminal attachment is reported with its presentation and the reason for
    /// it, a direct one with none, one whose worker gave no reason as such, and an attachment that
    /// is not a terminal not at all.
    #[test]
    fn each_terminal_attachment_is_reported_with_its_presentation_and_reason() {
        use kr_protocol::attachment::PresentationReason;

        let attachments = [
            attachment(
                1,
                AttachMode::Terminal,
                Some(TerminalPresentationMode::Direct),
                None,
            ),
            attachment(
                2,
                AttachMode::Terminal,
                Some(TerminalPresentationMode::Viewport),
                Some(PresentationReason::SizeMismatch),
            ),
            attachment(
                3,
                AttachMode::Terminal,
                Some(TerminalPresentationMode::Viewport),
                None,
            ),
            attachment(4, AttachMode::Semantic, None, None),
        ];
        let entries = terminal_attachments(&attachments)
            .iter()
            .map(Document::json)
            .collect::<Vec<_>>();
        assert_eq!(
            entries.len(),
            3,
            "the semantic attachment is not a terminal"
        );
        assert_eq!(entries[0]["presentation"], "direct");
        assert_eq!(entries[0]["presentation_reason"], Value::Null);
        assert_eq!(entries[1]["presentation"], "viewport");
        assert_eq!(entries[1]["presentation_reason"], "size_mismatch");
        assert_eq!(
            entries[1]["dimensions"],
            json!({ "columns": 100, "rows": 30 })
        );
        assert_eq!(entries[1]["terminal_profile_id"], "xterm-256color");
        assert_eq!(entries[2]["presentation_reason"], Value::Null);

        let lines = terminal_attachment_lines(&attachments);
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0].as_str(),
            format!("attachment {}: direct", attachments[0].attachment_id)
        );
        assert_eq!(
            lines[1].as_str(),
            format!(
                "attachment {}: viewport (size_mismatch): its size is not the session's",
                attachments[1].attachment_id
            )
        );
        assert!(
            lines[2]
                .as_str()
                .ends_with("viewport, with no reason reported by this session's worker")
        );
    }

    #[test]
    fn a_closure_is_rendered_whole() {
        let record = ClosureRecord {
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [2; 16],
            )),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: kr_protocol::scalars::Nullable::some(kr_protocol::scalars::U64::new(
                143,
            )),
            root_signal: kr_protocol::scalars::Nullable::some("SIGTERM".to_owned()),
            terminated: vec![kr_protocol::session::TerminatedProcess {
                identity: kr_protocol::identity::ProcessStartIdentity::new(
                    42,
                    kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                    7,
                ),
                name: kr_protocol::scalars::Nullable::some("sh".to_owned()),
                forced: true,
            }],
            surviving: vec![
                kr_protocol::session::SurvivingResource {
                    kind: "process".to_owned(),
                    detail: "a window the broker opened".to_owned(),
                },
                kr_protocol::session::SurvivingResource {
                    kind: "desktop_resource".to_owned(),
                    detail: String::new(),
                },
            ],
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Volatile,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(9),
        };
        let rendered = closure(&record).json();
        assert_eq!(rendered["session_id"], json!(record.session_id.to_string()));
        assert_eq!(rendered["session_epoch"], json!("1"), "{rendered}");
        assert_eq!(rendered["terminated"][0]["pid"], json!(42));
        assert_eq!(
            rendered["terminated"][0]["start"],
            json!({ "pid": "42", "source": "linux_proc_stat", "start_value": "7" }),
            "{rendered}"
        );
        assert_eq!(rendered["terminated"][0]["name"], json!("sh"));
        assert_eq!(rendered["terminated"][0]["forced"], json!(true));
        // A kind this host and its workers write is said as it is, any other replaced; a detail is
        // the host's sentence, said as its class and length.
        assert_eq!(
            rendered["surviving"],
            json!([
                { "kind": "process", "detail": "[message withheld, 26 bytes]" },
                { "kind": "[a resource kind]", "detail": "[message withheld, 0 bytes]" },
            ])
        );
        assert_eq!(rendered["reason"], json!("close_requested"));
        assert_eq!(rendered["exit_code"], json!(143));
        assert_eq!(rendered["signal"], json!("SIGTERM"));
        assert_eq!(rendered["ownership_coverage"], json!("incomplete"));
        assert_eq!(rendered["durability"], json!("volatile"));
        assert_eq!(rendered["closed_at_ms"], json!(9));
        let mut fields: Vec<&str> = rendered
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "closed_at_ms",
                "durability",
                "exit_code",
                "ownership_coverage",
                "reason",
                "session_epoch",
                "session_id",
                "signal",
                "surviving",
                "terminated",
            ],
            "every field is checked above"
        );
    }

    #[test]
    fn the_shell_mode_is_reported_rather_than_assumed() {
        let summary = summary_for_tests();
        assert_eq!(
            session(&summary).json()["shell_mode"],
            json!("native_compat")
        );
        assert_eq!(
            session_line(&summary).text(),
            "   3  live     native_compat   120x40   1 attachment  /bin/zsh"
        );
    }

    /// KR-REQ-23.25: text planted in every leaf of a session, its closure and its size that can
    /// hold free text reaches the session's document and its lines only as content the person
    /// asked for: the shell, the directory, the desktop and a terminated process's name. A
    /// surviving resource's detail is said as its class and length, and a kind this host does not
    /// write, and a signal no platform names, as their placeholders.
    #[test]
    fn planted_text_in_a_session_shows_only_where_it_was_asked_for() {
        let mut shown = std::collections::BTreeSet::new();
        for summary in planted::<SessionSummary>() {
            shown.extend(only_asked("kr status", &session(&summary)));
            only_asked_lines(
                "kr status",
                &[session_line(&summary), desktop_line(&summary)],
            );
            if let Some(record) = summary.closure.as_ref() {
                let rendered = closure(record).json();
                let withheld = format!("[message withheld, {} bytes]", planted_text().len());
                assert_eq!(rendered["surviving"][0]["detail"], json!(withheld));
                assert_eq!(rendered["surviving"][0]["kind"], json!("[a resource kind]"));
                assert_eq!(
                    rendered["signal"],
                    json!("[a signal name this build does not list]")
                );
            }
        }
        for asked in ["shell", "cwd", "closure.terminated[].name"] {
            assert!(
                shown.contains(asked),
                "{asked} shows what the session holds"
            );
        }
    }

    /// KR-REQ-23.25: the host's power, its build and its desktop show planted text only where the
    /// person asked for it (the desktop's identifier, its account and a capability's binary) and
    /// where the host's own export text is said through its door (what a logout does to each
    /// profile, and a capability's identity and reason). The assertion's name, why none is held,
    /// the platform's session name and the compositor's are the host's text, said as their class
    /// and length.
    #[test]
    fn planted_text_in_the_host_shows_only_where_it_was_asked_for() {
        for info in planted::<HostInfoResult>() {
            only_asked("kr doctor", &host(&info));
            assert!(!power_line(&info.power).as_str().contains(MARKER));
        }
        for state in planted::<SleepInhibitionState>() {
            let rendered = only_asked("kr host power", &power(&state));
            assert!(rendered.is_empty(), "{rendered:?}");
            let json = power(&state).json();
            assert_eq!(
                json["holder"],
                json!(format!("[name withheld, {} bytes]", planted_text().len()))
            );
        }
        let mut shown = std::collections::BTreeSet::new();
        for result in planted::<EnvironmentCapabilitiesResult>() {
            shown.extend(only_asked_or_host_text(
                "kr doctor",
                &environment_capabilities(&result),
                &[
                    "persistence[].mechanism",
                    "persistence[].detail",
                    "desktop.capabilities[].facility_identity",
                    "desktop.capabilities[].disabled_reason",
                ],
            ));
            only_asked_lines("kr doctor", &[desktop_summary_line(&result.desktop)]);
            // A capability's line says its reason through the door, and nothing else it holds
            // shows unasked.
            for (line, record) in capability_lines(&result.desktop)
                .iter()
                .zip(&result.desktop.records)
            {
                let door = record
                    .disabled_reason
                    .as_ref()
                    .map_or(0, |reason| reason.as_str().matches(MARKER).count());
                assert_eq!(line.unasked(MARKER), door, "{:?}", line.text());
            }
            for (line, entry) in persistence_lines(&result.persistence)
                .iter()
                .zip(&result.persistence)
            {
                assert_eq!(
                    line.as_str(),
                    format!(
                        "a {} session at logout: {} ({})",
                        entry.profile.as_str(),
                        entry.persistence.as_str(),
                        entry.mechanism().as_str()
                    )
                );
            }
        }
        for asked in [
            "desktop.desktop.os_user",
            "desktop.capabilities[].binary",
            "desktop.capabilities[].facility_identity",
            "desktop.capabilities[].disabled_reason",
        ] {
            assert!(shown.contains(asked), "{asked} shows what was asked for");
        }
    }
}
