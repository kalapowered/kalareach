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
use kr_client::shown::{Said, Shown};
use kr_protocol::attachment::{AttachMode, AttachmentSummary, TerminalPresentationMode};
use kr_protocol::desktop::{
    CapabilityRecord, DesktopCapabilityReport, DesktopContext, EnvironmentCapabilitiesResult,
    SleepInhibitionState,
};
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::session::{ClosureRecord, SessionState, SessionSummary};
use serde_json::{Value, json};

use crate::error::CliError;

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
pub fn failure(error: &CliError) -> Value {
    json!({
        "ok": false,
        "code": error.code(),
        "message": error.said().as_str(),
        "exit_code": error.exit_code(),
    })
}

/// Writes one line on standard error.
///
/// Every failure, warning and notice this program writes there goes through here or through
/// [`failed`], and each is a [`Shown`]: this program's own words, values with nothing in them to
/// hide, and what a reducer or a door decided may be said.
pub fn say(line: &Shown) {
    eprintln!("{line}");
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

/// Renders a host's answer as machine-readable output: the answer exactly as the host sent it,
/// marked as a success.
///
/// # Errors
///
/// Returns [`CliError::Other`] when the answer cannot be written as JSON.
pub fn answer<T: serde::Serialize>(answer: &T) -> Result<Value, CliError> {
    let mut document = serde_json::to_value(answer).map_err(|error| {
        CliError::Other(shown!(
            "the host's answer could not be written: {}",
            Shown::json(&error)
        ))
    })?;
    match document.as_object_mut() {
        Some(object) => {
            object.insert("ok".to_owned(), Value::Bool(true));
            Ok(document)
        }
        None => Ok(json!({ "ok": true, "answer": document })),
    }
}

/// Renders a host's answer that is also a failure: the answer exactly as the host sent it, with the
/// failure's code, message and exit status beside it and `ok` false.
///
/// # Errors
///
/// Returns [`CliError::Other`] when the answer cannot be written as JSON.
pub fn answer_that_failed<T: serde::Serialize>(
    answer: &T,
    error: &CliError,
) -> Result<Value, CliError> {
    let mut document = self::answer(answer)?;
    if let (Some(object), Value::Object(failed)) = (document.as_object_mut(), failure(error)) {
        object.extend(failed);
    }
    Ok(document)
}

/// Returns the name a value of one of the protocol's named sets goes by on the wire, which is the
/// name a person is shown.
#[must_use]
pub fn wire_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        _ => String::from("unnamed"),
    }
}

/// Prints one machine-readable document on standard output.
pub fn print_json(document: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(document).unwrap_or_else(|_| "{}".to_owned())
    );
}

/// Renders one session.
#[must_use]
pub fn session(summary: &SessionSummary) -> Value {
    json!({
        "session_id": summary.session_id.to_string(),
        "display_number": summary.display_number.get(),
        "environment_id": summary.environment_id.to_string(),
        "state": summary.state.as_str(),
        "shell_mode": summary.shell_mode.as_str(),
        "shell": summary.shell_path,
        "cwd": summary.cwd,
        "dimensions": {
            "columns": summary.dimensions.columns(),
            "rows": summary.dimensions.rows(),
        },
        "attachments": summary.attachment_count.get(),
        "worker_profile": summary.worker_profile.as_str(),
        // The desktop this session's processes run on, which is not the terminal it is shown in.
        // A session with no desktop says so with nulls rather than with a placeholder.
        "desktop": {
            "desktop_session_id": summary
                .desktop
                .desktop_session_id
                .as_ref()
                .map(ToString::to_string),
            "login_generation": summary.desktop.login_generation.as_ref().map(|value| value.get()),
        },
        "created_at_ms": summary.created_at_ms.get(),
        "closure": summary.closure.as_ref().map(closure),
    })
}

/// Renders a session's closure record, whole: how it closed, what it terminated and what survived
/// it.
#[must_use]
pub fn closure(record: &ClosureRecord) -> Value {
    json!({
        "session_id": record.session_id.to_string(),
        "session_epoch": serde_json::to_value(record.session_epoch).unwrap_or(Value::Null),
        "terminated": record.terminated.iter().map(|process| json!({
            "pid": process.identity.pid.get(),
            "start": serde_json::to_value(&process.identity).unwrap_or(Value::Null),
            "name": process.name.as_ref().cloned(),
            "forced": process.forced,
        })).collect::<Vec<_>>(),
        "surviving": record.surviving.iter().map(|resource| json!({
            "kind": resource.kind,
            "detail": resource.detail,
        })).collect::<Vec<_>>(),
        "reason": record.reason.as_str(),
        "exit_code": record.root_exit_code.as_ref().map(|code| code.get()),
        "signal": record.root_signal.as_ref().cloned(),
        "ownership_coverage": match record.ownership_coverage {
            kr_protocol::session::OwnershipCoverage::Complete => "complete",
            kr_protocol::session::OwnershipCoverage::Incomplete => "incomplete",
        },
        "durability": match record.durability {
            kr_protocol::session::Durability::Durable => "durable",
            kr_protocol::session::Durability::Volatile => "volatile",
        },
        "closed_at_ms": record.closed_at_ms.get(),
    })
}

/// Renders one session as a line for a person.
#[must_use]
pub fn session_line(summary: &SessionSummary) -> String {
    let state = match summary.state {
        SessionState::Creating => "creating",
        SessionState::Live => "live",
        SessionState::Closing => "closing",
        SessionState::Closed => "closed",
    };
    format!(
        "{:>4}  {:<8} {:<14} {:>4}x{:<4} {} attachment{}  {}",
        summary.display_number.get(),
        state,
        summary.shell_mode.as_str(),
        summary.dimensions.columns(),
        summary.dimensions.rows(),
        summary.attachment_count.get(),
        if summary.attachment_count.get() == 1 {
            ""
        } else {
            "s"
        },
        summary.shell_path,
    )
}

/// Renders the host's own state.
#[must_use]
pub fn host(info: &HostInfoResult) -> Value {
    json!({
        "build_id": info.build_id.to_string(),
        "protocol_version": info.protocol_version.to_string(),
        "environment_id": info.environment_id.to_string(),
        "generation": info.generation.get(),
        "live_sessions": info.live_sessions.get(),
        "session_limit": info.session_limit.get(),
        "started_at_ms": info.started_at_ms.get(),
        "default_worker_profile": info.default_worker_profile.as_str(),
        "power": power(&info.power),
    })
}

/// Renders what the host's sleep inhibition is doing.
#[must_use]
pub fn power(state: &SleepInhibitionState) -> Value {
    json!({
        "setting": state.setting.as_str(),
        "active": state.active,
        "reason": state.reason.as_ref().map(|reason| reason.as_str()),
        "mechanism": state.mechanism.as_str(),
        "power_source": state.power_source.as_str(),
        "sessions_with_work": state.sessions_with_work.get(),
        "pending_requests": state.pending_requests.get(),
        "since_ms": state.since_ms.as_ref().map(|since| since.get()),
        "holder": state.holder.as_ref().cloned(),
        "withheld_reason": state.withheld_reason.as_ref().cloned(),
        "description": state.describe(),
    })
}

/// Renders one desktop execution context.
#[must_use]
pub fn desktop(context: &DesktopContext) -> Value {
    json!({
        "desktop_session_id": context.desktop_session_id.as_ref().map(ToString::to_string),
        "kind": context.kind.as_str(),
        "platform_session": context.platform_session.as_ref().cloned(),
        "login_generation": context.login_generation.as_ref().map(|value| value.get()),
        "generation_source": context.generation_source.as_str(),
        "os_user": context.os_user,
        "uid": context.uid.as_ref().map(|uid| uid.get()),
        "graphic_access": context.graphic_access,
        "remote": context.remote,
        "availability": context.availability.as_str(),
        "container": context.container.as_str(),
        "display_server": context.display_server.as_str(),
        "compositor": context.compositor.as_ref().cloned(),
        "worker_profile": context.worker_profile.as_str(),
    })
}

/// Renders one capability record.
#[must_use]
pub fn capability(record: &CapabilityRecord) -> Value {
    json!({
        "capability": record.capability.to_string(),
        "version": record.version.get(),
        "revision": record.revision.get(),
        "state": record.state.as_str(),
        "evidence_source": record.evidence_source.as_str(),
        // A capability's own identity and its sentence come from whatever probed it: a binary
        // found on `PATH`, a facility's version string, a platform's own message. The host
        // withholds all three at its export boundary, so what is printed here is what it sent.
        "binary": record.identity.binary.0.as_deref(),
        "facility_identity": record.identity.version.0.as_deref(),
        "profile": record.identity.profile.as_ref().map(|profile| profile.as_str()),
        "invalidation": record
            .invalidation
            .iter()
            .map(|trigger| trigger.as_str())
            .collect::<Vec<_>>(),
        "disabled_reason": record.disabled_reason.0.as_deref(),
        "observed_at_ms": record.observed_at_ms.get(),
    })
}

/// Renders a desktop and what may be done on it.
#[must_use]
pub fn desktop_capabilities(report: &DesktopCapabilityReport) -> Value {
    json!({
        "desktop": desktop(&report.desktop),
        "capabilities": report.records.iter().map(capability).collect::<Vec<_>>(),
    })
}

/// Renders what one environment can currently do.
#[must_use]
pub fn environment_capabilities(result: &EnvironmentCapabilitiesResult) -> Value {
    json!({
        "environment_id": result.environment_id.to_string(),
        "default_worker_profile": result.default_worker_profile.as_str(),
        "desktop": desktop_capabilities(&result.desktop),
        "persistence": result.persistence.iter().map(|entry| json!({
            "profile": entry.profile.as_str(),
            "persistence": entry.persistence.as_str(),
            "mechanism": entry.mechanism().as_str(),
            "detail": entry.detail().as_str(),
        })).collect::<Vec<_>>(),
        "power": power(&result.power),
    })
}

/// Renders the execution context a session is about to be created in.
///
/// It is printed before the request is sent, because which desktop a command will be able to
/// reach is the kind of thing a person wants to know before a shell starts rather than after.
#[must_use]
pub fn execution_context_line(
    profile: kr_protocol::identity::WorkerProfile,
    chosen: bool,
) -> String {
    format!(
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
pub fn desktop_summary_line(report: &DesktopCapabilityReport) -> String {
    let desktop = &report.desktop;
    let Some(name) = desktop.desktop_session_id.as_ref() else {
        return "no graphical login session, so no desktop to bind a session to".to_owned();
    };
    let unavailable = report
        .records
        .iter()
        .filter(|record| !record.state.is_available())
        .count();
    format!(
        "desktop {name} ({}, {}, {} of {} capabilities established)",
        desktop.display_server.as_str(),
        desktop.availability.as_str(),
        report.records.len() - unavailable,
        report.records.len()
    )
}

/// Renders what a logout does to each execution profile, one line each.
#[must_use]
pub fn persistence_lines(persistence: &[kr_protocol::desktop::ProfilePersistence]) -> Vec<String> {
    persistence
        .iter()
        .map(|entry| {
            format!(
                "a {} session at logout: {} ({})",
                entry.profile.as_str(),
                entry.persistence.as_str(),
                entry.mechanism()
            )
        })
        .collect()
}

/// Renders each capability of one desktop as a line for a person.
#[must_use]
pub fn capability_lines(report: &DesktopCapabilityReport) -> Vec<String> {
    report
        .records
        .iter()
        .map(|record| {
            // What the host sent. Both the sentence and the facility name come from whatever
            // probed the capability, and both were withheld at the host's export boundary.
            let detail = record.disabled_reason.as_ref().cloned().unwrap_or_else(|| {
                record
                    .identity
                    .binary
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| "no facility named".to_owned())
            });
            format!(
                "  {:<26} {:<24} {detail}",
                record.capability.to_string(),
                record.state.as_str()
            )
        })
        .collect()
}

/// Renders the desktop a session runs on as a line for a person.
#[must_use]
pub fn desktop_line(summary: &SessionSummary) -> String {
    match summary.desktop.desktop_session_id.as_ref() {
        Some(desktop) => format!(
            "execution context {}: desktop {desktop}",
            summary.worker_profile.as_str()
        ),
        None => format!(
            "execution context {}: no desktop, and none of a desktop's handles",
            summary.worker_profile.as_str()
        ),
    }
}

/// Renders each terminal attachment's presentation and the reason for it.
///
/// Section 8 asks `kr status` to report each terminal attachment's mode and its reason. An
/// attachment that is not a terminal has neither and is left out. A viewport whose worker gave no
/// reason, which a worker built before reasons existed does, says so with a null.
#[must_use]
pub fn terminal_attachments(attachments: &[AttachmentSummary]) -> Value {
    Value::Array(
        attachments
            .iter()
            .filter(|summary| summary.mode == AttachMode::Terminal)
            .map(|summary| {
                json!({
                    "attachment_id": summary.attachment_id.to_string(),
                    "presentation": summary.presentation.as_ref().map(|mode| mode.as_str()),
                    "presentation_reason": summary.presentation_reason.map(|reason| reason.as_str()),
                    "dimensions": summary.dimensions.as_ref().map(|dimensions| json!({
                        "columns": dimensions.columns(),
                        "rows": dimensions.rows(),
                    })),
                    "terminal_profile_id": summary.terminal_profile_id.as_ref().cloned(),
                })
            })
            .collect(),
    )
}

/// Renders each terminal attachment's presentation and its reason as a line for a person.
#[must_use]
pub fn terminal_attachment_lines(attachments: &[AttachmentSummary]) -> Vec<String> {
    attachments
        .iter()
        .filter(|summary| summary.mode == AttachMode::Terminal)
        .map(|summary| {
            let presented = match (
                summary.presentation.as_ref().copied(),
                summary.presentation_reason,
            ) {
                (Some(TerminalPresentationMode::Direct), _) => "direct".to_owned(),
                (Some(TerminalPresentationMode::Viewport), Some(reason)) => {
                    format!("viewport ({}): {}", reason.as_str(), reason.describe())
                }
                (Some(TerminalPresentationMode::Viewport), None) => {
                    "viewport, with no reason reported by this session's worker".to_owned()
                }
                (None, _) => "no presentation reported".to_owned(),
            };
            format!("attachment {}: {presented}", summary.attachment_id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_carries_its_code_and_exit_status() {
        let value = failure(&CliError::AmbiguousSession(Shown::said("3")));
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["code"], json!("AMBIGUOUS_SESSION"));
        assert_eq!(value["exit_code"], json!(5));
    }

    #[test]
    fn the_execution_context_is_named_before_a_session_is_created() {
        let chosen =
            execution_context_line(kr_protocol::identity::WorkerProfile::DesktopBound, true);
        assert!(chosen.contains("desktop_bound"), "{chosen}");
        assert!(chosen.contains("chosen"), "{chosen}");
        let defaulted =
            execution_context_line(kr_protocol::identity::WorkerProfile::HeadlessUser, false);
        assert!(defaulted.contains("headless_user"), "{defaulted}");
        assert!(defaulted.contains("this host's default"), "{defaulted}");
    }

    #[test]
    fn a_session_says_which_desktop_it_runs_on_or_that_it_has_none() {
        let mut summary = summary_for_tests();
        let line = desktop_line(&summary);
        assert!(line.contains("headless_user"), "{line}");
        assert!(line.contains("no desktop"), "{line}");
        assert!(
            session(&summary)["desktop"]["desktop_session_id"].is_null(),
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
        let line = desktop_line(&summary);
        assert!(line.contains("desktop_bound"), "{line}");
        assert!(line.contains("session=100019"), "{line}");
        assert_eq!(
            session(&summary)["desktop"]["login_generation"],
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
        let rendered = terminal_attachments(&attachments);
        let entries = rendered.as_array().expect("a list");
        assert_eq!(
            entries.len(),
            3,
            "the semantic attachment is not a terminal: {rendered}"
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
            lines[0],
            format!("attachment {}: direct", attachments[0].attachment_id)
        );
        assert_eq!(
            lines[1],
            format!(
                "attachment {}: viewport (size_mismatch): its size is not the session's",
                attachments[1].attachment_id
            )
        );
        assert!(lines[2].ends_with("viewport, with no reason reported by this session's worker"));
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
            surviving: vec![kr_protocol::session::SurvivingResource {
                kind: "desktop_resource".to_owned(),
                detail: "a window the broker opened".to_owned(),
            }],
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Volatile,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(9),
        };
        let rendered = closure(&record);
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
        assert_eq!(
            rendered["surviving"],
            json!([{ "kind": "desktop_resource", "detail": "a window the broker opened" }])
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
        assert_eq!(session(&summary)["shell_mode"], json!("native_compat"));
        assert!(session_line(&summary).contains("native_compat"));
        assert!(session_line(&summary).contains("1 attachment"));
    }
}
