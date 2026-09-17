//! What a command prints.
//!
//! Two audiences, one set of facts. Text for a person is short and says what changed; `--json` is
//! the same information in a shape a script can read, with the stable error code and the exit code
//! a failure carries.
//!
//! Nothing here invents a status. A `native_compat` session is labelled as one everywhere it is
//! reported, because that label is the difference between a session that implements empty-prompt
//! Ctrl-D and one that does not.

use kr_protocol::desktop::{
    CapabilityRecord, DesktopCapabilityReport, DesktopContext, EnvironmentCapabilitiesResult,
    SleepInhibitionState,
};
use kr_protocol::hostinfo::{HostDoctorResult, HostInfoResult};
use kr_protocol::session::{SessionState, SessionSummary};
use serde_json::{Value, json};

use crate::error::CliError;

/// Renders a failure as machine-readable output.
#[must_use]
pub fn failure(error: &CliError) -> Value {
    json!({
        "ok": false,
        "code": error.code(),
        "message": error.to_string(),
        "exit_code": error.exit_code(),
    })
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
        "closure": summary.closure.as_ref().map(|closure| json!({
            "reason": closure.reason.as_str(),
            "exit_code": closure.root_exit_code.as_ref().map(|code| code.get()),
            "signal": closure.root_signal.as_ref().cloned(),
            "ownership_coverage": match closure.ownership_coverage {
                kr_protocol::session::OwnershipCoverage::Complete => "complete",
                kr_protocol::session::OwnershipCoverage::Incomplete => "incomplete",
            },
            "durability": match closure.durability {
                kr_protocol::session::Durability::Durable => "durable",
                kr_protocol::session::Durability::Volatile => "volatile",
            },
            "closed_at_ms": closure.closed_at_ms.get(),
        })),
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
        "binary": record.identity.binary.as_ref().cloned(),
        "facility_identity": record.identity.version.as_ref().cloned(),
        "profile": record.identity.profile.as_ref().map(|profile| profile.as_str()),
        "invalidation": record
            .invalidation
            .iter()
            .map(|trigger| trigger.as_str())
            .collect::<Vec<_>>(),
        "disabled_reason": record.disabled_reason.as_ref().cloned(),
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
            "mechanism": entry.mechanism,
            "detail": entry.detail,
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
                entry.mechanism
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
            "execution context {}: no desktop, so no inherited graphical access",
            summary.worker_profile.as_str()
        ),
    }
}

/// Renders diagnostics.
#[must_use]
pub fn doctor(result: &HostDoctorResult) -> Value {
    json!({
        "healthy": result.healthy,
        "checks": result.checks.iter().map(|check| json!({
            "id": check.id,
            "title": check.title,
            "status": check.status.as_str(),
            "detail": check.detail,
            "remedy": check.remedy.as_ref().cloned(),
        })).collect::<Vec<_>>(),
    })
}

/// Renders diagnostics as lines for a person.
#[must_use]
pub fn doctor_lines(result: &HostDoctorResult) -> String {
    let mut text = String::new();
    for check in &result.checks {
        text.push_str(&format!(
            "{:<10} {}\n           {}\n",
            check.status.as_str(),
            check.title,
            check.detail
        ));
        if let Some(remedy) = check.remedy.as_ref() {
            text.push_str(&format!("           {remedy}\n"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_carries_its_code_and_exit_status() {
        let value = failure(&CliError::AmbiguousSession("3".to_owned()));
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

    #[test]
    fn the_shell_mode_is_reported_rather_than_assumed() {
        let summary = summary_for_tests();
        assert_eq!(session(&summary)["shell_mode"], json!("native_compat"));
        assert!(session_line(&summary).contains("native_compat"));
        assert!(session_line(&summary).contains("1 attachment"));
    }
}
