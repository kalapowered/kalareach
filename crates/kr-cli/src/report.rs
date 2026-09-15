//! What a command prints.
//!
//! Two audiences, one set of facts. Text for a person is short and says what changed; `--json` is
//! the same information in a shape a script can read, with the stable error code and the exit code
//! a failure carries.
//!
//! Nothing here invents a status. A `native_compat` session is labelled as one everywhere it is
//! reported, because that label is the difference between a session that implements empty-prompt
//! Ctrl-D and one that does not.

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
    })
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
    fn the_shell_mode_is_reported_rather_than_assumed() {
        let summary = SessionSummary {
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
        };
        assert_eq!(session(&summary)["shell_mode"], json!("native_compat"));
        assert!(session_line(&summary).contains("native_compat"));
        assert!(session_line(&summary).contains("1 attachment"));
    }
}
