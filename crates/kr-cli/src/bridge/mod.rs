//! The process-bridge helper, and the enrolled environments it serves.
//!
//! Section 3 gives the local cross-environment command-line path one shape: an explicit process
//! bridge. Windows runs `wsl.exe --distribution <name> --user <user> --exec <absolute-kr-path>
//! bridge --stdio`, and a container host runs the equivalent against an enrolled container
//! identifier. The child this produces is the helper in this module. It authenticates to its own
//! environment's control daemon or worker through local IPC and carries bounded protocol frames on
//! its standard input and output, keeping standard error for diagnostics.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`pipe`] | The bounded frame codec over the standard streams, and the refusal that replaces a frame nobody may read |
//! | [`helper`] | `kr bridge --stdio`: the handshake, the admission rule and the relay |
//! | [`link`] | The connection an attached terminal speaks over, local or bridged |
//! | [`session`] | `kr new` and `kr attach` for a session in an enrolled environment |
//! | [`environments`] | `kr bridge list`, `enrol`, `forget` and `refresh` against this host's own daemon |
//!
//! **What the helper refuses, and why it is refused here as well as at the invoker.** The bridges
//! serve locally authenticated command-line invocations only. A Windows controller must never
//! route a network actor through one and relabel it a Linux local owner, so the invoker refuses to
//! open a bridge for a remote actor and this helper refuses a handshake that declares one. Neither
//! check is redundant: the invoker's is the one that holds when the invoker is this product, and
//! this one is what a destination environment can enforce for itself. A declaration can never
//! widen anything, because the destination still authenticates the helper by its own
//! operating-system credentials; what it can do is make an invoker's mistake a refusal rather
//! than a silent relabelling.
//!
//! **No Linux socket is opened from Windows.** The helper runs inside the destination, so the
//! socket or named pipe it connects to is its own environment's. Nothing here assumes a localhost
//! forwarding mode, and nothing here reads an environment variable for authority.

pub mod environments;
pub mod helper;
pub mod link;
pub mod pipe;
pub mod session;

use kr_client::shown::Shown;
use kr_protocol::identity::{
    EnvironmentEnrolment, EnvironmentInventoryRow, EnvironmentRefreshResult,
};

use crate::cli::BridgeCommand;
use crate::error::Result;
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::stdout_line;

/// Runs one `kr bridge` operation and writes its result.
///
/// An enrolment's label, target, user and helper are what the person recorded, shown to them; what
/// the host says of a bridge's readiness and of opening one is its sentence, said as its class and
/// its length.
///
/// # Errors
///
/// Returns the daemon's refusal, a usage failure, or a transport failure.
pub async fn print(command: &BridgeCommand, json: bool) -> Result<()> {
    match command {
        BridgeCommand::List(arguments) => {
            let inventory = environments::list(arguments).await?;
            if json {
                output::document(
                    &Document::new()
                        .with("rows", inventory.rows.iter().map(row).collect::<Vec<_>>()),
                );
            } else {
                output::lines(&list_lines(&inventory.rows));
            }
        }
        BridgeCommand::Enrol(arguments) => {
            let enrolled = environments::enrol(arguments).await?;
            if json {
                output::document(&Document::new().with("row", row(&enrolled.row)));
            } else {
                output::line(&enrolled_line(&enrolled.row));
            }
        }
        BridgeCommand::Forget(arguments) => {
            let removed = environments::forget(arguments).await?;
            if json {
                output::document(&Document::new().with("forgotten", removed.forgotten));
            } else if removed.forgotten {
                output::line(&stdout_line!("forgot {}", asked(&arguments.label)));
            } else {
                output::line(&stdout_line!(
                    "{} was not enrolled",
                    asked(&arguments.label)
                ));
            }
        }
        BridgeCommand::Refresh(arguments) => {
            let refreshed = environments::refresh(arguments).await?;
            if json {
                output::document(&refresh(&refreshed));
            } else {
                output::lines(&refresh_lines(&refreshed));
            }
        }
    }
    Ok(())
}

/// The inventory as lines for a person: each row, and what was observed of it.
fn list_lines(rows: &[EnvironmentInventoryRow]) -> Vec<Line> {
    if rows.is_empty() {
        return vec![stdout_line!("no environments are enrolled")];
    }
    let mut lines = Vec::new();
    for row in rows {
        let enrolment = &row.enrolment;
        lines.push(stdout_line!(
            "{}  {}  {}  {}  {}  last seen {} ms  {}",
            asked(&enrolment.label),
            enrolment.access.as_str(),
            asked(&enrolment.target),
            asked(&enrolment.os_user),
            Asked::text(Request::Bridges, &enrolment.helper_path),
            row.last_observed_at_ms.get(),
            environments::presence_text(row.status),
        ));
        lines.push(stdout_line!(
            "    {}; {}",
            environments::observation_text(row.observation),
            readiness_detail(row)
        ));
    }
    lines
}

/// What enrolling an environment tells a person.
fn enrolled_line(row: &EnvironmentInventoryRow) -> Line {
    stdout_line!(
        "enrolled {} as environment {}",
        asked(&row.enrolment.label),
        row.enrolment.environment_id
    )
}

/// What a refresh tells a person: the row, what opening the bridge did, whether it answered or
/// not, as the host's sentence, and what the helper said it speaks.
fn refresh_lines(refreshed: &EnvironmentRefreshResult) -> Vec<Line> {
    let mut lines = vec![
        stdout_line!(
            "{} is {}{}",
            asked(&refreshed.row.enrolment.label),
            environments::presence_text(refreshed.row.status),
            if refreshed.started {
                ", started by this refresh"
            } else {
                ""
            }
        ),
        stdout_line!("    {}", connection(refreshed)),
    ];
    if let Some(verification) = refreshed.verification.as_ref() {
        lines.push(stdout_line!(
            "    speaks protocol {}.{}, carries frames to {} bytes",
            verification.protocol_version.major,
            verification.protocol_version.minor,
            verification.max_frame_len.get()
        ));
    }
    lines
}

/// What an enrolment holds, which its owner recorded.
fn asked(text: &str) -> Asked {
    Asked::text(Request::Bridges, text)
}

/// What the host says of a bridge's readiness, as its class and its length.
fn readiness_detail(row: &EnvironmentInventoryRow) -> Shown {
    crate::shown::exported("EnvironmentReadiness", "detail", &row.readiness.detail)
}

/// What the host says opening a bridge did, as its class and its length.
fn connection(refreshed: &EnvironmentRefreshResult) -> Shown {
    crate::shown::exported(
        "EnvironmentRefreshResult",
        "connection",
        &refreshed.connection,
    )
}

/// An enrolment, in the shape the protocol answers it.
fn enrolment(enrolment: &EnvironmentEnrolment) -> Document {
    Document::new()
        .with("environment_id", closed(&enrolment.environment_id))
        .with("access", closed(&enrolment.access))
        .with("label", asked(&enrolment.label))
        .with("target", asked(&enrolment.target))
        .with("os_user", asked(&enrolment.os_user))
        .with(
            "helper_path",
            Asked::text(Request::Bridges, &enrolment.helper_path),
        )
        .with(
            "clipboard_destination",
            enrolment
                .clipboard_destination
                .as_ref()
                .map(|destination| asked(destination)),
        )
        // Whether the destination does anything, which a record kept from before a destination had
        // to be one the host delivers to can say differently from the text it holds.
        .with("takes_clipboard_writes", enrolment.takes_clipboard_writes())
        .with("approved_at_ms", closed(&enrolment.approved_at_ms))
}

/// A row of the inventory, in the shape the protocol answers it.
fn row(row: &EnvironmentInventoryRow) -> Document {
    Document::new()
        .with("enrolment", enrolment(&row.enrolment))
        .with("last_observed_at_ms", closed(&row.last_observed_at_ms))
        .with("status", closed(&row.status))
        .with("observation", closed(&row.observation))
        .with(
            "readiness",
            Document::new()
                .with("helper_enrolled", row.readiness.helper_enrolled)
                .with("channel_scoped", row.readiness.channel_scoped)
                .with("detail", readiness_detail(row)),
        )
}

/// A refresh, in the shape the protocol answers it.
fn refresh(refreshed: &EnvironmentRefreshResult) -> Document {
    Document::new()
        .with("row", row(&refreshed.row))
        .with("started", refreshed.started)
        .with(
            "verification",
            refreshed.verification.as_ref().map(|verification| {
                Document::new()
                    .with("environment_id", closed(&verification.environment_id))
                    .with("os_user", asked(&verification.os_user))
                    .with("role", closed(&verification.role))
                    .with("protocol_version", closed(&verification.protocol_version))
                    .with("max_frame_len", closed(&verification.max_frame_len))
            }),
        )
        .with("connection", connection(refreshed))
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::{
        EnvironmentEnrolResult, EnvironmentInventoryResult, EnvironmentRefreshResult,
    };

    use super::*;
    use crate::output::planted::{only_asked, only_asked_lines, planted, planted_text};
    use crate::shown::marker::MARKER;

    /// KR-REQ-18.11: a record that holds a destination this host does not deliver to is shown as one
    /// that takes no clipboard writes, whatever text it holds, and one that names the terminal as
    /// one that does.
    #[test]
    fn a_stored_destination_the_host_does_not_deliver_to_is_shown_as_taking_none() {
        let mut record = EnvironmentEnrolment {
            environment_id: kr_protocol::ids::EnvironmentId::new(
                kr_protocol::scalars::Uuid::from_bytes([7; 16]),
            ),
            access: kr_protocol::identity::EnvironmentAccess::WslDistribution,
            label: "dest".to_owned(),
            target: "Ubuntu".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: kr_protocol::scalars::Nullable::some(
                "clipboard-sync".to_owned(),
            ),
            approved_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        };
        assert_eq!(enrolment(&record).json()["takes_clipboard_writes"], false);
        record.clipboard_destination = kr_protocol::scalars::Nullable::null();
        assert_eq!(enrolment(&record).json()["takes_clipboard_writes"], false);
        record.clipboard_destination = kr_protocol::scalars::Nullable::some(
            kr_protocol::identity::CLIPBOARD_DESTINATION_TERMINAL.to_owned(),
        );
        assert_eq!(enrolment(&record).json()["takes_clipboard_writes"], true);
    }

    /// KR-REQ-23.25: planted text in the bridge's answers shows only where the person asked for it
    /// (what they recorded of an enrolment: its label, target, user, helper and clipboard
    /// destination, and the user a helper verified), in the documents and in the lines. What the
    /// host says of a bridge's readiness and of opening one is said as its class and its length.
    #[test]
    fn planted_text_in_the_bridge_shows_only_where_it_was_asked_for() {
        let mut shown = std::collections::BTreeSet::new();
        for inventory in planted::<EnvironmentInventoryResult>() {
            shown.extend(only_asked(
                "kr bridge list",
                &Document::new().with("rows", inventory.rows.iter().map(row).collect::<Vec<_>>()),
            ));
            only_asked_lines("kr bridge list", &list_lines(&inventory.rows));
        }
        for enrolled in planted::<EnvironmentEnrolResult>() {
            shown.extend(only_asked(
                "kr bridge enrol",
                &Document::new().with("row", row(&enrolled.row)),
            ));
            only_asked_lines("kr bridge enrol", &[enrolled_line(&enrolled.row)]);
        }
        for refreshed in planted::<EnvironmentRefreshResult>() {
            shown.extend(only_asked("kr bridge refresh", &refresh(&refreshed)));
            only_asked_lines("kr bridge refresh", &refresh_lines(&refreshed));
            let withheld = format!("[message withheld, {} bytes]", planted_text().len());
            assert_eq!(
                refresh(&refreshed).json()["connection"],
                serde_json::json!(withheld)
            );
            assert!(!connection(&refreshed).as_str().contains(MARKER));
        }
        for asked in [
            "rows[].enrolment.label",
            "rows[].enrolment.target",
            "rows[].enrolment.os_user",
            "rows[].enrolment.helper_path",
            "rows[].enrolment.clipboard_destination",
            "row.enrolment.label",
            "verification.os_user",
        ] {
            assert!(
                shown.contains(asked),
                "{asked} shows what was asked for: {shown:?}"
            );
        }
    }
}
