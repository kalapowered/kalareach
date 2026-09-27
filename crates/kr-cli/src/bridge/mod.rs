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
pub mod pipe;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::identity::{
    EnvironmentEnrolment, EnvironmentInventoryRow, EnvironmentRefreshResult,
};

use crate::cli::BridgeCommand;
use crate::error::Result;
use crate::output::{self, Asked, Document, Request, closed};
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
                if inventory.rows.is_empty() {
                    output::say(&Shown::said("no environments are enrolled"));
                }
                for row in &inventory.rows {
                    let enrolment = &row.enrolment;
                    output::line(&stdout_line!(
                        "{}  {}  {}  {}  {}  last seen {} ms  {}",
                        asked(&enrolment.label),
                        enrolment.access.as_str(),
                        asked(&enrolment.target),
                        asked(&enrolment.os_user),
                        Asked::path(Request::Bridges, &enrolment.helper_path),
                        row.last_observed_at_ms.get(),
                        environments::presence_text(row.status),
                    ));
                    output::say(&shown!(
                        "    {}; {}",
                        environments::observation_text(row.observation),
                        readiness_detail(row)
                    ));
                }
            }
        }
        BridgeCommand::Enrol(arguments) => {
            let enrolled = environments::enrol(arguments).await?;
            if json {
                output::document(&Document::new().with("row", row(&enrolled.row)));
            } else {
                output::line(&stdout_line!(
                    "enrolled {} as environment {}",
                    asked(&enrolled.row.enrolment.label),
                    enrolled.row.enrolment.environment_id
                ));
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
                output::line(&stdout_line!(
                    "{} is {}{}",
                    asked(&refreshed.row.enrolment.label),
                    environments::presence_text(refreshed.row.status),
                    if refreshed.started {
                        ", started by this refresh"
                    } else {
                        ""
                    }
                ));
                // What opening the bridge did, whether it answered or not, as the host's sentence.
                output::say(&shown!("    {}", connection(&refreshed)));
                if let Some(verification) = refreshed.verification.as_ref() {
                    output::say(&shown!(
                        "    speaks protocol {}.{}, carries frames to {} bytes",
                        verification.protocol_version.major,
                        verification.protocol_version.minor,
                        verification.max_frame_len.get()
                    ));
                }
            }
        }
    }
    Ok(())
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
            Asked::path(Request::Bridges, &enrolment.helper_path),
        )
        .with(
            "clipboard_destination",
            enrolment
                .clipboard_destination
                .as_ref()
                .map(|destination| asked(destination)),
        )
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
