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

use crate::cli::BridgeCommand;
use crate::error::Result;

/// Runs one `kr bridge` operation and writes its result.
///
/// # Errors
///
/// Returns the daemon's refusal, a usage failure, or a transport failure.
pub async fn print(command: &BridgeCommand, json: bool) -> Result<()> {
    match command {
        BridgeCommand::List(arguments) => {
            let inventory = environments::list(arguments).await?;
            if json {
                println!("{}", to_json(&inventory)?);
            } else {
                if inventory.rows.is_empty() {
                    println!("no environments are enrolled");
                }
                for row in &inventory.rows {
                    println!(
                        "{}  {}  {}  {}  {}  last seen {} ms  {}",
                        row.enrolment.label,
                        row.enrolment.access.as_str(),
                        row.enrolment.target,
                        row.enrolment.os_user,
                        row.enrolment.helper_path,
                        row.last_observed_at_ms.get(),
                        environments::presence_text(row.status),
                    );
                    println!(
                        "    {}; {}",
                        environments::observation_text(row.observation),
                        row.readiness.detail
                    );
                }
            }
        }
        BridgeCommand::Enrol(arguments) => {
            let enrolled = environments::enrol(arguments).await?;
            if json {
                println!("{}", to_json(&enrolled)?);
            } else {
                println!(
                    "enrolled {} as environment {}",
                    enrolled.row.enrolment.label, enrolled.row.enrolment.environment_id
                );
            }
        }
        BridgeCommand::Forget(arguments) => {
            let removed = environments::forget(arguments).await?;
            if json {
                println!("{}", to_json(&removed)?);
            } else if removed.forgotten {
                println!("forgot {}", arguments.label);
            } else {
                println!("{} was not enrolled", arguments.label);
            }
        }
        BridgeCommand::Refresh(arguments) => {
            let refreshed = environments::refresh(arguments).await?;
            if json {
                println!("{}", to_json(&refreshed)?);
            } else {
                println!(
                    "{} is {}{}",
                    refreshed.row.enrolment.label,
                    environments::presence_text(refreshed.row.status),
                    if refreshed.started {
                        ", started by this refresh"
                    } else {
                        ""
                    }
                );
                // What opening the bridge did, whether it answered or not. A person reading this
                // after a failure has the program, the environment or the refusal in front of them.
                println!("    {}", refreshed.connection);
                if let Some(verification) = refreshed.verification.as_ref() {
                    println!(
                        "    speaks protocol {}.{}, carries frames to {} bytes",
                        verification.protocol_version.major,
                        verification.protocol_version.minor,
                        verification.max_frame_len.get()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Renders one result as the machine-readable form.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|error| {
        crate::error::CliError::Other(kr_client::shown!(
            "the result could not be written: {}",
            kr_client::shown::Shown::json(&error)
        ))
    })
}
