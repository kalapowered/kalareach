//! `kr device`: the devices paired with this host, and revoking one.
//!
//! Both go through the control daemon under this user's own authority on this host, which is the
//! local owner's. A listing shows, beside each device, the last authority revision it
//! acknowledged: a device that is offline cannot apply a revocation it has not received, and a
//! person deciding whether a revocation has taken effect needs to see which have answered. A
//! revocation names the device by its identifier and takes every grant the device holds with it.

use kr_ipc::paths::HostPaths;
use kr_protocol::ids::DeviceId;
use kr_protocol::method::Method;
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, DeviceRevokeParams, DeviceSummary, RevocationResult,
};

use kr_protocol::error::{ErrorCode, ProtocolError};

use crate::cli::{DeviceCommand, DeviceListArguments, DeviceRevokeArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

/// Runs one `kr device` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DeviceCommand, json: bool) -> Result<()> {
    match command {
        DeviceCommand::List(arguments) => list(paths, &arguments, json).await,
        DeviceCommand::Revoke(arguments) => revoke(paths, &arguments, json).await,
    }
}

/// `kr device list`.
async fn list(paths: &HostPaths, arguments: &DeviceListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: DeviceListResult = daemon
        .read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: arguments.include_revoked,
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&listed)?);
        return Ok(());
    }
    if listed.devices.is_empty() {
        println!("no paired devices");
    }
    for device in &listed.devices {
        println!("{}", line(device));
    }
    println!(
        "authority revision {}{}",
        listed.authority_revision,
        if listed.feed_stale {
            "; the revocation feed is unreachable, so what is shown may be stale"
        } else {
            ""
        }
    );
    Ok(())
}

/// `kr device revoke`.
///
/// The daemon answers a revocation of a device it never paired as one that revoked nothing, which
/// is right for a repeat and says nothing useful about a mistyped identifier. So the device is
/// looked for first, among the revoked ones too, and one this host never paired is refused with
/// nothing sent. A device paired between the two calls is refused as unknown, and asking again
/// finds it.
async fn revoke(paths: &HostPaths, arguments: &DeviceRevokeArguments, json: bool) -> Result<()> {
    let device: DeviceId = identifier(&arguments.device, "a device")?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let known: DeviceListResult = daemon
        .read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        )
        .await?;
    if !known
        .devices
        .iter()
        .any(|summary| summary.device_id == device)
    {
        return Err(CliError::Refused(ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            format!("no device {device} has been paired with this host, so nothing was revoked"),
        )));
    }
    let revoked: RevocationResult = daemon
        .mutate(
            Method::DeviceRevoke,
            &DeviceRevokeParams { device_id: device },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&revoked)?);
    } else {
        print!("{}", revocation(device, &revoked));
    }
    Ok(())
}

/// What a revocation did, as lines for a person: the grants it took, and how far each affected
/// session's worker has got in fencing what the device could still have been doing.
///
/// The revocation is recorded when this is printed, and it is complete only once every worker's
/// barrier holds. A worker still pending is named with why, and so is every action a worker could
/// not show did not run before the revocation reached it.
fn revocation(device: DeviceId, revoked: &RevocationResult) -> String {
    let grants = revoked.revoked_grants.len();
    let mut text = format!(
        "Revoked device {device} and {grants} grant{}, at authority revision {}.\n",
        if grants == 1 { "" } else { "s" },
        revoked.authority_revision
    );
    let barrier = &revoked.barrier;
    if barrier.workers.is_empty() {
        text.push_str("No session's worker was affected.\n");
    } else if barrier.holds() {
        text.push_str("Every affected session's worker has fenced it.\n");
    } else {
        text.push_str("The revocation is not complete until these sessions' workers fence it:\n");
    }
    for worker in &barrier.workers {
        if !worker.state.holds() {
            text.push_str(&format!(
                "  session {}: {}{}\n",
                worker.session_id,
                worker.state.as_str(),
                if worker.detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", worker.detail)
                }
            ));
        }
        for action in &worker.possibly_executed {
            text.push_str(&format!(
                "  session {}: action {} ({}) may have run before the revocation, and is {}\n",
                worker.session_id,
                action.action_id,
                action.method.as_str(),
                report::wire_name(&action.state)
            ));
        }
    }
    text
}

/// One device as a line for a person.
fn line(device: &DeviceSummary) -> String {
    let standing = if device.revoked {
        "revoked"
    } else if device.manages_host {
        "owner"
    } else {
        "paired"
    };
    let acknowledged = device.acknowledged_revision.as_ref().map_or_else(
        || "no acknowledgement yet".to_owned(),
        |revision| format!("acknowledged revision {revision}"),
    );
    format!(
        "{}  {standing:<8} {}  {acknowledged}",
        device.device_id, device.display_name
    )
}

#[cfg(test)]
mod tests {
    use kr_protocol::action::{
        BarrierState, PossiblyExecutedAction, RevocationBarrier, WorkerBarrier,
    };
    use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision, SessionId};
    use kr_protocol::receipt::ReceiptState;
    use kr_protocol::scalars::{CanonicalSet, Nullable, U64, Uuid};

    use super::*;

    fn worker(byte: u8, state: BarrierState, detail: &str) -> WorkerBarrier {
        WorkerBarrier {
            session_id: SessionId::new(Uuid::from_bytes([byte; 16])),
            state,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: detail.to_owned(),
        }
    }

    fn revoked(workers: Vec<WorkerBarrier>) -> RevocationResult {
        RevocationResult {
            authority_revision: AuthorityRevision::new(4),
            revoked_grants: CanonicalSet::new(),
            barrier: RevocationBarrier {
                authority_revision: AuthorityRevision::new(4),
                workers,
            },
        }
    }

    #[test]
    fn a_worker_still_pending_is_named_with_why() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let mut pending = worker(2, BarrierState::Pending, "the worker has not answered yet");
        pending.possibly_executed.push(PossiblyExecutedAction {
            action_id: ActionId::new(Uuid::from_bytes([3; 16])),
            actor_id: ActorId::new("device:phone").expect("an actor"),
            method: kr_protocol::method::Method::InputWrite.into(),
            state: ReceiptState::Accepted,
        });
        let text = revocation(
            device,
            &revoked(vec![pending, worker(4, BarrierState::Acknowledged, "")]),
        );
        assert!(text.contains("is not complete until"), "{text}");
        assert!(
            text.contains(&format!(
                "session {}: pending (the worker has not answered yet)",
                SessionId::new(Uuid::from_bytes([2; 16]))
            )),
            "{text}"
        );
        assert!(
            text.contains("may have run before the revocation"),
            "{text}"
        );
        assert!(
            !text.contains(&SessionId::new(Uuid::from_bytes([4; 16])).to_string()),
            "a worker whose barrier holds needs no line: {text}"
        );
    }

    #[test]
    fn a_revocation_every_worker_fenced_says_so() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let text = revocation(device, &revoked(vec![worker(2, BarrierState::Ended, "")]));
        assert!(
            text.contains("Every affected session's worker has fenced it."),
            "{text}"
        );
        let text = revocation(device, &revoked(Vec::new()));
        assert!(text.contains("No session's worker was affected."), "{text}");
    }
}
