//! `kr device`: the devices paired with this host, and revoking one.
//!
//! Both go through the control daemon under this user's own authority on this host, which is the
//! local owner's. A listing shows, beside each device, the last authority revision it
//! acknowledged: a device that is offline cannot apply a revocation it has not received, and a
//! person deciding whether a revocation has taken effect needs to see which have answered. A
//! revocation names the device by its identifier and takes every grant the device holds with it.

use kr_client::shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::DeviceId;
use kr_protocol::method::Method;
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, DeviceRevokeParams, DeviceSummary, RevocationResult,
};

use kr_client::error::refusal;
use kr_protocol::error::ErrorCode;

use crate::cli::{DeviceCommand, DeviceListArguments, DeviceRevokeArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report::{self, Completion};

/// Runs one `kr device` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DeviceCommand, json: bool) -> Result<Completion> {
    match command {
        DeviceCommand::List(arguments) => list(paths, &arguments, json)
            .await
            .map(|()| Completion::Done),
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
///
/// A revocation is complete only once every affected session's worker has fenced it. Until then
/// it is pending, never a success: the command prints what it did and which workers it waits for,
/// and fails. Asking again is answered with the revocation as it then stands.
async fn revoke(
    paths: &HostPaths,
    arguments: &DeviceRevokeArguments,
    json: bool,
) -> Result<Completion> {
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
        return Err(CliError::Refused(refusal(
            ErrorCode::ResourceUnavailable,
            shown!(
                "no device {} has been paired with this host, so nothing was revoked",
                device
            ),
        )));
    }
    let revoked: RevocationResult = daemon
        .mutate(
            Method::DeviceRevoke,
            &DeviceRevokeParams { device_id: device },
        )
        .await?;
    let pending = pending(device, &revoked);
    match (&pending, json) {
        (None, true) => report::print_json(&report::answer(&revoked)?),
        (Some(error), true) => report::print_json(&report::answer_that_failed(&revoked, error)?),
        (None, false) => print!("{}", revocation(device, &revoked)),
        (Some(error), false) => {
            print!("{}", revocation(device, &revoked));
            report::failed(error);
        }
    }
    Ok(pending.map_or(Completion::Done, Completion::Reported))
}

/// The failure a revocation some worker has not fenced yet is reported as, or none when every
/// affected worker's barrier holds.
fn pending(device: DeviceId, revoked: &RevocationResult) -> Option<CliError> {
    let waiting = revoked.barrier.pending();
    if waiting.is_empty() {
        return None;
    }
    Some(CliError::Unfinished {
        code: ErrorCode::ResourceUnavailable,
        message: shown!(
            "the revocation of device {} is recorded and still pending: {} session \
             worker{} {} not fenced it yet, and asking again reports how far it has got",
            device,
            waiting.len(),
            if waiting.len() == 1 { "" } else { "s" },
            if waiting.len() == 1 { "has" } else { "have" }
        ),
    })
}

/// What a revocation did, as lines for a person: the grants it took, and how far each affected
/// session's worker has got in fencing what the device could still have been doing.
///
/// A worker still pending is named with why. So is a worker whose barrier holds but whose
/// evidence is not all here: names the host has not received yet, actions the worker could hold
/// no name for, or anything else the host says about it. Every action a worker could not show did
/// not run before the revocation reached it is named too.
fn revocation(device: DeviceId, revoked: &RevocationResult) -> String {
    let grants = revoked.revoked_grants.len();
    let barrier = &revoked.barrier;
    let mut text = if barrier.holds() {
        format!(
            "Revoked device {device} and {grants} grant{}, at authority revision {}.\n",
            if grants == 1 { "" } else { "s" },
            revoked.authority_revision
        )
    } else {
        format!(
            "The revocation of device {device} is pending, at authority revision {}: {grants} \
             grant{} revoked, and it is complete only when these sessions' workers fence it.\n",
            revoked.authority_revision,
            if grants == 1 { "" } else { "s" }
        )
    };
    if barrier.workers.is_empty() {
        text.push_str("No session's worker was affected.\n");
    } else if barrier.holds() {
        text.push_str("Every affected session's worker has fenced it.\n");
    }
    for worker in &barrier.workers {
        let names_pending = worker.names_pending.get();
        let omitted = worker.omitted_actions.get();
        if !worker.state.holds() || !worker.detail.is_empty() || names_pending > 0 || omitted > 0 {
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
        if names_pending > 0 {
            text.push_str(&format!(
                "  session {}: {names_pending} action name{} not reached this host yet\n",
                worker.session_id,
                if names_pending == 1 { " has" } else { "s have" }
            ));
        }
        if omitted > 0 {
            text.push_str(&format!(
                "  session {}: {omitted} affected action{} could not be named\n",
                worker.session_id,
                if omitted == 1 { "" } else { "s" }
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
        assert!(
            text.contains("is pending, at authority revision 4"),
            "{text}"
        );
        assert!(
            !text.contains("Revoked device"),
            "a pending revocation is no success: {text}"
        );
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
    fn a_pending_revocation_is_a_failure_and_a_complete_one_is_not() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let waiting = revoked(vec![
            worker(2, BarrierState::Pending, ""),
            worker(3, BarrierState::Acknowledged, ""),
        ]);
        let error = pending(device, &waiting).expect("pending is not success");
        assert_eq!(error.code(), "RESOURCE_UNAVAILABLE");
        assert_eq!(error.exit_code(), 1);
        assert!(
            error
                .to_string()
                .contains("1 session worker has not fenced it"),
            "{error}"
        );
        assert!(pending(device, &revoked(vec![worker(3, BarrierState::Ended, "")])).is_none());
        assert!(pending(device, &revoked(Vec::new())).is_none());
    }

    #[test]
    fn a_worker_that_fenced_it_with_evidence_missing_says_what_is_missing() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let mut late = worker(
            5,
            BarrierState::Acknowledged,
            "a page of names is still to come",
        );
        late.names_pending = U64::new(3);
        let mut unnamed = worker(6, BarrierState::Ended, "");
        unnamed.omitted_actions = U64::new(1);
        let quiet = worker(7, BarrierState::Acknowledged, "");
        let text = revocation(device, &revoked(vec![late, unnamed, quiet]));
        let session = |byte| SessionId::new(Uuid::from_bytes([byte; 16])).to_string();
        assert!(
            text.contains(&format!(
                "session {}: acknowledged (a page of names is still to come)",
                session(5)
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "session {}: 3 action names have not reached this host yet",
                session(5)
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "session {}: 1 affected action could not be named",
                session(6)
            )),
            "{text}"
        );
        assert!(
            !text.contains(&session(7)),
            "nothing to say about it: {text}"
        );
        assert!(
            text.contains("Every affected session's worker has fenced it."),
            "{text}"
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
