//! `kr device`: the devices paired with this host, and revoking one.
//!
//! Both go through the control daemon under this user's own authority on this host, which is the
//! local owner's. A listing shows, beside each device, the last authority revision it
//! acknowledged: a device that is offline cannot apply a revocation it has not received, and a
//! person deciding whether a revocation has taken effect needs to see which have answered. A
//! revocation names the device by its identifier and takes every grant the device holds with it.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::DeviceId;
use kr_protocol::method::Method;
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, DeviceRevokeParams, DeviceSummary, RevocationResult,
};

use kr_protocol::error::ErrorCode;

use crate::cli::{DeviceCommand, DeviceListArguments, DeviceRevokeArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed, left};
use crate::report::{self, Completion};
use crate::stdout_line;

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
        output::document(&list_document(&listed));
        return Ok(());
    }
    if listed.devices.is_empty() {
        output::say(&Shown::said("no paired devices"));
    }
    for device in &listed.devices {
        output::line(&line(device));
    }
    output::say(&shown!(
        "authority revision {}{}",
        listed.authority_revision,
        if listed.feed_stale {
            "; the revocation feed is unreachable, so what is shown may be stale"
        } else {
            ""
        }
    ));
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
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::ResourceUnavailable,
            shown!(
                "no device {} has been paired with this host, so nothing was revoked",
                device
            ),
        ));
    }
    let revoked: RevocationResult = daemon
        .mutate(
            Method::DeviceRevoke,
            &DeviceRevokeParams { device_id: device },
        )
        .await?;
    let pending = pending(device, &revoked);
    match (&pending, json) {
        (None, true) => output::document(&revocation_document(&revoked)),
        (Some(error), true) => {
            output::document(&report::with_failure(revocation_document(&revoked), error))
        }
        (None, false) => output::lines(&revocation(device, &revoked)),
        (Some(error), false) => {
            output::lines(&revocation(device, &revoked));
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
    // A cut list names the workers still waiting before any that is not, so what it shows is a
    // floor: how many are waiting in all is not said.
    let cut = revoked.barrier.workers_total.get() > revoked.barrier.workers.len() as u64;
    Some(CliError::Unfinished {
        code: ErrorCode::ResourceUnavailable,
        message: shown!(
            "the revocation of device {} is recorded and still pending: {}{} session \
             worker{} {} not fenced it yet, and asking again reports how far it has got",
            device,
            if cut { "at least " } else { "" },
            waiting.len(),
            if waiting.len() == 1 { "" } else { "s" },
            if waiting.len() == 1 { "has" } else { "have" }
        ),
    })
}

/// The paired devices, for a script, in the shape the protocol answers them: the name each device
/// gave itself is shown to the person who asked for the list.
fn list_document(listed: &DeviceListResult) -> Document {
    Document::new()
        .with(
            "devices",
            listed
                .devices
                .iter()
                .map(|device| {
                    Document::new()
                        .with("device_id", closed(&device.device_id))
                        .with(
                            "display_name",
                            Asked::text(Request::Devices, &device.display_name),
                        )
                        .with("grant_id", closed(&device.grant_id))
                        .with("paired_at_ms", closed(&device.paired_at_ms))
                        .with(
                            "acknowledged_revision",
                            closed(&device.acknowledged_revision),
                        )
                        .with("acknowledged_at_ms", closed(&device.acknowledged_at_ms))
                        .with("revoked", device.revoked)
                        .with("keys", closed(&device.keys))
                        .with("manages_host", device.manages_host)
                })
                .collect::<Vec<_>>(),
        )
        .with("authority_revision", closed(&listed.authority_revision))
        .with(
            "feed_synchronised_at_ms",
            closed(&listed.feed_synchronised_at_ms),
        )
        .with("feed_stale", listed.feed_stale)
        .with("ok", true)
}

/// A revocation, for a script, in the shape the protocol answers it: the actors and the methods of
/// the actions it names are what the host recorded for the person revoking, and a worker's detail
/// is the host's sentence, said as its class and length.
fn revocation_document(revoked: &RevocationResult) -> Document {
    Document::new()
        .with("authority_revision", closed(&revoked.authority_revision))
        .with("revoked_grants", closed(&revoked.revoked_grants))
        .with(
            "revoked_grants_total",
            closed(&revoked.revoked_grants_total),
        )
        .with(
            "barrier",
            Document::new()
                .with(
                    "authority_revision",
                    closed(&revoked.barrier.authority_revision),
                )
                .with("workers_total", closed(&revoked.barrier.workers_total))
                .with(
                    "workers",
                    revoked
                        .barrier
                        .workers
                        .iter()
                        .map(|worker| {
                            Document::new()
                                .with("session_id", closed(&worker.session_id))
                                .with("state", closed(&worker.state))
                                .with(
                                    "acknowledged_revision",
                                    closed(&worker.acknowledged_revision),
                                )
                                .with(
                                    "rejected_actions",
                                    worker
                                        .rejected_actions
                                        .iter()
                                        .map(|action| {
                                            Document::new()
                                                .with(
                                                    "actor_id",
                                                    Asked::text(
                                                        Request::Devices,
                                                        &action.actor_id.to_string(),
                                                    ),
                                                )
                                                .with("action_id", closed(&action.action_id))
                                        })
                                        .collect::<Vec<_>>(),
                                )
                                .with(
                                    "possibly_executed",
                                    worker
                                        .possibly_executed
                                        .iter()
                                        .map(|action| {
                                            Document::new()
                                                .with("action_id", closed(&action.action_id))
                                                .with(
                                                    "actor_id",
                                                    Asked::text(
                                                        Request::Devices,
                                                        &action.actor_id.to_string(),
                                                    ),
                                                )
                                                .with(
                                                    "method",
                                                    Asked::text(
                                                        Request::Devices,
                                                        action.method.as_str(),
                                                    ),
                                                )
                                                .with("state", closed(&action.state))
                                        })
                                        .collect::<Vec<_>>(),
                                )
                                .with(
                                    "rejected_actions_total",
                                    closed(&worker.rejected_actions_total),
                                )
                                .with(
                                    "possibly_executed_total",
                                    closed(&worker.possibly_executed_total),
                                )
                                .with("omitted_actions", closed(&worker.omitted_actions))
                                .with("names_pending", closed(&worker.names_pending))
                                .with(
                                    "detail",
                                    crate::shown::exported(
                                        "WorkerBarrier",
                                        "detail",
                                        &worker.detail,
                                    ),
                                )
                        })
                        .collect::<Vec<_>>(),
                ),
        )
        .with("ok", true)
}

/// What a revocation did, as lines for a person: the grants it took, and how far each affected
/// session's worker has got in fencing what the device could still have been doing.
///
/// A worker still pending is named with why. So is a worker whose barrier holds but whose
/// evidence is not all here: names the host has not received yet, actions the worker could hold
/// no name for, or anything else the host says about it. Every action a worker could not show did
/// not run before the revocation reached it is named too.
fn revocation(device: DeviceId, revoked: &RevocationResult) -> Vec<Line> {
    let grants = usize::try_from(revoked.revoked_grants_total.get()).unwrap_or(usize::MAX);
    let barrier = &revoked.barrier;
    let mut lines = vec![if barrier.holds() {
        stdout_line!(
            "Revoked device {} and {} grant{}, at authority revision {}.",
            device,
            grants,
            if grants == 1 { "" } else { "s" },
            revoked.authority_revision
        )
    } else {
        stdout_line!(
            "The revocation of device {} is pending, at authority revision {}: {} grant{} \
             revoked, and it is complete only when these sessions' workers fence it.",
            device,
            revoked.authority_revision,
            grants,
            if grants == 1 { "" } else { "s" }
        )
    }];
    if barrier.workers.is_empty() {
        lines.push(stdout_line!("No session's worker was affected."));
    } else if barrier.holds() {
        lines.push(stdout_line!(
            "Every affected session's worker has fenced it."
        ));
    }
    for worker in &barrier.workers {
        let names_pending = worker.names_pending.get();
        let omitted = worker.omitted_actions.get();
        if !worker.state.holds() || !worker.detail.is_empty() || names_pending > 0 || omitted > 0 {
            lines.push(if worker.detail.is_empty() {
                stdout_line!("  session {}: {}", worker.session_id, worker.state.as_str())
            } else {
                stdout_line!(
                    "  session {}: {} ({})",
                    worker.session_id,
                    worker.state.as_str(),
                    crate::shown::exported("WorkerBarrier", "detail", &worker.detail)
                )
            });
        }
        if names_pending > 0 {
            lines.push(stdout_line!(
                "  session {}: {} action name{} not reached this host yet",
                worker.session_id,
                names_pending,
                if names_pending == 1 { " has" } else { "s have" }
            ));
        }
        if omitted > 0 {
            lines.push(stdout_line!(
                "  session {}: {} affected action{} could not be named",
                worker.session_id,
                omitted,
                if omitted == 1 { "" } else { "s" }
            ));
        }
        for action in &worker.possibly_executed {
            lines.push(stdout_line!(
                "  session {}: action {} ({}) may have run before the revocation, and is {}",
                worker.session_id,
                action.action_id,
                Asked::text(Request::Devices, action.method.as_str()),
                crate::shown::wire_word(action.state)
            ));
        }
        // An answer carries as many of the names as one frame can, and says how many there were.
        let left_out = worker
            .possibly_executed_total
            .get()
            .saturating_sub(worker.possibly_executed.len() as u64);
        if left_out > 0 {
            lines.push(stdout_line!(
                "  session {}: {} more action{} may have run before the revocation, and {} not \
                 named here",
                worker.session_id,
                left_out,
                if left_out == 1 { "" } else { "s" },
                if left_out == 1 { "is" } else { "are" }
            ));
        }
    }
    let workers_left_out = barrier
        .workers_total
        .get()
        .saturating_sub(barrier.workers.len() as u64);
    if workers_left_out > 0 {
        lines.push(stdout_line!(
            "{} more session worker{} {} not listed here.",
            workers_left_out,
            if workers_left_out == 1 { "" } else { "s" },
            if workers_left_out == 1 { "is" } else { "are" }
        ));
    }
    lines
}

/// One device as a line for a person: the name it gave itself is shown to the person who asked.
fn line(device: &DeviceSummary) -> Line {
    let standing = if device.revoked {
        "revoked"
    } else if device.manages_host {
        "owner"
    } else {
        "paired"
    };
    let acknowledged = device.acknowledged_revision.as_ref().map_or_else(
        || Shown::said("no acknowledgement yet"),
        |revision| shown!("acknowledged revision {}", *revision),
    );
    stdout_line!(
        "{}  {} {}  {}",
        device.device_id,
        left(8, &standing),
        Asked::text(Request::Devices, &device.display_name),
        acknowledged
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

    /// KR-REQ-23.25: text planted in every leaf of a device list and a revocation that can hold
    /// free text reaches their documents and lines only as a device's own name and the actors and
    /// methods a revocation names; a worker's detail is said as its class and length, and every
    /// other leaf is what the protocol encodes.
    #[test]
    fn planted_text_in_devices_shows_only_where_it_was_asked_for() {
        use crate::output::planted::{
            only_asked, only_asked_lines, planted, planted_text, same_encoding,
        };

        let mut shown = std::collections::BTreeSet::new();
        for listed in planted::<DeviceListResult>() {
            let document = list_document(&listed);
            shown.extend(only_asked("kr device list", &document));
            same_encoding(
                "kr device list",
                &document,
                &serde_json::to_value(&listed).expect("the list encodes"),
                &[],
                &["ok"],
            );
            only_asked_lines(
                "kr device list",
                &listed.devices.iter().map(line).collect::<Vec<_>>(),
            );
        }
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        for revoked in planted::<RevocationResult>() {
            let document = revocation_document(&revoked);
            shown.extend(only_asked("kr device revoke", &document));
            same_encoding(
                "kr device revoke",
                &document,
                &serde_json::to_value(&revoked).expect("the revocation encodes"),
                &["barrier.workers[].detail"],
                &["ok"],
            );
            assert_eq!(
                document.json()["barrier"]["workers"][0]["detail"],
                serde_json::json!(format!(
                    "[message withheld, {} bytes]",
                    planted_text().len()
                ))
            );
            only_asked_lines("kr device revoke", &revocation(device, &revoked));
        }
        for asked in [
            "devices[].display_name",
            "barrier.workers[].rejected_actions[].actor_id",
            "barrier.workers[].possibly_executed[].actor_id",
        ] {
            assert!(
                shown.contains(asked),
                "{asked} shows what was asked for: {shown:?}"
            );
        }
    }

    /// The lines a revocation prints, as a person reads them.
    fn written(lines: Vec<Line>) -> String {
        lines
            .iter()
            .map(|line| format!("{}\n", line.text()))
            .collect()
    }

    fn worker(byte: u8, state: BarrierState, detail: &str) -> WorkerBarrier {
        WorkerBarrier {
            session_id: SessionId::new(Uuid::from_bytes([byte; 16])),
            state,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            rejected_actions_total: U64::new(0),
            possibly_executed: Vec::new(),
            possibly_executed_total: U64::new(0),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: detail.to_owned(),
        }
    }

    fn revoked(workers: Vec<WorkerBarrier>) -> RevocationResult {
        RevocationResult {
            authority_revision: AuthorityRevision::new(4),
            revoked_grants: CanonicalSet::new(),
            revoked_grants_total: U64::new(0),
            barrier: RevocationBarrier::new(AuthorityRevision::new(4), workers),
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
        let text = written(revocation(
            device,
            &revoked(vec![pending, worker(4, BarrierState::Acknowledged, "")]),
        ));
        assert!(
            text.contains("is pending, at authority revision 4"),
            "{text}"
        );
        assert!(
            !text.contains("Revoked device"),
            "a pending revocation is no success: {text}"
        );
        // Why it is pending is the host's sentence, said as its class and length.
        assert!(
            text.contains(&format!(
                "session {}: pending ([message withheld, 31 bytes])",
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
        assert_eq!(error.code().as_str(), "RESOURCE_UNAVAILABLE");
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
        let text = written(revocation(device, &revoked(vec![late, unnamed, quiet])));
        let session = |byte| SessionId::new(Uuid::from_bytes([byte; 16])).to_string();
        assert!(
            text.contains(&format!(
                "session {}: acknowledged ([message withheld, 32 bytes])",
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

    /// KR-REQ-09.12: an answer the host cut says so. The grants are counted from the total, a
    /// cut list of workers that still has a pending one is a floor and is called one, and names left
    /// out are counted.
    #[test]
    fn an_answer_the_host_cut_says_how_much_it_left_out() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let mut cut = revoked(vec![worker(2, BarrierState::Pending, "")]);
        cut.revoked_grants_total = U64::new(9_000);
        cut.barrier.workers_total = U64::new(5_000);
        cut.barrier.workers[0].possibly_executed_total = U64::new(7);
        let text = written(revocation(device, &cut));
        assert!(text.contains("9000 grants revoked"), "{text}");
        assert!(
            text.contains("4999 more session workers are not listed here."),
            "{text}"
        );
        assert!(
            text.contains(
                "7 more actions may have run before the revocation, and are not named here"
            ),
            "{text}"
        );
        let error = pending(device, &cut).expect("a pending barrier");
        assert!(
            error
                .to_string()
                .contains("at least 1 session worker has not fenced it"),
            "{error}"
        );

        let whole = revoked(vec![worker(2, BarrierState::Pending, "")]);
        let text = written(revocation(device, &whole));
        assert!(!text.contains("not listed here"), "{text}");
        let error = pending(device, &whole).expect("a pending barrier");
        assert!(!error.to_string().contains("at least"), "{error}");
    }

    #[test]
    fn a_revocation_every_worker_fenced_says_so() {
        let device = DeviceId::new(Uuid::from_bytes([1; 16]));
        let text = written(revocation(
            device,
            &revoked(vec![worker(2, BarrierState::Ended, "")]),
        ));
        assert!(
            text.contains("Every affected session's worker has fenced it."),
            "{text}"
        );
        let text = written(revocation(device, &revoked(Vec::new())));
        assert!(text.contains("No session's worker was affected."), "{text}");
    }
}
