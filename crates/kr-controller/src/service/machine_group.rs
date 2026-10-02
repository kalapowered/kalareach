//! The machine group this daemon records, reports and changes.
//!
//! An environment records its own machine group in a file of its own ([`crate::machine`]). This
//! module is the daemon's side of it: the group is minted when the daemon first starts, reported
//! by `host.info` and `environment.list`, and changed by exactly three owner-approved steps,
//! `machine.join`, `machine.merge` and `machine.split`, each on this environment alone.
//!
//! A group grants nothing. Nothing in this daemon reads a group to decide a right, a route, what a
//! device may see or whom it may pair with, and no step touches a key, a grant, a device, a
//! session or the environment's identity: a step writes the one record.
//!
//! **One step at a time.** A step is claimed in the same store as every other action the daemon
//! performs on its own account, performed, and its receipt kept there. The whole sequence runs on a
//! task of its own, behind one lock, so a caller that goes away does not cancel a write, and a
//! second step cannot replace the record between the first one's write and its receipt. Before each
//! step, and once at start, the claim the record's last change names is settled from the record: if
//! an attempt ended after its write and before its receipt, its answer is kept before anything can
//! change the record again.
//!
//! **What a step is answered with.** A retry is answered from the receipt. A claim an earlier
//! attempt left unfinished is answered from the record when its last change names that actor and
//! action, and otherwise as an outcome this host does not know. It is never performed again.

use std::sync::Arc;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::ids::{ActionId, ActorId, MachineId};
use kr_protocol::machine::{
    MachineChange, MachineGroup as Reported, MachineJoinParams, MachineMergeParams,
    MachineSplitParams, MachineStepResult,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};

use crate::error::{ControllerError, Result};
use crate::machine::{Approval, Change, Expected, MachineGroup, MachineStore};
use crate::singleton::SingletonLock;

use super::authority_changes::decoded;
use super::{Controller, encode, parse, respond, wall_clock_ms};

/// What this daemon holds of its environment's machine group.
pub(super) struct Machine {
    held: Held,
    /// Holds a step from its first look at the record to its receipt, so that one step's write is
    /// never followed by another's before the first has its answer kept.
    steps: tokio::sync::Mutex<()>,
    /// Where this host's own tests end the next step after its write and before its receipt, as a
    /// daemon that stopped there would. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    receipt_lost: std::sync::atomic::AtomicBool,
    /// Where this host's own tests stop a step once it has claimed its action, before it checks
    /// its admission again and writes. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_the_write: super::ReadPause,
}

/// The record, or why there is none to use.
enum Held {
    /// The record is open, and steps are taken against it.
    Serving(MachineStore),
    /// The record exists and cannot be used, or could not be created. It is left exactly as it is:
    /// a group minted over it would be a change nobody approved. Holds why, for the daemon's own
    /// log and for `host.doctor`.
    Refused(String),
}

impl Machine {
    /// Opens the environment's record, minting its group when this is its first start.
    ///
    /// A record that cannot be read, that belongs to another environment, or that cannot be
    /// created leaves the daemon serving with no group: the record is not touched, every step is
    /// refused and `host.doctor` says what is wrong with it.
    ///
    /// # Errors
    ///
    /// Returns what the store returns other than a storage failure, which it never does for a lock
    /// that is this environment's own.
    pub(super) fn open(
        lock: &SingletonLock,
        paths: &EnvironmentPaths,
        now_ms: u64,
    ) -> Result<Self> {
        let held = match MachineStore::open(lock, paths, now_ms) {
            Ok(store) => Held::Serving(store),
            Err(ControllerError::Storage { detail, .. }) => {
                eprintln!(
                    "kr-controller: this environment's machine group record cannot be used, so the \
                     daemon serves with no group until it is repaired: {detail}"
                );
                Held::Refused(detail)
            }
            Err(other) => return Err(other),
        };
        Ok(Self {
            held,
            steps: tokio::sync::Mutex::new(()),
            #[cfg(feature = "testing")]
            receipt_lost: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "testing")]
            before_the_write: super::ReadPause::default(),
        })
    }
}

/// Where a step takes the environment.
#[derive(Clone, Copy, Debug)]
enum Move {
    Join(MachineId),
    Merge(MachineId),
    Split,
}

/// The sentence a refused step carries, which names no path: the answer can reach a paired device.
const NO_RECORD: &str = "this environment has no usable machine group record, so no step is taken; \
                         host.doctor says what is wrong with it";

/// What a step that wrote nothing is answered with.
const NOT_WRITTEN: &str = "this environment's machine group record could not be written, and it \
                           is as it was";

impl Controller {
    /// The group this environment records, as `host.info` and `environment.list` report it.
    ///
    /// None where there is no record to read: the daemon is serving with no group, or the record
    /// cannot be read now.
    pub(super) fn machine_report(&self) -> Option<Reported> {
        let Held::Serving(store) = &self.machine.held else {
            return None;
        };
        store.group().ok().as_ref().map(reported)
    }

    /// Takes one machine group step on this environment, under the admission it arrived with.
    ///
    /// The step is claimed, performed and its receipt kept on a task of its own: dropping this
    /// future never cancels a write.
    ///
    /// # Errors
    ///
    /// Returns the refusal the step was decided against, a storage failure naming nothing written,
    /// or an outcome this host does not know.
    pub(super) async fn machine_step(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let (movement, expected) = read_step(method, &mutation.params)?;
        // A daemon with no usable record takes no step, and claims nothing: the answer is the same
        // however often it is asked, and a claim would turn it into an outcome nobody knows.
        if matches!(self.machine.held, Held::Refused(_)) {
            return Err(ControllerError::Storage {
                operation: "change the machine group record",
                detail: NO_RECORD.to_owned(),
            });
        }
        // A step that carries no freshness is a retry of an action this host may already hold,
        // which has been answered before this point; what it may not do is be performed.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not be performed"
                    .to_owned(),
            });
        }
        let controller = Arc::clone(self);
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        tokio::spawn(async move {
            controller
                .machine_step_serially(&actor_id, &mutation, movement, expected, carried)
                .await
        })
        .await
        .unwrap_or_else(|_| {
            Err(ControllerError::Uncertain {
                detail: "the task that took this step ended before it answered, and this host's \
                         records may not show what it did; ask again with the same action to be \
                         told what it did"
                    .to_owned(),
            })
        })
    }

    async fn machine_step_serially(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        movement: Move,
        expected: Expected,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let _serial = self.machine.steps.lock().await;
        // The step before this one may have written the record and ended before its receipt. Its
        // answer is kept now, from the record, before this step can replace the record.
        self.settle_machine_record()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let hold = match self.sharing.grants().claim_action(
            actor_id,
            mutation.action_id,
            &digest,
            kr_ipc::now_ms().get(),
        )? {
            crate::grants::ActionClaim::Claimed { hold } => hold,
            crate::grants::ActionClaim::Recorded(record) => {
                return self.machine_recorded(actor_id, mutation.action_id, record);
            }
        };
        let approval = Approval {
            actor: actor_id.clone(),
            action_id: mutation.action_id,
        };
        #[cfg(feature = "testing")]
        self.machine.before_the_write.wait().await;
        let outcome = self
            .machine_perform(movement, expected, approval, carried)
            .await
            .and_then(|record| encode(&result_of(self.paths.environment_id(), &record)));
        // A daemon that stopped here would leave the record written and no receipt.
        #[cfg(feature = "testing")]
        if self
            .machine
            .receipt_lost
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            drop(hold);
            return Err(ControllerError::Uncertain {
                detail: "a test ended this step after its write and before its receipt".to_owned(),
            });
        }
        let kept = self.settle_machine_claim(&hold, &outcome);
        drop(hold);
        kept.and(outcome)
    }

    /// Writes the step to the record on a blocking thread, with the admission checked again at
    /// the write.
    ///
    /// The check and the write are one step with respect to a withdrawal of authority:
    /// [`Self::under_registration`] holds the connection table across both, so a revocation or a
    /// lapsed deadline lands wholly before the check or wholly after the write. The write is a
    /// short one: the store waits only for a call of this daemon on the same record, and this
    /// daemon takes one step at a time. The one thing that can hold it longer is a platform that
    /// keeps the replaced record open, for which the store gives up after its own bound.
    async fn machine_perform(
        self: &Arc<Self>,
        movement: Move,
        expected: Expected,
        approval: Approval,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<MachineGroup> {
        let controller = Arc::clone(self);
        let now_ms = wall_clock_ms();
        tokio::task::spawn_blocking(move || {
            let Held::Serving(store) = &controller.machine.held else {
                return Err(ControllerError::Storage {
                    operation: "change the machine group record",
                    detail: NO_RECORD.to_owned(),
                });
            };
            let lock = &controller.lock;
            controller
                .under_registration(&carried, || match movement {
                    Move::Join(into) => store.join(lock, into, expected, &approval, now_ms),
                    Move::Merge(into) => store.merge(lock, into, expected, &approval, now_ms),
                    Move::Split => store.split(lock, expected, &approval, now_ms),
                })
                .and_then(|written| written)
        })
        .await
        .unwrap_or_else(|_| {
            Err(ControllerError::Uncertain {
                detail: "the write of the machine group record ended before it answered".to_owned(),
            })
        })
        .map_err(|error| match error {
            // What the store said names the file and what the system answered, and a step's answer
            // can reach a paired device. The daemon's own log has the detail.
            ControllerError::Storage { detail, .. } => {
                eprintln!("kr-controller: a machine group step wrote nothing: {detail}");
                ControllerError::Storage {
                    operation: "change the machine group record",
                    detail: NOT_WRITTEN.to_owned(),
                }
            }
            other => other,
        })
    }

    /// Keeps what a step came to under the claim that carried it.
    ///
    /// A refusal the step was decided against is kept, as for every action this daemon claims. So is
    /// a storage failure: the store guarantees such a step wrote nothing, so the answer is final
    /// for that action and the owner asks again under a new one. A step that was written and whose
    /// directory could not be flushed is not kept: the claim stays unfinished, and the record,
    /// which names it, answers a retry.
    fn settle_machine_claim(
        &self,
        hold: &crate::grants::ClaimHold,
        outcome: &Result<ParamsValue>,
    ) -> Result<()> {
        if let Err(error @ ControllerError::Storage { .. }) = outcome {
            if let Err(unrecorded) = self.sharing.grants().retain_refusal(
                hold,
                error.code(),
                &error.to_string(),
                kr_ipc::now_ms().get(),
            ) {
                eprintln!("kr-controller: could not record an action's refusal: {unrecorded}");
            }
            return Ok(());
        }
        self.settle_claim(hold, outcome)
    }

    /// Answers a step whose action this host already holds a claim on, before freshness is asked
    /// for, or says there is none.
    ///
    /// Both doors call this for the three methods, ahead of everything that decides a first
    /// admission: section 9 keeps a receipt readable after the window that admitted it has gone.
    pub(super) fn machine_retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Option<ControlFrame> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        match self
            .sharing
            .grants()
            .recorded_action(actor_id, mutation.action_id, &digest)
        {
            Ok(Some(record)) => Some(respond(
                mutation.request_id,
                self.machine_recorded(actor_id, mutation.action_id, record),
            )),
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }

    /// The answer a claimed step is owed: its result, its refusal, that it is still running, or,
    /// for a claim whose attempt ended without recording what it did, what the record shows.
    fn machine_recorded(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        record: crate::grants::ActionRecord,
    ) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result } => decoded(&result),
            crate::grants::ActionRecord::Refused { code, detail } => {
                Err(ControllerError::Refused { code, detail })
            }
            crate::grants::ActionRecord::InFlight => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "another attempt under this action identifier has not finished".to_owned(),
            }),
            crate::grants::ActionRecord::Unfinished => {
                let Held::Serving(store) = &self.machine.held else {
                    return Err(unfinished_and_unknown());
                };
                match store.group() {
                    Ok(record) if names(&record, actor_id, action_id) => {
                        encode(&result_of(self.paths.environment_id(), &record))
                    }
                    _ => Err(unfinished_and_unknown()),
                }
            }
        }
    }

    /// Keeps, under its claim, the answer to the step the record's last change names, if its
    /// attempt ended without recording one.
    ///
    /// Run at start, before anything is served, and before every step. What the record shows has
    /// to be on disk before a receipt says so, so the state directory is flushed first, and a
    /// flush that fails leaves the claim as it is: the step it names was never reported as done.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the receipt cannot be written.
    pub(super) fn settle_machine_record(&self) -> Result<()> {
        let Held::Serving(store) = &self.machine.held else {
            return Ok(());
        };
        let Ok(record) = store.group() else {
            return Ok(());
        };
        let step = match &record.change {
            Change::Created { .. } => return Ok(()),
            Change::Joined(step) | Change::Merged(step) | Change::Split(step) => step,
        };
        if kr_flush::flush_directory(self.paths.state_dir(), kr_flush::NameKind::File).is_err() {
            return Ok(());
        }
        let result = encode(&result_of(self.paths.environment_id(), &record))?;
        self.sharing.grants().settle_unfinished(
            &step.actor,
            step.action_id,
            &kr_cbor::encode(result.as_value()),
            kr_ipc::now_ms().get(),
        )?;
        Ok(())
    }

    /// The doctor's check of the machine group record.
    ///
    /// A record that cannot be used is a failure, and the remedy is the whole repair: this daemon
    /// never replaces a record it could not read, because a group minted over it would be a change
    /// nobody approved.
    pub(super) fn machine_check(&self) -> DoctorCheck {
        const TITLE: &str = "This environment records its own machine group";
        let read = match &self.machine.held {
            Held::Serving(store) => store.group(),
            Held::Refused(reason) => Err(ControllerError::Storage {
                operation: "read the machine group record",
                detail: reason.clone(),
            }),
        };
        match read {
            Ok(record) => DoctorCheck::new(
                "machine-group",
                TITLE,
                DoctorStatus::Ok,
                Sentence::new()
                    .stated("the record is at revision ")
                    .number(record.revision)
                    .stated(", written by a ")
                    .stated(change_of(&record.change).as_str())
                    .stated(" of this environment's own"),
                None,
            ),
            Err(error) => DoctorCheck::new(
                "machine-group",
                TITLE,
                DoctorStatus::Failed,
                Sentence::new()
                    .stated(
                        "the machine-group record in this environment's state directory cannot \
                         be used, so this daemon serves with no group and takes no step, and its \
                         cause is in this daemon's log: ",
                    )
                    .withheld(ContentClass::Message, &error.to_string()),
                Some(
                    "If the machine-group file is damaged or belongs to another environment, move \
                     it aside under a name that does not begin with .machine-group. and end with \
                     .tmp, then restart this environment's control daemon: a missing record is a \
                     first start and mints a group of one. Run kr host machine join to put the \
                     environment back in a known group if you want one. If the file could not be \
                     created, make the state directory writable and restart the daemon.",
                ),
            ),
        }
    }

    /// Stops the next machine group step once it has claimed its action, before its admission is
    /// checked again and the record is written. Returns the end that says the step has arrived,
    /// and the end that lets it go. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn hold_the_next_machine_step(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.machine.before_the_write.arm()
    }

    /// Ends the next machine group step after its write and before its receipt, as a daemon that
    /// stopped there would. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn lose_the_next_machine_receipt(&self) {
        self.machine
            .receipt_lost
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Refuses the parameters of a step that are not the ones its method takes.
///
/// # Errors
///
/// Returns [`ControllerError::InvalidArgument`] for parameters that do not read as the method's.
pub(in crate::service) fn check_step(method: Method, params: &ParamsValue) -> Result<()> {
    read_step(method, params).map(|_| ())
}

/// Reads one step's movement and the record it was approved against.
fn read_step(method: Method, params: &ParamsValue) -> Result<(Move, Expected)> {
    let expected = |expected: kr_protocol::machine::MachineExpected| Expected {
        machine_id: expected.machine_id,
        revision: expected.revision.get(),
    };
    match method {
        Method::MachineJoin => {
            let params: MachineJoinParams = parse(params)?;
            Ok((Move::Join(params.machine_id), expected(params.expected)))
        }
        Method::MachineMerge => {
            let params: MachineMergeParams = parse(params)?;
            Ok((Move::Merge(params.machine_id), expected(params.expected)))
        }
        Method::MachineSplit => {
            let params: MachineSplitParams = parse(params)?;
            Ok((Move::Split, expected(params.expected)))
        }
        other => Err(ControllerError::InvalidArgument(format!(
            "{} is not a machine group step",
            other.as_str()
        ))),
    }
}

/// Whether the record's last change is the step this actor took under this action.
fn names(record: &MachineGroup, actor_id: &ActorId, action_id: ActionId) -> bool {
    match &record.change {
        Change::Created { .. } => false,
        Change::Joined(step) | Change::Merged(step) | Change::Split(step) => {
            step.actor == *actor_id && step.action_id == action_id
        }
    }
}

const fn change_of(change: &Change) -> MachineChange {
    match change {
        Change::Created { .. } => MachineChange::Created,
        Change::Joined(_) => MachineChange::Joined,
        Change::Merged(_) => MachineChange::Merged,
        Change::Split(_) => MachineChange::Split,
    }
}

/// The record as the protocol reports it.
fn reported(record: &MachineGroup) -> Reported {
    Reported {
        machine_id: record.machine_id,
        revision: U64::new(record.revision),
        change: change_of(&record.change),
        previous: match &record.change {
            Change::Created { .. } => Nullable::null(),
            Change::Joined(step) | Change::Merged(step) | Change::Split(step) => {
                Nullable::some(step.previous)
            }
        },
    }
}

/// What a step is answered with, and the receipt it leaves.
fn result_of(
    environment_id: kr_protocol::ids::EnvironmentId,
    record: &MachineGroup,
) -> MachineStepResult {
    MachineStepResult {
        environment_id,
        machine: reported(record),
    }
}

/// The answer to an action whose attempt ended without recording what it did, when the record does
/// not show what it did either.
fn unfinished_and_unknown() -> ControllerError {
    ControllerError::Uncertain {
        detail: "an earlier attempt at this action ended without recording what it did, and this \
                 host's records do not show it; it is not performed again, so read this \
                 environment's machine group before asking under a new action"
            .to_owned(),
    }
}
