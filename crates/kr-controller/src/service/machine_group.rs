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
//! task of its own, behind one lock, so a caller that goes away does not cancel a write that has
//! started, and a second step cannot replace the record between the first one's write and its
//! receipt. A caller that goes before the record is replaced loses its registration, so the check
//! made at the replacement refuses the step, and that refusal is what a retry of the action is
//! answered with. The same check refuses a step whose accepted deadline passes, or whose authority
//! is withdrawn, while its new record is being written and flushed. Before each
//! step, and once at start, the claim the record's last change names is settled from the record,
//! after the record's directory has been flushed: if an attempt ended after its write and before
//! its receipt, its answer is kept before anything can change the record again, and a step is not
//! taken while that cannot be done.
//!
//! **What a step is answered with.** A retry is answered from the receipt. A claim an earlier
//! attempt left unfinished is settled from the record under the same lock, and answered from the
//! receipt that gives when the record's last change names that actor and action; otherwise, and
//! while what the record shows cannot be confirmed to survive a crash, it is answered as an
//! outcome this host does not know. It is never performed again.

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
use crate::machine::{Approval, Change, Expected, MachineGroup, MachineStore, Standing};
use crate::singleton::SingletonLock;

use super::authority_changes::decoded;
use super::{Controller, encode, parse, respond, wall_clock_ms};

/// What this daemon holds of its environment's machine group.
pub(super) struct Machine {
    held: Held,
    /// Holds a step from its first look at the record to its receipt, so that one step's write is
    /// never followed by another's before the first has its answer kept.
    steps: tokio::sync::Mutex<()>,
    /// Where this host's own tests make a step fail in the ways a stopped daemon or a failing disk
    /// would. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    faults: Faults,
    /// Where this host's own tests stop a step once it has claimed its action, before it checks
    /// its admission again and writes. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_the_write: super::ReadPause,
    /// Where this host's own tests stop a step once its new record is written and flushed, before
    /// the record is replaced. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_the_publication: PublicationPause,
    /// Where this host's own tests stop a retry that has just found its action's claim unfinished,
    /// before it takes its turn. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    after_the_claim_is_read: super::ReadPause,
}

/// A point on the blocking thread that replaces the record, which a test can stop a step at: the
/// step says it has arrived and waits until the test lets it go. Armed once, it fires once.
#[cfg(feature = "testing")]
#[derive(Default)]
struct PublicationPause(
    std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
);

#[cfg(feature = "testing")]
impl PublicationPause {
    fn arm(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = std::sync::mpsc::channel();
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, going));
        (arrival, go)
    }

    /// Waits here when the pause is armed. Blocks the calling thread, which is a blocking one.
    fn hold(&self) {
        let armed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.recv();
        }
    }
}

/// What this host's own tests make fail. Each flag but one is taken by the first step to meet it;
/// the recovery flush fails for as long as it is set.
#[cfg(feature = "testing")]
#[derive(Default)]
struct Faults {
    /// The step ends after its write and before its receipt, as a daemon that stopped there would.
    receipt_lost: std::sync::atomic::AtomicBool,
    /// The step's receipt cannot be kept, as when the registry cannot be written.
    receipt_unwritable: std::sync::atomic::AtomicBool,
    /// The step's write is reported as one whose directory could not be flushed.
    write_unconfirmed: std::sync::atomic::AtomicBool,
    /// The flush that settles an earlier step fails for as long as this is set.
    recovery_flush_fails: std::sync::atomic::AtomicBool,
    /// The step's write fails before it changes anything, as a disk that cannot be written would
    /// make it.
    write_fails: std::sync::atomic::AtomicBool,
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
            faults: Faults::default(),
            #[cfg(feature = "testing")]
            before_the_write: super::ReadPause::default(),
            #[cfg(feature = "testing")]
            before_the_publication: PublicationPause::default(),
            #[cfg(feature = "testing")]
            after_the_claim_is_read: super::ReadPause::default(),
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

/// What a step that cannot be taken, because an earlier step's change is not confirmed to survive a
/// crash, is refused with.
const UNCONFIRMED: &str = "an earlier change to this environment's machine group record could not \
                           be confirmed to survive a crash, so no step is taken until it can be";

/// What a step whose write was published, and whose directory could not be flushed, is answered
/// with: no path, because the answer can reach a paired device.
const NOT_CONFIRMED: &str = "this environment's machine group record was changed, but its directory \
                             could not be flushed, so whether the change survives a crash is not \
                             known; asking again under the same action says what the record shows";

/// What a step that wrote nothing is answered with.
const NOT_WRITTEN: &str = "this environment's machine group record could not be written, and it \
                           is as it was";

/// Whether the authority a step was admitted under stands, as the store asks it when it replaces the
/// record.
struct StepStanding<'a> {
    controller: &'a Controller,
    carried: &'a crate::authority::AdmittedMutation,
}

impl std::fmt::Debug for StepStanding<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StepStanding")
    }
}

impl Standing for StepStanding<'_> {
    fn while_standing(
        &self,
        publish: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> Result<std::io::Result<()>> {
        #[cfg(feature = "testing")]
        self.controller.machine.before_the_publication.hold();
        self.controller.under_registration(self.carried, publish)
    }
}

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
        self.settle_machine_record().await?;
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
                return self.machine_recorded(record);
            }
        };
        #[cfg(feature = "testing")]
        self.machine.before_the_write.wait().await;
        let outcome = self
            .machine_perform(
                movement,
                expected,
                actor_id.clone(),
                mutation.action_id,
                carried,
            )
            .await
            .and_then(|record| encode(&result_of(self.paths.environment_id(), &record)));
        // A daemon that stopped here would leave the record written and no receipt.
        #[cfg(feature = "testing")]
        if self
            .machine
            .faults
            .receipt_lost
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            drop(hold);
            return Err(ControllerError::Uncertain {
                detail: "a test ended this step after its write and before its receipt".to_owned(),
            });
        }
        // A receipt that cannot be kept does not change what the step did, and the caller is told
        // that: the claim stays unfinished, and the record, which names the step, is what the next
        // step and a retry settle it from.
        if let Err(unrecorded) = self.settle_machine_claim(&hold, &outcome) {
            eprintln!(
                "kr-controller: a machine group step's receipt could not be kept: {unrecorded}"
            );
        }
        drop(hold);
        outcome
    }

    /// Writes the step to the record on a blocking thread, with the authority it was admitted
    /// under checked again at the moment the record is replaced.
    ///
    /// What has been withdrawn already is refused before the record is read. After that the store
    /// writes and flushes the new record, and replaces the old one through [`StepStanding`], which
    /// runs the replacement only while the registration, the authority revision and the accepted
    /// deadline stand: [`Self::under_registration`] holds the connection table across that check
    /// and the replacement, so a revocation lands wholly before it or wholly after, and a deadline
    /// that passes while the record is being written leaves the old record. The table is not held
    /// while the file is written and flushed, or while a replacement that the platform refuses for
    /// a moment waits to be tried again.
    async fn machine_perform(
        self: &Arc<Self>,
        movement: Move,
        expected: Expected,
        actor: ActorId,
        action_id: ActionId,
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
            #[cfg(feature = "testing")]
            if controller
                .machine
                .faults
                .write_fails
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(ControllerError::Storage {
                    operation: "write the machine group record",
                    detail: format!(
                        "{}: a test made the write fail",
                        controller
                            .paths
                            .state_dir()
                            .join(crate::machine::RECORD_FILE)
                            .display()
                    ),
                });
            }
            // A caller whose authority is already gone is refused before it is told anything of
            // the record, such as that its precondition no longer holds.
            controller.check_registration(&carried)?;
            let standing = StepStanding {
                controller: &controller,
                carried: &carried,
            };
            let approval = Approval {
                actor,
                action_id,
                standing: &standing,
            };
            let lock = &controller.lock;
            let written = match movement {
                Move::Join(into) => store.join(lock, into, expected, &approval, now_ms),
                Move::Merge(into) => store.merge(lock, into, expected, &approval, now_ms),
                Move::Split => store.split(lock, expected, &approval, now_ms),
            };
            // A write whose directory could not be flushed, as the store reports it.
            #[cfg(feature = "testing")]
            let written = match written {
                Ok(_)
                    if controller
                        .machine
                        .faults
                        .write_unconfirmed
                        .swap(false, std::sync::atomic::Ordering::SeqCst) =>
                {
                    Err(ControllerError::Uncertain {
                        detail: format!(
                            "{} now names a machine group, but its directory could not be flushed",
                            controller
                                .paths
                                .state_dir()
                                .join(crate::machine::RECORD_FILE)
                                .display()
                        ),
                    })
                }
                other => other,
            };
            written
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
            // The same, for a step that did write and whose flush failed.
            ControllerError::Uncertain { detail } => {
                eprintln!("kr-controller: a machine group step is not confirmed: {detail}");
                ControllerError::Uncertain {
                    detail: NOT_CONFIRMED.to_owned(),
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
        #[cfg(feature = "testing")]
        if self
            .machine
            .faults
            .receipt_unwritable
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ControllerError::Storage {
                operation: "keep a machine group step's receipt",
                detail: "a test made the receipt unwritable".to_owned(),
            });
        }
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
    pub(super) async fn machine_retained(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Option<ControlFrame> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let answer =
            match self
                .sharing
                .grants()
                .recorded_action(actor_id, mutation.action_id, &digest)
            {
                Ok(None) => return None,
                Ok(Some(crate::grants::ActionRecord::Unfinished)) => {
                    #[cfg(feature = "testing")]
                    self.machine.after_the_claim_is_read.wait().await;
                    self.machine_unfinished(actor_id, mutation.action_id, &digest)
                        .await
                }
                Ok(Some(record)) => self.machine_recorded(record),
                Err(error) => Err(error),
            };
        Some(respond(mutation.request_id, answer))
    }

    /// The answer a claimed step is owed once its claim is known to have a result, a refusal, or
    /// an attempt still running. A claim that is none of those is
    /// [`Self::machine_unfinished`]'s.
    fn machine_recorded(&self, record: crate::grants::ActionRecord) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result } => decoded(&result),
            crate::grants::ActionRecord::Refused { code, detail } => {
                Err(ControllerError::Refused { code, detail })
            }
            crate::grants::ActionRecord::InFlight => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "another attempt under this action identifier has not finished".to_owned(),
            }),
            crate::grants::ActionRecord::Unfinished => Err(unfinished_and_unknown()),
        }
    }

    /// The answer to a step whose attempt ended without recording what it did.
    ///
    /// It is settled from the record under the step lock, so that no other step can replace the
    /// record between the record being read and the receipt being kept, and after the record's
    /// directory has been flushed, so that a result is never given for a change that a crash can
    /// still take back. What the claim then holds is the answer. Where it holds none, or the
    /// record could not be settled, the outcome is not known.
    async fn machine_unfinished(
        self: &Arc<Self>,
        actor_id: &ActorId,
        action_id: ActionId,
        digest: &kr_protocol::scalars::Digest256,
    ) -> Result<ParamsValue> {
        let _serial = self.machine.steps.lock().await;
        if let Err(error) = self.settle_machine_record().await {
            eprintln!(
                "kr-controller: an unfinished machine group step could not be settled: {error}"
            );
        }
        match self
            .sharing
            .grants()
            .recorded_action(actor_id, action_id, digest)?
        {
            Some(crate::grants::ActionRecord::Unfinished) | None => Err(unfinished_and_unknown()),
            Some(record) => self.machine_recorded(record),
        }
    }

    /// Keeps, under its claim, the answer to the step the record's last change names, if its
    /// attempt ended without recording one.
    ///
    /// Run at start, before anything is served, before every step, and before a retry of an
    /// unfinished step is answered; the last two hold the step lock. What the record shows has to
    /// be on disk before a receipt says so, so the state directory is flushed first on a blocking
    /// thread.
    ///
    /// # Errors
    ///
    /// Returns a storage failure, naming no path, when the record cannot be read now, when its
    /// directory cannot be flushed, or when the receipt cannot be written: a step is not taken, and
    /// an unfinished one is not answered, while the change the record shows cannot be confirmed.
    pub(super) async fn settle_machine_record(self: &Arc<Self>) -> Result<()> {
        let controller = Arc::clone(self);
        tokio::task::spawn_blocking(move || controller.settle_machine_record_blocking())
            .await
            .unwrap_or_else(|_| {
                Err(ControllerError::Storage {
                    operation: "change the machine group record",
                    detail: UNCONFIRMED.to_owned(),
                })
            })
    }

    fn settle_machine_record_blocking(&self) -> Result<()> {
        let Held::Serving(store) = &self.machine.held else {
            return Ok(());
        };
        let unconfirmed = |why: &dyn std::fmt::Display| {
            eprintln!("kr-controller: a machine group change cannot be confirmed: {why}");
            ControllerError::Storage {
                operation: "change the machine group record",
                detail: UNCONFIRMED.to_owned(),
            }
        };
        let record = store.group().map_err(|error| unconfirmed(&error))?;
        let step = match &record.change {
            Change::Created { .. } => return Ok(()),
            Change::Joined(step) | Change::Merged(step) | Change::Split(step) => step,
        };
        #[cfg(feature = "testing")]
        let flushed = if self
            .machine
            .faults
            .recovery_flush_fails
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            Err(std::io::Error::other("a test made the flush fail"))
        } else {
            kr_flush::flush_directory(self.paths.state_dir(), kr_flush::NameKind::File)
        };
        #[cfg(not(feature = "testing"))]
        let flushed = kr_flush::flush_directory(self.paths.state_dir(), kr_flush::NameKind::File);
        flushed.map_err(|error| unconfirmed(&error))?;
        let result = encode(&result_of(self.paths.environment_id(), &record))?;
        self.sharing
            .grants()
            .settle_unfinished(
                &step.actor,
                step.action_id,
                &kr_cbor::encode(result.as_value()),
                kr_ipc::now_ms().get(),
            )
            .map_err(|error| unconfirmed(&error))?;
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
                    .stated(", last written by ")
                    .stated(match change_of(&record.change) {
                        MachineChange::Created => "this environment's first start",
                        MachineChange::Joined => "a join the owner took",
                        MachineChange::Merged => "a merge the owner took part in",
                        MachineChange::Split => "a split the owner took",
                    }),
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
                    "A file that is whole is read again when this environment's control daemon \
                     restarts, so restart it first. If the machine-group file is damaged or \
                     belongs to another environment, move it aside under a name that does not \
                     both begin with .machine-group. and end with .tmp, such as \
                     machine-group.damaged, and restart the daemon: a missing record is a first \
                     start and mints a group of one. Run kr host machine join to put the \
                     environment back in a known group if you want one. If the file could not be \
                     created, make the state directory writable (kr doctor names it) and restart \
                     the daemon.",
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

    /// Stops the next machine group step once its new record is written and flushed, before the
    /// record is replaced and before the step's authority is asked about for the last time. Returns
    /// the end that says the step has arrived, and the end that lets it go. For this host's own
    /// tests.
    #[cfg(feature = "testing")]
    pub fn hold_the_next_machine_publication(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.machine.before_the_publication.arm()
    }

    /// Stops the next retry of a machine group step that has found its action's claim unfinished,
    /// before it takes its turn behind the steps in progress. Returns the end that says the retry
    /// has arrived, and the end that lets it go. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn hold_the_next_machine_retry(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.machine.after_the_claim_is_read.arm()
    }

    /// Ends the next machine group step after its write and before its receipt, as a daemon that
    /// stopped there would. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn lose_the_next_machine_receipt(&self) {
        self.machine
            .faults
            .receipt_lost
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Makes the receipt of the next machine group step unwritable, as when the registry cannot be
    /// written, after the step has written its record. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn make_the_next_machine_receipt_unwritable(&self) {
        self.machine
            .faults
            .receipt_unwritable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reports the next machine group step as one whose record was written and whose directory
    /// could not be flushed, as the store reports it. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn report_the_next_machine_write_as_unconfirmed(&self) {
        self.machine
            .faults
            .write_unconfirmed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Makes the next machine group step fail to write the record, before it changes anything, as a
    /// disk that cannot be written would. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn fail_the_next_machine_write(&self) {
        self.machine
            .faults
            .write_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Makes the flush that settles an earlier machine group step fail, or work again. For this
    /// host's own tests.
    #[cfg(feature = "testing")]
    pub fn fail_the_machine_recovery_flush(&self, failing: bool) {
        self.machine
            .faults
            .recovery_flush_fails
            .store(failing, std::sync::atomic::Ordering::SeqCst);
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
