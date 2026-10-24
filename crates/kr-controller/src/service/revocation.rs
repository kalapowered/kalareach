//! Revoking a grant or a device, transferring control, and the host's policy.

use kr_protocol::scalars::TimestampMs;

use crate::error::Result;

use super::barrier::{OwnBarrier, Reach};
use super::{Controller, net};

/// Who the answer to a revocation is written for, and so how much of the host's barrier it names.
///
/// It is a function of the actor that made the revocation and of nothing else, so no path that
/// answers a revocation (the first answer, a repeat, a retry of an unfinished claim) can answer a
/// device as it answers the owner. It covers `grant.revoke`, the one revocation a device makes;
/// `device.revoke` and `grant.transfer` are the owner's at this machine alone, are answered as the
/// owner's, and are refused to a device before anything is claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The owner at this machine: every worker the host holds.
    Host,
    /// A paired device: the workers of the sessions the grant it revoked covers. The barrier is
    /// host-wide, and a worker's session, and what its fence named, belong to whoever may see that
    /// session, so a device is told of no other.
    Device,
}

impl Audience {
    /// The audience of an answer to `actor_id`.
    ///
    /// The owner is the caller at this machine, over its own socket. Anything this host cannot
    /// recognise as that peer is answered as a device, because that is the answer that withholds.
    #[must_use]
    pub fn of(actor_id: &kr_protocol::ids::ActorId) -> Self {
        if super::routes::is_owners_own_socket(actor_id) {
            Self::Host
        } else {
            Self::Device
        }
    }
}

impl Controller {
    /// Revokes a grant, its descendants, and everything they were being used for.
    ///
    /// The order is the one section 10 requires and the one a revocation cannot be correct
    /// without. The grants go first, because a grant still in the store is a grant the next
    /// request would be decided against. Then the revision advances, which invalidates every
    /// outstanding dispatch lease at once and deregisters the connections admitted under the
    /// authority just withdrawn. Then the connections holding those registrations are fenced, so a
    /// subscription already open is closed rather than left reading. Then the revision is
    /// announced to every worker, and what comes back is the per-worker completion status: a
    /// revocation is complete for a worker once that worker has acknowledged the revision and
    /// fenced the undispatched actions it affects, or once it is confirmed ended.
    ///
    /// A revocation that withdrew nothing — the grant and its subtree were already revoked —
    /// advances no revision. Advancing one would fence every live connection on the host for a
    /// retry that changed nothing. The exception is a call's voice grant with a close still on its
    /// way: that retry owes a fence of its own, which withdraws no connection (a call's grant
    /// names none).
    ///
    /// `audience` is who the answer is for ([`Audience`]). `carried` is the admission of the
    /// mutation this revocation is performing, when it is performing one. It is checked again
    /// inside the transaction that withdraws the rows, once
    /// the rows have been read and immediately before the first of them changes: an admission has
    /// a deadline, and the wait for the store's lock and the read that follows it can each outlast
    /// one. The local owner's own revocation carries none.
    ///
    /// `claim` is that mutation's hold on its action, and the rows it withdraws are written beside
    /// the claim in the same transaction, so a repeat of an action whose answer was never recorded
    /// is told exactly what it withdrew (`Self::revocation_on_record`).
    ///
    /// # Errors
    ///
    /// Returns an error when the grant store or the registry cannot be read or written, or when
    /// the admission has lapsed by the time the rows would be withdrawn.
    pub async fn revoke_grant(
        &self,
        grant_id: kr_protocol::ids::GrantId,
        audience: Audience,
        carried: Option<&crate::authority::AdmittedMutation>,
        claim: Option<&crate::grants::ClaimHold>,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        let now_ms = self.settled_now_ms();
        // The revocation writes its own fence debt inside the same transaction that revokes the
        // rows, so a failure afterwards leaves a record a retry can see. Nothing newly revoked is
        // not the same as nothing owed.
        //
        // The registry guard is held across the withdrawal and dropped before the fence, which
        // takes it again. It is what the admission is checked against, so holding it through the
        // write is what makes the check mean something at the moment of the write.
        let revocation = match carried {
            Some(carried) => {
                let registry = self.registry.lock().await;
                self.check_admission(&registry, carried)?;
                self.sharing.revoke(
                    grant_id,
                    now_ms,
                    || self.check_admission(&registry, carried),
                    claim,
                )?
            }
            None => self.sharing.revoke(grant_id, now_ms, || Ok(()), claim)?,
        };
        let own = self.publish_debts(&Self::under_the_grants(&revocation));
        self.complete_revocation(
            audience,
            Some(grant_id),
            revocation.revoked.iter().copied().collect(),
            own,
        )
        .await
    }

    /// A device record's debt, when it wrote one, as one that reaches the connections of that
    /// device and what it holds at a worker, and no others; as one that reaches every connection
    /// when the device and the grants it held together name more than one notice carries, which a
    /// barrier would otherwise split across two revisions, the second of them after the answer.
    fn for_the_device(
        device_id: kr_protocol::ids::DeviceId,
        names_beside: usize,
        debt: Option<crate::grants::store::DebtId>,
    ) -> Vec<(crate::grants::store::DebtId, Reach)> {
        debt.into_iter()
            .map(|debt| (debt, Self::device_reach(device_id, names_beside)))
            .collect()
    }

    /// The reach of a device's own record, given how many names the grants it held are named by.
    fn device_reach(device_id: kr_protocol::ids::DeviceId, names_beside: usize) -> Reach {
        if names_beside < kr_protocol::worker::MAX_REVISION_REACH_NAMES {
            Reach::Device(device_id)
        } else {
            Reach::Host
        }
    }

    /// The debt of the grants a device held, as [`Self::under_the_grants`] names them, or as one
    /// that reaches every connection when they and the device name more than a notice carries.
    fn for_the_device_grants(
        revocation: &crate::grants::GrantRevocation,
    ) -> Vec<(crate::grants::store::DebtId, Reach)> {
        if revocation.reached_holding_leases.len() < kr_protocol::worker::MAX_REVISION_REACH_NAMES {
            Self::under_the_grants(revocation)
        } else {
            revocation
                .debt
                .into_iter()
                .map(|debt| (debt, Reach::Host))
                .collect()
        }
    }

    /// A revocation's debt, when it wrote one, as one that reaches the connections acting under
    /// the grants of the subtree it withdrew and no others.
    ///
    /// The grants are everything of the subtree that anyone held
    /// ([`crate::grants::GrantRevocation::reached`]), not only what this call revoked: a grant a
    /// concurrent revocation withdrew just before this one read the subtree is fenced by whichever
    /// barrier runs first.
    fn under_the_grants(
        revocation: &crate::grants::GrantRevocation,
    ) -> Vec<(crate::grants::store::DebtId, Reach)> {
        revocation
            .debt
            .into_iter()
            .map(|debt| {
                (
                    debt,
                    Reach::Grants {
                        grants: revocation.reached.iter().copied().collect(),
                        holding_leases: revocation.reached_holding_leases.clone(),
                    },
                )
            })
            .collect()
    }

    /// Revokes every grant one device holds, then revokes the device itself.
    ///
    /// The grants go first for the same reason as above. The registrations are the daemon's table
    /// of admitted connections, and the barrier its debts raise withdraws those of the device and
    /// of the connections acting under the grants it withdrew, admits every other connection again
    /// at the revision now in force, and closes the connections that lost theirs; the revoked
    /// device's record is already marked so it cannot be re-admitted at all. The workers are told
    /// the device and the grants, so what they take is the input lease and the size claim of the
    /// device's attachments and of those made under the grants withdrawn, and not those of any
    /// other device. A device that held so many grants that, with the device, they name more than
    /// a notice carries is fenced as the whole host is, in one barrier.
    ///
    /// `carried` and `claim` are as [`Self::revoke_grant`]: the admission of the mutation this is
    /// performing, and its hold on its action, which the withdrawn rows are written beside.
    /// This withdrawal is more than one write and they are not in one store, so the admission is
    /// checked while it can still decide: before the grants are read, inside the transaction that
    /// withdraws them, and again before the device record when that transaction withdrew nothing
    /// and the record is therefore the whole withdrawal. Once something is withdrawn, the rest
    /// follows whatever the clock has done since, because a half-finished revocation is worse than
    /// a late one.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant store, the device record or the registry cannot be written,
    /// or when the admission has lapsed before anything was withdrawn.
    pub async fn revoke_device_authority(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        carried: Option<&crate::authority::AdmittedMutation>,
        claim: Option<&crate::grants::ClaimHold>,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        let now_ms = self.settled_now_ms();
        // Every write this makes happens while the registry guard is held, and the guard goes
        // before the fence, which takes it again. The block is what drops it: nothing this holds
        // may be alive across the await below.
        let (revocation, lapsed, owes, own, recorded) = {
            // The guard is taken whether or not the revocation carries an admission. A push
            // registration reads its device again and writes its destination under it, so a
            // revocation without one (the feed's, and the replay's) could mark the device and end
            // its destination between the two, and the registration would then write a destination
            // for a device that is no longer paired, which nothing ends.
            let registry = self.registry.lock().await;
            if let Some(carried) = carried {
                self.check_admission(&registry, carried)?;
            }
            let revocation = self.sharing.grants().revoke_device(
                device_id,
                now_ms,
                || self.still_admitted(Some(&*registry), carried),
                claim,
            )?;
            // The transaction that revoked is the restriction, and it has committed.
            let own = self.publish_debts(&Self::for_the_device_grants(&revocation));
            // The device record is marked revoked before the revision advances, so nothing can be
            // authorised against it in between. The directory is a view on this daemon's own
            // registry database, which is the file the network half keeps its device records in.
            // A device can hold its grant in the pairing record and have no row in the grant
            // store, so its own withdrawal owes a fence in its own right, keyed by the device's
            // identity. The intent is written **before** the record changes, because a debt
            // recorded after a withdrawal that then failed to record would be a withdrawal nothing
            // fences.
            // The intent is written only when there is a withdrawal to fence, and once written it
            // is never taken back: a caller that decided its own work was done and deleted the row
            // could delete the row another caller was relying on. Reading the record first is what
            // keeps a repeat from fencing the host again, and two callers racing the first
            // revocation both fence, which is the harmless direction.
            //
            // Whether the admission still decides anything from here depends on what the
            // transaction above did. If it withdrew something, that is committed, and a deadline
            // passing afterwards is no reason to stop half way: grants withdrawn beside a device
            // record still live is the dangerous state, and a revocation takes authority away
            // rather than granting any, so finishing a late one is the safe direction. If it
            // withdrew nothing — the paired device whose grant lives in its pairing record — then
            // the record below is the whole withdrawal, nothing is committed, and each wait
            // between here and it gets its own check.
            let withdrew = !revocation.revoked.is_empty();
            if !withdrew {
                self.still_admitted(Some(&*registry), carried)?;
            }
            let record_is_live = self
                .devices
                .record_for_device(device_id)?
                .is_some_and(|record| record.revoked_at_ms.is_none());
            let record_debt = if record_is_live {
                if !withdrew {
                    self.still_admitted(Some(&*registry), carried)?;
                }
                Some(self.owe_debt(
                    &format!("the revocation of device {device_id}'s record"),
                    Self::device_reach(device_id, revocation.reached_holding_leases.len()),
                )?)
            } else {
                None
            };
            // The last wait before the record is marked was the debt. A refusal here withdraws
            // nothing, but it leaves a fence owed, so it is answered *after* that fence rather
            // than in place of it.
            let lapsed = if withdrew {
                None
            } else {
                self.still_admitted(Some(&*registry), carried).err()
            };
            let recorded = if lapsed.is_none() {
                self.devices
                    .revoke(device_id, TimestampMs::new(now_ms))
                    .map(|_| ())
            } else {
                Ok(())
            };
            // The record's debt is published whether or not the record was marked: a barrier for
            // a restriction that did not land withdraws nothing more, and a debt left pending would
            // never be retired. A record that could not be marked answers with its error, and what
            // it published is left to the debt pass.
            let own = own.and(self.publish_debts(&Self::for_the_device(
                device_id,
                revocation.reached_holding_leases.len(),
                record_debt,
            )));
            if recorded.is_ok() && lapsed.is_none() {
                self.unbind_device(device_id);
            }
            let owes = revocation.debt.is_some() || record_debt.is_some();
            (revocation, lapsed, owes, own, recorded)
        };
        // The device is unpaired, so the host stops delivering to it, forgets what it delivers
        // under and owes the gateway a revocation (section 16). A revocation the admission lapsed
        // before it began changed nothing and ends nothing. A device record that could not be
        // marked revoked ends the destination all the same: the grants are withdrawn, the
        // destination sends under the device's own pairing grant, which the unmarked record still
        // holds, and nothing else would stop it. The error is answered after the destination is
        // ended.
        // A device the host no longer pairs holds no call: the voice sessions it started end, and
        // the service is told to close the calls, instead of running to their deadlines. On a task
        // of its own, so that a service that answers slowly holds neither the fence nor this
        // answer: the revocation does not wait for the provider's billing. It starts here, before
        // the record's error is answered, because a record that could not be marked leaves the
        // grants withdrawn all the same, and a call that nothing ends would run to its deadline.
        if lapsed.is_none() {
            self.retire_push_destination(device_id);
            if let Some(voice) = self.voice.get() {
                let voice = std::sync::Arc::clone(voice);
                tokio::spawn(async move {
                    voice
                        .coordinator()
                        .end_calls_of_revoked_device(device_id, now_ms)
                        .await;
                });
            }
        }
        recorded?;
        match lapsed {
            // Nothing was withdrawn and nothing is owed, so there is nothing to finish.
            Some(error) if !owes => Err(error),
            Some(error) => {
                self.complete_revocation(
                    Audience::Host,
                    None,
                    revocation.revoked.iter().copied().collect(),
                    own,
                )
                .await?;
                Err(error)
            }
            None => {
                self.complete_revocation(
                    Audience::Host,
                    None,
                    revocation.revoked.iter().copied().collect(),
                    own,
                )
                .await
            }
        }
    }

    /// Transfers control of a session, then fences what the transfer took away.
    ///
    /// The store's half is one transaction: the replacement is issued and the source revoked
    /// together. The daemon's half is the one every revocation takes, because a transfer *is* a
    /// revocation for the device that gave it up: the revision advances, the connections admitted
    /// under the old authority are fenced, and the answer carries the per-worker completion status.
    ///
    /// `clock` is the one the owner's confirmation was measured on. `carried` is the admission of
    /// the mutation performing the transfer, which is asked again inside the transaction that
    /// writes, and `claim` is that mutation's hold, as for [`Self::revoke_grant`].
    ///
    /// # Errors
    ///
    /// Returns an error when the transfer is refused or the registry cannot be written. It is
    /// refused when the receiving device has been revoked since the plan was built: a device
    /// revocation holds the registry lock across its writes, so the record read under that lock is
    /// the one the grant is written against.
    pub async fn transfer_control(
        &self,
        plan: &kr_protocol::confirmation::TransferControlPlan,
        confirmation: &crate::sharing::ConfirmedAction,
        clock: &(dyn kr_pairing::platform::PairingClock + Sync),
        carried: Option<&crate::authority::AdmittedMutation>,
        claim: Option<&crate::grants::ClaimHold>,
    ) -> Result<kr_protocol::sharing::GrantTransferResult> {
        // Written down before anything is decided from it. The transfer decides the source's expiry
        // again at the moment it writes, and a lapse it finds there is owed its record, which is
        // written before the refusal goes back.
        let now_ms = self.settled_now_ms();
        let write = crate::sharing::TransferWrite {
            authority_revision: self.policy().authority_revision(),
            now_ms,
            claim,
        };
        // The admission is checked under the registry lock, which is held across the write and
        // dropped before the fence, which takes it again.
        let transfer = match carried {
            Some(carried) => {
                let registry = self.registry.lock().await;
                self.check_admission(&registry, carried)?;
                self.receiving_device_is_paired(plan).and_then(|()| {
                    self.sharing
                        .transfer_control(plan, confirmation, clock, write, || {
                            self.check_admission(&registry, carried)
                        })
                })
            }
            None => self.receiving_device_is_paired(plan).and_then(|()| {
                self.sharing
                    .transfer_control(plan, confirmation, clock, write, || Ok(()))
            }),
        };
        self.settle_floor();
        let transfer = transfer?;
        let own = self.publish_debts(&Self::under_the_grants(&transfer.revoked));
        self.complete_transfer(
            transfer.issued,
            transfer.revoked.revoked.iter().copied().collect(),
            own,
        )
        .await
    }

    /// Whether the device a transfer hands control to is still paired with this host.
    ///
    /// The plan read the device when it was built, and a revocation of the device can have landed
    /// since: it takes the registry lock this is read under, so a device revoked before this is
    /// refused, and one revoked after it has the grant written here revoked with its others.
    fn receiving_device_is_paired(
        &self,
        plan: &kr_protocol::confirmation::TransferControlPlan,
    ) -> Result<()> {
        let paired = self
            .devices
            .record_for_device(plan.to_device_id)?
            .is_some_and(|record| record.is_paired());
        if paired {
            Ok(())
        } else {
            Err(crate::error::ControllerError::PermissionDenied {
                detail: "the receiving device is not paired with this host".to_owned(),
            })
        }
    }

    /// Raises the one barrier after a revocation, and reports it.
    ///
    /// Shared by every revocation path so the order cannot drift between them. Each path publishes
    /// its debts itself, once, the moment its restriction has been attempted, and hands `own` here;
    /// this captures them with whatever else is owed. A revocation that found its work already done
    /// published none (unless a close was still on its way under a call's grant, which it owes a
    /// fence for), and its barrier captures whatever is still owed, which is how a retry of a
    /// revocation whose barrier failed fences for it. Nothing newly withdrawn and nothing owed is
    /// answered with the revision in force and the barrier as it stands.
    pub(super) async fn complete_revocation(
        &self,
        audience: Audience,
        named: Option<kr_protocol::ids::GrantId>,
        revoked_grants: kr_protocol::scalars::CanonicalSet<kr_protocol::ids::GrantId>,
        own: OwnBarrier,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        // Both come from the barrier: it reads the registry, which is where a revision is
        // allocated, and a second reading taken separately can be a different one. An answer that
        // named one revision and carried a barrier for another would be evidence of no single
        // moment.
        let barrier = self.barrier(own).await?;
        let barrier = self.barrier_for(audience, named, barrier)?;
        // A revoked owner is no longer a key the feed may be told can remove this host.
        if let Some(runtime) = self.feed_runtime() {
            runtime.wake();
        }
        // Cut to what one control frame carries: a revocation takes effect whatever it withdrew,
        // and the caller is owed an answer it can decode. Every total is counted before the cut.
        let answer = kr_protocol::sharing::RevocationResult::bounded(
            barrier.authority_revision,
            revoked_grants.iter().copied(),
            barrier,
        );
        if !answer.fits_a_frame() {
            Self::report_uncarriable_answer("a revocation");
        }
        Ok(answer)
    }

    /// The barrier as `audience` is told of it.
    ///
    /// A device is told of the workers of the sessions the grant it revoked covers, and of no
    /// other: the barrier names every worker the host holds, and for a worker the session it
    /// serves and the actions its fence named. The grant is the one the request names, so a
    /// revocation that finds it already revoked, and withdraws nothing, is told of the same
    /// workers, and a barrier still pending for them is still read as pending. A delegation
    /// narrows what it is made from, so what the grant covers covers what descends from it. A
    /// share and a transfer's replacement name their sessions, so a device does not revoke a grant
    /// over every session; were one named, the device would hold a share over every session
    /// above it, and is told of them all.
    ///
    /// # Errors
    ///
    /// Returns a refusal when a device is asked about no grant, which is no answer a device is
    /// given, and a storage error when the grant cannot be read.
    pub(super) fn barrier_for(
        &self,
        audience: Audience,
        named: Option<kr_protocol::ids::GrantId>,
        barrier: kr_protocol::action::RevocationBarrier,
    ) -> Result<kr_protocol::action::RevocationBarrier> {
        if audience == Audience::Host {
            return Ok(barrier);
        }
        let Some(named) = named else {
            return Err(crate::error::ControllerError::PermissionDenied {
                detail: "a device is told of the workers of the grant it revokes".to_owned(),
            });
        };
        let mut covered = std::collections::BTreeSet::new();
        if let Some(record) = self.sharing.grants().record(named)? {
            match record.grant.session_selector {
                kr_protocol::grant::SessionSelector::Any => return Ok(barrier),
                kr_protocol::grant::SessionSelector::These { session_ids } => {
                    covered.extend(session_ids.iter().copied());
                }
                kr_protocol::grant::SessionSelector::None => {}
            }
        }
        Ok(barrier.within(&covered))
    }

    /// The same, for a transfer: the grant written travels in the answer beside the revocation,
    /// which is cut to what is left of a frame once the grant has its share.
    pub(super) async fn complete_transfer(
        &self,
        replacement: kr_protocol::grant::Grant,
        revoked_grants: kr_protocol::scalars::CanonicalSet<kr_protocol::ids::GrantId>,
        own: OwnBarrier,
    ) -> Result<kr_protocol::sharing::GrantTransferResult> {
        let barrier = self.barrier(own).await?;
        let answer = kr_protocol::sharing::GrantTransferResult::bounded(
            replacement,
            barrier.authority_revision,
            revoked_grants.iter().copied(),
            barrier,
        );
        if !answer.fits_a_frame() {
            Self::report_uncarriable_answer("a transfer");
        }
        Ok(answer)
    }

    /// Says that an answer cannot be read by its caller although the change it reports has taken
    /// effect.
    fn report_uncarriable_answer(what: &str) {
        eprintln!(
            "kr-controller: the answer to {what} is larger than one control frame can carry even \
             when cut, so its caller cannot read it; the change has taken effect"
        );
    }

    /// Changes this host's policy and writes the result down.
    ///
    /// Every accepted change goes through here. A policy that could be changed without being
    /// persisted would come back as the previous one after an ordinary restart, which is the same
    /// failure as accepting a restored old policy by a different route.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the policy cannot be written.
    pub fn update_policy<T>(
        &self,
        change: impl FnOnce(&mut crate::grants::HostPolicy) -> T,
    ) -> Result<T> {
        self.commit_policy(
            |policy| Ok(change(policy)),
            |grants, snapshot, _| grants.store_policy(snapshot),
            |_| Ok(()),
        )
    }

    /// Changes this host's policy for the action `hold` claimed, and writes the policy and the
    /// action's answer down in one transaction.
    ///
    /// `change` may refuse, and then nothing is written, published or advanced. It returns the
    /// value the caller wants back and the bytes the claim keeps as the action's answer.
    /// `still_admitted` runs inside the transaction, once the store's lock is held and before the
    /// first write, so the wait for that lock cannot outlast the admission, the owner's
    /// confirmation or any precondition the caller asks again there.
    ///
    /// # Errors
    ///
    /// Returns what `change` or `still_admitted` refuses with, and a storage error when the policy
    /// or the answer cannot be written; then neither is.
    pub fn update_policy_claimed<T>(
        &self,
        hold: &crate::grants::ClaimHold,
        change: impl FnOnce(&mut crate::grants::HostPolicy) -> Result<(T, Vec<u8>)>,
        still_admitted: impl FnOnce() -> Result<()>,
    ) -> Result<T> {
        self.commit_policy(
            change,
            |grants, snapshot, (_, answer)| {
                grants.store_policy_claimed(
                    snapshot,
                    hold,
                    answer,
                    kr_ipc::now_ms().get(),
                    still_admitted,
                )
            },
            |_| Ok(()),
        )
        .map(|(value, _)| value)
    }

    /// Changes this host's policy for the action `hold` claimed as [`Self::update_policy_claimed`]
    /// does, writing the event of exclusive management having ended with it when `ending` names
    /// one, and giving `still_admitted` the transaction's own connection.
    ///
    /// # Errors
    ///
    /// As [`Self::update_policy_claimed`].
    pub fn update_policy_checked<T>(
        &self,
        hold: &crate::grants::ClaimHold,
        change: impl FnOnce(&mut crate::grants::HostPolicy) -> Result<(T, Vec<u8>)>,
        ending: Option<&crate::grants::ExclusiveEnding>,
        still_admitted: impl FnOnce(&rusqlite::Connection) -> Result<()>,
    ) -> Result<T> {
        self.commit_policy(
            change,
            |grants, snapshot, (_, answer)| {
                grants.store_policy_checked(
                    snapshot,
                    hold,
                    answer,
                    kr_ipc::now_ms().get(),
                    ending,
                    still_admitted,
                )
            },
            |_| Ok(()),
        )
        .map(|(value, _)| value)
    }

    /// The one way a change to the policy is made, written and put in force.
    ///
    /// The lock is held across the write. Releasing it first would let two accepted changes reach
    /// the store out of order and leave the older one on disk, which is the restriction silently
    /// coming back after the next restart. The change is made to a copy and published only once it
    /// is written down. Mutating the live policy first would let a relaxation that failed to
    /// persist take effect anyway, and an error the caller sees would be an error about something
    /// that happened. A change that refuses leaves the policy, its epoch and the store as they were.
    ///
    /// `write` is what the registry takes of the change, and gets the snapshot to write to it.
    /// `then` is what the change writes beside the registry, after the registry took it: the
    /// applied policies, which the registry has no place for. A request the registry refuses
    /// writes nothing in `then`, and a stop between the two leaves what `then` writes as it was.
    ///
    /// Once the registry took the change it is the host's policy, whatever `then` answers. The
    /// registry is what a restart reads, and the policy in force follows it: a change the registry
    /// holds but the policy in force lacks would be written over by the next change, which is
    /// made from the policy in force. So when `then` fails, the policy in force takes the change
    /// as the registry holds it, which is all of it but the applied policies `then` writes, and
    /// the error is returned after that. Stopping the host's decisions until a write succeeded
    /// would instead turn a disk fault that a repeated request repairs into a host that cannot
    /// decide.
    pub(super) fn commit_policy<C>(
        &self,
        change: impl FnOnce(&mut crate::grants::HostPolicy) -> Result<C>,
        write: impl FnOnce(
            &crate::grants::GrantDirectory,
            &crate::grants::StoredPolicy,
            &C,
        ) -> Result<()>,
        then: impl FnOnce(&C) -> Result<()>,
    ) -> Result<C> {
        let mut held = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut candidate = held.clone();
        let value = change(&mut candidate)?;
        // The offline bound's time is taken with the policy that holds it: a change measured from
        // another synchronisation starts it again, and any other change keeps the time already
        // spent. Its record is written before the policy and is one of its own, so a stop between
        // the two leaves the record the policy on disk is measured from as it was. The anchor is
        // changed only under the policy's lock, which is held from here until it is put in force.
        let previous = self.lifetimes.offline_anchor();
        let next = net::offline_anchor(
            candidate.offline_validity(),
            previous,
            &self.lifetimes.anchor_sources(),
        )?;
        let snapshot = candidate.snapshot();
        write(self.sharing.grants(), &snapshot, &value)?;
        let unwritten = then(&value).err();
        if unwritten.is_some() {
            candidate = candidate.with_applied_policies_of(&held);
        }
        self.utc_floor.wrote(snapshot.utc_floor_ms.get());
        if next != previous
            && let Err(error) = self
                .devices
                .forget_offline_anchors_except(next.map(|next| next.synchronised_at_ms()))
        {
            eprintln!("kr-controller: could not forget stale offline bound records: {error}");
        }
        // The time bounds the written policy states, published under its lock before it is put in
        // force, so a reader that loads a cell sees what the policy it could read says.
        candidate.publish_leases(&held);
        net::publish_offline_bound(
            candidate.offline_cell(),
            candidate.offline_validity(),
            next,
            self.clock.now(),
            self.settled_utc_now(),
        );
        *held = candidate;
        self.mirror_the_feed_standing_of(&held);
        self.lifetimes.hold_offline_anchor(next, &held);
        // Published with the policy, under its lock, so a decision that reads this epoch reads the
        // policy it names or a later one.
        self.advance_authority_epoch();
        unwritten.map_or(Ok(value), Err)
    }

    /// Removes a revoked device's bindings from every organisation this host is enrolled in, so
    /// no lease answers for it again.
    ///
    /// A write that fails is logged and leaves the binding on disk. The device is revoked by
    /// then, with every grant it held, so nothing is decided under that binding meanwhile.
    pub(crate) fn unbind_device(&self, device_id: kr_protocol::ids::DeviceId) {
        let bound = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_bound(device_id);
        if bound && let Err(error) = self.update_policy(|policy| policy.unbind_device(device_id)) {
            eprintln!(
                "kr-controller: could not remove a revoked device's organisation bindings: {error}"
            );
        }
    }
}
