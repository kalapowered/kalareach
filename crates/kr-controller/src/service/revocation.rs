//! Revoking a grant or a device, transferring control, and the host's policy.

use kr_protocol::scalars::TimestampMs;

use crate::error::Result;

use super::barrier::{OwnBarrier, Reach};
use super::{Controller, net};

/// The clock the owner-confirmation ceremony reads, which is this daemon's own.
///
/// The monotonic reading and the boot identity are what a confirmation's deadline is measured on,
/// so a wall clock that moves cannot lengthen one.
#[derive(Debug)]
struct PairingTime;

impl kr_pairing::platform::PairingClock for PairingTime {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        // The daemon's own boot value, hashed to the fixed width this clock's identity uses. Two
        // boots differ here whenever they differ there, which is the whole of what it is for.
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
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
    /// retry that changed nothing.
    ///
    /// `carried` is the admission of the mutation this revocation is performing, when it is
    /// performing one. It is checked again inside the transaction that withdraws the rows, once
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
        let own = self.publish_debts(&Self::host_wide(revocation.debt));
        self.complete_revocation(revocation.revoked.iter().copied().collect(), own)
            .await
    }

    /// A revocation's debt, when it wrote one, as one that reaches every connection.
    fn host_wide(
        debt: Option<crate::grants::store::DebtId>,
    ) -> Vec<(crate::grants::store::DebtId, Reach)> {
        debt.into_iter().map(|debt| (debt, Reach::Host)).collect()
    }

    /// Revokes every grant one device holds, then revokes the device itself.
    ///
    /// The grants go first for the same reason as above. What this does **not** do is withdraw
    /// that one device's network registration selectively: that is `net::Network::revoke_device`,
    /// which owns the in-memory registrations, and this daemon reaches it through the network
    /// entry point rather than from here. What happens instead is the daemon-wide fence, which is
    /// stricter rather than weaker: every registration is withdrawn and re-admitted at the
    /// revision now in force, and the revoked device's record is already marked so it cannot be
    /// re-admitted at all.
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
            let registry = match carried {
                Some(carried) => {
                    let registry = self.registry.lock().await;
                    self.check_admission(&registry, carried)?;
                    Some(registry)
                }
                None => None,
            };
            let revocation = self.sharing.grants().revoke_device(
                device_id,
                now_ms,
                || self.still_admitted(registry.as_deref(), carried),
                claim,
            )?;
            // The transaction that revoked is the restriction, and it has committed.
            let own = self.publish_debts(&Self::host_wide(revocation.debt));
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
                self.still_admitted(registry.as_deref(), carried)?;
            }
            let record_is_live = self
                .devices
                .record_for_device(device_id)?
                .is_some_and(|record| record.revoked_at_ms.is_none());
            let record_debt = if record_is_live {
                if !withdrew {
                    self.still_admitted(registry.as_deref(), carried)?;
                }
                Some(self.owe_debt(
                    &format!("the revocation of device {device_id}'s record"),
                    Reach::Host,
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
                self.still_admitted(registry.as_deref(), carried).err()
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
            let own = own.and(self.publish_debts(&Self::host_wide(record_debt)));
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
        if lapsed.is_none() {
            self.retire_push_destination(device_id);
        }
        recorded?;
        match lapsed {
            // Nothing was withdrawn and nothing is owed, so there is nothing to finish.
            Some(error) if !owes => Err(error),
            Some(error) => {
                self.complete_revocation(revocation.revoked.iter().copied().collect(), own)
                    .await?;
                Err(error)
            }
            None => {
                self.complete_revocation(revocation.revoked.iter().copied().collect(), own)
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
    /// # Errors
    ///
    /// Returns an error when the transfer is refused or the registry cannot be written.
    pub async fn transfer_control(
        &self,
        plan: &crate::sharing::TransferPlan,
        confirmation: &crate::sharing::ConfirmedTransfer,
    ) -> Result<(
        crate::sharing::ControlTransfer,
        kr_protocol::sharing::RevocationResult,
    )> {
        // Written down before anything is decided from it. The transfer decides the source's expiry
        // again at the moment it writes, and a lapse it finds there is owed its record, which is
        // written before the refusal goes back.
        let now_ms = self.settled_now_ms();
        let revision = self.policy().authority_revision();
        let transfer =
            self.sharing
                .transfer_control(plan, confirmation, &PairingTime, revision, now_ms);
        self.settle_floor();
        let transfer = transfer?;
        let own = self.publish_debts(&Self::host_wide(transfer.revoked.debt));
        let completed = self
            .complete_revocation(transfer.revoked.revoked.iter().copied().collect(), own)
            .await?;
        Ok((transfer, completed))
    }

    /// Raises the one barrier after a revocation, and reports it.
    ///
    /// Shared by every revocation path so the order cannot drift between them. Each path publishes
    /// its debts itself, once, the moment its restriction has been attempted, and hands `own` here;
    /// this captures them with whatever else is owed. A revocation that found its work already done
    /// published none, and its barrier captures whatever is still owed, which is how a retry of a
    /// revocation whose barrier failed fences for it. Nothing newly withdrawn and nothing owed is
    /// answered with the revision in force and the barrier as it stands.
    pub(super) async fn complete_revocation(
        &self,
        revoked_grants: kr_protocol::scalars::CanonicalSet<kr_protocol::ids::GrantId>,
        own: OwnBarrier,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        // Both come from the barrier: it reads the registry, which is where a revision is
        // allocated, and a second reading taken separately can be a different one. An answer that
        // named one revision and carried a barrier for another would be evidence of no single
        // moment.
        let barrier = self.barrier(own).await?;
        // Cut to what one control frame carries: a revocation takes effect whatever it withdrew,
        // and the caller is owed an answer it can decode. Every total is counted before the cut.
        let answer = kr_protocol::sharing::RevocationResult::bounded(
            barrier.authority_revision,
            revoked_grants.iter().copied(),
            barrier,
        );
        if !answer.fits_a_frame() {
            eprintln!(
                "kr-controller: the answer to a revocation is larger than one control frame can \
                 carry even when cut, so its caller cannot read it; the revocation has taken effect"
            );
        }
        Ok(answer)
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
        // The lock is held across the write. Releasing it first would let two accepted changes
        // reach the store out of order and leave the older one on disk, which is the restriction
        // silently coming back after the next restart.
        let mut held = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The change is made to a copy and published only once it is written down. Mutating the
        // live policy first would let a relaxation that failed to persist take effect anyway, and
        // an error the caller sees would be an error about something that happened.
        let mut candidate = held.clone();
        let value = change(&mut candidate);
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
        self.sharing.grants().store_policy(&snapshot)?;
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
        self.lifetimes.hold_offline_anchor(next, &held);
        // Published with the policy, under its lock, so a decision that reads this epoch reads the
        // policy it names or a later one.
        self.advance_authority_epoch();
        Ok(value)
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
