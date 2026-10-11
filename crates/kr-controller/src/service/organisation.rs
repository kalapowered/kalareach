//! Organisation policy: enrolling this host in an organisation, and reporting what it holds.
//!
//! Section 17 has a host opt into an organisation's policy and pin its policy-signing authority.
//! The owner does that with `organisation.enrol`, which is an authority change like a grant's
//! creation: it is claimed, performed once and answered from its record. Two things set it apart.
//! The owner's confirmation names exactly the chain the host verified, so the host spends that
//! confirmation before it claims the action; a request that finds none has written nothing, and an
//! owner's client that polls for the confirmation leaves no row behind per attempt. And what the
//! action changes is the policy, which is written together with the action's answer in one
//! transaction, so a host never holds an enrolment it cannot answer for.

use kr_protocol::confirmation::{
    ConfirmationDisplay, ExclusiveManagementPlan, OrganisationEnrolPlan,
};
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::OrganisationId;
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    HostDeviceView, MembershipPresentParams, MembershipPresentResult, OrganisationChangeMarker,
    OrganisationEnrolParams, OrganisationEnrolResult, OrganisationEnrolmentView,
    OrganisationExclusiveSetParams, OrganisationExclusiveSetResult, OrganisationLeaseView,
    OrganisationListResult, OrganisationMemberView, OrganisationWithdrawParams,
};
use kr_protocol::pairing::{ConfirmationChannel, KeyPurpose, SensitiveAction, key_id};
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, KeyId, Nullable, TimestampMs};

use crate::error::{ControllerError, Result};
use crate::grants::LeaseRefused;
use crate::grants::organisation::{ChainRefused, LeaseInstalled};
use crate::grants::{CLOCK_DISTRUSTED, FLOOR_UNRECORDED};
use crate::sharing::ConfirmedAction;

use super::Audience;
use super::barrier::Reach;
use super::{Controller, encode, parse};

/// What `organisation.enrol` has settled before it claims the action: the chain, the plan the
/// owner confirmed for it, and the confirmation this host spent.
pub(super) struct EnrolIntent {
    params: OrganisationEnrolParams,
    plan: OrganisationEnrolPlan,
    confirmed: ConfirmedAction,
}

/// What `organisation.exclusive.set` has settled before it claims the action: the plan the owner
/// confirmed and the confirmation this host spent.
pub(super) struct ExclusiveIntent {
    plan: ExclusiveManagementPlan,
    confirmed: ConfirmedAction,
}

/// What an organisation change that needs the owner's confirmation has settled before it claims
/// its action.
pub(super) enum OrganisationIntent {
    /// `organisation.enrol`.
    Enrol(Box<EnrolIntent>),
    /// `organisation.exclusive.set`.
    Exclusive(ExclusiveIntent),
}

/// The identifier of a policy-signing key, which is how an administrator reads one out.
fn policy_key_id(key: &AuthorisationKey) -> KeyId {
    key_id(KeyPurpose::Authorisation, key.as_bytes())
}

/// The refusal a chain or a clock that cannot enrol this host is reported as.
///
/// A chain that does not verify is a bad argument from a caller that already manages the host.
/// A host that distrusts its clock, or cannot write down the reading a head is judged at, says so
/// as it does everywhere else: neither is a fact about the chain.
pub(super) fn chain_refusal(refused: ChainRefused) -> ControllerError {
    match refused {
        ChainRefused::ClockUntrusted => ControllerError::ClockUntrusted {
            detail: CLOCK_DISTRUSTED.to_owned(),
        },
        ChainRefused::FloorUnrecorded => ControllerError::Refused {
            code: ErrorCode::StorageUnavailable,
            detail: FLOOR_UNRECORDED.to_owned(),
        },
        other => ControllerError::Refused {
            code: ErrorCode::InvalidArgument,
            detail: other.to_string(),
        },
    }
}

/// Whether this policy lets the host leave `organisation_id`.
fn check_withdrawal(
    policy: &crate::grants::HostPolicy,
    organisation_id: OrganisationId,
) -> Result<()> {
    if policy.enrolment(organisation_id).is_none() {
        return Err(ControllerError::InvalidArgument(
            "this host is not enrolled in that organisation".to_owned(),
        ));
    }
    if policy.is_exclusively_managed() && policy.enrolments().count() == 1 {
        return Err(ControllerError::InvalidArgument(
            "this host is exclusively organisation-managed, and leaving its last organisation \
             would leave nothing to answer for it; end exclusive management first"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Whether this policy lets the host change exclusive management as `plan` says.
///
/// Turning it on needs an enrolment, because a personal grant answers to an organisation's lease
/// there and a host with none has nothing to answer to, and a device that can recover the host,
/// because the owner's own devices stop being served when their lease ends. Either way the change
/// has to be a change, and the organisations the owner confirmed are the ones the host is enrolled
/// in.
fn check_exclusive_change(
    policy: &crate::grants::HostPolicy,
    plan: &ExclusiveManagementPlan,
    recoverable: bool,
) -> Result<()> {
    if policy.is_exclusively_managed() == plan.exclusive {
        return Err(ControllerError::InvalidArgument(if plan.exclusive {
            "this host is exclusively organisation-managed already".to_owned()
        } else {
            "this host is not exclusively organisation-managed".to_owned()
        }));
    }
    let enrolled: CanonicalSet<OrganisationId> = policy
        .enrolments()
        .map(|(organisation_id, _)| organisation_id)
        .collect();
    if enrolled != plan.organisation_ids {
        return Err(ControllerError::PermissionDenied {
            detail: "the organisations this host is enrolled in are not the ones the owner \
                     confirmed"
                .to_owned(),
        });
    }
    if plan.exclusive {
        if enrolled.is_empty() {
            return Err(ControllerError::InvalidArgument(
                "this host is enrolled in no organisation, so there is nothing to manage it \
                 exclusively"
                    .to_owned(),
            ));
        }
        require_a_device_that_can_recover(recoverable)?;
    }
    Ok(())
}

/// Refuses making the host exclusive while a worker that may be alive cannot be told what the
/// local owner may do: it would serve its local caller without the hold.
fn require_every_worker_can_be_told(lacking: &[kr_protocol::ids::SessionId]) -> Result<()> {
    if lacking.is_empty() {
        return Ok(());
    }
    Err(ControllerError::InvalidArgument(format!(
        "{} session worker(s) cannot be told what this host's local owner may do (a session an \
         earlier release started, or one this host has not reached), so they would serve a local \
         caller without the owner's membership lease; end them with `kr close` first",
        lacking.len()
    )))
}

/// Refuses making the host exclusive when no owner device could confirm for it once its leases
/// ended.
fn require_a_device_that_can_recover(recoverable: bool) -> Result<()> {
    if recoverable {
        Ok(())
    } else {
        Err(ControllerError::InvalidArgument(
            "no owner device of this host has a grant that never expires and reaches this \
             environment, so nothing could confirm for it once its leases ended; pair one first"
                .to_owned(),
        ))
    }
}

/// The refusal a lease that a rule refuses is reported as: `PERMISSION_DENIED` naming the rule,
/// except where the clock decided it, which keeps the code every other decision of the clock has.
fn lease_refusal(refused: LeaseRefused) -> ControllerError {
    match refused {
        LeaseRefused::ClockUntrusted => ControllerError::ClockUntrusted {
            detail: CLOCK_DISTRUSTED.to_owned(),
        },
        LeaseRefused::FloorUnrecorded => ControllerError::Refused {
            code: ErrorCode::StorageUnavailable,
            detail: FLOOR_UNRECORDED.to_owned(),
        },
        other => ControllerError::PermissionDenied {
            detail: format!("{} ({})", other.detail(), other.name()),
        },
    }
}

impl Controller {
    /// Arms the pause a withdrawal from an organisation, or making the host exclusively
    /// organisation-managed, stops at once its policy is written, before its fence is published.
    /// Returns the end that says the change has arrived, and the end that lets it go. The pause
    /// holds the thread, not the task, and the registry's guard with it. It fires once.
    #[cfg(feature = "testing")]
    pub fn pause_organisation_restriction_after_commit(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_an_organisation_restriction_commits.arm()
    }

    /// Verifies the chain an owner asks to enrol this host in and states the plan whose digest the
    /// owner confirms.
    ///
    /// The whole chain is verified first, at this host's reading of UTC while it trusts its clock:
    /// the structure, every link under its predecessor's key, the head under the last link's key
    /// and current. Nothing is shown to an owner before that, so a chain that does not verify is
    /// never confirmed, and the plan is the verified chain's: its first key and the key signing now.
    ///
    /// # Errors
    ///
    /// Returns why the chain cannot enrol this host, or a storage error from the clock's record.
    pub(crate) fn organisation_enrol_plan(
        &self,
        params: &OrganisationEnrolParams,
    ) -> Result<OrganisationEnrolPlan> {
        let reading = self.lifetimes.clock_trust().sample(&self.devices)?;
        self.policy()
            .verify_enrolment(&params.authority, reading.as_ref())
            .map_err(chain_refusal)?;
        OrganisationEnrolPlan::of_authority(&params.authority).ok_or_else(|| {
            ControllerError::InvalidArgument("a chain names at least its first key".to_owned())
        })
    }

    /// The challenge's description, for `owner.confirmation.request` of an enrolment.
    pub(crate) fn organisation_enrol_resolved(
        &self,
        params: &OrganisationEnrolParams,
    ) -> Result<crate::service::net::owner::Resolved> {
        let plan = self.organisation_enrol_plan(params)?;
        Ok(crate::service::net::owner::Resolved {
            action: OrganisationEnrolPlan::sensitive_action(),
            digest: plan
                .action_digest()
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
            destination: None,
            rights: CanonicalSet::new(),
            display: plan.display(),
            bootstrap: false,
        })
    }

    /// Settles what `organisation.enrol` needs before it claims the action: parses it, verifies
    /// the chain, and spends the owner's answered confirmation of exactly that chain.
    ///
    /// The confirmation is spent first, and written to the acceptance record before the policy
    /// changes, so a stop before the commit wastes it and enrols nothing, and it is never spent
    /// twice. With none the request fails here, before anything is claimed, so the refusal is not
    /// kept under the action and an owner's client may ask again with a fresh one.
    ///
    /// # Errors
    ///
    /// Returns why the chain cannot enrol this host, or `OWNER_CONFIRMATION_REQUIRED` when no
    /// answered confirmation of exactly this chain stands.
    pub(super) fn organisation_enrol_intent(
        &self,
        mutation: &MutationRequest,
    ) -> Result<EnrolIntent> {
        let params: OrganisationEnrolParams = parse(&mutation.params)?;
        let plan = self.organisation_enrol_plan(&params)?;
        let digest = plan
            .action_digest()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let rights = CanonicalSet::new();
        let expectation =
            self.owner
                .expectation(SensitiveAction::ChangeHostAuthority, digest, None, &rights);
        // Only a challenge this host described as an enrolment: one a caller described with the
        // same action and digest was shown to the owner as the caller's own words.
        let confirmed = self.owner.spend_answered(
            &expectation,
            &|display| matches!(display, ConfirmationDisplay::EnrolOrganisation { .. }),
            "enrol an organisation's policy",
        )?;
        Ok(EnrolIntent {
            params,
            plan,
            confirmed,
        })
    }

    /// Enrols this host in an organisation, under the claim of the action that asked.
    ///
    /// The registry's guard is taken first, and held to the end: the fence this host owes is asked
    /// about under it, and so is the authority revision the enrolment takes, so an enrolment cannot
    /// take the revision a barrier is about to replace. Under the policy's lock the chain is
    /// verified again at a reading taken now, and the policy row and the action's answer are
    /// written in one transaction, in which the admission and the owner's confirmation are asked
    /// again, after every wait for a lock, immediately before the first write.
    ///
    /// # Errors
    ///
    /// Returns what the admission, the confirmation, the chain or the store refuses with. Nothing
    /// is enrolled then.
    pub(super) async fn organisation_enrol(
        &self,
        carried: crate::authority::AdmittedMutation,
        hold: &crate::grants::ClaimHold,
        intent: EnrolIntent,
    ) -> Result<ParamsValue> {
        let EnrolIntent {
            params,
            plan,
            confirmed,
        } = intent;
        let digest = plan
            .action_digest()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let registry = self.registry.lock().await;
        self.check_admission(&registry, &carried)?;
        let revision = registry.authority_revision()?;
        let reading = self.lifetimes.clock_trust().sample(&self.devices)?;
        let answer = self.update_policy_claimed(
            hold,
            |policy| {
                let verified = policy
                    .verify_enrolment(&params.authority, reading.as_ref())
                    .map_err(chain_refusal)?;
                policy.enrol(verified, revision).map_err(chain_refusal)?;
                let answer = OrganisationEnrolResult {
                    organisation_id: plan.organisation_id,
                    enrolment_revision: revision,
                    accepted_head: plan.anchor.revision,
                    root_key_id: policy_key_id(&plan.root.public_key),
                };
                let bytes = kr_cbor::encode(encode(&answer)?.as_value());
                Ok((answer, bytes))
            },
            || {
                self.check_admission(&registry, &carried)?;
                self.owner
                    .covers(&confirmed, digest, "organisation enrolment")?;
                self.head_holds_still(
                    params.authority.head.payload.expires_at_ms,
                    reading.as_ref(),
                )
            },
        )?;
        drop(registry);
        encode(&answer)
    }

    /// `organisation.withdraw`: this host leaves an organisation's policy, and is fenced for it.
    ///
    /// A withdrawal restricts work already admitted: every grant that requires the organisation
    /// stops being honoured and every lease installed under the enrolment ends with it. So it
    /// follows the order of every restriction. The registry's guard is taken first and held through
    /// the publication of the debt, because a debt that is only owed refuses nothing, and a guard
    /// let go earlier would let an enrolment pass the fence and read the revision the barrier is
    /// about to replace. The debt is written first, one for the whole host on every withdrawal,
    /// which also advances the revision when no grant required the organisation. The enrolment is
    /// removed and the claim's marker is written in one transaction, so a repeat of the action can
    /// tell a withdrawal that committed from one that never began; the debt is published whether
    /// or not the write landed; and the answer is built from the barrier, which is raised once the
    /// guard is let go.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` when this host is not enrolled in the organisation, or when it is
    /// exclusively organisation-managed and this is its last enrolment, and what the admission, the
    /// store or the barrier refuse with.
    pub(super) async fn organisation_withdraw(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
        hold: &crate::grants::ClaimHold,
    ) -> Result<ParamsValue> {
        let params: OrganisationWithdrawParams = parse(&mutation.params)?;
        let organisation_id = params.organisation_id;
        let marker = kr_cbor::encode(
            encode(&OrganisationChangeMarker::Withdrawn { organisation_id })?.as_value(),
        );
        let (written, own) = {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)?;
            // Refused before anything is owed: a fence for a withdrawal that cannot happen is a
            // revision advanced and every connection fenced for nothing.
            check_withdrawal(&self.policy(), organisation_id)?;
            let debt = self.owe_debt(
                &format!("the withdrawal of organisation {organisation_id}"),
                Reach::Host,
            )?;
            let written = self.update_policy_claimed(
                hold,
                |policy| {
                    check_withdrawal(policy, organisation_id)?;
                    policy.withdraw(organisation_id);
                    Ok(((), marker))
                },
                || self.check_admission(&registry, &carried),
            );
            // Nothing is awaited between the write and the publication of its debt, here or in a
            // test that stops the thread between them.
            #[cfg(feature = "testing")]
            self.after_an_organisation_restriction_commits.wait();
            (written, self.publish_debts(&[(debt, Reach::Host)]))
        };
        match written {
            Ok(()) => {
                let completed = self
                    .complete_revocation(Audience::Host, None, CanonicalSet::new(), own)
                    .await?;
                encode(&completed)
            }
            // The debt is published and its barrier is the debt pass's.
            Err(error) => Err(error),
        }
    }

    /// The marker a recorded answer to an organisation change that restricts keeps, when `record`
    /// is one: the change committed, and its answer is built from the barrier.
    pub(super) fn organisation_marker(
        &self,
        mutation: &MutationRequest,
        record: &crate::grants::ActionRecord,
    ) -> Option<OrganisationChangeMarker> {
        let crate::grants::ActionRecord::Answered { result } = record else {
            return None;
        };
        if !matches!(
            mutation.method.method(),
            Some(Method::OrganisationWithdraw | Method::OrganisationExclusiveSet)
        ) {
            return None;
        }
        kr_cbor::decode(result, &kr_cbor::Limits::DEFAULT)
            .ok()
            .and_then(|value| ParamsValue::new(value).to_typed().ok())
    }

    /// The answer to an organisation change whose marker is recorded: the revision and the
    /// per-worker completion of the fence as the barrier stands now, raised again if it is still
    /// owed.
    ///
    /// # Errors
    ///
    /// Returns what the barrier refuses with.
    pub(super) async fn answered_from_the_barrier(
        &self,
        marker: OrganisationChangeMarker,
    ) -> Result<ParamsValue> {
        self.answered_from_the_barrier_with(self.publish_debts(&[]), marker)
            .await
    }

    /// The answer to an organisation change whose fence `own` is raised now.
    async fn answered_from_the_barrier_with(
        &self,
        own: super::barrier::OwnBarrier,
        marker: OrganisationChangeMarker,
    ) -> Result<ParamsValue> {
        let completed = self
            .complete_revocation(Audience::Host, None, CanonicalSet::new(), own)
            .await?;
        match marker {
            OrganisationChangeMarker::Withdrawn { .. } => encode(&completed),
            OrganisationChangeMarker::ExclusiveOn => encode(&OrganisationExclusiveSetResult {
                exclusive: true,
                authority_revision: completed.authority_revision,
                barrier: Nullable::some(completed.barrier),
            }),
        }
    }

    /// The rights ceiling this host's configuration has in force, which narrows every paired
    /// device's grant.
    fn rights_ceiling_in_force(&self) -> Option<CanonicalSet<kr_protocol::rights::ActionRight>> {
        self.rights_ceiling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The plan whose digest the owner confirms for making the host exclusively
    /// organisation-managed, or ending that: the new value and the organisations the host is
    /// enrolled in now, so a confirmation for one state of the host is not carried to another.
    fn exclusive_plan(&self, exclusive: bool) -> ExclusiveManagementPlan {
        ExclusiveManagementPlan {
            exclusive,
            organisation_ids: self
                .policy()
                .enrolments()
                .map(|(organisation_id, _)| organisation_id)
                .collect(),
        }
    }

    /// The challenge's description, for `owner.confirmation.request` of a change of exclusive
    /// management.
    ///
    /// A change this host would refuse is refused here, before anyone is asked to confirm it.
    ///
    /// # Errors
    ///
    /// Returns why the host cannot make the change now.
    pub(crate) fn organisation_exclusive_resolved(
        &self,
        exclusive: bool,
    ) -> Result<crate::service::net::owner::Resolved> {
        let plan = self.exclusive_plan(exclusive);
        let recoverable = self
            .owner
            .an_owner_device_can_recover(self.paths.environment_id())?;
        check_exclusive_change(&self.policy(), &plan, recoverable)?;
        Ok(crate::service::net::owner::Resolved {
            action: ExclusiveManagementPlan::sensitive_action(),
            digest: plan
                .action_digest()
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
            destination: None,
            rights: CanonicalSet::new(),
            display: plan.display(),
            // The terminal may confirm ending exclusive management when no device is left that can
            // confirm for the host, and nothing else: it is decided again wherever the challenge
            // is answered, spent and committed.
            bootstrap: !exclusive && self.owner.recovery_open()?,
        })
    }

    /// Settles what `organisation.exclusive.set` needs before it claims the action: parses it and
    /// spends the owner's answered confirmation of exactly this change.
    ///
    /// As an enrolment's, the confirmation is spent first and a request that finds none is refused
    /// before anything is claimed.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when no answered confirmation of exactly this change
    /// stands.
    pub(super) fn organisation_exclusive_intent(
        &self,
        mutation: &MutationRequest,
    ) -> Result<ExclusiveIntent> {
        let params: OrganisationExclusiveSetParams = parse(&mutation.params)?;
        let plan = self.exclusive_plan(params.exclusive);
        let digest = plan
            .action_digest()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let rights = CanonicalSet::new();
        let expectation = self.owner.expectation(
            ExclusiveManagementPlan::sensitive_action(),
            digest,
            None,
            &rights,
        );
        let confirmed = self.owner.spend_answered(
            &expectation,
            &|display| matches!(display, ConfirmationDisplay::ExclusiveManagement { .. }),
            "change exclusive organisation management",
        )?;
        Ok(ExclusiveIntent { plan, confirmed })
    }

    /// `organisation.exclusive.set`: makes this host exclusively organisation-managed, or ends
    /// that, under the claim of the action that asked.
    ///
    /// Turning it off enlarges what the host serves and restricts nothing, so it writes the policy,
    /// the action's answer and the event of its having ended in one transaction and has no fence to
    /// raise. Turning it on restricts work already admitted, as a withdrawal does, and follows the
    /// same order: the registry's guard to the publication of the debt, the debt first, the policy
    /// and the claim's marker in one transaction, and an answer built from the barrier. Inside the
    /// transaction the admission, the owner's confirmation and, for turning it on, a device that
    /// can recover the host are asked again, after every wait for a lock and before the first
    /// write.
    ///
    /// # Errors
    ///
    /// Returns what the admission, the confirmation, the policy or the store refuses with. Nothing
    /// is changed then.
    pub(super) async fn organisation_exclusive(
        &self,
        carried: crate::authority::AdmittedMutation,
        hold: &crate::grants::ClaimHold,
        intent: ExclusiveIntent,
    ) -> Result<ParamsValue> {
        let ExclusiveIntent { plan, confirmed } = intent;
        let digest = plan
            .action_digest()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let environment_id = self.paths.environment_id();
        // Read and released before anything else is held. A configuration acceptance takes the
        // ceiling and then the grants store; a read inside the store's transaction would take them
        // the other way round. A ceiling that moves after this read is a stale one for this
        // change only: the doors read the ceiling in force.
        let ceiling = self.rights_ceiling_in_force();
        if !plan.exclusive {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)?;
            check_exclusive_change(&self.policy(), &plan, true)?;
            let answer = OrganisationExclusiveSetResult {
                exclusive: false,
                authority_revision: registry.authority_revision()?,
                barrier: Nullable::null(),
            };
            let bytes = kr_cbor::encode(encode(&answer)?.as_value());
            let ending = crate::grants::ExclusiveEnding {
                channel: confirmed.channel(),
                organisation_ids: plan.organisation_ids.clone(),
            };
            self.update_policy_checked(
                hold,
                |policy| {
                    check_exclusive_change(policy, &plan, true)?;
                    policy.set_exclusively_managed(false);
                    Ok(((), bytes))
                },
                Some(&ending),
                |connection| {
                    self.check_admission(&registry, &carried)?;
                    self.owner
                        .covers(&confirmed, digest, "change of exclusive management")?;
                    // The terminal confirms this only while no device can confirm it, read from
                    // the transaction's own file: one that appeared since is the one to ask. The
                    // ceiling was read before the transaction: it is taken before the store
                    // everywhere else, and a configuration acceptance holds it while it writes.
                    if confirmed.channel() == ConfirmationChannel::LocalBootstrapTerminal
                        && crate::grants::an_owner_device_can_recover(
                            connection,
                            environment_id,
                            ceiling.as_ref(),
                        )?
                    {
                        return Err(ControllerError::Refused {
                            code: ErrorCode::OwnerConfirmationRequired,
                            detail: "an owner device that can confirm for this host exists, so \
                                     the terminal no longer confirms the end of exclusive \
                                     management; confirm on that device"
                                .to_owned(),
                        });
                    }
                    Ok(())
                },
            )?;
            drop(registry);
            return encode(&answer);
        }
        let marker = kr_cbor::encode(encode(&OrganisationChangeMarker::ExclusiveOn)?.as_value());
        let (written, own) = {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)?;
            // Refused before anything is owed: a fence for a change that cannot happen is a
            // revision advanced and every connection fenced for nothing.
            let recoverable = self.owner.an_owner_device_can_recover(environment_id)?;
            check_exclusive_change(&self.policy(), &plan, recoverable)?;
            require_every_worker_can_be_told(
                &self.workers_without_local_enforcement_in(&registry)?,
            )?;
            let debt = self.owe_debt(
                "making this host exclusively organisation-managed",
                Reach::Host,
            )?;
            let written = self.update_policy_checked(
                hold,
                |policy| {
                    check_exclusive_change(policy, &plan, true)?;
                    policy.set_exclusively_managed(true);
                    Ok(((), marker))
                },
                None,
                |connection| {
                    self.check_admission(&registry, &carried)?;
                    self.owner
                        .covers(&confirmed, digest, "change of exclusive management")?;
                    // The devices are read from the transaction's own file, so an enablement
                    // never commits after the last device that can recover the host has been
                    // revoked.
                    require_every_worker_can_be_told(
                        &self.workers_without_local_enforcement_in(&registry)?,
                    )?;
                    require_a_device_that_can_recover(crate::grants::an_owner_device_can_recover(
                        connection,
                        environment_id,
                        ceiling.as_ref(),
                    )?)
                },
            );
            // Nothing is awaited between the write and the publication of its debt, here or in a
            // test that stops the thread between them.
            #[cfg(feature = "testing")]
            self.after_an_organisation_restriction_commits.wait();
            (written, self.publish_debts(&[(debt, Reach::Host)]))
        };
        written?;
        self.answered_from_the_barrier_with(own, OrganisationChangeMarker::ExclusiveOn)
            .await
    }

    /// Whether the chain's head is still current, and this host still trusts the clock that said
    /// so, once the enrolment has waited for the locks it writes under.
    ///
    /// The head was judged at a reading taken before those waits, and the head's lifetime is a
    /// bound that can pass while they last. This asks again at the clock now, under the floor, and
    /// reads nothing that writes: the caller is inside the store's transaction, which a second
    /// connection to the same file cannot write under.
    ///
    /// # Errors
    ///
    /// Returns the refusal the chain or the clock earns: a distrusted clock, a head that has run
    /// out, or a bound this host cannot answer while the floor is owed its record.
    fn head_holds_still(
        &self,
        head_expires_at: TimestampMs,
        read: Option<&crate::service::net::devices::ObservedUtc>,
    ) -> Result<()> {
        if !self.lifetimes.clock_trust().is_trusted_now() {
            return Err(chain_refusal(ChainRefused::ClockUntrusted));
        }
        let head_ends = kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: head_expires_at,
        };
        let read_at = read.map_or(0, |reading| reading.now.get());
        if self.sharing.grants().bound_passed(head_ends, read_at)? {
            return Err(chain_refusal(ChainRefused::HeadNotCurrent));
        }
        Ok(())
    }

    /// `membership.present`: a paired device presents the lease its organisation signed for it,
    /// with the organisation's chain when it has moved, and is answered once the lease is installed
    /// and the fence it may owe is published.
    ///
    /// The registry's guard is taken first and held to the end, like the owner's other authority
    /// changes: the fence this host may owe is asked about under it, and the admission is asked
    /// again inside the transaction that writes the policy. The key the lease must name is the one
    /// the device's record holds, which the connection proved when it was admitted. A repeat of a
    /// lease still in force is answered as the first presentation was, since the policy decides
    /// the lease again each time; a lease that is not in force is answered with the rule that
    /// refuses it, which is why the answer to a lost reply is the same lease presented again.
    ///
    /// # Errors
    ///
    /// Returns the rule that refuses the lease: `PERMISSION_DENIED` naming it, `CLOCK_UNTRUSTED`
    /// when this host distrusts its clock, and a storage error when the floor the refusal stood on
    /// or the policy cannot be written. A chain that does not verify refuses the presentation.
    pub(crate) async fn membership_present(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        proven_key: &AuthorisationKey,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: MembershipPresentParams = parse(&mutation.params)?;
        let registry = self.registry.lock().await;
        self.check_admission(&registry, &carried)?;
        let installed = self
            .present_membership_lease(
                device_id,
                proven_key,
                &params.lease,
                params.authority.as_ref(),
                Some((&registry, &carried)),
            )?
            .map_err(lease_refusal)?;
        drop(registry);
        encode(&self.presented(&installed)?)
    }

    /// What the host tells a device whose lease it installed or found installed.
    fn presented(&self, installed: &LeaseInstalled) -> Result<MembershipPresentResult> {
        let ended_at_terminal = self
            .sharing
            .grants()
            .exclusive_management_events()?
            .into_iter()
            .rev()
            .find(|event| {
                event.channel == kr_protocol::pairing::ConfirmationChannel::LocalBootstrapTerminal
            })
            .map_or_else(Nullable::null, |event| Nullable::some(event.at_ms));
        Ok(MembershipPresentResult {
            organisation_id: installed.organisation_id,
            account_id: installed.account_id.clone(),
            key_revision: installed.key_revision,
            expires_at_ms: TimestampMs::new(installed.expires_at_ms),
            exclusive: self.policy().is_exclusively_managed(),
            exclusive_ended_at_terminal_ms: ended_at_terminal,
        })
    }

    /// Refuses a proposed grant that requires an organisation this host cannot answer for.
    ///
    /// A grant that requires an organisation authorises nothing unless this host is enrolled in
    /// it, at the revision the grant names, and a member's lease answers for it, so an invitation
    /// for one that cannot be honoured would be access nothing could use. The rights are held to
    /// what the owner role of an organisation may carry, the ceiling a lease can state: a right
    /// above it could never be used either.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` naming the rule the proposal breaks.
    pub(crate) fn check_organisation_proposal(
        &self,
        proposed: &kr_protocol::pairing::ProposedGrant,
    ) -> Result<()> {
        let Some(requirement) = proposed.organisation.as_ref() else {
            return Ok(());
        };
        let policy = self.policy();
        let enrolment = policy
            .enrolment(requirement.organisation_id)
            .ok_or_else(|| {
                ControllerError::InvalidArgument(
                    "this host is not enrolled in the organisation this grant requires".to_owned(),
                )
            })?;
        if requirement.policy_revision != enrolment.enrolment_revision() {
            return Err(ControllerError::InvalidArgument(
                "this grant names another enrolment of that organisation than this host's"
                    .to_owned(),
            ));
        }
        if !proposed
            .actions
            .is_subset(&kr_protocol::account::TeamRole::Owner.maximum_grants())
        {
            return Err(ControllerError::InvalidArgument(
                "this grant carries a right above what an organisation's owner role may hold"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// `organisation.list`: what this host holds for each organisation it is enrolled in, whether
    /// it is exclusively organisation-managed, whether it trusts its clock, and the times
    /// exclusive management was turned off.
    pub(crate) async fn organisation_list(&self) -> Result<ParamsValue> {
        let without_local_enforcement = {
            let registry = self.registry.lock().await;
            self.workers_without_local_enforcement_in(&registry)?
        };
        let host_device = HostDeviceView {
            device_id: self.local_owner_device(),
            authorisation_key: self.host_authorisation_key,
        };
        let policy = self.policy();
        let clock_trusted = self
            .lifetimes
            .clock_trust()
            .sample(&self.devices)?
            .is_some();
        let enrolments = policy
            .enrolments()
            .map(|(organisation_id, enrolment)| {
                let members = enrolment
                    .members()
                    .map(|(device_id, binding)| {
                        let lease = policy
                            .lease_record(organisation_id, &binding.account_id, &binding.device_key)
                            .map_or_else(Nullable::null, |record| {
                                Nullable::some(OrganisationLeaseView {
                                    issued_at_ms: TimestampMs::new(record.issued_at_ms),
                                    expires_at_ms: TimestampMs::new(record.expires_at_ms),
                                })
                            });
                        OrganisationMemberView {
                            device_id,
                            account_id: binding.account_id.clone(),
                            device_key_id: policy_key_id(&binding.device_key),
                            bound_at_ms: TimestampMs::new(binding.bound_at_ms),
                            lease,
                        }
                    })
                    .collect();
                OrganisationEnrolmentView {
                    organisation_id,
                    root_key_id: policy_key_id(&enrolment.root().payload.public_key),
                    anchor_revision: enrolment.anchor().payload.key_revision,
                    anchor_key_id: policy_key_id(&enrolment.anchor().payload.public_key),
                    accepted_head: enrolment.accepted_head(),
                    enrolment_revision: enrolment.enrolment_revision(),
                    members,
                }
            })
            .collect();
        encode(&OrganisationListResult {
            enrolments,
            exclusive: policy.is_exclusively_managed(),
            clock_trusted,
            exclusive_events: self.sharing.grants().exclusive_management_events()?,
            host_device,
            workers_without_local_enforcement: without_local_enforcement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::an_owner_establishes_the_clock::{Door, TTL_MS, distrusting};
    use crate::service::net::devices::ObservedUtc;
    use crate::service::net::tests::{daemon_on, manual_clocks, stopped};
    use kr_protocol::error::ErrorCode;
    use std::sync::atomic::Ordering;

    const MINUTE_MS: u64 = 60_000;

    fn reading(now: u64) -> ObservedUtc {
        ObservedUtc {
            now: TimestampMs::new(now),
            behind_ms: 0,
        }
    }

    /// KR-REQ-17.53: the check an enrolment makes inside the policy transaction finds a head that
    /// has run out since it was judged, and answers a head that has not as current.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_check_inside_the_transaction_finds_a_head_that_ran_out_while_it_waited() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on(&temp, clocks).await;
        let start = wall.load(Ordering::SeqCst);
        let head_ends = TimestampMs::new(start + 10 * MINUTE_MS);
        let judged = reading(start);

        controller
            .head_holds_still(head_ends, Some(&judged))
            .expect("a head with ten minutes left is current");
        wall.store(start + 9 * MINUTE_MS, Ordering::SeqCst);
        controller
            .head_holds_still(head_ends, Some(&judged))
            .expect("and with one minute left");

        wall.store(start + 11 * MINUTE_MS, Ordering::SeqCst);
        let refused = controller
            .head_holds_still(head_ends, Some(&judged))
            .expect_err("a head that ran out during the wait is not enrolled");
        assert!(
            matches!(
                refused.code(),
                ErrorCode::InvalidArgument | ErrorCode::StorageUnavailable
            ),
            "{refused:?}"
        );
        stopped(controller).await;
    }

    /// KR-REQ-17.53: the same check finds a clock the host stopped trusting since the head was
    /// judged, whatever the head says.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_check_inside_the_transaction_finds_a_clock_distrusted_while_it_waited() {
        let (_temp, controller, _continuous, wall, _clocks) = distrusting().await;
        let now = wall.load(Ordering::SeqCst);
        let refused = controller
            .head_holds_still(TimestampMs::new(now + 10 * MINUTE_MS), Some(&reading(now)))
            .expect_err("a clock that is not trusted judges no head");
        assert_eq!(refused.code(), ErrorCode::ClockUntrusted, "{refused:?}");
        stopped(controller).await;
    }
    /// KR-REQ-17.54: a host that is not on the network and has an owner is exclusively managed with
    /// no owner device to confirm for it, and its owner at its terminal ends that: the request, the
    /// answer and the spend all go through the host's own owner authority, which no network
    /// service stands between, and the change is written and ends exclusive management.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_off_the_network_ends_exclusive_management_at_its_terminal() {
        use kr_protocol::confirmation::{
            ConfirmationSubject, OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
        };
        use kr_protocol::ids::ActionId;
        use kr_protocol::organisation::{
            OrganisationExclusiveSetParams, OrganisationExclusiveSetResult,
        };

        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, _wall, clocks) = manual_clocks();
        let controller = daemon_on(&temp, clocks).await;
        controller
            .update_policy(|policy| policy.set_exclusively_managed(true))
            .expect("the host is exclusively organisation-managed");
        rusqlite::Connection::open(temp.environment().registry_database())
            .expect("opens the registry")
            .execute(
                "INSERT INTO host_owner (id, how, established_at_ms) VALUES (0, 'migrated', 1)",
                [],
            )
            .expect("the host has an owner");
        let door = Door::open(&temp, &controller).await;

        let challenge: OwnerConfirmationRequestResult = door
            .perform(door.mutation(
                Method::OwnerConfirmationRequest,
                ActionId::new(kr_ipc::new_uuid()),
                TTL_MS,
                &OwnerConfirmationRequestParams {
                    subject: ConfirmationSubject::SetExclusiveManagement { exclusive: false },
                },
            ))
            .await
            .expect("the host asks its terminal, with no network");
        assert!(
            challenge.initial_bootstrap,
            "no device is left that could confirm: the terminal does"
        );
        door.answer(&challenge.request)
            .await
            .expect("the terminal answers");
        let ended: OrganisationExclusiveSetResult = door
            .perform(door.mutation(
                Method::OrganisationExclusiveSet,
                ActionId::new(kr_ipc::new_uuid()),
                TTL_MS,
                &OrganisationExclusiveSetParams { exclusive: false },
            ))
            .await
            .expect("the host spends the terminal's answer");
        assert!(!ended.exclusive);
        assert!(!controller.policy().is_exclusively_managed());
        let events = controller
            .sharing()
            .grants()
            .exclusive_management_events()
            .expect("readable");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].channel,
            kr_protocol::pairing::ConfirmationChannel::LocalBootstrapTerminal
        );
        drop(door);
        stopped(controller).await;
    }
}
