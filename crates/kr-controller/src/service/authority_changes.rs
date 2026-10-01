//! The grant and device mutations, each under a durable claim, and the grant and device lists.

use std::collections::BTreeMap;

use kr_ipc::client::LocalClient;
use kr_protocol::agent::{AgentApprovalInspectParams, AgentApprovalInspectResult, AgentSubject};
use kr_protocol::broker::{DecoderLedgerEntry, MAX_PROJECTION_SUMMARY_LEN};
use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::gateway::{PendingKind, PendingResource};
use kr_protocol::ids::{ActorId, PendingResourceId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::projection::AgentResourceSnapshotContinuation;
use kr_protocol::question::{QuestionReadParams, QuestionReadResult};
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::sharing::{
    MAX_NAMED_RESOURCES, NamedApprovalPreview, NamedQuestionPreview, RoleSelection,
};

use crate::error::{ControllerError, Result};

use super::{Controller, encode, net, parse, respond};

impl Controller {
    /// Answers an authority change this host already holds a claim on, before freshness is asked
    /// for.
    ///
    /// Section 9 keeps a receipt readable after the window that admitted it has gone, and a retry of
    /// a revocation that could not reach its record would otherwise be told its window is gone
    /// rather than what happened. What the answer is, for each state a claim can be in, is
    /// [`Self::recorded_authority_change`].
    pub(super) async fn retained_authority_answer(
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
                self.recorded_authority_change(actor_id, mutation, record)
                    .await,
            )),
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }

    /// The same answer, for a caller that cannot wait: a paired device's preview-key registration.
    ///
    /// Every state is answered here but an unfinished revocation, whose answer waits for any fence
    /// it still owes; this gives none for one, and the claim the caller then takes answers it.
    pub(super) fn retained_authority_change(
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
            Ok(Some(record)) => self
                .answer_without_fence(mutation, &record)
                .map(|answer| respond(mutation.request_id, answer)),
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }

    /// Claims one authority change for this attempt, or reads what an earlier attempt's claim
    /// holds.
    ///
    /// [`crate::grants::ActionClaim::Claimed`] is this attempt's hold: it wrote the claim and is the
    /// one attempt that may perform the change. Anything else is answered by
    /// [`Self::recorded_authority_change`], and nothing is performed.
    fn claim_authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        now_ms: u64,
    ) -> Result<crate::grants::ActionClaim> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        self.sharing
            .grants()
            .claim_action(actor_id, mutation.action_id, &digest, now_ms)
    }

    /// The answer an authority change an earlier attempt claimed is owed.
    ///
    /// A change that happened is answered with what it produced, and one that was refused with its
    /// refusal. One whose attempt is still running is told so, which is transient: the payload is
    /// the same one, so this is not a conflict, and the caller asks again for the answer. One whose
    /// attempt ended without recording what it did is never performed again, however long ago it
    /// was claimed: an attempt is not known to have stopped short of its effect, and section 9 does
    /// not dispatch an identifier again because its receipt is incomplete. It is answered from
    /// what this host's own records prove the change did ([`Self::answer_without_fence`],
    /// [`Self::revocation_on_record`]), and otherwise as an outcome this host does not know.
    async fn recorded_authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        record: crate::grants::ActionRecord,
    ) -> Result<ParamsValue> {
        match self.answer_without_fence(mutation, &record) {
            Some(answer) => answer,
            None => self.revocation_on_record(actor_id, mutation).await,
        }
    }

    /// The answer a record is owed, when nothing has to run first: every state but an unfinished
    /// revocation, whose answer waits for any fence it still owes.
    ///
    /// A grant and the invitation that carries it take identities derived from the action and are
    /// written in one commit, so finding them is finding what this action wrote, and the answer is
    /// rebuilt from what was written rather than proposed again. Nothing else outside a revocation
    /// names the action that changed it: a device's record can hold the key a registration asked
    /// for because another action registered the same key, a destination's credential says nothing
    /// about which request set it, and a voice change is not an authority change.
    fn answer_without_fence(
        &self,
        mutation: &MutationRequest,
        record: &crate::grants::ActionRecord,
    ) -> Option<Result<ParamsValue>> {
        match record {
            crate::grants::ActionRecord::Answered { result } => Some(decoded(result)),
            crate::grants::ActionRecord::Refused { code, detail } => {
                Some(Err(ControllerError::Refused {
                    code: *code,
                    detail: detail.clone(),
                }))
            }
            crate::grants::ActionRecord::InFlight => Some(Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "another attempt under this action identifier has not finished".to_owned(),
            })),
            crate::grants::ActionRecord::Unfinished => match mutation.method.method() {
                Some(Method::GrantRevoke | Method::DeviceRevoke) => None,
                Some(Method::GrantCreate) => {
                    let (grant_id, invitation_id) =
                        Self::share_identities(mutation.action_id.get());
                    Some(self.sharing.shared(grant_id, invitation_id).and_then(
                        |shared| match shared {
                            Some(shared) => encode(&shared),
                            None => Err(unfinished_and_unknown()),
                        },
                    ))
                }
                _ => Some(Err(unfinished_and_unknown())),
            },
        }
    }

    /// What an unfinished revocation did, answered the way a revocation that finds its work done
    /// is answered, once this host's records show nothing is left for it to do.
    ///
    /// Nothing is left for a grant revocation once the grant it names stands revoked, because its
    /// descendants went with it and none can be delegated from it since. Nothing is left for a
    /// device revocation once the device's own record stands revoked, its last write, and so does
    /// every grant the device holds: grants withdrawn beside a live record are not a finished
    /// withdrawal, and a record revoked some other way says nothing of the grants. Answering then
    /// and performing the revocation again would come to the same thing, so it is answered, and
    /// never performed. The answer names what the action's own revocation withdrew, as its claim
    /// records it ([`crate::grants::GrantDirectory::recorded_withdrawal`]), and nothing when it
    /// withdrew nothing. Any fence still owed runs first, so the answer's revision and barrier are
    /// ones that hold; a fence is always safe to raise, and it is the one the earlier attempt owed.
    /// Anything short of that, and a claim an earlier build left with no record of what it
    /// withdrew, is an outcome this host does not know.
    async fn revocation_on_record(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        let nothing_left = match mutation.method.method() {
            Some(Method::GrantRevoke) => {
                let params: kr_protocol::sharing::GrantRevokeParams = parse(&mutation.params)?;
                self.sharing
                    .grants()
                    .record(params.grant_id)?
                    .is_some_and(|record| record.revoked_at_ms.is_some())
            }
            Some(Method::DeviceRevoke) => {
                let params: kr_protocol::sharing::DeviceRevokeParams = parse(&mutation.params)?;
                self.devices
                    .record_for_device(params.device_id)?
                    .is_some_and(|record| record.revoked_at_ms.is_some())
                    && self
                        .sharing
                        .grants()
                        .records_for_device(params.device_id)?
                        .iter()
                        .all(|held| held.revoked_at_ms.is_some())
            }
            _ => false,
        };
        if !nothing_left {
            return Err(unfinished_and_unknown());
        }
        let Some(withdrawn) = self
            .sharing
            .grants()
            .recorded_withdrawal(actor_id, mutation.action_id)?
        else {
            return Err(unfinished_and_unknown());
        };
        encode(
            &self
                .complete_revocation(withdrawn.into_iter().collect(), self.publish_debts(&[]))
                .await?,
        )
    }

    /// Keeps what a claimed action came to, under the hold that claimed it.
    ///
    /// A result is kept, and so is a refusal the action was decided against: one whose code says
    /// the same request cannot succeed if it is sent again, which is the answer the action is owed
    /// from then on. A failure that says the request might succeed later, a store that could not
    /// be written or a resource that was busy, says nothing final about the action, so nothing is
    /// kept for it: the claim stays unfinished, and a retry is answered from what this host's
    /// records prove the action did.
    ///
    /// # Errors
    ///
    /// Returns a storage error when a result cannot be recorded. A refusal that cannot be recorded
    /// is not an error of its own: the caller is given the refusal, and a retry reads the action
    /// as unfinished.
    pub(super) fn settle_claim(
        &self,
        hold: &crate::grants::ClaimHold,
        outcome: &Result<ParamsValue>,
    ) -> Result<()> {
        let now_ms = kr_ipc::now_ms().get();
        match outcome {
            Ok(result) => self.sharing.grants().retain_result(
                hold,
                &kr_cbor::encode(result.as_value()),
                now_ms,
            ),
            Err(error)
                if matches!(
                    error.code().retry_category(),
                    kr_protocol::error::RetryCategory::NoRetry
                        | kr_protocol::error::RetryCategory::ConfigurationChange
                ) =>
            {
                if let Err(unrecorded) = self.sharing.grants().retain_refusal(
                    hold,
                    error.code(),
                    &error.to_string(),
                    now_ms,
                ) {
                    eprintln!("kr-controller: could not record an action's refusal: {unrecorded}");
                }
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    /// Lists the grants `issuer` may see: the grants it issued, and everything delegated from them.
    ///
    /// A local caller is the operating-system owner of this environment, so the issuer it lists
    /// grants for is this host itself, which sees every grant here. A paired device lists as
    /// itself, and sees what its own delegation authority reaches.
    pub(crate) fn grant_list(
        &self,
        issuer: kr_protocol::ids::DeviceId,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantListParams = parse(params)?;
        let result = self.sharing.list_for_issuer(
            issuer,
            params.session_id.as_ref().copied(),
            params.include_resolved,
            self.settled_now_ms(),
        )?;
        encode(&result)
    }

    /// Lists the paired devices, with each one's last authority acknowledgement.
    ///
    /// Section 10 puts the acknowledgement in the list because an offline host cannot apply a
    /// revocation it has not received, and a person deciding whether a revocation has taken effect
    /// needs to see which hosts have answered. The feed's staleness is beside it for the same
    /// reason: a list that looked current because nothing had contradicted it would be worse than
    /// no list.
    pub(super) async fn device_list(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::DeviceListParams = parse(params)?;
        let records = self.devices.devices()?;
        let status = self.authority_feed().status();
        // The revision in force is the registry's. The feed's accepted revision is what it has
        // seen and the policy's is what it was last told, and either can be behind the allocator
        // after a revocation this daemon took by another path.
        let authority_revision = {
            let registry = self.registry.lock().await;
            registry.authority_revision()?
        };
        let mut devices = Vec::new();
        for record in records {
            if record.revoked_at_ms.is_some() && !params.include_revoked {
                continue;
            }
            let acknowledged = self.authority_feed().last_acknowledgement(record.device_id);
            devices.push(kr_protocol::sharing::DeviceSummary {
                device_id: record.device_id,
                display_name: record.device_name.as_str().to_owned(),
                grant_id: record.grant.grant_id,
                paired_at_ms: record.paired_at_ms,
                acknowledged_revision: kr_protocol::scalars::Nullable(acknowledged),
                acknowledged_at_ms: kr_protocol::scalars::Nullable::null(),
                revoked: record.revoked_at_ms.is_some(),
                keys: kr_protocol::scalars::Nullable(record.public_keys()),
                manages_host: record
                    .grant
                    .actions
                    .contains(&kr_protocol::rights::ActionRight::HostManage),
            });
        }
        devices.sort_by_key(|device| device.device_id);
        encode(&kr_protocol::sharing::DeviceListResult {
            devices,
            authority_revision,
            feed_synchronised_at_ms: status.last_synchronised_at_ms,
            feed_stale: status.stale,
        })
    }

    /// Records the four keys a device paired before this host kept them all declares, once.
    ///
    /// The device is the one the connection authenticated as, and the declaration is signed by the
    /// authorisation key this host recorded when it committed the pairing: that key is what binds
    /// the two new keys to the device the owner approved, as the signed bundle bound the other two.
    /// The transport and authorisation keys must be the ones on record and the four must be four
    /// different keys. A record that already holds its keys answers a declaration of the same keys
    /// with the record and a declaration of any others with a refusal: a declaration completes a
    /// record, it never replaces a key.
    ///
    /// The declaration's own checks come first, before the registry is taken: the keys they
    /// compare never change for a device, and the write checks its pairing again. The admission
    /// the declaration carries, the write and the record of the outcome are then one transaction
    /// in the device directory, taken with the registry held, so a revocation or a deadline that
    /// passed while this waited stops the write, and whatever the declaration ends as is kept with
    /// it. A retry of the same action is answered from that record; a failure to reach a store
    /// keeps nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the device is given: [`ControllerError::PermissionDenied`] for a device
    /// this host no longer pairs with, for keys that are not the recorded ones, for a signature
    /// that does not verify, for a declaration of keys other than the ones on record and for an
    /// admission that has lapsed; [`ControllerError::InvalidArgument`] for malformed parameters or
    /// a key declared for two purposes; [`ControllerError::IdConflict`] for an action identifier
    /// this host recorded with another request; and a storage error when a store cannot be
    /// reached.
    pub(crate) async fn device_keys_declared(
        &self,
        actor_id: &ActorId,
        device_id: kr_protocol::ids::DeviceId,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let declared = self.declared_keys(device_id, mutation)?;
        let recorded = {
            let registry = self.registry.lock().await;
            self.devices.declare_keys(
                actor_id,
                mutation.action_id,
                digest,
                device_id,
                declared,
                || self.check_admission(&registry, &carried),
                kr_ipc::now_ms(),
            )?
        };
        declaration_answer(mutation, &digest, recorded)
    }

    /// Makes a declaration's own checks, the ones made before its transaction.
    ///
    /// The outer error is a store that could not be read, which decides nothing; the inner one is
    /// a refusal, which a retry of the same declaration would meet again.
    fn declared_keys(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<kr_protocol::pairing::DevicePublicKeys, ProtocolError>> {
        let denied = |detail: &str| {
            Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                detail.to_owned(),
            ))
        };
        let params: kr_protocol::sharing::DeviceKeysCompleteParams = match parse(&mutation.params) {
            Ok(params) => params,
            Err(refusal) => return Ok(Err(refusal.to_protocol_error())),
        };
        let Some(record) = self
            .devices
            .record_for_device(device_id)?
            .filter(net::devices::DeviceRecord::is_paired)
        else {
            return Ok(denied("this host does not pair with that device"));
        };
        let keys = params.keys;
        if keys.transport != record.endpoint_id || keys.authorisation != record.authorisation {
            return Ok(denied(
                "the declared transport and authorisation keys are not the ones this host \
                 recorded at pairing",
            ));
        }
        if !keys.purposes_are_distinct() {
            return Ok(Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "each of a device's four keys is a different key",
            )));
        }
        let declaration = kr_protocol::sharing::DeviceKeysDeclaration { device_id, keys };
        if kr_crypto::sign::verify_object(
            &record.authorisation,
            kr_protocol::sharing::DEVICE_KEYS_DOMAIN,
            &declaration,
            &params.signature,
        )
        .is_err()
        {
            return Ok(denied(
                "the declaration is not signed by the authorisation key this host recorded for \
                 the device",
            ));
        }
        Ok(Ok(keys))
    }

    /// Performs one authority change under a durable claim, and records what it came to.
    ///
    /// The claim comes first. An authority change is exactly the effect a retry must not repeat:
    /// two `grant.revoke` calls under one action identifier would otherwise advance the revision
    /// twice and fence the host twice for one withdrawal. Only the attempt that writes the claim
    /// performs the change; any other is answered from the record
    /// ([`Self::recorded_authority_change`]).
    pub(super) async fn authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let claimed_at_ms = kr_ipc::now_ms().get();
        let hold = match self.claim_authority_change(actor_id, mutation, claimed_at_ms)? {
            crate::grants::ActionClaim::Claimed { hold } => hold,
            crate::grants::ActionClaim::Recorded(record) => {
                return self
                    .recorded_authority_change(actor_id, mutation, record)
                    .await;
            }
        };
        let outcome = match method {
            Method::GrantCreate => self.grant_create(mutation, carried, claimed_at_ms).await,
            Method::GrantRevoke => self.grant_revoke(mutation, carried, &hold).await,
            Method::DeviceRevoke => self.device_revoke(mutation, carried, &hold).await,
            Method::DevicePreviewKeyUpdate => {
                self.device_preview_key_update(actor_id, mutation).await
            }
            Method::DeliveryDestinationSecretSet => {
                self.delivery_destination_secret_set(mutation, carried)
                    .await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not an authority change this daemon serves",
                method.as_str()
            ))),
        };
        // Recorded before the hold goes, so a retry finds the answer rather than a claim with
        // neither an answer nor an attempt behind it.
        self.settle_claim(&hold, &outcome)?;
        drop(hold);
        outcome
    }

    /// Keeps the credential an external notification destination sends with.
    ///
    /// The owner's own act at this machine: the method is served on the local socket alone,
    /// because a credential decides who reads what a destination delivers. The credential is
    /// checked for the shape its service issues and then goes to the host's secret store; the
    /// answer names the destination, the kind, whether it is in force, and who can read what it
    /// delivers, and has no field the credential fits in. The action is claimed and retained like
    /// every authority change here, by a digest over the whole request, which covers a window
    /// identifier this host never writes down, so the retained digest cannot be used to test a
    /// guess of the credential.
    ///
    /// The admission is asked again under the registry lock, which is held across the write, so a
    /// withdrawal that completes while this waited stops it.
    async fn delivery_destination_secret_set(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params = secret_params(&mutation.params)?;
        let destination_id = destination_identifier(&params.destination_id)?;
        crate::push::external::check_secret(&params.secret)
            .map_err(ControllerError::InvalidArgument)?;
        let kind = params.secret.kind();
        let registry = self.registry.lock().await;
        self.check_admission(&registry, &carried)?;
        let stored = self
            .delivery
            .store_secret(&destination_id, &params.secret)?;
        drop(registry);
        encode(&kr_protocol::delivery::DeliveryDestinationSecretSetResult {
            destination_id: params.destination_id,
            kind,
            in_force: stored.in_force,
            recipients_can_read: kr_delivery::destination::DestinationKind::for_credential(kind)
                .who_can_read()
                .to_owned(),
        })
    }

    /// Shares a session: compiles the role, previews it, and writes the grant and its invitation.
    ///
    /// The questions and approvals the share names are previewed as the session's worker holds
    /// them now ([`Self::named_previews`]), before anything is written.
    async fn grant_create(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
        claimed_at_ms: u64,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantCreateParams = parse(&mutation.params)?;
        if params.owner_confirmation.is_present() {
            return Err(ControllerError::InvalidArgument(
                "an owner confirmation is completed through the owner-confirmation methods, and \
                 a local caller acts under its authenticated operating-system identity"
                    .to_owned(),
            ));
        }
        // A host that cannot show the issuer the screen does not share the screen. Section 25
        // requires the preview to show what is being shared, and this daemon holds no screen
        // content of its own: the worker does. An invitation that included it here would be one
        // whose issuer was shown nothing.
        if params.selection.include_live_screen {
            return Err(ControllerError::InvalidArgument(
                "this host cannot preview the screen this invitation would share, so it does not \
                 share it"
                    .to_owned(),
            ));
        }
        let named = self
            .named_previews(params.session_id, &params.selection)
            .await?;
        let (grant_id, invitation_id) = Self::share_identities(mutation.action_id.get());
        let request = crate::sharing::ShareRequest {
            invitation_id,
            grant_id,
            environment_id: self.paths.environment_id(),
            session_id: params.session_id,
            issuer_device_id: self.host_device_id(),
            recipient_device_id: params.recipient_device_id,
            parent_grant_id: params.parent_grant_id.as_ref().copied(),
            selection: params.selection.clone(),
            lifetime_ms: params.lifetime_ms.as_ref().map(|lifetime| lifetime.get()),
            accepted_notices: params.accepted_notices.clone(),
            live_screen: None,
            named_questions: named.questions,
            named_approvals: named.approvals,
            authority_revision: self.policy().authority_revision(),
            owner_confirmed: false,
            // The moment the claim was written, which is when this host accepted the action: the
            // invitation's lifetime runs from it.
            now_ms: claimed_at_ms,
        };
        // A delegation decides its parent's expiry at the moment it writes. The floor goes down
        // first, so a parent that expired before this request is refused as expired rather than
        // as a reading this host has not written down; a lapse found at the write itself is owed
        // its record, which is written before the refusal goes back.
        if request.parent_grant_id.is_some() {
            self.settled_now_ms();
        }
        // The admission is checked under the registry lock, and again inside the transaction that
        // writes the grant. Between the two are the preview, the delegation checks and the wait
        // for the grant store's own lock, and a window that was open when this began can be shut
        // by the time the write happens.
        let registry = self.registry.lock().await;
        self.check_admission(&registry, &carried)?;
        let result = self
            .sharing
            .share(&request, || self.check_admission(&registry, &carried));
        drop(registry);
        self.settle_floor();
        encode(&result?)
    }

    /// What the issuer of a share is shown of the current questions and approvals it names, as the
    /// session's worker holds them now.
    ///
    /// Section 10 lets an invitation name active questions and approval resources, previewed to
    /// the issuer even when they were created before the history cutoff. The session's worker holds
    /// them, so it is asked, on this daemon's own link to it, whose reads are the local owner's: a
    /// question by `question.read`, previewed while it is open, and an approval by the resource
    /// snapshot, which says which instance holds it and whether a decoder interpreted it, and then
    /// by its record under that instance, previewed while it can still be decided, pending or
    /// claimed ([`read_previews`]). A share naming nothing asks nothing.
    ///
    /// The link is taken out of its slot for the exchange and put back only once the exchange is
    /// whole ([`super::workers::WorkerLink`]); one that fails, runs out of time or is abandoned is closed
    /// instead, and the worker's lease stops renewing with it, since a link given back part way
    /// through a request would be read by the next caller as its own answer. The whole of the
    /// exchange, the wait for the link included, is bounded by
    /// [`super::workers::WORKER_EXCHANGE`]; running out of time while another operation holds the
    /// link leaves that operation's link, and the lease, as they were.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for a share naming more than
    /// [`MAX_NAMED_RESOURCES`] questions and approvals together, before anything is asked, for one
    /// naming what the worker holds no current record of, and for an approval whose request no
    /// preview can show; [`ControllerError::UnknownSession`] for a session this host knows no
    /// worker for; `RESOURCE_UNAVAILABLE` when the worker cannot be reached, answers with something
    /// else or does not answer in time; and any other refusal as the worker gave it.
    async fn named_previews(
        &self,
        session_id: SessionId,
        selection: &RoleSelection,
    ) -> Result<NamedPreviews> {
        let named = selection.named_questions.len() + selection.named_approvals.len();
        if named == 0 {
            return Ok(NamedPreviews::default());
        }
        if named > MAX_NAMED_RESOURCES {
            return Err(ControllerError::InvalidArgument(format!(
                "an invitation names at most {MAX_NAMED_RESOURCES} questions and approvals \
                 together, and this one names {named}"
            )));
        }
        let exchange = async {
            let mut link =
                self.worker_client_of(session_id)
                    .await
                    .map_err(|error| match error {
                        ControllerError::UnknownSession { .. } => error,
                        other => unreachable_worker(other),
                    })?;
            match read_previews(link.client(), session_id, selection).await {
                Ok(previews) => {
                    link.give_back();
                    Ok(previews)
                }
                Err(PreviewFailure::Refused(error)) => {
                    link.give_back();
                    Err(error)
                }
                // A link that failed part way is not given back, and is given up when it goes out
                // of scope here, as it is when this exchange runs out of time or is abandoned.
                Err(PreviewFailure::Link(error)) => Err(unreachable_worker(error)),
            }
        };
        tokio::time::timeout(super::workers::WORKER_EXCHANGE, exchange)
            .await
            .unwrap_or_else(|_| {
                Err(ControllerError::Refused {
                    code: ErrorCode::ResourceUnavailable,
                    detail: "the session's worker did not say in time what this invitation names"
                        .to_owned(),
                })
            })
    }

    /// Revokes a grant, its descendants, and everything they were being used for.
    async fn grant_revoke(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
        hold: &crate::grants::ClaimHold,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantRevokeParams = parse(&mutation.params)?;
        encode(
            &self
                .revoke_grant(params.grant_id, Some(&carried), Some(hold))
                .await?,
        )
    }

    /// Revokes a device, every grant it holds, and everything they were being used for.
    async fn device_revoke(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
        hold: &crate::grants::ClaimHold,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::DeviceRevokeParams = parse(&mutation.params)?;
        encode(
            &self
                .revoke_device_authority(params.device_id, Some(&carried), Some(hold))
                .await?,
        )
    }

    /// Registers or rotates a paired device's notification-preview key under the action it
    /// arrived with, and keeps what it produced.
    ///
    /// The action's result is retained the way every other authority change's is: claimed before
    /// the effect, recorded after it, and returned to a repeat of the same action whatever has
    /// happened since. A device whose answer was lost asks again with the same action and is told
    /// what it was told the first time, even after a later rotation or once the window this
    /// action was admitted in has closed; a new action with an old revision is still refused. An
    /// attempt that ended without recording its answer is not performed again, and the repeat is
    /// told the outcome is not known: the device's record may hold that key because another action
    /// registered it.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::device_preview_key_update`] refused with, a conflict when the action
    /// identifier was used for a different registration, a refusal while another attempt under the
    /// same action has not finished, and an unknown outcome for an attempt that ended unrecorded.
    pub async fn preview_key_update_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        let hold = match self.claim_authority_change(actor_id, mutation, kr_ipc::now_ms().get())? {
            crate::grants::ActionClaim::Claimed { hold } => hold,
            crate::grants::ActionClaim::Recorded(record) => {
                return self
                    .recorded_authority_change(actor_id, mutation, record)
                    .await;
            }
        };
        let outcome = self.device_preview_key_update(actor_id, mutation).await;
        self.settle_claim(&hold, &outcome)?;
        drop(hold);
        outcome
    }

    /// Brings the device directory up to the preview keys the delivery journal holds.
    ///
    /// A key update writes the delivery journal first and the device directory second. A host that
    /// stopped between the two has a journal one registration ahead, and nothing else would put
    /// the directory right if the device never asked again. So a start compares the two for every
    /// paired device the journal delivers to and records in the directory what the journal already
    /// holds. The journal is never moved back: it is the store that took the registration first.
    ///
    /// Returns how many devices it brought up to date.
    ///
    /// # Errors
    ///
    /// Returns an error when either store cannot be read or the directory cannot be written.
    pub fn recover_preview_keys(&self) -> Result<usize> {
        let destinations = self.delivery.with(|producer| {
            producer
                .journal()
                .destinations()
                .map_err(|error| ControllerError::Storage {
                    operation: "read the delivery destinations",
                    detail: error.to_string(),
                })
        })?;
        let mut recovered = 0;
        for destination in destinations {
            let Some(push) = destination.as_push() else {
                continue;
            };
            let Ok(device_id) = destination
                .id
                .as_str()
                .parse::<kr_protocol::ids::DeviceId>()
            else {
                continue;
            };
            let Some(record) = self.devices.record_for_device(device_id)? else {
                continue;
            };
            let revision = kr_protocol::ids::DeviceKeyRevision::new(push.preview_keys.revision);
            if record.revoked_at_ms.is_some() || record.device_key_revision >= revision {
                continue;
            }
            if self
                .devices
                .update_preview_key(device_id, push.preview_keys.current, revision)?
                == net::devices::PreviewKeyOutcome::Recorded
            {
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    /// Rotates a paired device's notification-preview key and revision.
    pub async fn device_preview_key_update(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::DevicePreviewKeyUpdateParams = parse(&mutation.params)?;
        // Section 16 registers this key through the device's own authenticated channel, so the
        // caller has to be a paired device and the device has to be the one it names. An actor
        // this host cannot resolve to a paired device is not one of them: a revocation between
        // the connection's admission and this write leaves exactly that, and it refuses here.
        if self.paired_device(actor_id) != Some(params.device_id) {
            return Err(ControllerError::InvalidArgument(
                "a paired device may register only its own preview key".to_owned(),
            ));
        }
        let now_ms = self.settled_now_ms();
        let destination_id =
            kr_delivery::destination::DestinationId::new(params.device_id.to_string())
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // What the device directory already holds decides whether this registration is one at all,
        // and it is read before anything is written so that a registration neither store will take
        // changes neither of them.
        let recorded = self
            .devices
            .record_for_device(params.device_id)?
            .filter(|record| record.revoked_at_ms.is_none())
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!(
                    "device {} is not paired or has been revoked",
                    params.device_id
                ))
            })?;
        if recorded.device_key_revision > params.revision
            || (recorded.device_key_revision == params.revision
                && recorded.notification_preview != Some(params.notification_preview))
        {
            return Err(ControllerError::InvalidArgument(format!(
                "revision {} does not follow the recorded revision {}",
                params.revision.get(),
                recorded.device_key_revision.get()
            )));
        }
        // The delivery journal is written first, because it is the store that can refuse a
        // registration for a reason the directory knows nothing about: section 16 keeps one
        // replaced key, so a rotation while an earlier replacement still has notifications
        // outstanding is refused. A refusal therefore leaves both stores as they were. Both take
        // the same registration again without complaint, so a resubmission after a lost answer,
        // and a restart between the two writes, both end with the two agreeing.
        match self.delivery.update_preview_key(
            &destination_id,
            params.notification_preview,
            params.revision.get(),
            now_ms,
        ) {
            Ok(()) => {}
            Err(ControllerError::InvalidArgument(message))
                if message.contains("is not a destination this host has configured") =>
            {
                // The device has registered a key before this host configured it as a delivery
                // destination. The directory holds the key, and configuring the destination takes
                // it from there.
            }
            Err(error) => return Err(error),
        }
        match self.devices.update_preview_key(
            params.device_id,
            params.notification_preview,
            params.revision,
        )? {
            net::devices::PreviewKeyOutcome::Recorded
            | net::devices::PreviewKeyOutcome::AlreadyRecorded => {}
            net::devices::PreviewKeyOutcome::RevisionBehind(recorded) => {
                return Err(ControllerError::InvalidArgument(format!(
                    "revision {} does not follow the recorded revision {}",
                    params.revision.get(),
                    recorded.get()
                )));
            }
            net::devices::PreviewKeyOutcome::NotPaired => {
                return Err(ControllerError::InvalidArgument(format!(
                    "device {} is not paired or has been revoked",
                    params.device_id
                )));
            }
        }
        encode(&kr_protocol::sharing::DevicePreviewKeyUpdateResult {
            device_id: params.device_id,
            revision: params.revision,
            notification_preview: params.notification_preview,
        })
    }

    /// The identities of the grant and of the invitation that carries it, for a share written as
    /// `action`.
    ///
    /// They are derived from the action the caller named, not minted fresh. An attempt that ended
    /// before it recorded its answer therefore left a grant and an invitation this host can find by
    /// the action alone, and a retry is answered from them.
    pub(super) fn share_identities(
        action: kr_protocol::scalars::Uuid,
    ) -> (kr_protocol::ids::GrantId, kr_protocol::ids::InvitationId) {
        (
            kr_protocol::ids::GrantId::new(Self::derived_identity(action, b"grant")),
            kr_protocol::ids::InvitationId::new(Self::derived_identity(action, b"invitation")),
        )
    }

    /// One identity derived from an action identifier and a purpose.
    ///
    /// Two identities from one action have to differ, and both have to be the same on a retry, so
    /// they are the digest of the action and a purpose label rather than anything freshly random.
    fn derived_identity(
        action: kr_protocol::scalars::Uuid,
        purpose: &[u8],
    ) -> kr_protocol::scalars::Uuid {
        let digest =
            kr_cbor::sha256(&[b"kr-sharing/1".as_slice(), purpose, action.as_bytes()].concat());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        kr_protocol::scalars::Uuid::from_bytes(bytes)
    }

    /// This host's own device identity, derived from its environment.
    #[must_use]
    pub(super) fn host_device_id(&self) -> kr_protocol::ids::DeviceId {
        kr_protocol::ids::DeviceId::new(self.paths.environment_id().get())
    }
}

/// The one refusal of parameters that do not read as `delivery.destination.secret.set`'s.
const SECRET_PARAMS_REFUSAL: &str = "delivery.destination.secret.set takes a destination_id and \
     one secret: {kind: slack or discord, webhook_url}, {kind: telegram, bot_token} or {kind: \
     email, account: {server, port, security, username, password, from_address}}";

/// Reads the parameters of `delivery.destination.secret.set`.
///
/// They carry a credential, and a decoder's own account of what it could not read quotes what it
/// was given: a webhook address sent where the object belongs, a field named with a token. So
/// every refusal here is one fixed sentence that repeats nothing the request carried.
pub(super) fn secret_params(
    params: &ParamsValue,
) -> Result<kr_protocol::delivery::DeliveryDestinationSecretSetParams> {
    params
        .to_typed()
        .map_err(|_| ControllerError::InvalidArgument(SECRET_PARAMS_REFUSAL.to_owned()))
}

/// Reads a notification destination's identifier out of a request.
pub(super) fn destination_identifier(
    text: &str,
) -> Result<kr_delivery::destination::DestinationId> {
    kr_delivery::destination::DestinationId::new(text).map_err(|_| {
        ControllerError::InvalidArgument(
            "a destination identifier is 1 to 128 bytes with no control characters".to_owned(),
        )
    })
}

/// The answer to an action whose attempt ended without recording what it did, when this host's
/// records do not show what it did either.
fn unfinished_and_unknown() -> ControllerError {
    ControllerError::Uncertain {
        detail: "an earlier attempt at this action ended without recording what it did, and this \
                 host's records do not show it; it is not performed again, so read what it \
                 concerns before asking under a new action"
            .to_owned(),
    }
}

/// What the issuer of a share is shown of the questions and approvals it names.
#[derive(Default)]
struct NamedPreviews {
    questions: Vec<NamedQuestionPreview>,
    approvals: Vec<NamedApprovalPreview>,
}

/// Why the session's worker could not say what a share names.
enum PreviewFailure {
    /// The link to the worker failed, and nothing is known about the share.
    Link(kr_ipc::IpcError),
    /// The worker answered, and its answer decides the share.
    Refused(ControllerError),
}

/// The refusal of a share whose worker could not be asked, or answered with something else: it says
/// nothing about the share, so it is transient and is not kept as the action's answer.
fn unreachable_worker(error: impl std::fmt::Display) -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::ResourceUnavailable,
        detail: format!(
            "the session's worker could not be asked what this invitation names: {error}"
        ),
    }
}

/// The refusal of a share naming a question the session's worker holds no open record of.
///
/// One text for a question it does not hold, another session's and one already answered,
/// cancelled or expired: which of them it was is nothing the issuer needs to share it.
fn no_open_question() -> PreviewFailure {
    PreviewFailure::Refused(ControllerError::InvalidArgument(
        "this invitation names a question this session holds no open record of, so its issuer \
         cannot be shown it"
            .to_owned(),
    ))
}

/// The refusal of a share naming an approval the session's worker holds no current record of:
/// one it does not hold, a resource that is not an approval a decoder interpreted, and one that has
/// ended, with one text.
fn no_current_approval() -> PreviewFailure {
    PreviewFailure::Refused(ControllerError::InvalidArgument(
        "this invitation names an approval this session holds no current record of, one still \
         pending or claimed, so its issuer cannot be shown it"
            .to_owned(),
    ))
}

/// A refusal the worker gave that is not one of the answers read as "no current record".
fn as_the_worker_gave_it(error: ProtocolError) -> PreviewFailure {
    PreviewFailure::Refused(ControllerError::Refused {
        code: error.code,
        detail: error.message,
    })
}

/// Reads an answer of the worker as `T`, or refuses the share as unreachable: a worker that answers
/// a read with something else has said nothing about it.
fn answered_as<T: kr_protocol::wire::WireMessage>(
    value: &ParamsValue,
) -> std::result::Result<T, PreviewFailure> {
    value
        .to_typed()
        .map_err(|error| PreviewFailure::Refused(unreachable_worker(error)))
}

/// Reads, on one link to the session's worker, what it holds of each question and approval
/// `selection` names, and builds what the issuer is shown of each.
///
/// A question is shown while it is open: its text, the revision it is at and when it was asked. An
/// approval is shown while it can still be decided: what it asks ([`what_it_asks`]) and when the
/// broker recorded it. The state and the moment are the record's own, read after the snapshot that
/// found it, so an approval that ended in between is not shown.
async fn read_previews(
    client: &mut LocalClient,
    session_id: SessionId,
    selection: &RoleSelection,
) -> std::result::Result<NamedPreviews, PreviewFailure> {
    let mut previews = NamedPreviews::default();
    for question_id in &selection.named_questions {
        let answered = client
            .request(
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id,
                    question_id: Nullable::some(*question_id),
                    include_resolved: true,
                },
            )
            .await
            .map_err(PreviewFailure::Link)?;
        let read: QuestionReadResult = match answered {
            Ok(value) => answered_as(&value)?,
            // The worker refuses a question it does not hold without saying whether it exists.
            Err(error) if error.code == ErrorCode::PermissionDenied => {
                return Err(no_open_question());
            }
            Err(error) => return Err(as_the_worker_gave_it(error)),
        };
        let Some(question) = read.questions.into_iter().find(|question| {
            question.question_id == *question_id
                && question.session_id == session_id
                && !question.state.is_resolved()
        }) else {
            return Err(no_open_question());
        };
        previews.questions.push(NamedQuestionPreview {
            question_id: question.question_id,
            revision: question.revision,
            question: question.question,
            created_at_ms: question.created_at_ms,
        });
    }
    if selection.named_approvals.is_empty() {
        return Ok(previews);
    }
    let held = holding(client, session_id, &selection.named_approvals).await?;
    for resource_id in &selection.named_approvals {
        let Some(resource) = held.get(resource_id).filter(|resource| {
            resource.kind == PendingKind::Approval && resource.interpretation_verified
        }) else {
            return Err(no_current_approval());
        };
        let answered = client
            .request(
                Method::AgentApprovalInspect,
                &AgentApprovalInspectParams {
                    subject: AgentSubject {
                        session_id,
                        application_instance_id: resource.application_instance_id,
                    },
                    resource_id: *resource_id,
                },
            )
            .await
            .map_err(PreviewFailure::Link)?;
        let record: AgentApprovalInspectResult = match answered {
            Ok(value) => answered_as(&value)?,
            // The worker answers a record it does not hold, or no longer holds under that
            // instance, as an unknown subject, with one text for every such case.
            Err(error) if error.code == ErrorCode::StaleSession => {
                return Err(no_current_approval());
            }
            Err(error) => return Err(as_the_worker_gave_it(error)),
        };
        if record.resource_id != *resource_id || record.state.is_terminal() {
            return Err(no_current_approval());
        }
        previews.approvals.push(NamedApprovalPreview {
            resource_id: *resource_id,
            summary: what_it_asks(&record.decoding).map_err(PreviewFailure::Refused)?,
            created_at_ms: record.recorded_at,
        });
    }
    Ok(previews)
}

/// The resources of `named` the session's broker holds, by identity, as one whole snapshot of its
/// resources says, read to its end.
///
/// The snapshot says which instance holds each one, which is what its record is read under. It is
/// read to its last page, so the worker keeps no copy of it for this link, and a snapshot that
/// ended before its last page was read is read again from its first, within the exchange's bound:
/// a part of one snapshot says nothing of what the rest of it held.
async fn holding(
    client: &mut LocalClient,
    session_id: SessionId,
    named: &CanonicalSet<PendingResourceId>,
) -> std::result::Result<BTreeMap<PendingResourceId, PendingResource>, PreviewFailure> {
    'snapshot: loop {
        let mut held = BTreeMap::new();
        let mut from = None;
        loop {
            let answered = client
                .request(
                    Method::EventsSnapshot,
                    &EventsSnapshotParams {
                        session_id,
                        agent_resources_from: Nullable(from.take()),
                    },
                )
                .await
                .map_err(PreviewFailure::Link)?;
            let page: EventsSnapshotResult = match answered {
                Ok(value) => answered_as(&value)?,
                Err(error) if error.code == ErrorCode::ResyncRequired => continue 'snapshot,
                Err(error) => return Err(as_the_worker_gave_it(error)),
            };
            let snapshot = page.agent_resources;
            held.extend(
                snapshot
                    .resources
                    .into_iter()
                    .filter(|resource| named.contains(&resource.resource_id))
                    .map(|resource| (resource.resource_id, resource)),
            );
            match snapshot.continue_after.0 {
                Some(after_resource_id) => {
                    from = Some(AgentResourceSnapshotContinuation {
                        snapshot_id: snapshot.snapshot_id,
                        after_resource_id,
                    });
                }
                None => return Ok(held),
            }
        }
    }
}

/// What the issuer is shown an approval asks: its decoder's summary, or where the decoder gave
/// none, the request as the upstream wrote it, whole, when that is text no longer than a summary
/// may be.
///
/// A connector's table can give an approval its decisions and no summary, as the Claude Code
/// channel's does, and then what a view shows is the request itself. A preview cut short would say
/// less than the recipient will read, and bytes that are not text say nothing to a person, so
/// neither is shown and the approval cannot be named.
///
/// # Errors
///
/// Returns [`ControllerError::InvalidArgument`] when the decoder gave no summary and the request is
/// not text of at most [`MAX_PROJECTION_SUMMARY_LEN`] bytes.
fn what_it_asks(decoding: &DecoderLedgerEntry) -> Result<String> {
    if !decoding.projection.summary.trim().is_empty() {
        return Ok(decoding.projection.summary.clone());
    }
    match std::str::from_utf8(decoding.source_bytes.as_slice()) {
        Ok(request) if request.len() <= MAX_PROJECTION_SUMMARY_LEN => Ok(request.to_owned()),
        _ => Err(ControllerError::InvalidArgument(format!(
            "this invitation names an approval whose decoder gave no summary and whose request is \
             not text of at most {MAX_PROJECTION_SUMMARY_LEN} bytes, so no preview can show its \
             issuer what it asks"
        ))),
    }
}

/// Reads back a result the action store kept in its canonical encoding.
pub(super) fn decoded(result: &[u8]) -> Result<ParamsValue> {
    kr_cbor::decode(result, &kr_cbor::Limits::DEFAULT)
        .map(ParamsValue::new)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Answers a key declaration from its recorded outcome.
///
/// The record is keyed by the actor and the action, and the digest decides whether this is the
/// same request or a reused identifier.
pub(super) fn declaration_answer(
    mutation: &MutationRequest,
    digest: &kr_protocol::scalars::Digest256,
    recorded: net::devices::RecordedDeclaration,
) -> Result<ParamsValue> {
    if recorded.payload_digest != *digest {
        return Err(ControllerError::IdConflict {
            token: mutation.action_id.to_string(),
        });
    }
    match recorded.outcome {
        net::devices::KeyDeclaration::Completed { device_id, keys } => {
            encode(&kr_protocol::sharing::DeviceKeysCompleteResult { device_id, keys })
        }
        net::devices::KeyDeclaration::Refused { code, message } => Err(ControllerError::Refused {
            code,
            detail: message,
        }),
    }
}
