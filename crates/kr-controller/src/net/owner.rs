//! Owner confirmation: the host's half of section 10's sensitive-action ceremony.
//!
//! Six actions need a fresh owner confirmation bound to the exact action digest, destination keys
//! and rights, host, nonce and a short expiry. This module is where those confirmations are asked
//! for, listed, answered and spent, and three rules shape it:
//!
//! * **The host describes the action.** A caller names a subject; [`OwnerAuthority::request`]
//!   takes the challenge's action, digest, destination and rights from the host's own resolution of
//!   it, never from the caller.
//! * **An answer is not a spend.** [`OwnerAuthority::complete`] verifies a proof against an enrolled
//!   signer and records the answer; the sensitive effect spends it later through
//!   [`OwnerAuthority::spend`], once, and only a challenge whose members equal the effect's own
//!   expectation can be spent. No effect takes a confirmation reference, so nothing a caller names
//!   can point one action at another's approval.
//! * **Who may sign is the host's record.** The enrolled signers are the authorisation keys of the
//!   live paired devices whose grant holds `host.manage`. The one exception is the initial
//!   bootstrap: while this host has no owner, a local caller at an interactive terminal outside a
//!   KalaReach session may establish the first one, with a proof signed by a key it presents. That
//!   key proves possession and nothing else, and once the first owner is committed the exception is
//!   over for good.
//!
//! What is not a confirmation, and is refused here: a proof carried by a session, plugin or
//! contact-tool channel; the operating-system credentials a local caller connected with; anything a
//! terminal printed; and a newly issued invitation, whose code or QR confirms nothing.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use kr_pairing::confirm::{
    ConfirmationExpectation, ConfirmationLedger, HostEnrolment, request_confirmation,
    verify_confirmation,
};
use kr_pairing::host::{OwnerApproval, OwnerContext};
use kr_protocol::actor::ActorIngress;
use kr_protocol::confirmation::{
    ConfirmationDisplay, OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationPendingResult, OwnerConfirmationRequestResult, PendingConfirmation,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActorId, ConfirmationId, DeviceId};
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePublicKeys, KeyPurpose, OwnerConfirmationProof,
    OwnerConfirmationRequest, SensitiveAction,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Digest256, EndpointKey, KeyId};

use super::devices::{DeviceDirectory, DeviceRecord};
use super::invitations::{ActionSubject, InvitationRows, PairingAction, another_subject};
use super::lifetimes::GrantLifetimes;
use super::pairing::HostPairingClock;
use crate::error::{ControllerError, Result};

/// Who is asking, as the host authenticated them.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The host-issued principal.
    pub actor_id: ActorId,
    /// How the caller reached the host.
    pub ingress: ActorIngress,
    /// The caller's device record, for a paired device.
    pub device: Option<DeviceRecord>,
}

impl Caller {
    /// Describes a local caller authenticated by its operating-system identity.
    #[must_use]
    pub const fn local(actor_id: ActorId) -> Self {
        Self {
            actor_id,
            ingress: ActorIngress::LocalIpc,
            device: None,
        }
    }

    /// Describes a paired device on an authorised connection.
    #[must_use]
    pub fn device(record: DeviceRecord) -> Self {
        Self {
            actor_id: record.principal(),
            ingress: ActorIngress::PairedDevice,
            device: Some(record),
        }
    }

    /// Returns the owner context an invitation this caller issues is bound to.
    #[must_use]
    pub fn owner_context(&self) -> OwnerContext {
        OwnerContext {
            actor_id: self.actor_id.clone(),
            ingress: self.ingress,
        }
    }

    /// Returns true when this caller holds owner authority on this host now.
    ///
    /// A local caller is the host's own account. A paired device is an owner device while its
    /// record stands, its grant holds `host.manage`, and that grant is in force under the host
    /// time contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant's lifetime cannot be read or recorded.
    pub fn is_owner(&self, lifetimes: &GrantLifetimes) -> Result<bool> {
        match (&self.device, self.ingress) {
            (None, ActorIngress::LocalIpc) => Ok(true),
            (Some(device), ActorIngress::PairedDevice) => Ok(device.is_paired()
                && device.grant.permits(ActionRight::HostManage)
                && lifetimes.in_force(device)?),
            _ => Ok(false),
        }
    }
}

/// An action the host has resolved from a caller's subject: exactly what a challenge will name.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The action.
    pub action: SensitiveAction,
    /// The digest of the exact effect.
    pub digest: Digest256,
    /// The keys the effect sends authority to, when it names a device.
    pub destination: Option<DevicePublicKeys>,
    /// The rights it grants.
    pub rights: CanonicalSet<ActionRight>,
    /// What an owner device shows the owner.
    pub display: ConfirmationDisplay,
    /// True when this is the establishment of the host's first owner, which is the only thing the
    /// initial bootstrap may confirm.
    pub first_owner: bool,
}

/// One outstanding challenge, as this host holds it beside the ledger.
#[derive(Clone, Debug)]
struct Entry {
    order: u64,
    request: OwnerConfirmationRequest,
    display: ConfirmationDisplay,
    first_owner: bool,
    answer: Option<Answer>,
}

/// A verified answer, and the signer it was verified against.
#[derive(Clone, Debug)]
struct Answer {
    proof: OwnerConfirmationProof,
    signer: AuthorisationKey,
}

/// The challenges this host has issued: kr-pairing's ledger, which consumes each once, and what
/// this host holds beside each one.
pub struct Challenges {
    ledger: ConfirmationLedger,
    entries: BTreeMap<[u8; 16], Entry>,
    issued: u64,
}

/// The host's owner-confirmation service.
pub struct OwnerAuthority {
    host_device_id: DeviceId,
    host_endpoint_id: EndpointKey,
    clock: HostPairingClock,
    rows: InvitationRows,
    state: Mutex<Challenges>,
}

impl std::fmt::Debug for OwnerAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerAuthority")
            .field("host", &self.host_device_id)
            .finish_non_exhaustive()
    }
}

/// A confirmation that matched an effect's expectation, ready to be consumed by it.
#[derive(Debug)]
pub struct Spendable {
    request: OwnerConfirmationRequest,
    proof: OwnerConfirmationProof,
    signer: AuthorisationKey,
    enrolment: HostEnrolment,
}

impl Spendable {
    /// Returns the approval kr-pairing consumes, bound to `owner`.
    #[must_use]
    pub const fn approval<'a>(&'a self, owner: &'a OwnerContext) -> OwnerApproval<'a> {
        OwnerApproval {
            owner,
            signer: &self.signer,
            enrolment: self.enrolment,
            request: &self.request,
            proof: &self.proof,
        }
    }

    /// Returns the proof, which the acceptance record names.
    #[must_use]
    pub const fn proof(&self) -> &OwnerConfirmationProof {
        &self.proof
    }

    /// Returns the challenge the proof answers.
    #[must_use]
    pub const fn request(&self) -> &OwnerConfirmationRequest {
        &self.request
    }
}

impl OwnerAuthority {
    /// Builds the service for one host.
    #[must_use]
    pub fn new(
        host_device_id: DeviceId,
        host_endpoint_id: EndpointKey,
        clock: HostPairingClock,
        rows: InvitationRows,
    ) -> Self {
        Self {
            host_device_id,
            host_endpoint_id,
            clock,
            rows,
            state: Mutex::new(Challenges {
                ledger: ConfirmationLedger::new(),
                entries: BTreeMap::new(),
                issued: 0,
            }),
        }
    }

    /// Returns whether this host has an owner yet.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the owner record cannot be read.
    pub fn enrolment(&self) -> Result<HostEnrolment> {
        Ok(match self.rows.host_owner()? {
            Some(_) => HostEnrolment::Enrolled,
            None => HostEnrolment::InitialBootstrap,
        })
    }

    /// Returns the expectation an effect of `action` over `digest` builds, for this host.
    #[must_use]
    pub const fn expectation<'a>(
        &self,
        action: SensitiveAction,
        digest: Digest256,
        destination: Option<&'a DevicePublicKeys>,
        rights: &'a CanonicalSet<ActionRight>,
    ) -> ConfirmationExpectation<'a> {
        ConfirmationExpectation {
            action,
            action_digest: digest,
            host_device_id: self.host_device_id,
            host_endpoint_id: self.host_endpoint_id,
            destination_keys: destination,
            destination_rights: rights,
        }
    }

    /// Issues the challenge for one resolved action.
    ///
    /// `action` is the caller's action and the digest of its whole mutation. The challenge an
    /// action asked for is recorded with the action before it is issued, so a retry of that
    /// mutation gets the same challenge, outstanding or not and across a restart, and the same
    /// identifier with another payload is `ID_CONFLICT`, whichever pairing method it was spent on.
    /// `admission` is asked immediately before anything is written.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for a caller without owner authority, `ID_CONFLICT` for a
    /// reused action, the admission's refusal, and an error when the random generator or the
    /// records are unavailable.
    pub fn request(
        &self,
        caller: &Caller,
        resolved: Resolved,
        action: (ActionId, Digest256),
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<OwnerConfirmationRequestResult> {
        if !caller.is_owner(self.rows.lifetimes())? {
            return Err(ControllerError::PermissionDenied {
                detail: "only this host's owner asks for an owner confirmation".to_owned(),
            });
        }
        let initial_bootstrap = self.enrolment()? == HostEnrolment::InitialBootstrap;
        let mut state = self.state();
        // Asked under the lock every challenge is issued under, so two copies of one request meet
        // here and the second is given the challenge the first recorded.
        if let Some(requested) = self.requested(caller, action) {
            return requested;
        }
        self.sweep(&mut state);
        let request = request_confirmation(
            &self.clock,
            resolved.action,
            resolved.digest,
            resolved.destination,
            resolved.rights.iter().copied().collect(),
            self.host_device_id,
            self.host_endpoint_id,
        )
        .map_err(refusal)?;
        // The admission is asked inside the transaction that records the request, after every wait
        // before it; nothing is issued unless that record is written.
        let recorded = self.rows.record_requested(
            &PairingAction {
                actor: caller.actor_id.clone(),
                action_id: action.0,
                digest: action.1,
                subject: ActionSubject::Requested(Box::new(request.clone())),
            },
            admission,
        )?;
        if let Some(request) = recorded {
            return Ok(OwnerConfirmationRequestResult {
                request,
                initial_bootstrap,
            });
        }
        self.issue(&mut state, &request, resolved.display, resolved.first_owner);
        Ok(OwnerConfirmationRequestResult {
            request,
            initial_bootstrap,
        })
    }

    /// Puts a challenge in the ledger and beside it what an owner is shown.
    fn issue(
        &self,
        state: &mut Challenges,
        request: &OwnerConfirmationRequest,
        display: ConfirmationDisplay,
        first_owner: bool,
    ) {
        state.ledger.issue(request, &self.clock);
        state.issued += 1;
        let order = state.issued;
        state.entries.insert(
            *request.confirmation_id.get().as_bytes(),
            Entry {
                order,
                request: request.clone(),
                display,
                first_owner,
                answer: None,
            },
        );
    }

    /// Issues the challenge for an effect whose caller presents the owner's proof itself: the
    /// project service's decisions about repository locations.
    ///
    /// The challenge is this host's like every other: in the same ledger, with the same lifetime,
    /// and listed by `owner.confirmation.pending` with what it approves, so an owner device reads
    /// exactly what it is asked to sign. The service keeps its own action identity, so no pairing
    /// action is recorded for it. A host with no owner device refuses it, because nothing on the
    /// host could answer it: the terminal bootstrap establishes the first owner and confirms
    /// nothing else.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` for a host with no owner device, and an error when the random
    /// generator or the records are unavailable.
    pub fn challenge(&self, resolved: Resolved) -> Result<OwnerConfirmationRequest> {
        if self.owner_devices()?.is_empty() {
            return Err(ControllerError::NotConfigured(
                "this host has no owner device to confirm this; pair one first".to_owned(),
            ));
        }
        let request = request_confirmation(
            &self.clock,
            resolved.action,
            resolved.digest,
            resolved.destination,
            resolved.rights.iter().copied().collect(),
            self.host_device_id,
            self.host_endpoint_id,
        )
        .map_err(refusal)?;
        let mut state = self.state();
        self.sweep(&mut state);
        self.issue(&mut state, &request, resolved.display, false);
        Ok(request)
    }

    /// Returns whether the ledger still holds exactly this challenge, inside its deadline.
    ///
    /// The deadline is the ledger's own, on the machine's continuous clock and bound to this boot,
    /// so a wall clock moved back does not keep a challenge alive.
    #[must_use]
    pub fn outstanding(&self, request: &OwnerConfirmationRequest) -> bool {
        let mut state = self.state();
        self.sweep(&mut state);
        state.ledger.outstanding(request.confirmation_id) == Some(request)
    }

    /// Verifies a proof a caller presents for an effect: an answer to an outstanding challenge
    /// that equals `expectation`, signed by a live owner device of this host after its own
    /// ceremony. Nothing is spent.
    ///
    /// The signers are the ones every other confirmation on this host is verified against: the
    /// authorisation keys of the live paired devices whose grant holds `host.manage` and is in
    /// force. A key the caller presents is never one, and neither is the terminal bootstrap.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` for a challenge that is not this one or not
    /// outstanding, another channel than an owner device's, or a signer that is not an owner
    /// device, and `PAIRING_AUTH_FAILED` when the signature fails.
    pub fn verify_presented(
        &self,
        expectation: &ConfirmationExpectation<'_>,
        proof: &OwnerConfirmationProof,
    ) -> Result<()> {
        expectation.require(&proof.request).map_err(refusal)?;
        if !matches!(
            proof.channel,
            ConfirmationChannel::OwnerDevicePresence | ConfirmationChannel::PairedOwnerDevice
        ) {
            return Err(confirmation_required(
                "this is confirmed by an owner device's own ceremony and nothing else",
            ));
        }
        let signer = self.owner_device_key(proof.signer_key_id)?;
        let mut state = self.state();
        self.sweep(&mut state);
        if state.ledger.outstanding(proof.request.confirmation_id) != Some(&proof.request) {
            return Err(confirmation_required(
                "that challenge is not outstanding on this host",
            ));
        }
        verify_confirmation(
            &self.clock,
            &proof.request,
            proof,
            &signer,
            HostEnrolment::Enrolled,
        )
        .map_err(refusal)
    }

    /// Spends a presented proof for `effect`, once, immediately before the effect.
    ///
    /// Authority can change between the verification and the spend, so the signer is looked up
    /// among the owner devices again, the proof verified again and the challenge consumed; the
    /// consumption is then written to the acceptance record, whose transaction reads the signer's
    /// authority once more. A crash between the two wastes the confirmation and never leaves an
    /// effect without its record.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when the proof no longer answers an outstanding
    /// challenge equal to `expectation` or its signer is no longer an owner device, and a registry
    /// error when the consumption cannot be recorded.
    pub fn spend_presented(
        &self,
        expectation: &ConfirmationExpectation<'_>,
        proof: &OwnerConfirmationProof,
        effect: &str,
    ) -> Result<()> {
        if !matches!(
            proof.channel,
            ConfirmationChannel::OwnerDevicePresence | ConfirmationChannel::PairedOwnerDevice
        ) {
            return Err(confirmation_required(
                "this is confirmed by an owner device's own ceremony and nothing else",
            ));
        }
        let signer = self.owner_device_key(proof.signer_key_id)?;
        let mut state = self.state();
        kr_pairing::confirm::accept_confirmation(
            &mut state.ledger,
            &self.clock,
            &proof.request,
            proof,
            &signer,
            HostEnrolment::Enrolled,
            expectation,
        )
        .map_err(refusal)?;
        state
            .entries
            .remove(proof.request.confirmation_id.get().as_bytes());
        drop(state);
        self.rows.record_consumed(proof, effect, kr_ipc::now_ms())
    }

    /// Returns the authorisation key of the live owner device whose key `signer` identifies.
    fn owner_device_key(&self, signer: KeyId) -> Result<AuthorisationKey> {
        self.owner_devices()?
            .into_iter()
            .find(|device| key_id(&device.authorisation) == signer)
            .map(|device| device.authorisation)
            .ok_or_else(|| confirmation_required("the signer is not an owner device of this host"))
    }

    /// Returns the answer an action that already asked for a challenge is owed, when it did.
    ///
    /// # Errors
    ///
    /// The inner result is `ID_CONFLICT` when the identifier was used with another payload, for
    /// this method or any other pairing method, and a registry error when the record cannot be
    /// read.
    #[must_use]
    pub fn requested(
        &self,
        caller: &Caller,
        action: (ActionId, Digest256),
    ) -> Option<Result<OwnerConfirmationRequestResult>> {
        let subject = match self.rows.answered(&caller.actor_id, action.0, action.1)? {
            Ok(subject) => subject,
            Err(error) => return Some(Err(error)),
        };
        Some(match subject {
            ActionSubject::Requested(request) => self.answer_requested(*request),
            _ => Err(another_subject()),
        })
    }

    /// Returns what an action that asked for `request` is answered with.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the owner record cannot be read.
    pub fn answer_requested(
        &self,
        request: OwnerConfirmationRequest,
    ) -> Result<OwnerConfirmationRequestResult> {
        Ok(OwnerConfirmationRequestResult {
            request,
            initial_bootstrap: self.enrolment()? == HostEnrolment::InitialBootstrap,
        })
    }

    /// Returns the answer an action that already completed a confirmation is owed, when it did.
    ///
    /// The action's record says which confirmation, and the acceptance record says what was
    /// accepted, so this holds after the challenge was spent and across a restart. It is given for
    /// the same action and payload and nothing else: the same proof under another action is a
    /// completion of its own, checked as one.
    ///
    /// # Errors
    ///
    /// The inner result is `ID_CONFLICT` when the identifier was used with another payload, for
    /// this method or any other pairing method, and a registry error when a record cannot be read.
    #[must_use]
    pub fn completed(
        &self,
        caller: &Caller,
        action: (ActionId, Digest256),
    ) -> Option<Result<OwnerConfirmationCompleteResult>> {
        let subject = match self.rows.answered(&caller.actor_id, action.0, action.1)? {
            Ok(subject) => subject,
            Err(error) => return Some(Err(error)),
        };
        Some(match subject {
            ActionSubject::Completed(confirmation_id) => self.answer_completed(confirmation_id),
            _ => Err(another_subject()),
        })
    }

    /// Returns what an action that completed `confirmation_id` is answered with, from the
    /// acceptance record.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the acceptance record cannot be read or has no row for it.
    pub fn answer_completed(
        &self,
        confirmation_id: ConfirmationId,
    ) -> Result<OwnerConfirmationCompleteResult> {
        let acceptance = self.rows.acceptance(confirmation_id)?.ok_or_else(|| {
            ControllerError::registry("a completed confirmation has no acceptance record")
        })?;
        Ok(OwnerConfirmationCompleteResult {
            confirmation_id,
            channel: acceptance.proof.channel,
            answered_at_ms: acceptance.answered_at_ms,
        })
    }

    /// Lists the challenges an owner can still answer, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for a caller without owner authority.
    pub fn pending(&self, caller: &Caller) -> Result<OwnerConfirmationPendingResult> {
        if !caller.is_owner(self.rows.lifetimes())? {
            return Err(ControllerError::PermissionDenied {
                detail: "only this host's owner reads its outstanding confirmations".to_owned(),
            });
        }
        let mut state = self.state();
        self.sweep(&mut state);
        let mut pending: Vec<&Entry> = state.entries.values().collect();
        pending.sort_by_key(|entry| entry.order);
        Ok(OwnerConfirmationPendingResult {
            pending: pending
                .into_iter()
                .map(|entry| PendingConfirmation {
                    request: entry.request.clone(),
                    display: entry.display.clone(),
                    answered: entry.answer.is_some(),
                })
                .collect(),
        })
    }

    /// Verifies a proof for an outstanding challenge and records the answer, with the action that
    /// completed it.
    ///
    /// A proof is accepted once. The same proof completed again under another action, while its
    /// challenge is outstanding, records that action and is answered with the acceptance as it
    /// already stands; once the challenge is spent it answers nothing.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when the proof answers no outstanding challenge,
    /// arrived through a channel that is never a confirmation, or comes from a signer this host
    /// does not accept for that channel, `PAIRING_AUTH_FAILED` when its signature fails, and
    /// `ID_CONFLICT` for a reused action.
    pub fn complete(
        &self,
        caller: &Caller,
        params: &OwnerConfirmationCompleteParams,
        action: (ActionId, Digest256),
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<OwnerConfirmationCompleteResult> {
        let proof = &params.proof;
        // Section 10: noninteractive confirmation from a session, plugin or contact-tool channel is
        // rejected, whoever carries it and whatever it is signed with.
        if !matches!(
            proof.channel,
            ConfirmationChannel::OwnerDevicePresence
                | ConfirmationChannel::PairedOwnerDevice
                | ConfirmationChannel::EnrolledPresenceSigner
                | ConfirmationChannel::LocalBootstrapTerminal
        ) {
            return Err(confirmation_required(
                "a session, plugin or contact-tool channel never carries an owner confirmation",
            ));
        }
        let enrolment = self.enrolment()?;
        let mut state = self.state();
        // Asked under the lock every answer is recorded under, so two copies of one completion meet
        // here and the second is given what the first recorded.
        if let Some(completed) = self.completed(caller, action) {
            return completed;
        }
        self.sweep(&mut state);
        let key = *proof.request.confirmation_id.get().as_bytes();
        let entry = state.entries.get(&key).ok_or_else(|| {
            confirmation_required("that challenge is not outstanding on this host")
        })?;
        if entry.request != proof.request {
            return Err(confirmation_required(
                "the proof answers a challenge this host did not issue",
            ));
        }
        let signer = self.signer_for(caller, proof, entry, enrolment, params)?;
        verify_confirmation(&self.clock, &entry.request, proof, &signer, enrolment)
            .map_err(refusal)?;
        let already = entry.answer.as_ref().map(|answer| &answer.proof == proof);
        if already == Some(false) {
            return Err(confirmation_required(
                "that challenge has already been answered with another proof",
            ));
        }
        // The admission is asked inside the transaction that records the answer, after every wait
        // before it.
        let answered_at_ms = self.rows.record_answered(
            proof,
            &PairingAction {
                actor: caller.actor_id.clone(),
                action_id: action.0,
                digest: action.1,
                subject: ActionSubject::Completed(proof.request.confirmation_id),
            },
            kr_ipc::now_ms(),
            admission,
        )?;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.answer = Some(Answer {
                proof: proof.clone(),
                signer,
            });
        }
        Ok(OwnerConfirmationCompleteResult {
            confirmation_id: proof.request.confirmation_id,
            channel: proof.channel,
            answered_at_ms,
        })
    }

    /// Takes the oldest answered challenge that equals `expectation`, member for member.
    ///
    /// The challenge stays in the ledger: the effect consumes it through the approval, and does so
    /// exactly once. The returned guard is the ledger it consumes it from.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when no answered challenge matches.
    pub fn spend(
        &self,
        expectation: &ConfirmationExpectation<'_>,
    ) -> Result<(Spendable, MutexGuard<'_, Challenges>)> {
        let enrolment = self.enrolment()?;
        let mut state = self.state();
        self.sweep(&mut state);
        let mut candidates: Vec<&Entry> = state
            .entries
            .values()
            .filter(|entry| entry.answer.is_some() && expectation.require(&entry.request).is_ok())
            .collect();
        if candidates.is_empty() {
            return Err(confirmation_required(
                "this action needs a fresh owner confirmation naming it",
            ));
        }
        candidates.sort_by_key(|entry| entry.order);
        // Each answer was verified when it arrived; the authority behind it is checked again now,
        // because a device can be revoked, or its grant run out, between the two. An answer whose
        // authority has gone is passed over, never spent, and the oldest answer that still stands
        // is the one taken. The store checks once more inside the transaction that records the
        // effect.
        let owner_keys: Vec<KeyId> = self
            .owner_devices()?
            .iter()
            .map(|device| key_id(&device.authorisation))
            .collect();
        let (request, answer) = candidates
            .iter()
            .find_map(|entry| {
                let answer = entry.answer.as_ref()?;
                let standing = match answer.proof.channel {
                    ConfirmationChannel::LocalBootstrapTerminal => {
                        enrolment == HostEnrolment::InitialBootstrap
                    }
                    _ => owner_keys.contains(&answer.proof.signer_key_id),
                };
                standing.then(|| (entry.request.clone(), answer.clone()))
            })
            .ok_or_else(|| {
                confirmation_required(
                    "the owner confirmation that answered this was given under authority this \
                     host no longer holds; confirm again",
                )
            })?;
        let spendable = Spendable {
            request,
            proof: answer.proof,
            signer: answer.signer,
            enrolment,
        };
        Ok((spendable, state))
    }

    /// Consumes an answered challenge for an effect outside the pairing records.
    ///
    /// The consumption is written durably before the caller performs the effect, so a crash between
    /// the two wastes the confirmation and never leaves the effect without its record.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when no answered challenge matches, and a registry
    /// error when the consumption cannot be recorded.
    pub fn consume_for(
        &self,
        expectation: &ConfirmationExpectation<'_>,
        effect: &str,
    ) -> Result<()> {
        let (spendable, mut state) = self.spend(expectation)?;
        kr_pairing::confirm::accept_confirmation(
            &mut state.ledger,
            &self.clock,
            &spendable.request,
            &spendable.proof,
            &spendable.signer,
            spendable.enrolment,
            expectation,
        )
        .map_err(refusal)?;
        state
            .entries
            .remove(spendable.request.confirmation_id.get().as_bytes());
        drop(state);
        self.rows
            .record_consumed(spendable.proof(), effect, kr_ipc::now_ms())
    }

    /// Returns the signer a proof must be verified against, and refuses a signer this host does
    /// not accept for the proof's channel.
    fn signer_for(
        &self,
        caller: &Caller,
        proof: &OwnerConfirmationProof,
        entry: &Entry,
        enrolment: HostEnrolment,
        params: &OwnerConfirmationCompleteParams,
    ) -> Result<AuthorisationKey> {
        match proof.channel {
            ConfirmationChannel::LocalBootstrapTerminal => {
                if enrolment != HostEnrolment::InitialBootstrap {
                    return Err(confirmation_required(
                        "this host has an owner, so the terminal bootstrap is over; confirm on an \
                         owner device",
                    ));
                }
                if caller.ingress != ActorIngress::LocalIpc || caller.device.is_some() {
                    return Err(confirmation_required(
                        "the terminal bootstrap is local to this host",
                    ));
                }
                if !entry.first_owner {
                    return Err(confirmation_required(
                        "the terminal bootstrap establishes this host's first owner and confirms \
                         nothing else",
                    ));
                }
                let signer = params.bootstrap_signer.0.ok_or_else(|| {
                    confirmation_required("a bootstrap proof names the key it was signed with")
                })?;
                if key_id(&signer) != proof.signer_key_id {
                    return Err(confirmation_required(
                        "the bootstrap proof was signed with another key",
                    ));
                }
                Ok(signer)
            }
            ConfirmationChannel::OwnerDevicePresence | ConfirmationChannel::PairedOwnerDevice => {
                if params.bootstrap_signer.is_present() {
                    return Err(confirmation_required(
                        "only a bootstrap proof presents its own key",
                    ));
                }
                let owner = self
                    .owner_devices()?
                    .into_iter()
                    .find(|device| key_id(&device.authorisation) == proof.signer_key_id)
                    .ok_or_else(|| {
                        confirmation_required("the signer is not an owner device of this host")
                    })?;
                // A paired device answers for its own ceremony. It cannot carry another device's
                // proof in, because the ceremony it vouches for is the one on its own screen.
                if let Some(device) = &caller.device
                    && device.device_id != owner.device_id
                {
                    return Err(confirmation_required(
                        "a device completes the confirmations it signed itself",
                    ));
                }
                Ok(owner.authorisation)
            }
            ConfirmationChannel::EnrolledPresenceSigner => Err(confirmation_required(
                "this host has no enrolled presence signer",
            )),
            ConfirmationChannel::Session
            | ConfirmationChannel::Plugin
            | ConfirmationChannel::ContactTool => Err(confirmation_required(
                "a session, plugin or contact-tool channel never carries an owner confirmation",
            )),
        }
    }

    /// Returns the live paired devices whose grant holds host management and is in force under
    /// the host time contract.
    ///
    /// Asking anchors each such grant's deadline, which is what the check inside the consuming
    /// transaction compares with the clock read there.
    fn owner_devices(&self) -> Result<Vec<DeviceRecord>> {
        let lifetimes = self.rows.lifetimes();
        let mut owners = Vec::new();
        for device in self.devices().devices()? {
            if device.is_paired()
                && device.grant.permits(ActionRight::HostManage)
                && lifetimes.in_force(&device)?
            {
                owners.push(device);
            }
        }
        Ok(owners)
    }

    fn devices(&self) -> &DeviceDirectory {
        self.rows.directory()
    }

    /// Drops entries whose challenge the ledger no longer holds: spent, expired or from before a
    /// reboot.
    fn sweep(&self, state: &mut Challenges) {
        state.ledger.expire(&self.clock);
        let Challenges {
            ledger, entries, ..
        } = state;
        entries.retain(|_, entry| ledger.outstanding(entry.request.confirmation_id).is_some());
    }

    fn state(&self) -> MutexGuard<'_, Challenges> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Challenges {
    /// Returns the ledger an effect consumes its confirmation from.
    pub fn ledger(&mut self) -> &mut ConfirmationLedger {
        &mut self.ledger
    }

    /// Forgets an entry whose challenge an effect consumed.
    pub fn forget(&mut self, request: &OwnerConfirmationRequest) {
        if self.ledger.outstanding(request.confirmation_id).is_none() {
            self.entries
                .remove(request.confirmation_id.get().as_bytes());
        }
    }
}

/// Returns the key identifier of an authorisation key, as a proof names its signer.
fn key_id(key: &AuthorisationKey) -> KeyId {
    kr_crypto::keys::key_id(KeyPurpose::Authorisation, key.as_bytes())
}

/// Returns an `OWNER_CONFIRMATION_REQUIRED` refusal with the host's reason.
fn confirmation_required(detail: &str) -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::OwnerConfirmationRequired,
        detail: detail.to_owned(),
    }
}

/// Returns a pairing failure under kr-pairing's own stable code.
///
/// The mapping is kr-pairing's, in one place, so the daemon cannot report a pairing outcome under a
/// code the rest of the build reports differently.
#[must_use]
pub fn refusal(error: kr_pairing::PairingError) -> ControllerError {
    ControllerError::Refused {
        code: error.code(),
        detail: error.to_string(),
    }
}
