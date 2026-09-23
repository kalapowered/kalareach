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
use kr_protocol::ids::{ActionId, ActorId, DeviceId};
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePublicKeys, KeyPurpose, OwnerConfirmationProof,
    OwnerConfirmationRequest, SensitiveAction,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Digest256, EndpointKey};

use super::devices::{DeviceDirectory, DeviceRecord};
use super::invitations::InvitationRows;
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

    /// Returns true when this caller holds owner authority on this host.
    ///
    /// A local caller is the host's own account. A paired device is an owner device when its live
    /// grant holds `host.manage`.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        match (&self.device, self.ingress) {
            (None, ActorIngress::LocalIpc) => true,
            (Some(device), ActorIngress::PairedDevice) => {
                device.is_paired() && device.grant.permits(ActionRight::HostManage)
            }
            _ => false,
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
    requested_by: ActorId,
    requested_under: Option<ActionId>,
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
    /// A retry of the same caller's action gets the challenge that action already issued, while it
    /// is still outstanding, rather than a second one.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for a caller without owner authority, and an error when the
    /// random generator or the owner record is unavailable.
    pub fn request(
        &self,
        caller: &Caller,
        resolved: Resolved,
        action: Option<ActionId>,
    ) -> Result<OwnerConfirmationRequestResult> {
        if !caller.is_owner() {
            return Err(ControllerError::PermissionDenied {
                detail: "only this host's owner asks for an owner confirmation".to_owned(),
            });
        }
        let initial_bootstrap = self.enrolment()? == HostEnrolment::InitialBootstrap;
        let mut state = self.state();
        self.sweep(&mut state);
        if let Some(action) = action
            && let Some(entry) = state.entries.values().find(|entry| {
                entry.requested_by == caller.actor_id && entry.requested_under == Some(action)
            })
        {
            return Ok(OwnerConfirmationRequestResult {
                request: entry.request.clone(),
                initial_bootstrap,
            });
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
        state.ledger.issue(&request, &self.clock);
        state.issued += 1;
        let order = state.issued;
        state.entries.insert(
            *request.confirmation_id.get().as_bytes(),
            Entry {
                order,
                request: request.clone(),
                display: resolved.display,
                first_owner: resolved.first_owner,
                requested_by: caller.actor_id.clone(),
                requested_under: action,
                answer: None,
            },
        );
        Ok(OwnerConfirmationRequestResult {
            request,
            initial_bootstrap,
        })
    }

    /// Lists the challenges an owner can still answer, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for a caller without owner authority.
    pub fn pending(&self, caller: &Caller) -> Result<OwnerConfirmationPendingResult> {
        if !caller.is_owner() {
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

    /// Verifies a proof for an outstanding challenge and records the answer.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when the proof answers no outstanding challenge,
    /// arrived through a channel that is never a confirmation, or comes from a signer this host
    /// does not accept for that channel, and `PAIRING_AUTH_FAILED` when its signature fails.
    pub fn complete(
        &self,
        caller: &Caller,
        params: &OwnerConfirmationCompleteParams,
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
        let now = kr_ipc::now_ms();
        self.rows.record_answered(proof, &caller.actor_id, now)?;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.answer = Some(Answer {
                proof: proof.clone(),
                signer,
            });
        }
        Ok(OwnerConfirmationCompleteResult {
            confirmation_id: proof.request.confirmation_id,
            channel: proof.channel,
            answered_at_ms: now,
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
        candidates.sort_by_key(|entry| entry.order);
        let entry = candidates.first().ok_or_else(|| {
            confirmation_required("this action needs a fresh owner confirmation naming it")
        })?;
        let answer = entry.answer.clone().expect("filtered on an answer");
        let spendable = Spendable {
            request: entry.request.clone(),
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

    /// Returns the live paired devices whose grant holds host management.
    fn owner_devices(&self) -> Result<Vec<DeviceRecord>> {
        Ok(self
            .devices()
            .devices()?
            .into_iter()
            .filter(|device| device.is_paired() && device.grant.permits(ActionRight::HostManage))
            .collect())
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
fn key_id(key: &AuthorisationKey) -> kr_protocol::scalars::KeyId {
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
