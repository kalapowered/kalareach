//! The pairing and owner-confirmation methods, as the daemon serves them to its two ingresses.
//!
//! A local caller and a paired device reach the same handlers, and each arrives with a
//! [`Caller`] the ingress built from what it authenticated: the operating-system identity of a
//! local socket, or the device record an authorised connection was admitted under. What a caller
//! may then do is the pairing service's decision, not the ingress's: the issuing owner of an
//! invitation is exact, and an owner device is a live device whose grant holds host management.
//!
//! The pairing state machines are synchronous and write their records before they answer, so each
//! call runs on a blocking thread, and the daemon's own tasks never wait on a disk write. A
//! mutation carries its admission with it onto that thread: the registration and the deadline it
//! was admitted under are asked again inside the transaction that writes its effect, because the
//! wait for the thread, for the invitation's lock, for the owner's confirmation and for the
//! database can each outlast either.

use std::sync::Arc;

use kr_pairing::confirm::HostEnrolment;
use kr_protocol::confirmation::{
    ConfirmationSubject, HostClockEstablishParams, OwnerConfirmationCompleteParams,
    OwnerConfirmationPendingParams, OwnerConfirmationRequestParams,
};
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::ids::{AuthorityRevision, ConnectionId};
use kr_protocol::invitation::{PairCancelParams, PairConfirmParams, PairInviteParams};
use kr_protocol::method::Method;
use kr_protocol::preauth::PairStatusParams;
use kr_protocol::scalars::Digest256;
use kr_transport::clock::ContinuousInstant;

pub use super::devices::CommitFn;
pub use super::invitations::Admission;
use super::owner::Caller;
use super::pairing::PairingHost;
use crate::authority::AdmittedMutation;
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// Returns true for the methods this module serves.
///
/// `pair.redeem` and `pair.finish` are not among them: an unpaired candidate reaches those through
/// the transport's pre-authorisation surface, which [`PairingHost`] implements directly.
#[must_use]
pub const fn serves(method: Method) -> bool {
    matches!(
        method,
        Method::PairInvite
            | Method::PairConfirm
            | Method::PairCancel
            | Method::PairStatus
            | Method::OwnerConfirmationRequest
            | Method::OwnerConfirmationPending
            | Method::OwnerConfirmationComplete
            | Method::HostClockEstablish
    )
}

/// What a pairing mutation carries to its effect so that the effect can hold its registration
/// standing through its commit: runs the commit it is handed while the registration, the fence and
/// the deadline it was admitted under are held ([`Controller::pairing_guard`]).
pub type CommitGuard = Arc<CommitFn>;

impl Controller {
    /// Returns the admission check of one mutation: its connection's registration under the
    /// revision it was admitted at, and the deadline it was accepted with.
    ///
    /// A mutation that carries no freshness at all may be answered from what this host already
    /// holds and may not write, so its check refuses.
    pub(crate) fn pairing_admission(
        self: &Arc<Self>,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
        deadline: Option<ContinuousInstant>,
    ) -> Admission {
        let (Some(admitted_revision), Some(deadline)) = (admitted, deadline) else {
            return Arc::new(|| {
                Err(ControllerError::WindowExpired {
                    detail: "this action carries no freshness, so it may be answered from what \
                             this host holds and may not write"
                        .to_owned(),
                })
            });
        };
        let controller = Arc::clone(self);
        let carried = AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: Some(deadline),
        };
        Arc::new(move || controller.check_registration(&carried))
    }

    /// Returns the guard of one mutation's commit: its registration under the revision it was
    /// admitted at and the deadline it was accepted with, held from the check to the end of the
    /// commit it is handed ([`Self::under_registration`]).
    ///
    /// A mutation that carries no freshness at all may be answered from what this host already
    /// holds and may not write, so its guard refuses.
    pub(crate) fn pairing_guard(
        self: &Arc<Self>,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
        deadline: Option<ContinuousInstant>,
    ) -> CommitGuard {
        let (Some(admitted_revision), Some(deadline)) = (admitted, deadline) else {
            return Arc::new(|_| {
                Err(ControllerError::WindowExpired {
                    detail: "this action carries no freshness, so it may be answered from what \
                             this host holds and may not write"
                        .to_owned(),
                })
            });
        };
        let controller = Arc::clone(self);
        let carried = AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: Some(deadline),
        };
        Arc::new(move |commit| {
            #[cfg(test)]
            controller.owner.pauses.after_the_connection.wait();
            controller
                .under_registration(&carried, commit)
                .and_then(|committed| committed)
        })
    }

    /// Serves one pairing or owner-confirmation read.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` on a host that is not on the network, and the refusal the
    /// pairing service decides.
    pub(crate) async fn pairing_read(
        self: &Arc<Self>,
        caller: Caller,
        method: Method,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        match method {
            Method::PairStatus => {
                let pairing = self.pairing_service()?;
                let params: PairStatusParams = decode(params)?;
                if caller.device.is_some() {
                    blocking(move || pairing.device_status(&caller, &params)).await
                } else {
                    blocking(move || pairing.owner_status(&caller, &params)).await
                }
            }
            // The challenges are the daemon's, networked or not.
            Method::OwnerConfirmationPending => {
                let _: OwnerConfirmationPendingParams = decode(params)?;
                let owner = Arc::clone(&self.owner);
                blocking(move || owner.pending(&caller)).await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a read the pairing service serves",
                method.as_str()
            ))),
        }
    }

    /// Returns what a repeated pairing mutation is owed, when its action already has an outcome.
    ///
    /// Asked before a first admission's freshness, like every other retained action on this host.
    pub(crate) async fn pairing_retained(
        self: &Arc<Self>,
        caller: Caller,
        method: Method,
        mutation: &MutationRequest,
    ) -> Option<Result<ParamsValue>> {
        if !serves(method) {
            return None;
        }
        let digest = match mutation_digest(mutation, &caller) {
            Ok(digest) => digest,
            Err(error) => return Some(Err(error)),
        };
        let action = (mutation.action_id, digest);
        // The owner-confirmation methods and the establishment of the clock are answered from the
        // daemon's own authority, which a host off the network has; the rest are the pairing
        // service's, which only a host on the network has.
        let owner = Arc::clone(&self.owner);
        let pairing = if matches!(
            method,
            Method::OwnerConfirmationRequest
                | Method::OwnerConfirmationComplete
                | Method::HostClockEstablish
        ) {
            None
        } else {
            Some(self.pairing_service().ok()?)
        };
        let mutation = mutation.clone();
        tokio::task::spawn_blocking(move || match (method, pairing) {
            (Method::OwnerConfirmationRequest, _) => owner
                .requested(&caller, action)
                .map(|answer| answer.and_then(|answer| encode(&answer))),
            (Method::OwnerConfirmationComplete, _) => owner
                .completed(&caller, action)
                .map(|answer| answer.and_then(|answer| encode(&answer))),
            (Method::HostClockEstablish, _) => owner
                .established(&caller, action)
                .map(|answer| answer.and_then(|answer| encode(&answer))),
            (_, Some(pairing)) => pairing.retained(&caller, &mutation, digest),
            (_, None) => None,
        })
        .await
        .unwrap_or_else(|_| {
            Some(Err(ControllerError::Uncertain {
                detail: "the pairing lookup stopped before it answered".to_owned(),
            }))
        })
    }

    /// Serves one pairing or owner-confirmation mutation.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` on a host that is not on the network, and the refusal the
    /// pairing service decides.
    pub(crate) async fn pairing_write(
        self: &Arc<Self>,
        caller: Caller,
        method: Method,
        mutation: &MutationRequest,
        admission: Admission,
        guard: CommitGuard,
    ) -> Result<ParamsValue> {
        let action = (mutation.action_id, mutation_digest(mutation, &caller)?);
        match method {
            // The effect that spends an owner's confirmation of the clock, and the confirmation
            // of it, are the daemon's own: a host off the network has no pairing service and
            // still has a clock. The effect is one blocking step, which a connection that goes
            // away does not cut.
            Method::HostClockEstablish => {
                let _: HostClockEstablishParams = decode(&mutation.params)?;
                let owner = Arc::clone(&self.owner);
                let boot = self.boot_epoch;
                blocking(move || owner.establish_clock(&caller, action, boot, guard.as_ref())).await
            }
            Method::OwnerConfirmationComplete => {
                let params: OwnerConfirmationCompleteParams = decode(&mutation.params)?;
                let owner = Arc::clone(&self.owner);
                blocking(move || owner.complete(&caller, &params, action, admission.as_ref())).await
            }
            Method::OwnerConfirmationRequest => {
                let params: OwnerConfirmationRequestParams = decode(&mutation.params)?;
                if caller.confirms_the_clock_only
                    && !matches!(params.subject, ConfirmationSubject::EstablishClock)
                {
                    return Err(crate::grants::continuity_lost());
                }
                if matches!(params.subject, ConfirmationSubject::EstablishClock) {
                    let owner = Arc::clone(&self.owner);
                    let on_the_network = self.network_guard().is_some();
                    return blocking(move || {
                        // A host that has an owner is confirmed by an owner device, and a device
                        // reaches a host only over its network: asking would leave a challenge
                        // nobody can answer.
                        if !on_the_network && owner.enrolment()? == HostEnrolment::Enrolled {
                            return Err(ControllerError::NotConfigured(
                                "this host has an owner, whose device is the only thing that can \
                                 confirm its clock, and it is not on the network; select a \
                                 network and restart it"
                                    .to_owned(),
                            ));
                        }
                        owner.request_clock(&caller, action, admission.as_ref())
                    })
                    .await;
                }
                let pairing = self.pairing_service()?;
                // A repository's root and an installation are described by the catalogue, from
                // the exact request and the records it holds, and the pairing service issues the
                // challenge for what it resolved.
                if matches!(
                    params.subject,
                    ConfirmationSubject::CatalogueAdd(_) | ConfirmationSubject::PluginInstall(_)
                ) {
                    // Only the owner asks, and that is decided before the catalogue reads or
                    // fetches anything for the subject: what it refuses with names the
                    // repository and the release, which a device without owner authority has no
                    // right to learn. A retried request was answered earlier, with the challenge
                    // it was given.
                    let owner = Arc::clone(&pairing);
                    let asker = caller.clone();
                    tokio::task::spawn_blocking(move || owner.require_owner(&asker))
                        .await
                        .map_err(|_| ControllerError::Uncertain {
                            detail: "the pairing step stopped before it answered".to_owned(),
                        })??;
                    let resolved = self
                        .catalogue
                        .resolve_confirmation(&params.subject)
                        .await
                        .map_err(|error| ControllerError::Refused {
                            code: error.code,
                            detail: error.message,
                        })?;
                    return blocking(move || {
                        pairing.request_resolved(&caller, resolved, action, admission.as_ref())
                    })
                    .await;
                }
                blocking(move || {
                    pairing.request_confirmation(&caller, &params, action, admission.as_ref())
                })
                .await
            }
            Method::PairInvite => {
                let pairing = self.pairing_service()?;
                let params: PairInviteParams = decode(&mutation.params)?;
                let network_config = self
                    .network_guard()
                    .ok_or_else(not_on_network)?
                    .network_config()?;
                blocking(move || {
                    pairing.invite(&caller, &params, action, network_config, &admission)
                })
                .await
            }
            Method::PairConfirm => {
                let pairing = self.pairing_service()?;
                let params: PairConfirmParams = decode(&mutation.params)?;
                // The grant is issued at the authority revision in force when it is written.
                let revision = self.authority_revision().await?;
                let confirmed = blocking(move || {
                    pairing.confirm(&caller, &params, action, revision, &admission)
                })
                .await?;
                // A device that now manages this host is a key the feed may be told can remove it.
                if let Some(runtime) = self.feed_runtime() {
                    runtime.wake();
                }
                Ok(confirmed)
            }
            Method::PairCancel => {
                let pairing = self.pairing_service()?;
                let params: PairCancelParams = decode(&mutation.params)?;
                blocking(move || pairing.cancel(&caller, &params, action, &admission)).await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation the pairing service serves",
                method.as_str()
            ))),
        }
    }

    /// Returns the pairing service of a host on the network.
    fn pairing_service(&self) -> Result<Arc<PairingHost>> {
        self.network_guard()
            .map(|guard| Arc::clone(guard.pairing()))
            .ok_or_else(not_on_network)
    }
}

/// Returns the digest a repeated mutation must match: the whole envelope, freshness window
/// included, under the actor that sent it, as every retained action on this host is keyed.
fn mutation_digest(mutation: &MutationRequest, caller: &Caller) -> Result<Digest256> {
    kr_protocol::digest::mutation_digest(mutation, &caller.actor_id)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Runs one synchronous pairing step on a blocking thread and encodes its answer.
async fn blocking<T, F>(step: F) -> Result<ParamsValue>
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let answer =
        tokio::task::spawn_blocking(step)
            .await
            .map_err(|_| ControllerError::Uncertain {
                detail: "the pairing step stopped before it answered".to_owned(),
            })??;
    ParamsValue::from_typed(&answer)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn decode<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn not_on_network() -> ControllerError {
    ControllerError::NotConfigured(
        "this host is not on the network, so it pairs nothing; select a network and restart it"
            .to_owned(),
    )
}
