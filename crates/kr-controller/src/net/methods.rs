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

use kr_protocol::confirmation::{
    OwnerConfirmationCompleteParams, OwnerConfirmationPendingParams, OwnerConfirmationRequestParams,
};
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::ids::{AuthorityRevision, ConnectionId};
use kr_protocol::invitation::{PairCancelParams, PairConfirmParams, PairInviteParams};
use kr_protocol::method::Method;
use kr_protocol::preauth::PairStatusParams;
use kr_protocol::scalars::Digest256;
use kr_transport::clock::ContinuousInstant;

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
    )
}

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
        let pairing = self.pairing_service()?;
        match method {
            Method::PairStatus => {
                let params: PairStatusParams = decode(params)?;
                if caller.device.is_some() {
                    blocking(move || pairing.device_status(&caller, &params)).await
                } else {
                    blocking(move || pairing.owner_status(&caller, &params)).await
                }
            }
            Method::OwnerConfirmationPending => {
                let _: OwnerConfirmationPendingParams = decode(params)?;
                blocking(move || pairing.pending_confirmations(&caller)).await
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
        let pairing = self.pairing_service().ok()?;
        let digest = match mutation_digest(mutation, &caller) {
            Ok(digest) => digest,
            Err(error) => return Some(Err(error)),
        };
        let mutation = mutation.clone();
        tokio::task::spawn_blocking(move || pairing.retained(&caller, method, &mutation, digest))
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
    ) -> Result<ParamsValue> {
        let pairing = self.pairing_service()?;
        let action = (mutation.action_id, mutation_digest(mutation, &caller)?);
        match method {
            Method::OwnerConfirmationRequest => {
                let params: OwnerConfirmationRequestParams = decode(&mutation.params)?;
                blocking(move || {
                    pairing.request_confirmation(&caller, &params, action, admission.as_ref())
                })
                .await
            }
            Method::OwnerConfirmationComplete => {
                let params: OwnerConfirmationCompleteParams = decode(&mutation.params)?;
                blocking(move || {
                    pairing.complete_confirmation(&caller, &params, admission.as_ref())
                })
                .await
            }
            Method::PairInvite => {
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
                let params: PairConfirmParams = decode(&mutation.params)?;
                // The grant is issued at the authority revision in force when it is written.
                let revision = self.authority_revision().await?;
                blocking(move || pairing.confirm(&caller, &params, revision, &admission)).await
            }
            Method::PairCancel => {
                let params: PairCancelParams = decode(&mutation.params)?;
                blocking(move || pairing.cancel(&caller, &params, &admission)).await
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
