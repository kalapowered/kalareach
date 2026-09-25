//! A device redeeming a direct invitation.
//!
//! A direct invitation pins the host's endpoint and carries a 256-bit secret, and it reaches no
//! rendezvous service. The device dials the pinned endpoint, refuses a connection whose peer is
//! any other endpoint before it offers anything on it, asks the host for a fresh challenge, and
//! answers with kr-pairing's proof, which carries the secret's tag over the transcript `D` and is
//! built only once the live peer has been checked again against the endpoint the invitation
//! pinned. The host answers with the value both devices display, which the device compares with
//! the one it computed from `D` itself before it shows it.

use kr_pairing::direct::{redeem_proof, verification_values_match};
use kr_protocol::pairing::{DirectQrPayload, direct_verification_value};
use kr_protocol::preauth::{PairRedeemParams, PairRedeemResult};
use tokio::sync::watch;

use super::candidate::{
    AttemptState, Pairing, RECOVERY_MARGIN_MS, Stage, Unpaired, WAIT_STEP, awaiting, within,
};
use super::failure::{FailureKind, PairingFailure, refused_by_host};
use super::link::{ConnectionPeer, LinkError};
use super::paired::{AttemptMode, PairedHost, PendingAttempt};

impl Pairing {
    /// Redeems a direct invitation.
    ///
    /// The payload holds the invitation's secret. The caller keeps it only for this call, and it
    /// clears itself when dropped.
    ///
    /// # Errors
    ///
    /// Returns how the attempt ended, which `progress` also shows.
    pub async fn pair_directly(
        &self,
        payload: &DirectQrPayload,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let outcome = self.direct_attempt(payload, progress).await;
        if let Err(failure) = &outcome {
            progress.send_replace(AttemptState::Ended {
                failure: failure.clone(),
            });
        }
        outcome
    }

    async fn direct_attempt(
        &self,
        payload: &DirectQrPayload,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingHost,
        });
        if self.hosts.by_endpoint(&payload.endpoint_id)?.is_some() {
            return Err(PairingFailure::new(
                FailureKind::AlreadyPaired,
                "this device is already paired with the host the invitation pins",
            ));
        }
        // Nothing this device does for another host may close the endpoint the attempt uses.
        let _held = within(WAIT_STEP, self.link.hold(&payload.network_config))
            .await
            .map_err(|error| reached(&error))?;
        let connection = within(
            WAIT_STEP,
            self.link
                .dial(&payload.network_config, &payload.endpoint_id),
        )
        .await
        .map_err(|error| reached(&error))?;
        let peer = ConnectionPeer::of(&connection);
        if peer.endpoint() != payload.endpoint_id {
            return Err(PairingFailure::new(
                FailureKind::HostMismatch,
                "the connection reached another endpoint than the invitation pins",
            ));
        }
        let mut preauth = within(
            WAIT_STEP,
            self.link
                .open_unpaired(&connection, &self.candidate.unpaired()),
        )
        .await
        .map_err(|error| reached(&error))?;
        let selection = preauth.selection().clone();
        if selection.endpoint_id != payload.endpoint_id {
            return Err(PairingFailure::new(
                FailureKind::HostMismatch,
                "the host's selection names another endpoint than the invitation pins",
            ));
        }
        if self.hosts.by_device(selection.device_id)?.is_some() {
            return Err(PairingFailure::new(
                FailureKind::AlreadyPaired,
                "this device is already paired with the host the invitation pins",
            ));
        }
        let asked = PairRedeemParams::Challenge {
            invitation_id: payload.invitation_id,
        };
        let challenge = match within(WAIT_STEP, preauth.redeem(&asked))
            .await
            .map_err(|error| reached(&error))?
        {
            PairRedeemResult::Challenge(challenge) => challenge,
            PairRedeemResult::Locked { .. } => {
                return Err(PairingFailure::new(
                    FailureKind::DidNotFinish,
                    "the host answered a challenge request with a lock",
                ));
            }
        };
        let (proof, transcript) = redeem_proof(
            payload,
            &challenge,
            &self.candidate.keys().authorisation,
            &self.candidate.identity(),
            &peer,
        )
        .map_err(|error| {
            let kind = match error {
                kr_pairing::PairingError::EndpointMismatch { .. }
                | kr_pairing::PairingError::ContextMismatch { .. } => FailureKind::HostMismatch,
                _ => FailureKind::DidNotFinish,
            };
            PairingFailure::new(kind, error.to_string())
        })?;
        let value = direct_verification_value(&transcript);
        let pending = PendingAttempt {
            mode: AttemptMode::Direct,
            invitation_id: payload.invitation_id,
            host_device_id: selection.device_id,
            host_key_revision: challenge.device_key_revision,
            host_keys: challenge.host_keys,
            host_endpoint_id: payload.endpoint_id,
            network_config: payload.network_config.clone(),
            proposed_grant: payload.proposed_grant.clone(),
            verification_value: value.clone(),
            value_confirmed: false,
            expires_at_ms: Some(payload.expires_at_ms.get()),
            // The payload's expiry is the one the transcript binds, so it bounds how long this
            // device keeps asking.
            recover_until_ms: payload
                .expires_at_ms
                .get()
                .saturating_add(RECOVERY_MARGIN_MS),
            tries_left: None,
        };
        // Kept before the proof leaves, so a device that restarts while the owner decides can ask
        // again.
        self.hosts.keep_attempt(&pending)?;
        // A host that takes the proof and holds its answer back is asked again, on a connection of
        // its own, like one whose answer was lost.
        let proved = PairRedeemParams::Direct(Box::new(proof));
        let redeemed = within(self.step(&pending), preauth.redeem(&proved)).await;
        let pending = match redeemed {
            Ok(PairRedeemResult::Locked {
                verification_value, ..
            }) => {
                if !verification_values_match(&value, &verification_value) {
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        FailureKind::HostMismatch,
                        "the host's verification value is not the one this device computed",
                    ));
                }
                self.value_confirmed(pending)?
            }
            Ok(PairRedeemResult::Challenge(_)) => {
                let _ = self.hosts.clear_attempt();
                return Err(PairingFailure::new(
                    FailureKind::DidNotFinish,
                    "the host answered a proof with another challenge",
                ));
            }
            Err(LinkError::Refused(refusal)) => {
                let _ = self.hosts.clear_attempt();
                return Err(PairingFailure::new(
                    refused_by_host(refusal.code, true),
                    refusal.message,
                ));
            }
            // Whether the host locked the invitation is unknown; asking is how to find out, on a
            // connection of its own.
            Err(LinkError::Lost(_) | LinkError::Configuration(_)) => {
                drop(preauth);
                drop(connection);
                return self.await_approval(pending, None, progress).await;
            }
        };
        progress.send_replace(awaiting(&pending));
        // Two questions were asked on the connection: the challenge and the proof.
        self.await_approval(
            pending,
            Some(Unpaired::new(connection, preauth, 2)),
            progress,
        )
        .await
    }
}

/// What a failure reaching the pinned host means.
fn reached(error: &LinkError) -> PairingFailure {
    let kind = match error {
        LinkError::Refused(refusal) => refused_by_host(refusal.code, true),
        LinkError::Lost(_) => FailureKind::HostUnreachable,
        LinkError::Configuration(_) => FailureKind::NotAnInvitation,
    };
    PairingFailure::new(kind, error.to_string())
}
