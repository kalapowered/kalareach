//! A device pairing with a host: the short-code attempt, and what both modes share once the
//! device has proved itself.
//!
//! kr-pairing holds the candidate's state machines and proofs and no transport; this module drives
//! them over the transport the host serves.
//!
//! ```text
//!   code:   room socket (wss) --admit, PAKE, tags, bundles--> host
//!           iroh, unpaired    --pair.finish----------------> host
//!   direct: iroh, unpaired    --pair.redeem (challenge, proof)> host
//!   both:   iroh, unpaired    --pair.status until committed--> host
//!           iroh, paired      --pair.status, environment.list-> host
//! ```
//!
//! # The start and its lookup
//!
//! kr-pairing's [`ClientAttempt::start`] charges this device's attempt budget first, which writes
//! and flushes files, and then calls a synchronous lookup. So the start runs on a blocking thread,
//! and the lookup it is given opens the room socket on the runtime and waits there for the room's
//! first frame, as the host's own reservation already does. The socket goes into a slot the
//! attempt owns and nowhere else: only a start that succeeded takes it out, and every other ending
//! drops it, which closes the socket. Cancelling the attempt reaches the lookup's wait itself,
//! because a blocking task cannot be aborted once it runs.
//!
//! # What a failure says
//!
//! How far the attempt got decides what an ending may claim ([`super::failure`]): reaching the
//! room; the room holding the socket before the host has spoken; the host having spoken before its
//! confirmation tag verifies; and afterwards, when the host's word is authenticated.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh::endpoint::Connection;
use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::bundles::BundleFrame;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::direct::{CandidateIdentity, verification_values_match};
use kr_pairing::host::HANDSHAKE_DEADLINE_MS;
use kr_pairing::platform::{ClientBudgetStore, LocatorRecord, PairingClock, RendezvousClient};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::GrantExpiry;
use kr_protocol::hostinfo::EnvironmentListResult;
use kr_protocol::ids::{AttemptId, BuildId, DeviceId, DeviceKeyRevision};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, ClientBundle, DeviceName, DevicePlatform,
    INVITATION_LIFETIME_MS, Locator, MAX_CLIENT_ATTEMPTS, PairStatus, RendezvousOrigin,
    group_verification_value,
};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::rendezvous::{
    ClientFrame, CloseReason, ServiceFrame, decode_message, encode_message,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, EndpointKey};
use kr_transport::handshake::LocalIdentity;
use kr_transport::preauth::PreAuthLimits;
use serde::Serialize;
use tokio::sync::{oneshot, watch};

use super::BoxFuture;
use super::failure::{FailureKind, PairingFailure, consumed, refused_by_host};
use super::invitation::origin_host;
use super::link::{ConnectionPeer, HostLink, LinkError, Preauth};
use super::paired::{AttemptMode, PairedHost, PairedHosts, PendingAttempt};
use super::room::{RoomConnector, RoomError, RoomRole, RoomSocket};

/// How long a candidate waits for the room's first frame once its socket is open.
///
/// The room serves a known locator's record at once and holds an unknown one until its own
/// ten-second deadline, so this is that deadline and a margin for the network.
pub const RECORD_WAIT: Duration = Duration::from_secs(15);

/// How often a waiting device asks the host where its attempt has reached.
///
/// A host answers an unpaired connection at most four times in any ten seconds
/// ([`PreAuthLimits`]), so a device that asked more often would be refused. Every three seconds
/// keeps inside that with room for the questions that came before the wait.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(3);

/// How much longer than the host's window a device lets a question age before it no longer counts
/// it. The host counts a question from when it arrived, which is later than when it was sent by
/// however long the network took, and that is never the same twice.
const WINDOW_MARGIN: Duration = Duration::from_secs(1);

/// How long a device waits before dialling a host again, in turn, and then every time after the
/// last.
pub const RECONNECT_DELAYS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// How many times a device that has just been committed tries to connect as what it became.
const PAIRED_CONNECT_TRIES: usize = 4;

/// How long one question to the host, or one dial of it, may take while the device waits for the
/// owner. A host that answers nothing is asked again, and the attempt's own deadline still holds.
pub const WAIT_STEP: Duration = Duration::from_secs(10);

/// How far past an invitation's expiry, by this device's clock, it keeps asking. Two clocks never
/// agree exactly, and the host decides expiry on its own.
pub const RECOVERY_MARGIN_MS: u64 = 60_000;

/// This device, as it pairs with hosts.
#[derive(Clone)]
pub struct Candidate {
    keys: DeviceKeys,
    name: DeviceName,
    platform: DevicePlatform,
    build_id: BuildId,
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Candidate")
            .field("endpoint_id", self.keys.transport.public())
            .field("name", &self.name)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

impl Candidate {
    /// This device: its keys, the name and platform its bundle declares, and its build.
    #[must_use]
    pub const fn new(
        keys: DeviceKeys,
        name: DeviceName,
        platform: DevicePlatform,
        build_id: BuildId,
    ) -> Self {
        Self {
            keys,
            name,
            platform,
            build_id,
        }
    }

    /// This device's keys.
    #[must_use]
    pub const fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// This device's endpoint identity.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointKey {
        *self.keys.transport.public()
    }

    /// Everything this device declares about itself when it redeems a direct invitation.
    #[must_use]
    pub fn identity(&self) -> CandidateIdentity {
        CandidateIdentity {
            keys: self.keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            device_name: self.name.clone(),
            platform: self.platform,
            endpoint_id: self.endpoint_id(),
        }
    }

    /// The bundle this device seals to a host that proved a code.
    fn bundle(&self) -> ClientBundle {
        ClientBundle {
            endpoint_id: self.endpoint_id(),
            keys: self.keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            device_name: self.name.clone(),
            platform: self.platform,
        }
    }

    /// The identity this device offers before it is paired. The device identity in it is a
    /// random one the host does not use: the host assigns the record's own when it commits.
    #[must_use]
    pub fn unpaired(&self) -> LocalIdentity {
        self.paired_identity(DeviceId::new(kr_ipc::new_uuid()))
    }

    /// The identity this device connects to a host with, as the device `device_id` it became.
    #[must_use]
    pub fn paired_identity(&self, device_id: DeviceId) -> LocalIdentity {
        LocalIdentity::new(
            device_id,
            DeviceKeyRevision::new(1),
            self.endpoint_id(),
            self.keys.authorisation.clone(),
            self.build_id.clone(),
        )
    }
}

/// What an attempt is doing while it works.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Opening the room at the pairing service.
    ReachingService,
    /// Proving the code with the host through the room.
    CheckingCode,
    /// Reaching the host over the network.
    ReachingHost,
}

/// What a person is shown of a paired host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostView {
    /// The name the host gives people, when it could be read.
    pub name: Option<String>,
    /// True when this device became an owner of the host.
    pub owner: bool,
    /// What this device may do there, in words.
    pub authority: String,
    /// When this device's grant ends, if it does.
    pub grant_expires_at_ms: Option<u64>,
}

impl HostView {
    /// What a person is shown of `host`.
    #[must_use]
    pub fn of(host: &PairedHost) -> Self {
        Self {
            name: host.name.clone(),
            owner: host.is_owner(),
            authority: super::owner::describe_rights(&host.proposed_grant.actions),
            grant_expires_at_ms: expiry(&host.proposed_grant.expiry),
        }
    }
}

fn expiry(expiry: &GrantExpiry) -> Option<u64> {
    match expiry {
        GrantExpiry::Never => None,
        GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
    }
}

/// Where an attempt has got to, as a person is shown it. Nothing in it is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AttemptState {
    /// No attempt is running.
    Idle,
    /// The attempt is working, and a person waits only for the network.
    Working {
        /// What it is doing.
        stage: Stage,
    },
    /// The host has bound this device, and waits for its owner to approve it.
    AwaitingApproval {
        /// The value both devices display, grouped as both show it.
        value: String,
        /// When the invitation expires, once the host has said.
        expires_at_ms: Option<u64>,
        /// The rights the device would receive.
        rights: Vec<ActionRight>,
        /// What they would let it do, in words.
        authority: String,
        /// When those rights would end, if they would.
        grant_expires_at_ms: Option<u64>,
    },
    /// The connection to the host was lost while the owner decides, and is being made again.
    Reconnecting {
        /// The value both devices display, grouped, once the host has answered with it.
        value: Option<String>,
        /// When the invitation expires, once the host has said.
        expires_at_ms: Option<u64>,
    },
    /// The host committed this device, and the device has connected as what it became.
    Paired {
        /// The host.
        host: HostView,
    },
    /// The attempt ended without a pairing.
    Ended {
        /// How.
        failure: PairingFailure,
        /// How the attempt was made, which decides what a person can do next: a direct
        /// invitation is tried again only by pasting it again.
        mode: AttemptMode,
        /// The host name of the pairing service a code attempt went through, which its failures
        /// name. None for a direct invitation, which reaches no service, and for an attempt taken
        /// up after a restart, whose endings are the host's.
        service: Option<String>,
    },
}

/// How a candidate opens its room.
///
/// [`RoomConnector`] is the product's. A test puts an in-process room in its place.
pub trait CandidateRoom: Send + Sync {
    /// Opens a candidate socket in the room of `locator` at `origin`.
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>>;
}

impl CandidateRoom for RoomConnector {
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
        Box::pin(Self::open(self, origin, locator, RoomRole::Candidate))
    }
}

/// Everything a device's pairing attempts need.
pub struct Pairing {
    /// This device.
    pub candidate: Candidate,
    /// This device's attempt budget.
    pub budget: Arc<dyn ClientBudgetStore + Send + Sync>,
    /// This device's pairing clock.
    pub clock: Arc<dyn PairingClock + Send + Sync>,
    /// How this device opens a room.
    pub room: Arc<dyn CandidateRoom>,
    /// How this device reaches a host.
    pub link: Arc<dyn HostLink>,
    /// The hosts this device is paired with, and the attempt it waits on.
    pub hosts: Arc<PairedHosts>,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Pairing")
            .field("candidate", &self.candidate)
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

impl Pairing {
    /// Pairs by a short code through the room at `origin`.
    ///
    /// `origin` is the origin this device is set to use, or the one a scanned code names once the
    /// person confirmed it: it is both the room contacted and a member of the PAKE context, so a
    /// code entered for another origin cannot succeed here.
    ///
    /// # Errors
    ///
    /// Returns how the attempt ended, which `progress` also shows.
    pub async fn pair_by_code(
        &self,
        origin: &RendezvousOrigin,
        code: &EnteredCode,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let outcome = self.code_attempt(origin, code, progress).await;
        ended(
            progress,
            outcome,
            AttemptMode::Code,
            Some(origin_host(origin).to_owned()),
        )
    }

    /// Takes up an attempt that was waiting for the owner when this device last ran.
    ///
    /// Returns `None` when no attempt is waiting.
    pub async fn resume(
        &self,
        progress: &watch::Sender<AttemptState>,
    ) -> Option<Result<PairedHost, PairingFailure>> {
        let pending = match self.hosts.waiting_attempt() {
            Ok(Some(pending)) => pending,
            Ok(None) => return None,
            // Nothing says how the attempt was made; the ending this can be is the same either way.
            Err(failure) => return Some(ended(progress, Err(failure), AttemptMode::Code, None)),
        };
        let mode = pending.mode;
        progress.send_replace(reconnecting(&pending));
        // Nothing this device does for another host may close the endpoint the attempt uses.
        let _held = match within(WAIT_STEP, self.link.hold(&pending.network_config)).await {
            Ok(held) => held,
            Err(error) => {
                let failure = link_failed(&error, pending.tries_left);
                return Some(ended(progress, Err(failure), mode, None));
            }
        };
        // The host may have committed this device already, and this device recorded it and
        // stopped before it let the waiting attempt go. The host now answers that endpoint as the
        // paired device, so the record is what reaches it.
        let recorded = match self.hosts.by_device(pending.host_device_id) {
            Ok(recorded) => recorded,
            Err(failure) => {
                let failure = failure.or_tries(pending.tries_left);
                return Some(ended(progress, Err(failure), mode, None));
            }
        };
        let outcome = match recorded {
            Some(host) if host.host_endpoint_id == pending.host_endpoint_id => self
                .confirm_committed(host, &pending, progress)
                .await
                .map_err(|failure| failure.or_tries(pending.tries_left)),
            _ => self.await_approval(pending, None, progress).await,
        };
        Some(ended(progress, outcome, mode, None))
    }

    async fn code_attempt(
        &self,
        origin: &RendezvousOrigin,
        code: &EnteredCode,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingService,
        });
        let deadline = tokio::time::Instant::now() + Duration::from_millis(HANDSHAKE_DEADLINE_MS);
        let started = {
            let (budget, clock) = (Arc::clone(&self.budget), Arc::clone(&self.clock));
            let (origin, code) = (origin.clone(), code.clone());
            start_in_room(Arc::clone(&self.room), move |lookup| {
                ClientAttempt::start(&*budget, &*clock, lookup, &origin, &code)
            })
            .await
        };
        let ((attempt, admission, _record), socket) = match started {
            Ok(started) => started,
            Err(refused) => return Err(self.start_failure(refused, origin, code)),
        };
        // The attempt was charged, so every ending from here says how many tries are left.
        let tries = Some(attempt.remaining_attempts());
        // An invitation lives five minutes, so a code entered now cannot be open much past five
        // minutes from now, whatever the service advertised.
        let recover_until_ms = self
            .clock
            .wall_clock_ms()
            .saturating_add(INVITATION_LIFETIME_MS)
            .saturating_add(RECOVERY_MARGIN_MS);
        self.exchange(
            attempt,
            admission,
            Relay::new(socket, admission.attempt_id, deadline),
            recover_until_ms,
            progress,
        )
        .await
        .map_err(|failure| failure.or_tries(tries))
    }

    /// The short-code exchange, from the room's admission to the owner's decision.
    async fn exchange(
        &self,
        mut attempt: ClientAttempt,
        admission: kr_pairing::client::ClientAdmission,
        mut room: Relay,
        recover_until_ms: u64,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let tries = Some(attempt.remaining_attempts());
        let clock = &*self.clock;

        // The room admitted the socket, and nothing the host said has arrived: every ending here
        // is the same uncertain one.
        let no_host = |stop: RoomStop| stop.failure(FailureKind::NoHostAnswered, tries);
        room.frame(ClientFrame::Attempt {
            attempt_id: admission.attempt_id,
        })
        .await
        .map_err(no_host)?;
        room.send(&RendezvousMessage::Admit {
            client_nonce: admission.client_nonce,
        })
        .await
        .map_err(no_host)?;
        progress.send_replace(AttemptState::Working {
            stage: Stage::CheckingCode,
        });
        let first = room.receive().await.map_err(no_host)?;

        // The host has spoken, through a relay nothing authenticates yet.
        let (host_nonce, host_pake) = match first {
            RendezvousMessage::HostPake {
                host_nonce,
                message,
            } => (host_nonce, message),
            other => return Err(answered_otherwise(&other, tries)),
        };
        let stalled = |stop: RoomStop| stop.failure(FailureKind::TimedOut, tries);
        let client_pake = attempt
            .with_host_nonce(host_nonce, clock)
            .map_err(|error| step_failed(&error, tries))?;
        room.send(&RendezvousMessage::ClientPake {
            message: Bytes::new(client_pake),
        })
        .await
        .map_err(stalled)?;
        let tag = attempt
            .receive_host_pake(host_pake.as_slice(), clock)
            .map_err(|error| step_failed(&error, tries))?;
        room.send(&RendezvousMessage::ClientConfirmation { tag })
            .await
            .map_err(stalled)?;
        let host_tag = match room.receive().await.map_err(stalled)? {
            RendezvousMessage::HostConfirmation { tag } => tag,
            other => return Err(answered_otherwise(&other, tries)),
        };
        attempt
            .verify_host_confirmation(&host_tag, clock)
            .map_err(|error| step_failed(&error, tries))?;

        // The host's tag verified: what it says from here is its own word.
        let unfinished = |stop: RoomStop| stop.failure(FailureKind::DidNotFinish, tries);
        let host_bundle = match room.receive().await.map_err(unfinished)? {
            RendezvousMessage::Bundle {
                sequence,
                nonce,
                ciphertext,
            } => attempt
                .open_host_bundle(
                    &BundleFrame {
                        direction: BundleDirection::HostToClient,
                        sequence,
                        message_type: BundleMessageType::HostBundle,
                        nonce,
                        ciphertext: ciphertext.into_vec(),
                    },
                    clock,
                )
                .map_err(|error| step_failed(&error, tries))?,
            other => return Err(answered_otherwise(&other, tries)),
        };
        let bundle = &host_bundle.bundle;
        if self.hosts.by_device(bundle.device_id)?.is_some()
            || self.hosts.by_endpoint(&bundle.endpoint_id)?.is_some()
        {
            return Err(PairingFailure::new(
                FailureKind::AlreadyPaired,
                "this device is already paired with the host that proved the code",
            ));
        }
        let sealed = attempt
            .seal_client_bundle(
                &self.candidate.keys.authorisation,
                self.candidate.bundle(),
                clock,
            )
            .map_err(|error| step_failed(&error, tries))?;
        room.send(&RendezvousMessage::Bundle {
            sequence: sealed.sequence,
            nonce: sealed.nonce,
            ciphertext: Bytes::new(sealed.ciphertext),
        })
        .await
        .map_err(unfinished)?;
        match room.receive().await.map_err(unfinished)? {
            RendezvousMessage::BundleAccepted => {}
            other => return Err(answered_otherwise(&other, tries)),
        }
        drop(room);

        // The host, at the endpoint its authenticated bundle pinned, which nothing this device does
        // for another host may close while the attempt runs.
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingHost,
        });
        let _held = within(WAIT_STEP, self.link.hold(&bundle.network_config))
            .await
            .map_err(|error| link_failed(&error, tries))?;
        let connection = within(
            WAIT_STEP,
            self.link.dial(&bundle.network_config, &bundle.endpoint_id),
        )
        .await
        .map_err(|error| link_failed(&error, tries))?;
        // The live peer is the connection's own. kr-pairing refuses one that is not the bundle's
        // endpoint before this device offers anything on the connection.
        let request = attempt
            .finish_request(
                &ConnectionPeer::of(&connection),
                &self.candidate.endpoint_id(),
                clock,
            )
            .map_err(|error| step_failed(&error, tries))?;
        let mut preauth = within(
            WAIT_STEP,
            self.link
                .open_unpaired(&connection, &self.candidate.unpaired()),
        )
        .await
        .map_err(|error| link_failed(&error, tries))?;
        let selection = preauth.selection();
        if selection.endpoint_id != bundle.endpoint_id || selection.device_id != bundle.device_id {
            return Err(PairingFailure::new(
                FailureKind::HostMismatch,
                "the host's selection names another endpoint or device than its bundle",
            ));
        }
        let value = attempt
            .verification_value()
            .map_err(|error| step_failed(&error, tries))?;
        let pending = PendingAttempt {
            mode: AttemptMode::Code,
            invitation_id: request.invitation_id,
            host_device_id: bundle.device_id,
            host_key_revision: bundle.device_key_revision,
            host_keys: bundle.keys,
            host_endpoint_id: bundle.endpoint_id,
            network_config: bundle.network_config.clone(),
            proposed_grant: bundle.proposed_grant.clone(),
            verification_value: value.clone(),
            value_confirmed: false,
            expires_at_ms: None,
            recover_until_ms,
            tries_left: tries,
        };
        // Kept before the finish leaves, so a device that restarts while the owner decides can
        // ask again.
        self.hosts.keep_attempt(&pending)?;
        // A host that takes the finish and holds its answer back is asked again, on a connection
        // of its own, like one whose answer was lost.
        let finished = within(self.step(&pending), preauth.finish(&request)).await;
        let pending = match finished {
            Ok(finished) => {
                if !verification_values_match(&value, &finished.verification_value) {
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        FailureKind::HostMismatch,
                        "the host's verification value is not the one this device computed",
                    ));
                }
                self.value_confirmed(pending)?
            }
            Err(LinkError::Refused(refusal)) => {
                let _ = self.hosts.clear_attempt();
                return Err(PairingFailure::new(
                    refused_by_host(refusal.code, false),
                    refusal.message,
                )
                .with_tries(tries));
            }
            // Whether the host bound the finish is unknown; asking is how to find out, on a
            // connection of its own.
            Err(LinkError::Lost(_) | LinkError::Configuration(_)) => {
                drop(preauth);
                drop(connection);
                return self.await_approval(pending, None, progress).await;
            }
        };
        progress.send_replace(awaiting(&pending));
        // One question was asked on the connection: the finish.
        self.await_approval(
            pending,
            Some(Unpaired::new(connection, preauth, 1)),
            progress,
        )
        .await
    }

    /// Records that the host answered with the value this device computed, so a restart shows
    /// it while it asks again.
    pub(crate) fn value_confirmed(
        &self,
        mut pending: PendingAttempt,
    ) -> Result<PendingAttempt, PairingFailure> {
        pending.value_confirmed = true;
        self.hosts.keep_attempt(&pending)?;
        Ok(pending)
    }

    /// Says what a start that did not return an attempt means.
    fn start_failure(
        &self,
        refused: StartRefused,
        origin: &RendezvousOrigin,
        code: &EnteredCode,
    ) -> PairingFailure {
        let tries = self.tries_left(origin, code);
        match refused {
            StartRefused::Pairing { error, room } => match (error, room) {
                (PairingError::ClientAttemptsExhausted, _) => PairingFailure::new(
                    FailureKind::DeviceTriesUsed,
                    "this code has no tries left on this device",
                )
                .with_tries(Some(0)),
                (PairingError::Store { reason }, _) => {
                    PairingFailure::new(FailureKind::StoreFailed, reason)
                }
                (_, Some(ending)) => ending.with_tries(tries),
                (error, None) => PairingFailure::new(FailureKind::DidNotFinish, error.to_string())
                    .with_tries(tries),
            },
            StartRefused::Lost(detail) => {
                PairingFailure::new(FailureKind::DidNotFinish, detail).with_tries(tries)
            }
        }
    }

    /// How many tries this device has left with a code, read from its budget.
    fn tries_left(&self, origin: &RendezvousOrigin, code: &EnteredCode) -> Option<u32> {
        let key = kr_pairing::client::budget_key(&*self.budget, origin, code).ok()?;
        let record = self.budget.load(&key).ok()??;
        Some(MAX_CLIENT_ATTEMPTS.saturating_sub(record.attempts))
    }

    /// Waits for the owner, then connects as what the device became.
    ///
    /// `held` is the unpaired connection the attempt proved itself on, when it still has one. A
    /// connection lost meanwhile is dialled again, unpaired, until the invitation expires: the
    /// host identifies a candidate by its endpoint.
    pub(crate) async fn await_approval(
        &self,
        pending: PendingAttempt,
        held: Option<Unpaired>,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let tries = pending.tries_left;
        self.waiting(pending, held, progress)
            .await
            .map_err(|failure| failure.or_tries(tries))
    }

    async fn waiting(
        &self,
        mut pending: PendingAttempt,
        mut held: Option<Unpaired>,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let params = PairStatusParams {
            invitation_id: pending.invitation_id,
        };
        // The budget every host serves an unpaired connection by, unless it was built otherwise.
        let limits = PreAuthLimits::default();
        let mut reconnects = 0_usize;
        loop {
            // The attempt's own deadline holds on every pass, whatever the host last said: a host
            // that keeps answering that the owner has not decided does not hold the device past
            // it, and neither does one that holds the connection open and answers nothing.
            if self.clock.wall_clock_ms() >= pending.recover_until_ms {
                let _ = self.hosts.clear_attempt();
                return Err(PairingFailure::new(
                    FailureKind::ApprovalUnknown,
                    "the attempt's time ran out before the host said it committed this device or \
                     ended the invitation",
                ));
            }
            // Each question stays inside the host's budget for the connection: it waits for the
            // window to make room. Near the end of a connection's questions the device changes to
            // a fresh one, which is no loss of contact and is not shown as one; a connection that
            // has none left is let go.
            if let Some(unpaired) = held.as_mut() {
                match unpaired.asked.turn(tokio::time::Instant::now(), &limits) {
                    Turn::Now => {}
                    Turn::After(wait) => {
                        tokio::time::sleep(wait.min(self.left(&pending))).await;
                        continue;
                    }
                    Turn::Spent => {
                        drop(held.take());
                        held = self.reconnect(&pending).await;
                        continue;
                    }
                }
            }
            // The old connection keeps its last question until a fresh one has answered: a host
            // that commits the device meanwhile serves it no unpaired surface on a new connection,
            // and the old one is then the only place left to learn what the device became.
            let changed = if held
                .as_ref()
                .is_some_and(|unpaired| unpaired.asked.nearly_spent(&limits))
            {
                self.fresh_answer(&pending, &params).await
            } else {
                None
            };
            let asked = match changed {
                Some((fresh, answer)) => {
                    held = Some(fresh);
                    Ok(answer)
                }
                None => match held.as_mut() {
                    Some(unpaired) => {
                        unpaired.asked.asked(tokio::time::Instant::now());
                        within(self.step(&pending), unpaired.preauth.status(&params)).await
                    }
                    None => Err(LinkError::Lost("no connection".to_owned())),
                },
            };
            match asked {
                Ok(answer) => {
                    reconnects = 0;
                    match self.answered(&mut pending, answer, progress)? {
                        Some((device_id, grant_id)) => {
                            let _ = held.take();
                            return self
                                .committed(&pending, device_id, grant_id, progress)
                                .await;
                        }
                        None => tokio::time::sleep(STATUS_INTERVAL.min(self.left(&pending))).await,
                    }
                }
                // A host whose window is fuller than this device counted says so and keeps the
                // connection: that is no answer about the attempt, so the device waits the window
                // out and asks again. A host that ended the connection with it is found out by the
                // next question, as a connection lost.
                Err(LinkError::Refused(refusal)) if refusal.code == ErrorCode::RateLimited => {
                    tokio::time::sleep(limits.window.min(self.left(&pending))).await;
                }
                Err(LinkError::Refused(refusal)) => {
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        refused_by_host(refusal.code, pending.mode == AttemptMode::Direct),
                        refusal.message,
                    ));
                }
                Err(LinkError::Lost(_) | LinkError::Configuration(_)) => {
                    // The connection is gone; it is let go of before the wait, not after.
                    drop(held.take());
                    progress.send_replace(reconnecting(&pending));
                    let delay = RECONNECT_DELAYS[reconnects.min(RECONNECT_DELAYS.len() - 1)]
                        .min(self.left(&pending));
                    reconnects += 1;
                    tokio::time::sleep(delay).await;
                    if self.left(&pending).is_zero() {
                        continue;
                    }
                    held = self.reconnect(&pending).await;
                    if held.is_some() {
                        progress.send_replace(awaiting(&pending));
                    }
                }
            }
        }
    }

    /// How long `pending` has left, by this device's clock.
    fn left(&self, pending: &PendingAttempt) -> Duration {
        Duration::from_millis(
            pending
                .recover_until_ms
                .saturating_sub(self.clock.wall_clock_ms()),
        )
    }

    /// How long one question to the host of `pending`, or one connection to it, may take: a step,
    /// and never past the attempt's deadline.
    pub(crate) fn step(&self, pending: &PendingAttempt) -> Duration {
        WAIT_STEP.min(self.left(pending))
    }

    /// Reads one status answer. Returns the committed identities once the host committed.
    #[allow(clippy::type_complexity)]
    fn answered(
        &self,
        pending: &mut PendingAttempt,
        answer: PairStatusResult,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<Option<(DeviceId, kr_protocol::ids::GrantId)>, PairingFailure> {
        match answer.status {
            PairStatus::AwaitingApproval {
                verification_value,
                expires_at_ms,
                ..
            } => {
                if !verification_values_match(&pending.verification_value, &verification_value) {
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        FailureKind::HostMismatch,
                        "the host's verification value is not the one this device computed",
                    ));
                }
                let newly_confirmed = !pending.value_confirmed;
                pending.value_confirmed = true;
                self.learned(pending, expires_at_ms.get(), newly_confirmed, progress)?;
                Ok(None)
            }
            // The host holds the invitation for this device and has not bound its value.
            PairStatus::Locked { expires_at_ms, .. } => {
                self.learned(pending, expires_at_ms.get(), false, progress)?;
                Ok(None)
            }
            PairStatus::Committed {
                device_id,
                grant_id,
            } => Ok(Some((device_id, grant_id))),
            PairStatus::Consumed { reason } => {
                let _ = self.hosts.clear_attempt();
                Err(PairingFailure::new(
                    consumed(reason),
                    "the host consumed the invitation",
                ))
            }
            PairStatus::Open { .. } => {
                let _ = self.hosts.clear_attempt();
                Err(PairingFailure::new(
                    FailureKind::DidNotFinish,
                    "the host no longer holds the invitation for this device",
                ))
            }
        }
    }

    /// Records what a status answer taught this device: the invitation's expiry the first time
    /// the host names it, and that the host answered with this device's value.
    fn learned(
        &self,
        pending: &mut PendingAttempt,
        expires_at_ms: u64,
        newly_confirmed: bool,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<(), PairingFailure> {
        let new_expiry = pending.expires_at_ms != Some(expires_at_ms);
        if new_expiry {
            pending.expires_at_ms = Some(expires_at_ms);
            // The host's word, authenticated, can only bring the deadline forward.
            pending.recover_until_ms = pending
                .recover_until_ms
                .min(expires_at_ms.saturating_add(RECOVERY_MARGIN_MS));
        }
        if new_expiry || newly_confirmed {
            self.hosts.keep_attempt(pending)?;
            progress.send_replace(awaiting(pending));
        }
        Ok(())
    }

    /// A fresh unpaired connection to the host of `pending`, and its answer to the first question
    /// asked on it; `None` when no connection opens or it does not answer.
    async fn fresh_answer(
        &self,
        pending: &PendingAttempt,
        params: &PairStatusParams,
    ) -> Option<(Unpaired, PairStatusResult)> {
        let mut fresh = self.reconnect(pending).await?;
        fresh.asked.asked(tokio::time::Instant::now());
        let answer = within(self.step(pending), fresh.preauth.status(params))
            .await
            .ok()?;
        Some((fresh, answer))
    }

    /// Dials the host again, unpaired, and opens its pre-authorisation surface.
    async fn reconnect(&self, pending: &PendingAttempt) -> Option<Unpaired> {
        let connection = within(
            self.step(pending),
            self.link
                .dial(&pending.network_config, &pending.host_endpoint_id),
        )
        .await
        .ok()?;
        if ConnectionPeer::of(&connection).endpoint() != pending.host_endpoint_id {
            return None;
        }
        let preauth = within(
            self.step(pending),
            self.link
                .open_unpaired(&connection, &self.candidate.unpaired()),
        )
        .await
        .ok()?;
        Some(Unpaired::new(connection, preauth, 0))
    }

    /// Records the host that committed this device, and connects to it as what it became.
    async fn committed(
        &self,
        pending: &PendingAttempt,
        device_id: DeviceId,
        grant_id: kr_protocol::ids::GrantId,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        let host = PairedHost {
            host_device_id: pending.host_device_id,
            host_key_revision: pending.host_key_revision,
            host_keys: pending.host_keys,
            host_endpoint_id: pending.host_endpoint_id,
            network_config: pending.network_config.clone(),
            device_id,
            grant_id,
            proposed_grant: pending.proposed_grant.clone(),
            name: None,
            paired_at_ms: self.clock.wall_clock_ms(),
        };
        // The record first: a device that stops between the two keeps both, and resuming then
        // reaches the host through the record rather than as a candidate it no longer is.
        self.hosts.record(host.clone())?;
        self.confirm_committed(host, pending, progress).await
    }

    /// Connects to a host that committed this device, as the device it became, checks that the
    /// host reports it so, and only then lets the waiting attempt go and reports the pairing.
    ///
    /// A host that cannot be reached leaves the attempt waiting, so the next start asks again,
    /// until its time has passed, which is checked before every step; the record of the host stays
    /// either way, because the host committed this device.
    async fn confirm_committed(
        &self,
        mut host: PairedHost,
        pending: &PendingAttempt,
        progress: &watch::Sender<AttemptState>,
    ) -> Result<PairedHost, PairingFailure> {
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingHost,
        });
        let device_id = host.device_id;
        let identity = self.candidate.paired_identity(device_id);
        let params = PairStatusParams {
            invitation_id: pending.invitation_id,
        };
        let mut last = String::new();
        for (index, delay) in RECONNECT_DELAYS
            .iter()
            .take(PAIRED_CONNECT_TRIES)
            .enumerate()
        {
            if index > 0 {
                tokio::time::sleep((*delay).min(self.left(pending))).await;
            }
            // The attempt's own deadline holds here too. Past it the device stops asking, and it
            // keeps its record of the host, which committed it.
            if self.left(pending).is_zero() {
                last = "the attempt's time ran out".to_owned();
                break;
            }
            let session = match within(
                self.step(pending),
                self.link.connect_paired(&host, &identity),
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    last = error.to_string();
                    continue;
                }
            };
            let status: Result<PairStatusResult, LinkError> = within(self.step(pending), async {
                session
                    .read(Method::PairStatus, &params)
                    .await
                    .map_err(|error| LinkError::Lost(error.to_string()))
            })
            .await;
            match status.map(|answer| answer.status) {
                Ok(PairStatus::Committed {
                    device_id: committed,
                    ..
                }) if committed == device_id => {}
                Ok(_) => {
                    session.close();
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        FailureKind::HostMismatch,
                        "the host does not report this device as the one it committed",
                    ));
                }
                Err(error) => {
                    session.close();
                    last = error.to_string();
                    continue;
                }
            }
            let environments: Result<EnvironmentListResult, LinkError> =
                within(self.step(pending), async {
                    session
                        .read(Method::EnvironmentList, &EmptyParams {})
                        .await
                        .map_err(|error| LinkError::Lost(error.to_string()))
                })
                .await;
            session.close();
            if let Some(label) = environments.ok().and_then(|listed| {
                listed
                    .environments
                    .into_iter()
                    .next()
                    .map(|environment| environment.label)
            }) {
                host.name = Some(label);
            }
            self.hosts.record(host.clone())?;
            self.hosts.clear_attempt()?;
            progress.send_replace(AttemptState::Paired {
                host: HostView::of(&host),
            });
            return Ok(host);
        }
        if self.left(pending).is_zero() {
            let _ = self.hosts.clear_attempt();
        }
        Err(PairingFailure::new(
            FailureKind::HostUnreachable,
            format!("the host committed this device, which could not connect as it: {last}"),
        ))
    }
}

/// Waits at most `bound` for one question to a host, or one connection to it. A host that has not
/// answered by then is treated as a connection lost: what it decided is asked again, not assumed.
pub(crate) async fn within<T>(
    bound: Duration,
    step: impl std::future::Future<Output = Result<T, LinkError>>,
) -> Result<T, LinkError> {
    tokio::time::timeout(bound, step).await.unwrap_or_else(|_| {
        Err(LinkError::Lost(
            "the host answered nothing in time".to_owned(),
        ))
    })
}

/// An unpaired connection to the host a device is waiting on, and the questions asked on it.
pub(crate) struct Unpaired {
    /// Held so the connection stays open while its surface is used, and closed with it.
    _connection: Connection,
    preauth: Box<dyn Preauth>,
    asked: Asked,
}

impl Unpaired {
    /// `connection` and its pre-authorisation surface, on which `already` questions were asked
    /// just now: the finish, or a direct invitation's challenge and proof.
    pub(crate) fn new(connection: Connection, preauth: Box<dyn Preauth>, already: usize) -> Self {
        Self {
            _connection: connection,
            preauth,
            asked: Asked::after(already, tokio::time::Instant::now()),
        }
    }
}

/// The questions a device has asked on one unpaired connection, counted as the host counts them.
///
/// A host answers an unpaired connection [`PreAuthLimits::max_requests`] times in all, and
/// [`PreAuthLimits::max_requests_per_window`] times in any [`PreAuthLimits::window`]. Past the
/// second it refuses the question and keeps the connection; past the first it answers once more
/// and ends the connection. So a device that waits spaces its questions to keep the window from
/// filling, and moves to a fresh connection once this one has no questions left.
#[derive(Debug)]
struct Asked {
    /// When each question still inside the window was sent, oldest first.
    recent: VecDeque<tokio::time::Instant>,
    /// Every question asked on the connection.
    total: usize,
}

/// When the next question on a connection may go.
#[derive(Debug, PartialEq, Eq)]
enum Turn {
    /// Now.
    Now,
    /// Once this much time has passed, when an older question leaves the window.
    After(Duration),
    /// Never on this connection: it has no questions left.
    Spent,
}

impl Asked {
    /// A connection on which `already` questions were asked at `now`.
    fn after(already: usize, now: tokio::time::Instant) -> Self {
        Self {
            recent: std::iter::repeat_n(now, already).collect(),
            total: already,
        }
    }

    /// When the next question may go, at `now`, inside `limits`.
    fn turn(&mut self, now: tokio::time::Instant, limits: &PreAuthLimits) -> Turn {
        if self.total >= limits.max_requests {
            return Turn::Spent;
        }
        let window = limits.window + WINDOW_MARGIN;
        while self
            .recent
            .front()
            .is_some_and(|sent| now.saturating_duration_since(*sent) >= window)
        {
            self.recent.pop_front();
        }
        match self.recent.front() {
            Some(oldest) if self.recent.len() >= limits.max_requests_per_window => {
                Turn::After(window.saturating_sub(now.saturating_duration_since(*oldest)))
            }
            _ => Turn::Now,
        }
    }

    /// True when the connection has one question left, or none.
    fn nearly_spent(&self, limits: &PreAuthLimits) -> bool {
        self.total + 1 >= limits.max_requests
    }

    /// Counts one question, sent at `now`.
    fn asked(&mut self, now: tokio::time::Instant) {
        self.total += 1;
        self.recent.push_back(now);
    }
}

/// A method that takes no parameters, as the empty map the protocol expects.
#[derive(Serialize)]
struct EmptyParams {}

/// Shows the waiting state of `pending`: waiting for the owner, with the value, once the host has
/// answered with it, and reaching the host until then.
pub(crate) fn awaiting(pending: &PendingAttempt) -> AttemptState {
    if !pending.value_confirmed {
        return AttemptState::Working {
            stage: Stage::ReachingHost,
        };
    }
    AttemptState::AwaitingApproval {
        value: group_verification_value(&pending.verification_value),
        expires_at_ms: pending.expires_at_ms,
        rights: pending.proposed_grant.actions.iter().copied().collect(),
        authority: super::owner::describe_rights(&pending.proposed_grant.actions),
        grant_expires_at_ms: expiry(&pending.proposed_grant.expiry),
    }
}

/// Shows that the connection to the host of `pending` is being made again. The value stays on
/// screen once the host has answered with it, and is not shown before.
fn reconnecting(pending: &PendingAttempt) -> AttemptState {
    AttemptState::Reconnecting {
        value: pending
            .value_confirmed
            .then(|| group_verification_value(&pending.verification_value)),
        expires_at_ms: pending.expires_at_ms,
    }
}

/// Publishes how an attempt ended, and passes it on.
pub(crate) fn ended(
    progress: &watch::Sender<AttemptState>,
    outcome: Result<PairedHost, PairingFailure>,
    mode: AttemptMode,
    service: Option<String>,
) -> Result<PairedHost, PairingFailure> {
    if let Err(failure) = &outcome {
        progress.send_replace(AttemptState::Ended {
            failure: failure.clone(),
            mode,
            service,
        });
    }
    outcome
}

/// What a message from the host means, when it was not the one expected.
///
/// A refusal names the host's reason. Before the host's tag verifies it travelled through a relay
/// nothing authenticates, which is why the words for it say "the host reports"; afterwards it is
/// the host's own word. Anything else is an attempt that did not finish.
fn answered_otherwise(message: &RendezvousMessage, tries: Option<u32>) -> PairingFailure {
    match message {
        RendezvousMessage::Refused { code, .. } => PairingFailure::new(
            refused_by_host(*code, false),
            format!("the host reported {}", code.as_str()),
        )
        .with_tries(tries),
        _ => PairingFailure::new(
            FailureKind::DidNotFinish,
            "the host sent a message out of order",
        )
        .with_tries(tries),
    }
}

/// What a step kr-pairing refused means.
fn step_failed(error: &PairingError, tries: Option<u32>) -> PairingFailure {
    let kind = match error {
        PairingError::Expired => FailureKind::TimedOut,
        PairingError::EndpointMismatch { .. } => FailureKind::HostMismatch,
        PairingError::AuthenticationFailed
        | PairingError::ContextMismatch { .. }
        | PairingError::ReplayedSequence { .. } => FailureKind::NotAuthenticated,
        _ => FailureKind::DidNotFinish,
    };
    PairingFailure::new(kind, error.to_string()).with_tries(tries)
}

/// What a failure reaching the host means, once its bundle pinned it.
fn link_failed(error: &LinkError, tries: Option<u32>) -> PairingFailure {
    let kind = match error {
        LinkError::Refused(refusal) => refused_by_host(refusal.code, false),
        LinkError::Lost(_) => FailureKind::HostUnreachable,
        LinkError::Configuration(_) => FailureKind::DidNotFinish,
    };
    PairingFailure::new(kind, error.to_string()).with_tries(tries)
}

/// How the room ended an exchange that was under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoomStop {
    /// The room said why, in its last frame.
    Closed(CloseReason),
    /// The socket ended without a last frame.
    Ended,
    /// The attempt's own deadline passed.
    TimedOut,
    /// The room sent something no attempt reads.
    Unreadable,
}

impl RoomStop {
    /// The failure this ending is in the phase that expects `kind`.
    ///
    /// The attempt's own deadline is the one ending that says more than the phase does, until the
    /// host has spoken: before it, nothing the room did is evidence about the invitation.
    fn failure(self, kind: FailureKind, tries: Option<u32>) -> PairingFailure {
        let kind = match (self, kind) {
            (_, FailureKind::NoHostAnswered) => FailureKind::NoHostAnswered,
            (Self::TimedOut, _) => FailureKind::TimedOut,
            (_, kind) => kind,
        };
        PairingFailure::new(kind, format!("the room ended the exchange: {self:?}"))
            .with_tries(tries)
    }
}

/// One attempt's frames through the room.
struct Relay {
    socket: RoomSocket,
    attempt_id: AttemptId,
    deadline: tokio::time::Instant,
}

impl Relay {
    const fn new(
        socket: RoomSocket,
        attempt_id: AttemptId,
        deadline: tokio::time::Instant,
    ) -> Self {
        Self {
            socket,
            attempt_id,
            deadline,
        }
    }

    async fn frame(&self, frame: ClientFrame) -> Result<(), RoomStop> {
        tokio::time::timeout_at(self.deadline, self.socket.outgoing.send(frame))
            .await
            .map_err(|_| RoomStop::TimedOut)?
            .map_err(|_| RoomStop::Ended)
    }

    async fn send(&self, message: &RendezvousMessage) -> Result<(), RoomStop> {
        let payload = encode_message(message).map_err(|_| RoomStop::Unreadable)?;
        self.frame(ClientFrame::Relay {
            attempt_id: self.attempt_id,
            payload,
        })
        .await
    }

    async fn receive(&mut self) -> Result<RendezvousMessage, RoomStop> {
        let frame = tokio::time::timeout_at(self.deadline, self.socket.incoming.recv())
            .await
            .map_err(|_| RoomStop::TimedOut)?
            .ok_or(RoomStop::Ended)?;
        match frame {
            ServiceFrame::Relay {
                attempt_id,
                payload,
            } if attempt_id == self.attempt_id => {
                decode_message(payload.as_slice()).map_err(|_| RoomStop::Unreadable)
            }
            ServiceFrame::Closed { reason } => Err(RoomStop::Closed(reason)),
            _ => Err(RoomStop::Unreadable),
        }
    }
}

/// Why kr-pairing's start returned no attempt.
#[derive(Debug)]
pub(crate) enum StartRefused {
    /// It refused, and when the lookup failed, how the room ended.
    Pairing {
        /// What kr-pairing returned.
        error: PairingError,
        /// How the room ended, when that is what failed.
        room: Option<PairingFailure>,
    },
    /// The blocking thread did not finish.
    Lost(String),
}

/// Runs kr-pairing's start on a blocking thread with a lookup that opens the room.
///
/// `start` is given the lookup; whatever it returns is handed back beside the socket its lookup
/// opened, when it succeeded. The socket belongs to a slot this function owns: only a successful
/// start takes it out, and every other ending drops it, which closes the socket. Dropping this
/// future cancels the lookup's wait, and whatever the blocking thread returns afterwards is
/// discarded with the slot.
pub(crate) async fn start_in_room<T, F>(
    room: Arc<dyn CandidateRoom>,
    start: F,
) -> Result<(T, RoomSocket), StartRefused>
where
    T: Send + 'static,
    F: FnOnce(&dyn RendezvousClient) -> kr_pairing::Result<T> + Send + 'static,
{
    let (_keep_open, cancelled) = oneshot::channel::<()>();
    let slot = Arc::new(Mutex::new(None));
    let ending = Arc::new(Mutex::new(None));
    let lookup = RoomLookup {
        runtime: tokio::runtime::Handle::current(),
        room,
        slot: Arc::clone(&slot),
        ending: Arc::clone(&ending),
        cancelled: Mutex::new(Some(cancelled)),
    };
    let joined = tokio::task::spawn_blocking(move || start(&lookup)).await;
    let socket = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    match joined {
        Ok(Ok(value)) => match socket {
            Some(socket) => Ok((value, socket)),
            None => Err(StartRefused::Lost(
                "the attempt started without opening its room".to_owned(),
            )),
        },
        Ok(Err(error)) => Err(StartRefused::Pairing {
            error,
            room: ending.lock().unwrap_or_else(PoisonError::into_inner).take(),
        }),
        Err(error) => Err(StartRefused::Lost(format!(
            "the attempt's start did not finish: {error}"
        ))),
    }
}

/// The lookup kr-pairing's start is given.
struct RoomLookup {
    runtime: tokio::runtime::Handle,
    room: Arc<dyn CandidateRoom>,
    slot: Arc<Mutex<Option<RoomSocket>>>,
    ending: Arc<Mutex<Option<PairingFailure>>>,
    cancelled: Mutex<Option<oneshot::Receiver<()>>>,
}

impl RendezvousClient for RoomLookup {
    fn lookup(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
    ) -> kr_pairing::Result<LocatorRecord> {
        let cancelled = self
            .cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let outcome = self.runtime.block_on(async {
            let opened = first_record(&*self.room, origin, locator);
            match cancelled {
                Some(cancelled) => tokio::select! {
                    outcome = opened => outcome,
                    _ = cancelled => Err(PairingFailure::new(
                        FailureKind::DidNotFinish,
                        "the attempt was cancelled",
                    )),
                },
                None => opened.await,
            }
        });
        match outcome {
            Ok((record, socket)) => {
                *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(socket);
                Ok(record)
            }
            Err(failure) => {
                let error = if failure.kind == FailureKind::ServiceNotPairing {
                    PairingError::RendezvousConfiguration {
                        reason: failure.detail.clone(),
                    }
                } else {
                    PairingError::RendezvousUnavailable {
                        reason: failure.detail.clone(),
                    }
                };
                *self.ending.lock().unwrap_or_else(PoisonError::into_inner) = Some(failure);
                Err(error)
            }
        }
    }
}

/// Opens the room and waits for its first frame, which for a served locator is the record.
async fn first_record(
    room: &dyn CandidateRoom,
    origin: &RendezvousOrigin,
    locator: &Locator,
) -> Result<(LocatorRecord, RoomSocket), PairingFailure> {
    let mut socket = room
        .open(origin, locator)
        .await
        .map_err(|error| PairingFailure::new(room_failure(&error), error.to_string()))?;
    let no_host = |detail: &str| PairingFailure::new(FailureKind::NoHostAnswered, detail);
    match tokio::time::timeout(RECORD_WAIT, socket.incoming.recv()).await {
        Ok(Some(ServiceFrame::Record {
            invitation_id,
            expires_at_ms,
        })) => Ok((
            LocatorRecord {
                invitation_id,
                advertised_expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
            },
            socket,
        )),
        Ok(Some(ServiceFrame::Closed { reason })) => {
            Err(no_host(&format!("the room closed the socket: {reason:?}")))
        }
        Ok(Some(_)) => Err(no_host("the room sent something before a record")),
        Ok(None) => Err(no_host("the room ended the socket")),
        Err(_) => Err(no_host("the room served no record in time")),
    }
}

/// What a room that did not open means for a candidate.
///
/// An answer that is a page or a redirect where the upgrade should be, a route the origin does not
/// have, or no upgrade at all shows an origin that does not serve the room: the device's
/// configuration to fix. Everything else says only that the service could not serve this socket
/// now.
#[must_use]
pub fn room_failure(error: &RoomError) -> FailureKind {
    match error {
        RoomError::Refused { status, .. }
            if (200..400).contains(status) || matches!(status, 404 | 405) =>
        {
            FailureKind::ServiceNotPairing
        }
        RoomError::Configuration { .. } | RoomError::NotAnUpgrade { .. } => {
            FailureKind::ServiceNotPairing
        }
        RoomError::Refused { .. } | RoomError::Unreachable { .. } => {
            FailureKind::ServiceUnreachable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::InvitationId;
    use kr_protocol::scalars::Uuid;
    use tokio::sync::mpsc;

    /// A room a test holds the far end of.
    struct HeldRoom {
        serve_record: bool,
        opened: Mutex<usize>,
        far: Mutex<Vec<(mpsc::Sender<ServiceFrame>, mpsc::Receiver<ClientFrame>)>>,
    }

    impl HeldRoom {
        fn new(serve_record: bool) -> Arc<Self> {
            Arc::new(Self {
                serve_record,
                opened: Mutex::new(0),
                far: Mutex::new(Vec::new()),
            })
        }

        fn opened(&self) -> usize {
            *self.opened.lock().expect("the count")
        }

        /// Waits until the device's end of the one socket is gone.
        async fn closed_within(&self, bound: Duration) -> bool {
            let far = self.far.lock().expect("the far ends").pop();
            let Some((_to_device, mut from_device)) = far else {
                return false;
            };
            tokio::time::timeout(bound, async { while from_device.recv().await.is_some() {} })
                .await
                .is_ok()
        }
    }

    impl CandidateRoom for HeldRoom {
        fn open<'a>(
            &'a self,
            _origin: &'a RendezvousOrigin,
            _locator: &'a Locator,
        ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
            *self.opened.lock().expect("the count") += 1;
            let (to_device, incoming) = mpsc::channel(8);
            let (outgoing, from_device) = mpsc::channel(8);
            if self.serve_record {
                to_device
                    .try_send(ServiceFrame::Record {
                        invitation_id: InvitationId::new(Uuid::from_bytes([4; 16])),
                        expires_at_ms: 1_764_000_000_000,
                    })
                    .expect("room for the record");
            }
            self.far
                .lock()
                .expect("the far ends")
                .push((to_device, from_device));
            Box::pin(async move { Ok(RoomSocket { outgoing, incoming }) })
        }
    }

    fn origin() -> RendezvousOrigin {
        RendezvousOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn locator() -> Locator {
        Locator::new("aB3x").expect("a locator")
    }

    async fn a_successful_start_hands_the_socket_over_once() {
        let room = HeldRoom::new(true);
        let (record, _socket) = start_in_room(room.clone() as Arc<dyn CandidateRoom>, |lookup| {
            lookup.lookup(&origin(), &locator())
        })
        .await
        .expect("started");
        assert_eq!(
            record.invitation_id,
            InvitationId::new(Uuid::from_bytes([4; 16]))
        );
        assert_eq!(room.opened(), 1);
    }

    async fn cancelling_ends_the_wait_and_closes_the_socket() {
        let room = HeldRoom::new(false);
        let starting = tokio::spawn(start_in_room(
            room.clone() as Arc<dyn CandidateRoom>,
            |lookup| lookup.lookup(&origin(), &locator()),
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while room.opened() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the room was opened");
        starting.abort();
        assert!(
            room.closed_within(Duration::from_secs(1)).await,
            "the socket closed within a second of the cancellation"
        );
    }

    async fn a_start_that_fails_after_its_lookup_closes_the_socket() {
        let room = HeldRoom::new(true);
        let refused = start_in_room(room.clone() as Arc<dyn CandidateRoom>, |lookup| {
            lookup.lookup(&origin(), &locator())?;
            Err::<(), _>(PairingError::Store {
                reason: "the random generator failed".to_owned(),
            })
        })
        .await
        .expect_err("refused after the lookup");
        assert!(matches!(
            refused,
            StartRefused::Pairing {
                error: PairingError::Store { .. },
                room: None
            }
        ));
        assert!(room.closed_within(Duration::from_secs(1)).await);
    }

    async fn a_refused_charge_opens_nothing() {
        let room = HeldRoom::new(true);
        let refused = start_in_room(room.clone() as Arc<dyn CandidateRoom>, |_lookup| {
            Err::<(), _>(PairingError::ClientAttemptsExhausted)
        })
        .await
        .expect_err("refused");
        assert!(matches!(
            refused,
            StartRefused::Pairing {
                error: PairingError::ClientAttemptsExhausted,
                ..
            }
        ));
        assert_eq!(room.opened(), 0, "a refused charge opens no room");
    }

    /// KR-REQ-10.32: the lookup bridge, on a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_lookup_bridge_on_a_multi_threaded_runtime() {
        a_successful_start_hands_the_socket_over_once().await;
        cancelling_ends_the_wait_and_closes_the_socket().await;
        a_start_that_fails_after_its_lookup_closes_the_socket().await;
        a_refused_charge_opens_nothing().await;
    }

    /// KR-REQ-10.32: the lookup bridge, on a current-thread runtime, where the awaiting thread is
    /// the one that drives the room's I/O while the blocking thread waits.
    #[tokio::test(flavor = "current_thread")]
    async fn the_lookup_bridge_on_a_current_thread_runtime() {
        a_successful_start_hands_the_socket_over_once().await;
        cancelling_ends_the_wait_and_closes_the_socket().await;
        a_start_that_fails_after_its_lookup_closes_the_socket().await;
        a_refused_charge_opens_nothing().await;
    }

    /// KR-REQ-10.19: a room that did not open is the service being unreachable, except where the
    /// answer shows the origin serves no room.
    #[test]
    fn a_room_that_did_not_open_says_what_it_shows_about_the_origin() {
        let refused = |status| RoomError::Refused {
            origin: "https://reach.kala.to".to_owned(),
            status,
        };
        for status in [200, 204, 301, 302, 404, 405] {
            assert_eq!(
                room_failure(&refused(status)),
                FailureKind::ServiceNotPairing,
                "{status}"
            );
        }
        for status in [400, 403, 408, 429, 500, 502, 503] {
            assert_eq!(
                room_failure(&refused(status)),
                FailureKind::ServiceUnreachable,
                "{status}"
            );
        }
    }

    /// KR-REQ-10.23: a waiting device's questions keep inside the budget a host serves an unpaired
    /// connection by. After the questions that proved it, it asks while the window has room,
    /// waits for the oldest question to age out of the window, with a margin, once the window is
    /// full, and calls the connection spent once every question the host answers has been asked,
    /// so the next goes on a fresh one. A device that asked on the old rate, once a second, would
    /// have filled the window with its third status question.
    #[test]
    fn a_waiting_device_asks_inside_the_hosts_budget() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let window = limits.window + WINDOW_MARGIN;

        // A direct invitation's challenge and proof, then two status questions a second apart.
        let mut asked = Asked::after(2, start);
        assert_eq!(asked.turn(start, &limits), Turn::Now);
        asked.asked(start);
        assert_eq!(asked.turn(at(1), &limits), Turn::Now);
        asked.asked(at(1));
        // The window is full: the third waits until the challenge and proof have aged out.
        assert_eq!(
            asked.turn(at(2), &limits),
            Turn::After(window - Duration::from_secs(2))
        );
        assert_eq!(asked.turn(start + window, &limits), Turn::Now);

        // Every question the host answers on one connection, then none. The device changes
        // connection while one is left.
        let mut asked = Asked::after(1, start);
        let mut now = start;
        while asked.total < limits.max_requests {
            assert_eq!(
                asked.nearly_spent(&limits),
                asked.total + 1 == limits.max_requests,
                "{}",
                asked.total
            );
            match asked.turn(now, &limits) {
                Turn::Now => asked.asked(now),
                Turn::After(wait) => now += wait,
                Turn::Spent => panic!("spent after {} questions", asked.total),
            }
            now += STATUS_INTERVAL;
        }
        assert_eq!(asked.turn(now, &limits), Turn::Spent);

        // At the steady rate the window never fills.
        let mut asked = Asked::after(0, start);
        let mut now = start;
        for _ in 0..limits.max_requests {
            assert_eq!(asked.turn(now, &limits), Turn::Now, "{:?}", now - start);
            asked.asked(now);
            now += STATUS_INTERVAL;
        }
    }
}
