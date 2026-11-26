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
use kr_protocol::ids::{AttemptId, BuildId, DeviceId, DeviceKeyRevision, InvitationId};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, ClientBundle, DeviceName, DevicePlatform,
    INVITATION_LIFETIME_MS, Locator, MAX_CLIENT_ATTEMPTS, NetworkConfig, PairStatus,
    RendezvousOrigin, group_verification_value,
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
use super::checkpoint::{
    Answer, Outcome, PairingId, ReadCause, Settled, Unsettled, read_checkpoint,
};
use super::failure::{FailureKind, PairingFailure, consumed, refused_by_host};
use super::invitation::origin_host;
use super::link::{ConnectionPeer, HostLink, LinkError, Preauth};
use super::paired::{AttemptMode, PairedHost, PairedHosts, PendingAttempt};
use super::room::{RoomConnector, RoomError, RoomRole, RoomSocket};
use crate::session::Session;
use crate::shown::{Said, Shown};

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

/// How many questions a connection has left when a waiting device starts to look for a fresh
/// one: enough that several fresh connections can be tried before its last question is needed.
const CHANGE_WITH_LEFT: usize = 4;

/// How long a host serves an unpaired connection before it ends it, whatever was asked on it,
/// counted from when the host answered the connection's handshake.
const UNPAIRED_LIFE: Duration = kr_transport::listener::DEFAULT_HANDSHAKE_DEADLINE;

/// How long before a connection ends, or before the attempt's deadline, a waiting device asks its
/// last question there: time for the question to arrive and for its answer to come back.
const LAST_CALL_MARGIN: Duration = Duration::from_secs(10);

/// How late for a connection's last call a waiting device may still ask its last question there,
/// because the timer that wakes it for the call may fire a little late. Any later, and the device
/// lets the connection go rather than send a question the host may no longer be there to answer.
const LAST_CALL_GRACE: Duration = Duration::from_secs(1);

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

/// How long the read of a host's backup checkpoint may take as the device is committed. It is
/// shorter than [`WAIT_STEP`]: the last screen of a pairing is not held for a host that answers
/// nothing, and that host stays owed, unless an earlier answer of that pairing is on file.
pub const CHECKPOINT_WITHIN: Duration = Duration::from_secs(3);

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
    /// Its platform. Never its keys, and never its name or its build, which are whatever it was
    /// given.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Candidate")
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
    /// random one the host does not use: the host commits the device under the identity derived
    /// for it ([`Self::derived_identity`]).
    #[must_use]
    pub fn unpaired(&self) -> LocalIdentity {
        self.paired_identity(DeviceId::new(kr_ipc::new_uuid()), DeviceKeyRevision::new(1))
    }

    /// The identity the host commits this device under for `invitation_id`, derived from the
    /// invitation and this device's authorisation key, at the first revision of its keys. A device
    /// that was committed while it was not listening connects as this identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error only when the derivation's input breaks the encoding's profile.
    pub fn derived_identity(
        &self,
        invitation_id: InvitationId,
    ) -> Result<LocalIdentity, PairingError> {
        let device_id = kr_pairing::identity::committed_device_id(
            invitation_id,
            self.keys.authorisation.public(),
        )?;
        Ok(self.paired_identity(device_id, DeviceKeyRevision::new(1)))
    }

    /// The identity this device connects to a host with, as the device `device_id` it became, at the
    /// revision of its keys the host holds. A host refuses a device that offers another.
    #[must_use]
    pub fn paired_identity(
        &self,
        device_id: DeviceId,
        revision: DeviceKeyRevision,
    ) -> LocalIdentity {
        LocalIdentity::new(
            device_id,
            revision,
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
#[derive(Clone, PartialEq, Eq, Serialize)]
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
            authority: super::owner::describe_rights(
                &host.proposed_grant.actions,
                &host.proposed_grant.session_selector,
            ),
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
#[derive(Clone, PartialEq, Eq, Serialize)]
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

impl std::fmt::Debug for AttemptState {
    /// Which stage the attempt is at and when it expires. Never the verification value, a host's
    /// name or what the host said of its authority or its service.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => formatter.write_str("Idle"),
            Self::Working { stage } => formatter
                .debug_struct("Working")
                .field("stage", stage)
                .finish(),
            Self::AwaitingApproval {
                expires_at_ms,
                rights,
                grant_expires_at_ms,
                ..
            } => formatter
                .debug_struct("AwaitingApproval")
                .field("expires_at_ms", expires_at_ms)
                .field("rights", rights)
                .field("grant_expires_at_ms", grant_expires_at_ms)
                .finish_non_exhaustive(),
            Self::Reconnecting { expires_at_ms, .. } => formatter
                .debug_struct("Reconnecting")
                .field("expires_at_ms", expires_at_ms)
                .finish_non_exhaustive(),
            Self::Paired { .. } => formatter.debug_struct("Paired").finish_non_exhaustive(),
            Self::Ended { failure, mode, .. } => formatter
                .debug_struct("Ended")
                .field("failure", failure)
                .field("mode", mode)
                .finish_non_exhaustive(),
        }
    }
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
    /// The identity this device connects to `host` with: the revision of its keys is the one the
    /// records hold now, read at each connection and not taken from the copy of the host record a
    /// caller kept, since a copy made before the host took a higher revision would offer the old
    /// one and be refused. When the records no longer hold the pairing, the copy's is used.
    #[must_use]
    pub fn paired_identity_for(&self, host: &PairedHost) -> LocalIdentity {
        let revision = self
            .hosts
            .by_device(host.host_device_id)
            .ok()
            .flatten()
            .filter(|held| held.device_id == host.device_id)
            .map_or(host.device_key_revision, |held| held.device_key_revision);
        self.candidate.paired_identity(host.device_id, revision)
    }

    /// What a first dial that was lost means when the managed service's answer held it back, and
    /// none otherwise: no free capacity to admit this device through the relay the dial addresses,
    /// with what the service named, or a fault of the service.
    ///
    /// Only a dial that was lost is asked, and only about the dial itself: a failure after it, on
    /// the connection, is never a reason to blame the service. The route's own deadline ending a dial
    /// counts as lost, which is the usual way a relay that drops what an unadmitted device sends
    /// ends one.
    pub(super) fn relay_failure(
        &self,
        error: &LinkError,
        network: &NetworkConfig,
        host: &EndpointKey,
    ) -> Option<PairingFailure> {
        if !matches!(error, LinkError::Lost(_)) {
            return None;
        }
        self.link
            .relay_refusal(network, host)
            .map(PairingFailure::of_relay)
    }

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
                .confirm_committed(Known::Told(Box::new(host)), &pending, progress, None)
                .await
                .and_then(Confirmed::into_paired)
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

        // The host, through the services its authenticated bundle pinned.
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingHost,
        });
        let connection = within(
            WAIT_STEP,
            self.link.dial(&bundle.network_config, &bundle.endpoint_id),
        )
        .await
        .map_err(|error| {
            let failure =
                match self.relay_failure(&error, &bundle.network_config, &bundle.endpoint_id) {
                    Some(failure) => failure.with_tries(tries),
                    None => link_failed(&error, tries),
                };
            failure.with_invitation_spent()
        })?;
        // The live peer is the connection's own. kr-pairing refuses one that is not the bundle's
        // endpoint before this device offers anything on the connection.
        let request = attempt
            .finish_request(
                &ConnectionPeer::of(&connection),
                &self.candidate.endpoint_id(),
                clock,
            )
            .map_err(|error| step_failed(&error, tries))?;
        // The host counts the connection's time from when it answers the handshake, which is
        // after the device's offer arrives: a time read before the offer goes is never later.
        let opened = tokio::time::Instant::now();
        let mut preauth = within(
            WAIT_STEP,
            self.link
                .open_unpaired(&connection, &self.candidate.unpaired()),
        )
        .await
        .map_err(|error| link_failed(&error, tries).with_invitation_spent())?;
        let selection = preauth.selection();
        // The transport has refused a selection that names another endpoint than the one that
        // answered, and kr-pairing refused a connection that is not the bundle's endpoint above.
        if selection.device_id != bundle.device_id {
            return Err(PairingFailure::new(
                FailureKind::HostMismatch,
                "the host's selection names another device than its bundle",
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
                    Shown::protocol(&refusal),
                )
                .with_tries(tries));
            }
            // Whether the host bound the finish is unknown; asking is how to find out, on a
            // connection of its own.
            Err(
                LinkError::Lost(_)
                | LinkError::Configuration(_)
                | LinkError::Membership(..)
                | LinkError::ConnectionRefused(_)
                | LinkError::Declined(_)
                | LinkError::Selection(_),
            ) => {
                drop(preauth);
                drop(connection);
                return self.await_approval(pending, None, progress).await;
            }
        };
        progress.send_replace(awaiting(&pending));
        // One question was asked on the connection: the finish.
        self.await_approval(
            pending,
            Some(Unpaired::new(connection, preauth, opened, 1)),
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
                (error @ PairingError::Store { .. }, _) => {
                    PairingFailure::new(FailureKind::StoreFailed, Shown::pairing(&error))
                }
                (_, Some(ending)) => ending.with_tries(tries),
                (error, None) => {
                    PairingFailure::new(FailureKind::DidNotFinish, Shown::pairing(&error))
                        .with_tries(tries)
                }
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
        let mut refused = 0_u32;
        // How many recoveries in a row reached no connection as the device it was committed as.
        let mut lost_recoveries = 0_usize;
        let mut fresh_failed = 0_usize;
        // Whether a look for a fresh connection has just failed.
        let mut looked = false;
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
            // Each question stays inside the host's budget for the connection, and goes no later
            // than the connection's last call; `plan` says what comes next. Near the end of a
            // connection the device changes to a fresh one, which is no loss of contact and is not
            // shown as one; a connection that has no question left is let go.
            //
            // A host that commits the device tells only the connection that carried its proof what
            // it became, so the connection the device already has is then the only place to learn
            // it without the recovery. So the device changes to a fresh connection only once it has answered, and
            // keeps the last question on the old one while fresh connections fail, for the
            // connection's last call. Every step before the cutoff ends by the cutoff, the wait for
            // an answer and the rest after it included, so the device is free to ask that question
            // on time.
            let looked_just_now = std::mem::take(&mut looked);
            let next = match held.as_mut() {
                Some(unpaired) => {
                    let now = tokio::time::Instant::now();
                    plan(
                        &mut unpaired.asked,
                        now,
                        self.attempt_call(&pending, now),
                        &limits,
                        looked_just_now,
                    )
                }
                // No connection: the question below finds that out, as a lost connection.
                None => Next::Ask,
            };
            let mut answered = None;
            match next {
                Next::Ask => {}
                Next::Wait(wait) => {
                    tokio::time::sleep(wait.min(self.left(&pending))).await;
                    continue;
                }
                Next::Keep => {
                    // The pause grows with each look that failed in a row while the question is
                    // kept, as a reconnection's does.
                    let pause = RECONNECT_DELAYS[fresh_failed.min(RECONNECT_DELAYS.len() - 1)];
                    fresh_failed += 1;
                    let until = self.until_cutoff(&pending, held.as_ref());
                    tokio::time::sleep(pause.min(until)).await;
                    continue;
                }
                Next::LetGo => {
                    drop(held.take());
                    fresh_failed = 0;
                    held = self.reconnect(&pending).await;
                    continue;
                }
                Next::Look { within: bound } => {
                    match within(bound, self.fresh_answer(&pending, &params)).await {
                        Ok((fresh, answer)) => {
                            held = Some(fresh);
                            fresh_failed = 0;
                            answered = Some(Ok(answer));
                        }
                        // The host's own word on a fresh connection is its word about the attempt.
                        Err(LinkError::Refused(refusal)) => {
                            fresh_failed = 0;
                            answered = Some(Err(LinkError::Refused(refusal)));
                        }
                        // The look took time, so the next step is planned from when it ended.
                        Err(
                            LinkError::Lost(_)
                            | LinkError::Configuration(_)
                            | LinkError::Membership(..)
                            | LinkError::ConnectionRefused(_)
                            | LinkError::Declined(_)
                            | LinkError::Selection(_),
                        ) => {
                            looked = true;
                            continue;
                        }
                    }
                }
            }
            let asked = match answered {
                Some(answered) => answered,
                None => match held.as_mut() {
                    Some(unpaired) => {
                        let now = tokio::time::Instant::now();
                        unpaired.asked.asked(now, self.attempt_call(&pending, now));
                        within(self.step(&pending), unpaired.preauth.status(&params)).await
                    }
                    None => Err(LinkError::lost(Shown::said("no connection"))),
                },
            };
            match asked {
                Ok(answer) => {
                    reconnects = 0;
                    refused = 0;
                    lost_recoveries = 0;
                    match self.answered(&mut pending, answer, progress)? {
                        Some((device_id, grant_id)) => {
                            let _ = held.take();
                            return self
                                .committed(&pending, device_id, grant_id, progress)
                                .await;
                        }
                        // The device asks again at its pace, and `plan` says when.
                        None => rest(held.as_mut(), STATUS_INTERVAL),
                    }
                }
                // A host whose window is fuller than this device counted says so and keeps the
                // connection: that is no answer about the attempt, so the device rests and asks
                // again. The host counts the questions it refuses too, and its window may be longer
                // than the one this device paces by, so each refusal in a row doubles the rest. A
                // host that ended the connection with it is found out by the next question, as a
                // connection lost.
                Err(LinkError::Refused(refusal)) if refusal.code == ErrorCode::RateLimited => {
                    rest(held.as_mut(), pause_after_refusals(refused, &limits));
                    refused += 1;
                }
                // A host that refuses the question this way may have committed the device on a
                // connection this one is not, and the commitment is then the device's to learn: it
                // connects as the device it was committed as and asks the host, which answers only
                // a device that proves the key it was committed under. The connection it holds is
                // kept, so its reserved question is still asked when the recovery reaches no host.
                Err(LinkError::Refused(refusal)) if refusal.code == ErrorCode::PermissionDenied => {
                    let reserve = self.reserve(&pending, held.as_ref());
                    match self
                        .confirm_committed(Known::Derived, &pending, progress, reserve)
                        .await?
                    {
                        Confirmed::Paired(host) => return Ok(*host),
                        Confirmed::NotReached => {
                            lost_recoveries += 1;
                            progress.send_replace(awaiting(&pending));
                            rest(held.as_mut(), recovery_rest(lost_recoveries));
                        }
                    }
                }
                Err(LinkError::Refused(refusal)) => {
                    let _ = self.hosts.clear_attempt();
                    return Err(PairingFailure::new(
                        refused_by_host(refusal.code, pending.mode == AttemptMode::Direct),
                        Shown::protocol(&refusal),
                    ));
                }
                Err(
                    LinkError::Lost(_)
                    | LinkError::Configuration(_)
                    | LinkError::Membership(..)
                    | LinkError::ConnectionRefused(_)
                    | LinkError::Declined(_)
                    | LinkError::Selection(_),
                ) => {
                    // The connection is gone; it is let go of before the wait, not after.
                    drop(held.take());
                    fresh_failed = 0;
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

    /// The attempt's last call, [`LAST_CALL_MARGIN`] before its deadline, as a moment on the
    /// clock `now` was read from. The deadline is a fixed time on the device's clock, so every
    /// reading names the same moment; once it has passed, the call is `now` itself.
    fn attempt_call(
        &self,
        pending: &PendingAttempt,
        now: tokio::time::Instant,
    ) -> tokio::time::Instant {
        now + self.left(pending).saturating_sub(LAST_CALL_MARGIN)
    }

    /// The cutoff of the question `held` keeps for it, as a moment, while that question has not
    /// gone: a recovery that starts while it is unasked ends by then and leaves the question to
    /// be asked. Nothing when no connection is held or its kept question has gone.
    fn reserve(
        &self,
        pending: &PendingAttempt,
        held: Option<&Unpaired>,
    ) -> Option<tokio::time::Instant> {
        let held = held.filter(|held| !held.asked.kept)?;
        let now = tokio::time::Instant::now();
        Some(cutoff(&held.asked, self.attempt_call(pending, now)))
    }

    /// How long until the cutoff on `held`, read once from both clocks; nothing once it has come,
    /// or when there is no connection.
    fn until_cutoff(&self, pending: &PendingAttempt, held: Option<&Unpaired>) -> Duration {
        let now = tokio::time::Instant::now();
        held.map_or(Duration::ZERO, |held| {
            cutoff(&held.asked, self.attempt_call(pending, now)).saturating_duration_since(now)
        })
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
    /// asked on it, or why there is none: a connection that does not open or does not answer is
    /// lost, and a refusal is the host's own word.
    async fn fresh_answer(
        &self,
        pending: &PendingAttempt,
        params: &PairStatusParams,
    ) -> Result<(Unpaired, PairStatusResult), LinkError> {
        let mut fresh = self
            .reconnect(pending)
            .await
            .ok_or_else(|| LinkError::lost(Shown::said("no fresh connection opened")))?;
        let now = tokio::time::Instant::now();
        fresh.asked.asked(now, self.attempt_call(pending, now));
        let answer = within(self.step(pending), fresh.preauth.status(params)).await?;
        Ok((fresh, answer))
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
        let opened = tokio::time::Instant::now();
        let preauth = within(
            self.step(pending),
            self.link
                .open_unpaired(&connection, &self.candidate.unpaired()),
        )
        .await
        .ok()?;
        Some(Unpaired::new(connection, preauth, opened, 0))
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
            device_key_revision: DeviceKeyRevision::new(1),
        };
        // The record first: a device that stops between the two keeps both, and resuming then
        // reaches the host through the record rather than as a candidate it no longer is.
        self.hosts.record(host.clone())?;
        self.confirm_committed(Known::Told(Box::new(host)), pending, progress, None)
            .await
            .and_then(Confirmed::into_paired)
    }

    /// Connects to a host that committed this device, as the device it became, checks that the
    /// host reports it so, and only then lets the waiting attempt go and reports the pairing.
    ///
    /// `Told` is a commitment the host named, whose record is written. `Derived` is one the device
    /// learns only by proving it: the identity is the one derived for it, the record is written
    /// after the host answers on the connection that proved it, and a refusal that is the host's
    /// word about the connect ends the attempt. A host that cannot be reached leaves a `Told`
    /// attempt waiting, so the next start asks again, until its time has passed, which is checked
    /// before every step; the record of the host stays either way, because the host committed this
    /// device. A `Derived` recovery that reaches no host returns [`Confirmed::NotReached`], and
    /// the attempt goes on waiting.
    ///
    /// A recovery that must leave the question a held connection keeps for its cutoff to be asked
    /// is given that cutoff as `reserve`: every wait of this routine ends by it, and a recovery
    /// that is due to end already starts no connection.
    async fn confirm_committed(
        &self,
        known: Known,
        pending: &PendingAttempt,
        progress: &watch::Sender<AttemptState>,
        reserve: Option<tokio::time::Instant>,
    ) -> Result<Confirmed, PairingFailure> {
        progress.send_replace(AttemptState::Working {
            stage: Stage::ReachingHost,
        });
        let (credentials, identity) = match &known {
            Known::Told(host) => (
                host.credentials(),
                self.candidate
                    .paired_identity(host.device_id, host.device_key_revision),
            ),
            Known::Derived => match self.candidate.derived_identity(pending.invitation_id) {
                Ok(identity) => (pending.credentials(), identity),
                Err(_) => {
                    return Err(self.unknown(crate::shown!(
                        "this device could not work out the identity it is committed under"
                    )));
                }
            },
        };
        let device_id = identity.device_id;
        let params = PairStatusParams {
            invitation_id: pending.invitation_id,
        };
        let mut last = Shown::said("no connection was tried");
        for (index, delay) in RECONNECT_DELAYS
            .iter()
            .take(PAIRED_CONNECT_TRIES)
            .enumerate()
        {
            if index > 0 {
                let rest = (*delay).min(self.left(pending));
                tokio::time::sleep(until_reserve(rest, reserve)).await;
            }
            // The attempt's own deadline holds here too. Past it the device stops asking, and a
            // `Told` device keeps its record of the host, which committed it.
            if self.left(pending).is_zero() {
                last = Shown::said("the attempt's time ran out");
                break;
            }
            let Some(step) = self.recovery_step(pending, reserve) else {
                break;
            };
            let session =
                match within(step, self.link.connect_paired(&credentials, &identity)).await {
                    Ok(session) => session,
                    // The host's word about the connect, which asking again does not change.
                    Err(LinkError::Refused(refusal))
                        if !refusal.code.retry_category().permits_automatic_retry() =>
                    {
                        return Err(self.unknown(Shown::protocol(&refusal)));
                    }
                    Err(error) => {
                        last = error.said();
                        continue;
                    }
                };
            let Some(step) = self.recovery_step(pending, reserve) else {
                session.close();
                break;
            };
            // Whatever goes wrong with this question, the host's refusals too, is asked again on
            // a new connection: no refusal of it says anything about the commitment.
            let status: Result<PairStatusResult, LinkError> = within(step, async {
                session
                    .read(Method::PairStatus, &params)
                    .await
                    .map_err(|error| LinkError::lost(error.said()))
            })
            .await;
            let grant_id = match status.map(|answer| answer.status) {
                Ok(PairStatus::Committed {
                    device_id: committed,
                    grant_id,
                }) if committed == device_id => grant_id,
                Ok(other) => {
                    session.close();
                    return Err(match known {
                        Known::Told(_) => {
                            let _ = self.hosts.clear_attempt();
                            PairingFailure::new(
                                FailureKind::HostMismatch,
                                "the host does not report this device as the one it committed",
                            )
                        }
                        Known::Derived => self.unknown(match other {
                            PairStatus::Committed { .. } => {
                                crate::shown!(
                                    "the host reported another device as the one it committed"
                                )
                            }
                            _ => crate::shown!("the host did not report this device as committed"),
                        }),
                    });
                }
                Err(error) => {
                    session.close();
                    last = error.said();
                    continue;
                }
            };
            let mut host = match known {
                Known::Told(host) => *host,
                Known::Derived => {
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
                        device_key_revision: DeviceKeyRevision::new(1),
                    };
                    self.hosts.record(host.clone())?;
                    host
                }
            };
            let environments: Result<EnvironmentListResult, LinkError> =
                match self.recovery_step(pending, reserve) {
                    Some(step) => {
                        within(step, async {
                            session
                                .read(Method::EnvironmentList, &EmptyParams {})
                                .await
                                .map_err(|error| LinkError::lost(error.said()))
                        })
                        .await
                    }
                    None => Err(LinkError::lost(Shown::said("the recovery's time ran out"))),
                };
            let answer = if host.is_owner() {
                self.read_answer(&session, pending, reserve).await
            } else {
                None
            };
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
            if let Some(answer) = answer {
                self.settle_answer(&host, answer).await;
            }
            self.hosts.clear_attempt()?;
            progress.send_replace(AttemptState::Paired {
                host: HostView::of(&host),
            });
            return Ok(Confirmed::Paired(Box::new(host)));
        }
        match known {
            // The attempt is over only when its time is: the next wait asks again.
            Known::Derived => Ok(Confirmed::NotReached),
            Known::Told(_) => {
                if self.left(pending).is_zero() {
                    let _ = self.hosts.clear_attempt();
                }
                Err(PairingFailure::new(
                    FailureKind::HostUnreachable,
                    crate::shown!(
                        "the host committed this device, which could not connect as it: {}",
                        last
                    ),
                ))
            }
        }
    }

    /// Asks the host of an owner device for its backup checkpoint on `session`, once, for no longer
    /// than [`CHECKPOINT_WITHIN`] and no longer than the recovery has. A host that cannot answer
    /// leaves the device owed, unless an earlier answer of this pairing is on file: the failure is
    /// logged and does not fail the pairing.
    async fn read_answer(
        &self,
        session: &Session,
        pending: &PendingAttempt,
        reserve: Option<tokio::time::Instant>,
    ) -> Option<Answer> {
        let step = self.recovery_step(pending, reserve)?;
        let read = tokio::time::timeout(step.min(CHECKPOINT_WITHIN), read_checkpoint(session))
            .await
            .unwrap_or(Err(ReadCause::TimedOut));
        match read {
            Ok(answer) => Some(answer),
            Err(cause) => {
                tracing::warn!(cause = ?cause, "the host's backup checkpoint could not be read");
                None
            }
        }
    }

    /// Keeps what the host answered for the pairing `host` holds, on a blocking thread, since the
    /// file's lock can take two seconds. A failure is logged and never fails the pairing: the host
    /// stays owed, unless an earlier answer of this pairing is on file.
    async fn settle_answer(&self, host: &PairedHost, answer: Answer) {
        let names_checkpoint = matches!(answer, Answer::Checkpoint(_));
        let checkpoints = self.hosts.checkpoints();
        let id = PairingId::of(host);
        let now_ms = self.clock.wall_clock_ms();
        let settled =
            tokio::task::spawn_blocking(move || checkpoints.settle_checkpoint(id, &answer, now_ms))
                .await;
        match settled {
            Ok(Ok(Settled { outcome, confirmed })) => match outcome {
                Outcome::Lower => tracing::warn!(
                    "a host named a lower backup generation than this device holds, and the held checkpoint stands"
                ),
                Outcome::Disagrees => tracing::warn!(
                    "a host named another manifest than this device holds for the same backup generation, and the held checkpoint stands"
                ),
                Outcome::NothingPublished if !confirmed => tracing::warn!(
                    "the host's answer that it has no backup checkpoint was saved, and the directory could not be confirmed to hold it"
                ),
                Outcome::New | Outcome::Raised | Outcome::Same if !confirmed => tracing::warn!(
                    "the host's answer was saved, and the directory could not be confirmed to hold it"
                ),
                Outcome::New | Outcome::Raised | Outcome::Same | Outcome::NothingPublished => {}
            },
            Ok(Err(Unsettled::Superseded)) if names_checkpoint => tracing::warn!(
                "the host's backup checkpoint came for a pairing that is no longer the host's current one, and a newer checkpoint can have been saved"
            ),
            Ok(Err(Unsettled::Superseded)) => tracing::warn!(
                "the host's answer that it has no backup checkpoint came for a pairing that is no longer the host's current one, and it was not saved"
            ),
            Ok(Err(cause)) => tracing::warn!(
                cause = ?cause,
                "the host's answer could not be saved, and the pairing stands"
            ),
            Err(_) => {
                tracing::warn!("the host's answer could not be saved, and the pairing stands")
            }
        }
    }

    /// How long one step of a recovery may take: a step of the attempt, ended by `reserve` when
    /// there is one. `None` once the reserve has come.
    fn recovery_step(
        &self,
        pending: &PendingAttempt,
        reserve: Option<tokio::time::Instant>,
    ) -> Option<Duration> {
        let step = self.step(pending);
        match reserve {
            None => Some(step),
            Some(by) => {
                let until = by.saturating_duration_since(tokio::time::Instant::now());
                (!until.is_zero()).then(|| step.min(until))
            }
        }
    }

    /// Ends the attempt as one whose outcome the device cannot know, having cleared it.
    fn unknown(&self, why: Shown) -> PairingFailure {
        let _ = self.hosts.clear_attempt();
        PairingFailure::new(FailureKind::ApprovalUnknown, why)
    }
}

/// What a device knows of the commitment it confirms.
enum Known {
    /// The host named the device and its grant on the connection that proved the candidate, or the
    /// record was read at a restart. The record is written.
    Told(Box<PairedHost>),
    /// Only the identity the device derived for itself is known.
    Derived,
}

/// How a confirmation of a commitment ended, short of failing.
enum Confirmed {
    /// The host reported the commitment as it should and the pairing is complete.
    Paired(Box<PairedHost>),
    /// No connection as the device it was committed as reached the host, or the time reserved for
    /// a question ran out: the attempt goes on waiting.
    NotReached,
}

impl Confirmed {
    /// The pairing, for a caller whose commitment is already told: such a confirmation ends the
    /// attempt itself, so nothing is left waiting here.
    fn into_paired(self) -> Result<PairedHost, PairingFailure> {
        match self {
            Self::Paired(host) => Ok(*host),
            Self::NotReached => Err(PairingFailure::new(
                FailureKind::HostUnreachable,
                "the host committed this device, but this device could not connect under that identity",
            )),
        }
    }
}

/// `wait`, ended by `reserve` when there is one.
fn until_reserve(wait: Duration, reserve: Option<tokio::time::Instant>) -> Duration {
    reserve.map_or(wait, |by| {
        wait.min(by.saturating_duration_since(tokio::time::Instant::now()))
    })
}

/// How long a waiting device rests after `lost` recoveries in a row reached no connection as the
/// device it was committed as: no less than its pace, and longer with each loss, so that a host
/// that answers nothing is asked at most once in the last of the reconnection delays.
fn recovery_rest(lost: usize) -> Duration {
    STATUS_INTERVAL.max(RECONNECT_DELAYS[lost.min(RECONNECT_DELAYS.len() - 1)])
}

/// Waits at most `bound` for one question to a host, or one connection to it. A host that has not
/// answered by then is treated as a connection lost: what it decided is asked again, not assumed.
pub(crate) async fn within<T>(
    bound: Duration,
    step: impl std::future::Future<Output = Result<T, LinkError>>,
) -> Result<T, LinkError> {
    tokio::time::timeout(bound, step).await.unwrap_or_else(|_| {
        Err(LinkError::lost(Shown::said(
            "the host answered nothing in time",
        )))
    })
}

/// Rests the device for `pause` from now before its next question on `held`, when it holds a
/// connection. The waiting loop does not sleep for it: `plan` turns the rest into a wait, and never
/// one past the connection's cutoff while the question kept for it is still to go.
fn rest(held: Option<&mut Unpaired>, pause: Duration) {
    if let Some(unpaired) = held {
        unpaired
            .asked
            .rest_until(tokio::time::Instant::now() + pause);
    }
}

/// An unpaired connection to the host a device is waiting on, and the questions asked on it.
pub(crate) struct Unpaired {
    /// Held so the connection stays open while its surface is used, and closed with it. A
    /// scripted surface in a test of the waiting rule has no connection under it.
    _connection: Option<Connection>,
    preauth: Box<dyn Preauth>,
    asked: Asked,
}

impl Unpaired {
    /// `connection` and its pre-authorisation surface, which the device began to open at `opened`
    /// and on which `already` questions were asked just now: the finish, or a direct invitation's
    /// challenge and proof.
    pub(crate) fn new(
        connection: Connection,
        preauth: Box<dyn Preauth>,
        opened: tokio::time::Instant,
        already: usize,
    ) -> Self {
        Self {
            _connection: Some(connection),
            preauth,
            asked: Asked::after(already, opened, tokio::time::Instant::now()),
        }
    }

    /// A scripted surface with no connection under it, opened at `opened`, on which `already`
    /// questions were asked just now.
    #[cfg(test)]
    fn scripted(preauth: Box<dyn Preauth>, opened: tokio::time::Instant, already: usize) -> Self {
        Self {
            _connection: None,
            preauth,
            asked: Asked::after(already, opened, tokio::time::Instant::now()),
        }
    }
}

/// The questions a device has asked on one unpaired connection, counted as the host counts them.
///
/// A host answers an unpaired connection [`PreAuthLimits::max_requests`] times in all, and
/// [`PreAuthLimits::max_requests_per_window`] times in any [`PreAuthLimits::window`]. Past the
/// second it refuses the question and keeps the connection; past the first it answers once more
/// and ends the connection. It also ends the connection [`UNPAIRED_LIFE`] after it opened. So a
/// device that waits spaces its questions to keep the window from filling, asks nothing on a
/// connection after its last call, and moves to a fresh connection once this one has no questions
/// left.
#[derive(Debug)]
struct Asked {
    /// When each question still inside the window was sent, oldest first.
    recent: VecDeque<tokio::time::Instant>,
    /// Every question asked on the connection.
    total: usize,
    /// When the device began to open the connection's pre-authorisation surface, by its own clock:
    /// before its offer went, so no later than when the host answered it and began to count the
    /// connection's time.
    opened: tokio::time::Instant,
    /// Whether a question went at or after the connection's last call, which makes it the last.
    called: bool,
    /// Whether a question went at or after the cutoff: the one kept for it, and any after it.
    kept: bool,
    /// Until when the device rests before its next question here, at its own pace: after an
    /// answer, and after the host turned a question away as too soon.
    rest: tokio::time::Instant,
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
    /// A connection the device began to open at `opened`, on which `already` questions were asked
    /// at `now`.
    fn after(already: usize, opened: tokio::time::Instant, now: tokio::time::Instant) -> Self {
        Self {
            recent: std::iter::repeat_n(now, already).collect(),
            total: already,
            opened,
            called: false,
            kept: false,
            rest: now,
        }
    }

    /// When the next question may go, at `now`, inside `limits`.
    fn turn(&mut self, now: tokio::time::Instant, limits: &PreAuthLimits) -> Turn {
        if self.called || self.total >= limits.max_requests || now >= self.opened + UNPAIRED_LIFE {
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

    /// The latest moment a question on the connection is sure of an answer: far enough before the
    /// host ends it for the question to arrive and the answer to come back.
    fn last_call(&self) -> tokio::time::Instant {
        self.opened + UNPAIRED_LIFE.saturating_sub(LAST_CALL_MARGIN)
    }

    /// How many questions the connection has left at `now` when the last goes at `cutoff`: what
    /// the host's budget leaves, and no more than one every [`STATUS_INTERVAL`] fits before then,
    /// with the one at `cutoff` itself.
    fn left(
        &self,
        now: tokio::time::Instant,
        cutoff: tokio::time::Instant,
        limits: &PreAuthLimits,
    ) -> usize {
        if self.called {
            return 0;
        }
        let before =
            cutoff.saturating_duration_since(now).as_millis() / STATUS_INTERVAL.as_millis();
        let by_time = usize::try_from(before)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        limits.max_requests.saturating_sub(self.total).min(by_time)
    }

    /// How many of the questions asked so far the host's window still holds at `at`, a moment no
    /// earlier than the last question counted.
    fn in_window_at(&self, at: tokio::time::Instant, limits: &PreAuthLimits) -> usize {
        let window = limits.window + WINDOW_MARGIN;
        self.recent
            .iter()
            .filter(|sent| at.saturating_duration_since(**sent) < window)
            .count()
    }

    /// Counts one question, sent at `now` when the attempt's last call is `attempt_call`. One at
    /// or after the cutoff is the question kept for it, or one after it; one at or after the
    /// connection's own last call is the connection's last. Both are recorded as they happen,
    /// because the attempt's call reads as the present moment once it has passed.
    fn asked(&mut self, now: tokio::time::Instant, attempt_call: tokio::time::Instant) {
        self.total += 1;
        self.recent.push_back(now);
        self.kept |= now >= cutoff(self, attempt_call);
        self.called |= now >= self.last_call();
    }

    /// Rests until `until` before the next question here.
    fn rest_until(&mut self, until: tokio::time::Instant) {
        self.rest = until;
    }
}

/// What a waiting device does next with the connection it holds.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// Asks its next question on the connection now.
    Ask,
    /// Waits this long for the host's window to make room, then plans again.
    Wait(Duration),
    /// Looks for a fresh connection for at most `within`, and changes to it once it has answered.
    /// A look that fails is followed by a new plan, made when the look ended.
    Look { within: Duration },
    /// Keeps the next question for the cutoff, and pauses before it looks for a fresh connection
    /// again: a look has just failed.
    Keep,
    /// Lets the connection go: it has no question left.
    LetGo,
}

/// The cutoff on a connection whose questions are `asked`: its own last call, or the attempt's,
/// `attempt_call`, whichever comes first.
fn cutoff(asked: &Asked, attempt_call: tokio::time::Instant) -> tokio::time::Instant {
    asked.last_call().min(attempt_call)
}

/// Plans a waiting device's next step on a connection whose questions are `asked`, at `now`, when
/// the attempt's last call is `attempt_call`, inside the host's `limits`. `looked` says a look for
/// a fresh connection has just failed.
///
/// Before the cutoff the device asks at its pace, and from four questions before the end it looks
/// for a fresh connection before each one. It keeps a question for the cutoff, and looks for a
/// fresh connection meanwhile, when the question is the connection's last, when its answer could
/// still be out when the cutoff comes, or when it would leave the host's window no room there.
/// A device waits [`WAIT_STEP`] at most for an answer, so from that long before the cutoff the
/// only question left there is the kept one. The waiting loop takes no pause of its own on the
/// connection: `plan` decides every one, the rest after an answer included, and before the cutoff
/// none ends after it. A look that fails is followed by a new plan rather than by the question the
/// plan meant before it. So the device is free when the cutoff comes, and the kept question goes
/// then, waiting for nothing but the host's window, which has kept a place for it. At the
/// connection's own last call that question is the connection's last, and nothing goes on the
/// connection after it: a device that is later than a timer's grace lets the connection go
/// instead. After the attempt's last call every answer is final, so once its kept question has
/// gone the device asks there at its pace, until the connection's own last call, and looks for no
/// other.
fn plan(
    asked: &mut Asked,
    now: tokio::time::Instant,
    attempt_call: tokio::time::Instant,
    limits: &PreAuthLimits,
    looked: bool,
) -> Next {
    let window = match asked.turn(now, limits) {
        Turn::Spent => return Next::LetGo,
        Turn::Now => Duration::ZERO,
        Turn::After(wait) => wait,
    };
    let cutoff = cutoff(asked, attempt_call);
    let rest = asked.rest.saturating_duration_since(now);
    if now >= cutoff {
        let last_call = asked.last_call();
        if now.saturating_duration_since(last_call) > LAST_CALL_GRACE {
            return Next::LetGo;
        }
        // The question kept for the cutoff waits for the host's window alone; once it has gone,
        // the device keeps its pace again.
        let wait = if asked.kept { window.max(rest) } else { window };
        if wait.is_zero() {
            return Next::Ask;
        }
        // At the connection's own last call a question that has to wait may meet a connection the
        // host has ended.
        return if now >= last_call {
            Next::LetGo
        } else {
            Next::Wait(wait)
        };
    }
    let until = cutoff - now;
    // The device keeps its pace, and never past the cutoff.
    if !rest.is_zero() {
        return Next::Wait(rest.min(until));
    }
    let left = asked.left(now, cutoff, limits);
    let kept = left <= 1
        // The window stays full past the cutoff.
        || window > until
        // The answer could still be out when the cutoff comes, or come with it.
        || until <= WAIT_STEP
        // The question would take the window's last place through the cutoff.
        || (until < limits.window + WINDOW_MARGIN
            && asked.in_window_at(cutoff, limits) + 1 >= limits.max_requests_per_window);
    if kept {
        return if looked {
            Next::Keep
        } else {
            Next::Look { within: until }
        };
    }
    if !window.is_zero() {
        return Next::Wait(window);
    }
    if left <= CHANGE_WITH_LEFT && !looked {
        return Next::Look { within: until };
    }
    Next::Ask
}

/// How long a waiting device pauses after `refused` refusals in a row, as too soon, before its next
/// question. A host counts the questions it refuses as well, so a question asked again before the
/// host's own window has passed is refused again: the pause starts at the window this device paces
/// by and doubles with each refusal in a row, so it outgrows any window a host keeps. The attempt's
/// own deadline bounds it.
fn pause_after_refusals(refused: u32, limits: &PreAuthLimits) -> Duration {
    (limits.window + WINDOW_MARGIN).saturating_mul(2_u32.saturating_pow(refused))
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
        authority: super::owner::describe_rights(
            &pending.proposed_grant.actions,
            &pending.proposed_grant.session_selector,
        ),
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
            crate::shown!("the host reported {}", *code),
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
    PairingFailure::new(kind, Shown::pairing(error)).with_tries(tries)
}

/// What a failure reaching the host means, once its bundle pinned it.
fn link_failed(error: &LinkError, tries: Option<u32>) -> PairingFailure {
    let kind = match error {
        LinkError::Refused(refusal) => refused_by_host(refusal.code, false),
        LinkError::Lost(_)
        | LinkError::Membership(..)
        | LinkError::ConnectionRefused(_)
        | LinkError::Declined(_) => FailureKind::HostUnreachable,
        // The host answered, and what it answered is not the host the bundle names: a new try gets
        // the same answer, and costs one of this device's tries.
        LinkError::Selection(_) => FailureKind::HostMismatch,
        LinkError::Configuration(_) => FailureKind::DidNotFinish,
    };
    PairingFailure::new(kind, error.said()).with_tries(tries)
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
        PairingFailure::new(
            kind,
            crate::shown!("the room ended the exchange: {}", self.said()),
        )
        .with_tries(tries)
    }
}

impl Said for RoomStop {
    fn said(&self) -> Shown {
        match self {
            Self::Closed(reason) => crate::shown!("the room closed it: {}", closed(*reason)),
            Self::Ended => Shown::said("the socket ended without a last frame"),
            Self::TimedOut => Shown::said("the attempt's own deadline passed"),
            Self::Unreadable => Shown::said("the room sent something no attempt reads"),
        }
    }
}

/// Why the room said it closed a socket or an attempt.
const fn closed(reason: CloseReason) -> Shown {
    Shown::said(match reason {
        CloseReason::Deadline => "a candidate socket reached its deadline",
        CloseReason::Expired => "the record's advertised expiry passed",
        CloseReason::Cancelled => "the host closed the attempt or released the record",
        CloseReason::Superseded => "another socket took this role's place",
        CloseReason::Invalid => "a frame was not one of the room's vocabulary",
        CloseReason::Oversize => "a frame carried more than the room allows",
        CloseReason::Exhausted => "the attempt relayed more than the room allows in total",
        CloseReason::HostGone => "no host was attached to carry the frame",
    })
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
pub(crate) enum StartRefused {
    /// It refused, and when the lookup failed, how the room ended.
    Pairing {
        /// What kr-pairing returned.
        error: PairingError,
        /// How the room ended, when that is what failed.
        room: Option<PairingFailure>,
    },
    /// The blocking thread did not finish.
    Lost(Shown),
}

impl std::fmt::Debug for StartRefused {
    /// Which refusal it is, and a lost start's words. Never the pairing library's own text.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pairing { .. } => formatter.debug_struct("Pairing").finish_non_exhaustive(),
            Self::Lost(lost) => formatter.debug_tuple("Lost").field(lost).finish(),
        }
    }
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
    start_in_room_waiting(room, RECORD_WAIT, start).await
}

/// [`start_in_room`], with the room given `record_wait` to serve the first frame instead of
/// [`RECORD_WAIT`].
pub(crate) async fn start_in_room_waiting<T, F>(
    room: Arc<dyn CandidateRoom>,
    record_wait: Duration,
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
        record_wait,
        slot: Arc::clone(&slot),
        ending: Arc::clone(&ending),
        cancelled: Mutex::new(Some(cancelled)),
    };
    let joined = tokio::task::spawn_blocking(move || start(&lookup)).await;
    let socket = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    match joined {
        Ok(Ok(value)) => match socket {
            Some(socket) => Ok((value, socket)),
            None => Err(StartRefused::Lost(Shown::said(
                "the attempt started without opening its room",
            ))),
        },
        Ok(Err(error)) => Err(StartRefused::Pairing {
            error,
            room: ending.lock().unwrap_or_else(PoisonError::into_inner).take(),
        }),
        Err(error) => Err(StartRefused::Lost(crate::shown!(
            "the attempt's start did not finish: {}",
            Shown::task(&error)
        ))),
    }
}

/// The lookup kr-pairing's start is given.
struct RoomLookup {
    runtime: tokio::runtime::Handle,
    room: Arc<dyn CandidateRoom>,
    /// How long the room is given to serve its first frame.
    record_wait: Duration,
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
            let opened = first_record(&*self.room, origin, locator, self.record_wait);
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
                        reason: failure.detail.as_str().to_owned(),
                    }
                } else {
                    PairingError::RendezvousUnavailable {
                        reason: failure.detail.as_str().to_owned(),
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
    record_wait: Duration,
) -> Result<(LocatorRecord, RoomSocket), PairingFailure> {
    let mut socket = room
        .open(origin, locator)
        .await
        .map_err(|error| PairingFailure::new(room_failure(&error), error.said()))?;
    let no_host = |detail: Shown| PairingFailure::new(FailureKind::NoHostAnswered, detail);
    match tokio::time::timeout(record_wait, socket.incoming.recv()).await {
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
        Ok(Some(ServiceFrame::Closed { reason })) => Err(no_host(crate::shown!(
            "the room closed the socket: {}",
            closed(reason)
        ))),
        Ok(Some(_)) => Err(no_host(Shown::said(
            "the room sent something before a record",
        ))),
        Ok(None) => Err(no_host(Shown::said("the room ended the socket"))),
        Err(_) => Err(no_host(Shown::said("the room served no record in time"))),
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
    use super::super::checkpoint::{Acquisition, Held, PairedCheckpoint, SnapshotCause};
    use super::super::paired::{HostCredentials, read_hosts};
    use super::*;
    use kr_protocol::scalars::Uuid;
    use std::path::{Path, PathBuf};
    use tokio::sync::mpsc;

    /// How long a wait for the room may take before the test is taken to be hung.
    ///
    /// It only ends a test that would never finish. Nothing here waits for it to pass, and no test
    /// claims how long anything took.
    const HUNG: Duration = Duration::from_secs(60);

    /// How long a test gives a room to serve its first frame: longer than [`HUNG`], so that the
    /// room's own wait running out cannot be what closes a socket the test is waiting on.
    const ROOM_PATIENCE: Duration = Duration::from_secs(60 * 60);

    /// A room a test holds the far end of.
    struct HeldRoom {
        serve_record: bool,
        /// How many sockets the room has opened. It is raised once the socket's far end is kept, so
        /// a test that sees a socket counted has its far end.
        opened: tokio::sync::watch::Sender<usize>,
        far: Mutex<Vec<(mpsc::Sender<ServiceFrame>, mpsc::Receiver<ClientFrame>)>>,
    }

    impl HeldRoom {
        fn new(serve_record: bool) -> Arc<Self> {
            Arc::new(Self {
                serve_record,
                opened: tokio::sync::watch::Sender::new(0),
                far: Mutex::new(Vec::new()),
            })
        }

        fn opened(&self) -> usize {
            *self.opened.borrow()
        }

        /// Waits until the room has opened a socket.
        async fn until_opened(&self) {
            tokio::time::timeout(HUNG, self.opened.subscribe().wait_for(|opened| *opened > 0))
                .await
                .expect("the room was opened")
                .expect("the room is held");
        }

        /// Waits until the device's end of the socket the room opened last is gone, and says
        /// whether it went before the test is taken to be hung.
        async fn closed(&self) -> bool {
            let (_to_device, mut from_device) = self
                .far
                .lock()
                .expect("the far ends")
                .pop()
                .expect("the room opened a socket");
            tokio::time::timeout(HUNG, async { while from_device.recv().await.is_some() {} })
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
            self.opened.send_modify(|opened| *opened += 1);
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
        let starting = tokio::spawn(start_in_room_waiting(
            room.clone() as Arc<dyn CandidateRoom>,
            ROOM_PATIENCE,
            |lookup| lookup.lookup(&origin(), &locator()),
        ));
        room.until_opened().await;
        starting.abort();
        assert!(
            room.closed().await,
            "the socket closed after the cancellation"
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
        assert!(
            room.closed().await,
            "the socket closed after the failed start"
        );
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

    /// The lookup bridge, on a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_lookup_bridge_on_a_multi_threaded_runtime() {
        a_successful_start_hands_the_socket_over_once().await;
        cancelling_ends_the_wait_and_closes_the_socket().await;
        a_start_that_fails_after_its_lookup_closes_the_socket().await;
        a_refused_charge_opens_nothing().await;
    }

    /// The lookup bridge, on a current-thread runtime, where the awaiting thread is the one that
    /// drives the room's I/O while the blocking thread waits.
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
            retry_after: None,
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

    /// An attempt's last call far off, so the connection's own last call is the cutoff.
    fn far_off(start: tokio::time::Instant) -> tokio::time::Instant {
        start + Duration::from_secs(600)
    }

    /// The attempt's last call `call` as the waiting loop reads it at `now`: the moment itself
    /// until it comes, and the present moment once it has passed, as `Pairing::attempt_call` has it.
    fn attempts_call_as_read(
        now: tokio::time::Instant,
        call: tokio::time::Instant,
    ) -> tokio::time::Instant {
        now.max(call)
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
        let mut asked = Asked::after(2, start, start);
        assert_eq!(asked.turn(start, &limits), Turn::Now);
        asked.asked(start, far_off(start));
        assert_eq!(asked.turn(at(1), &limits), Turn::Now);
        asked.asked(at(1), far_off(start));
        // The window is full: the third waits until the challenge and proof have aged out.
        assert_eq!(
            asked.turn(at(2), &limits),
            Turn::After(window - Duration::from_secs(2))
        );
        assert_eq!(asked.turn(start + window, &limits), Turn::Now);

        // Every question the host answers on one connection, each as soon as the window has room,
        // then none.
        let mut asked = Asked::after(1, start, start);
        let mut now = start;
        while asked.total < limits.max_requests {
            match asked.turn(now, &limits) {
                Turn::Now => asked.asked(now, far_off(start)),
                Turn::After(wait) => now += wait,
                Turn::Spent => panic!("spent after {} questions", asked.total),
            }
        }
        assert!(now < asked.last_call(), "{:?}", now - start);
        assert_eq!(asked.turn(now, &limits), Turn::Spent);

        // At the steady rate the window never fills.
        let mut asked = Asked::after(0, start, start);
        let mut now = start;
        for _ in 0..limits.max_requests {
            assert_eq!(asked.turn(now, &limits), Turn::Now, "{:?}", now - start);
            asked.asked(now, far_off(start));
            now += STATUS_INTERVAL;
        }
    }

    /// KR-REQ-10.23: a host ends an unpaired connection a minute after it opened, whatever was
    /// asked on it. A waiting device counts a connection's questions by the time it has left as
    /// well as by the host's budget, asks the last at the connection's last call, early enough for
    /// the answer to come back, and asks nothing on it after that.
    #[test]
    fn a_connection_has_no_more_questions_than_fit_before_its_last_call() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let before = |call: tokio::time::Instant, seconds: u64| call - Duration::from_secs(seconds);
        let mut asked = Asked::after(1, start, start);
        let last_call = asked.last_call();
        assert_eq!(last_call, start + UNPAIRED_LIFE - LAST_CALL_MARGIN);
        // Early on the host's budget bounds the questions; later the time left before the last
        // call does, at one question every interval and one at the call itself.
        assert_eq!(
            asked.left(start, last_call, &limits),
            limits.max_requests - 1
        );
        assert_eq!(asked.left(before(last_call, 12), last_call, &limits), 5);
        assert_eq!(asked.left(before(last_call, 11), last_call, &limits), 4);
        assert_eq!(asked.left(before(last_call, 1), last_call, &limits), 1);
        assert_eq!(asked.left(last_call, last_call, &limits), 1);
        // An earlier last call, the attempt's own, counts the same way.
        assert_eq!(
            asked.left(start, start + Duration::from_secs(6), &limits),
            3
        );
        // A question before the last call leaves the connection open; one at the call is its last.
        asked.asked(before(last_call, 1), far_off(start));
        assert_eq!(asked.turn(last_call, &limits), Turn::Now);
        asked.asked(last_call, far_off(start));
        assert_eq!(asked.left(last_call, last_call, &limits), 0);
        assert_eq!(
            asked.turn(last_call + Duration::from_secs(1), &limits),
            Turn::Spent
        );
        // A connection the host has ended has no questions, whatever its budget.
        let mut idle = Asked::after(1, start, start);
        assert_eq!(idle.turn(start + UNPAIRED_LIFE, &limits), Turn::Spent);
    }

    /// KR-REQ-10.36, KR-REQ-10.23: once the attempt's own last call has come, its last seconds go
    /// to the connection the device holds. Every answer there is final, so the device asks at its
    /// pace and looks for no other connection, on every reading of its clocks after the call.
    #[test]
    fn after_the_attempts_last_call_the_held_connection_is_asked() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let call = |now: tokio::time::Instant| attempts_call_as_read(now, at(20));
        let mut asked = Asked::after(2, start, start);
        asked.asked(start, call(start));
        // Before the attempt's call, four questions from its end, the device looks elsewhere first;
        // two seconds from it, it keeps the question for the call.
        assert_eq!(
            plan(&mut asked, at(9), call(at(9)), &limits, false),
            Next::Look {
                within: Duration::from_secs(11)
            }
        );
        assert_eq!(
            plan(&mut asked, at(18), call(at(18)), &limits, false),
            Next::Look {
                within: Duration::from_secs(2)
            }
        );
        // At and after the call, whenever the clocks are read, the question goes.
        for now in [at(20), at(21), at(24)] {
            assert_eq!(plan(&mut asked, now, call(now), &limits, false), Next::Ask);
            asked.asked(now, call(now));
        }
    }

    /// KR-REQ-10.23: a waiting device plans each question by the host's budget and window and by the
    /// connection's last call: it asks at its pace, looks for a fresh connection first from four
    /// questions before the end by either count, keeps the last, asks it at the call, and lets the
    /// connection go after it, or once the host has ended the connection.
    #[test]
    fn a_waiting_device_plans_by_budget_window_and_last_call() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);

        // Early, with the window's room: ask.
        let mut asked = Asked::after(1, start, start);
        assert_eq!(plan(&mut asked, at(1), far, &limits, false), Next::Ask);
        // The window full before the cutoff: wait for it.
        for second in [1, 2, 3] {
            asked.asked(at(second), far);
        }
        assert_eq!(
            plan(&mut asked, at(4), far, &limits, false),
            Next::Wait(Duration::from_secs(7))
        );

        // By budget: with four left the device looks elsewhere first, and asks once that has
        // failed; the last one it keeps while looks fail.
        let mut asked = Asked::after(12, start, start);
        assert_eq!(
            plan(&mut asked, at(12), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(38)
            }
        );
        assert_eq!(plan(&mut asked, at(12), far, &limits, true), Next::Ask);
        let mut asked = Asked::after(15, start, start);
        assert_eq!(
            plan(&mut asked, at(12), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(38)
            }
        );
        assert_eq!(plan(&mut asked, at(12), far, &limits, true), Next::Keep);

        // By time: four left eleven seconds before the call, and the question kept two seconds
        // before it; the kept question goes at the call, and nothing after it.
        let mut asked = Asked::after(2, start, start);
        assert_eq!(
            plan(&mut asked, at(39), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(11)
            }
        );
        assert_eq!(
            plan(&mut asked, at(48), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(2)
            }
        );
        assert_eq!(plan(&mut asked, at(48), far, &limits, true), Next::Keep);
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::Ask);
        asked.asked(at(50), far);
        assert_eq!(plan(&mut asked, at(51), far, &limits, false), Next::LetGo);

        // A connection the host has ended has no question, whatever its budget.
        let mut idle = Asked::after(2, start, start);
        assert_eq!(plan(&mut idle, at(60), far, &limits, false), Next::LetGo);
    }

    /// KR-REQ-10.23: the question kept for a connection's last call always finds the host's window
    /// with room. A question that would take the window's last place through the call is kept for
    /// the call instead, so the kept question goes at the call itself, never later. This host keeps
    /// a window of twenty seconds, so the place is taken well before the call.
    #[test]
    fn the_hosts_window_keeps_room_for_the_question_at_the_last_call() {
        let limits = PreAuthLimits {
            window: Duration::from_secs(20),
            ..PreAuthLimits::default()
        };
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        // A slow start: the challenge and the proof at 32 s, eighteen seconds before the call.
        let mut asked = Asked::after(2, start, at(32));
        assert_eq!(asked.last_call(), at(50));
        assert_eq!(plan(&mut asked, at(32), far, &limits, false), Next::Ask);
        asked.asked(at(32), far);
        // A fourth question at 35 s would keep the window full until 53 s, past the call: it is
        // kept.
        assert_eq!(
            plan(&mut asked, at(35), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(15)
            }
        );
        assert_eq!(plan(&mut asked, at(35), far, &limits, true), Next::Keep);
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::Ask);
        asked.asked(at(50), far);
        assert_eq!(plan(&mut asked, at(51), far, &limits, false), Next::LetGo);
    }

    /// KR-REQ-10.23: a window that is full through a connection's last call, however it came to be,
    /// leaves the connection no question the host is sure to answer. The device looks for a fresh
    /// connection until the call, and then lets this one go rather than ask late.
    #[test]
    fn a_window_full_through_the_last_call_lets_the_connection_go() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        let mut asked = Asked::after(2, start, at(42));
        asked.asked(at(42), far);
        asked.asked(at(45), far);
        assert_eq!(
            plan(&mut asked, at(48), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(2)
            }
        );
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::LetGo);
        // The attempt's own last call is not the connection's end: there the device waits for the
        // window and asks.
        let mut asked = Asked::after(2, start, at(10));
        asked.asked(at(10), at(15));
        asked.asked(at(13), at(15));
        assert_eq!(
            plan(&mut asked, at(15), at(15), &limits, false),
            Next::Wait(Duration::from_secs(6))
        );
    }

    /// KR-REQ-10.23: a waiting device is free when a connection's last call comes. It waits for an
    /// answer for as long as [`WAIT_STEP`], so a question whose answer could still be out when the
    /// call comes is kept for the call instead, while the device looks for a fresh connection. Here
    /// every answer takes eight seconds: questions go at 0, 11, 22 and 33 seconds, and one at 44
    /// could be answered as late as 54, past the call at 50. So could the first question after a
    /// start that ended at 42 seconds.
    #[test]
    fn a_question_whose_answer_may_be_out_at_the_last_call_is_kept_for_it() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        // The finish, then a status question, and one after each eight-second answer and the
        // pause that follows it.
        let mut asked = Asked::after(1, start, start);
        for second in [0, 11, 22, 33] {
            assert_eq!(
                plan(&mut asked, at(second), far, &limits, false),
                Next::Ask,
                "at {second} s"
            );
            asked.asked(at(second), far);
        }
        assert_eq!(asked.last_call(), at(50));
        assert_eq!(
            plan(&mut asked, at(44), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(6)
            }
        );
        // A fresh connection that fails at once changes nothing: the question is still kept.
        assert_eq!(plan(&mut asked, at(44), far, &limits, true), Next::Keep);
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::Ask);

        // A slow start: the challenge and the proof at 42 s, eight seconds before the call.
        let mut asked = Asked::after(2, start, at(42));
        assert_eq!(
            plan(&mut asked, at(42), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(8)
            }
        );
        assert_eq!(plan(&mut asked, at(42), far, &limits, true), Next::Keep);
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::Ask);
        asked.asked(at(50), far);
        assert_eq!(plan(&mut asked, at(51), far, &limits, false), Next::LetGo);
    }

    /// KR-REQ-10.23: nothing goes on a connection after its last call, however the device came to
    /// be late for it: a question sent then may meet a connection the host has ended. A device that
    /// asked at 44 seconds and heard back at 52, past the call at 50, lets the connection go at 55
    /// rather than ask there. A device that a timer wakes a moment after the call is still on time
    /// for it, and one woken later than a timer's grace is not. After the attempt's own last call,
    /// too, the device asks the connection until its last call and not after it.
    #[test]
    fn nothing_goes_on_a_connection_after_its_last_call() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        let mut asked = Asked::after(1, start, start);
        for second in [0, 11, 22, 33, 44] {
            asked.asked(at(second), far);
        }
        assert_eq!(plan(&mut asked, at(55), far, &limits, false), Next::LetGo);

        let mut on_time = Asked::after(1, start, start);
        on_time.asked(at(33), far);
        let call = on_time.last_call();
        assert_eq!(
            plan(&mut on_time, call + LAST_CALL_GRACE, far, &limits, false),
            Next::Ask
        );
        assert_eq!(
            plan(
                &mut on_time,
                call + LAST_CALL_GRACE + Duration::from_millis(1),
                far,
                &limits,
                false
            ),
            Next::LetGo
        );

        let call = |now: tokio::time::Instant| attempts_call_as_read(now, at(30));
        let mut asked = Asked::after(1, start, start);
        asked.asked(at(33), call(at(33)));
        assert_eq!(
            plan(&mut asked, at(44), call(at(44)), &limits, false),
            Next::Ask
        );
        asked.asked(at(44), call(at(44)));
        assert_eq!(
            plan(&mut asked, at(52), call(at(52)), &limits, false),
            Next::LetGo
        );
    }

    /// KR-REQ-10.23: a look for a fresh connection takes time, so a failed one is followed by a new
    /// plan from when it ended, never by the question the plan meant before it. A look from 39
    /// seconds leaves time for a question and its answer before the call at 50; one that failed at
    /// 44 does not, and the question is kept. A look that failed at once is followed by the question
    /// itself, and not by another look.
    #[test]
    fn a_failed_look_is_followed_by_a_new_plan() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        let mut asked = Asked::after(2, start, start);
        assert_eq!(
            plan(&mut asked, at(39), far, &limits, false),
            Next::Look {
                within: Duration::from_secs(11)
            }
        );
        assert_eq!(plan(&mut asked, at(39), far, &limits, true), Next::Ask);
        assert_eq!(plan(&mut asked, at(44), far, &limits, true), Next::Keep);
    }

    /// KR-REQ-10.23: a host that counts the questions it refuses, and keeps a window longer than
    /// any fixed pause, still answers in the end: the pauses double past its window within an
    /// attempt's lifetime. Pauses that stopped growing at eight windows would keep a two-minute
    /// window full for good.
    #[test]
    fn pauses_after_refusals_outgrow_any_window_a_host_keeps() {
        let limits = PreAuthLimits::default();
        let lifetime = Duration::from_millis(INVITATION_LIFETIME_MS + RECOVERY_MARGIN_MS);
        // A host that answers one question in any `window` and counts the ones it refuses, asked
        // right after the finish and then after each pause: when it first answers, if it does.
        let first_answer = |window: Duration, pause: &dyn Fn(u32) -> Duration| {
            let mut charged = vec![Duration::ZERO];
            let mut now = Duration::ZERO;
            let mut refused = 0;
            while now < lifetime {
                let in_window = charged.iter().filter(|at| now - **at < window).count();
                charged.push(now);
                if in_window == 0 {
                    return Some(now);
                }
                now += pause(refused);
                refused += 1;
            }
            None
        };
        for window in [Duration::from_secs(20), Duration::from_secs(120)] {
            assert!(
                first_answer(window, &|refused| pause_after_refusals(refused, &limits)).is_some(),
                "{window:?}"
            );
        }
        assert_eq!(
            first_answer(Duration::from_secs(120), &|refused| {
                pause_after_refusals(refused.min(3), &limits)
            }),
            None,
            "pauses that stop growing never outlast the window"
        );
    }

    /// KR-REQ-10.23: an answer can be due at the very moment the cutoff comes. A look that failed
    /// with exactly [`WAIT_STEP`] left before the cutoff leaves the device a question whose answer
    /// could come as the cutoff does, so it keeps that question for the cutoff.
    #[test]
    fn a_question_whose_answer_is_due_at_the_last_call_is_kept_for_it() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        let mut asked = Asked::after(2, start, start);
        asked.asked(at(26), far);
        assert_eq!(plan(&mut asked, at(40), far, &limits, true), Next::Keep);
        assert_eq!(
            plan(&mut asked, at(40), far, &limits, false),
            Next::Look { within: WAIT_STEP }
        );
    }

    /// KR-REQ-10.23: the device rests between an answer and its next question, and `plan` turns the
    /// rest into a wait. Before the cutoff the wait ends at the cutoff; at the cutoff the question
    /// kept for it goes at once, whatever the rest; once that question has gone, the device rests
    /// between questions again.
    #[test]
    fn the_rest_after_an_answer_never_holds_the_kept_question_past_the_cutoff() {
        let limits = PreAuthLimits::default();
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let far = at(600);
        let mut asked = Asked::after(2, start, start);
        asked.asked(at(30), far);
        // An answer at 49 s, whose rest would end at 52 s, past the call at 50 s.
        asked.rest_until(at(52));
        assert_eq!(
            plan(&mut asked, at(49), far, &limits, false),
            Next::Wait(Duration::from_secs(1))
        );
        // The call comes with the rest still running: the kept question goes.
        assert_eq!(plan(&mut asked, at(50), far, &limits, false), Next::Ask);
        // The attempt's own last call at 20 s, once its kept question has gone: the rest holds.
        let call = |now: tokio::time::Instant| attempts_call_as_read(now, at(20));
        let mut asked = Asked::after(2, start, start);
        asked.asked(at(20), call(at(20)));
        asked.rest_until(at(23));
        assert_eq!(
            plan(&mut asked, at(21), call(at(21)), &limits, false),
            Next::Wait(Duration::from_secs(2))
        );
        assert_eq!(
            plan(&mut asked, at(23), call(at(23)), &limits, false),
            Next::Ask
        );
    }

    /// What a scripted host answers a status question with, and when.
    #[derive(Clone, Debug)]
    enum Reply {
        /// That the owner has not decided yet, this long after the question went.
        Waiting(Duration),
        /// That the question came too soon, this long after it went.
        TooSoon(Duration),
        /// That the question came too soon, at this moment.
        TooSoonAt(tokio::time::Instant),
        /// The host's refusal of the question with this code, at once.
        Refused(ErrorCode),
        /// The host's refusal, `PERMISSION_DENIED`, at this moment.
        RefusedAt(tokio::time::Instant),
        /// That the owner has not decided yet until this moment, and that the host committed the
        /// device from then on.
        CommittedFrom(tokio::time::Instant),
    }

    /// A host's pre-authorisation surface, scripted: every status question is answered as `reply`
    /// says, and the surface notes when each question went.
    struct Scripted {
        reply: Reply,
        asked: Arc<Mutex<Vec<tokio::time::Instant>>>,
        /// When a refusal that was waited for reached the device.
        answered: Arc<Mutex<Vec<tokio::time::Instant>>>,
        waiting: PairStatusResult,
    }

    impl Preauth for Scripted {
        fn selection(&self) -> &kr_protocol::hello::HostSelection {
            unreachable!("a waiting device does not read the selection")
        }

        fn finish<'a>(
            &'a mut self,
            _request: &'a kr_protocol::pairing::PairFinishRequest,
        ) -> BoxFuture<'a, Result<kr_protocol::preauth::PairFinishResult, LinkError>> {
            unreachable!("a waiting device sends no finish")
        }

        fn redeem<'a>(
            &'a mut self,
            _params: &'a kr_protocol::preauth::PairRedeemParams,
        ) -> BoxFuture<'a, Result<kr_protocol::preauth::PairRedeemResult, LinkError>> {
            unreachable!("a waiting device redeems nothing")
        }

        fn status<'a>(
            &'a mut self,
            _params: &'a PairStatusParams,
        ) -> BoxFuture<'a, Result<PairStatusResult, LinkError>> {
            self.asked
                .lock()
                .expect("the record")
                .push(tokio::time::Instant::now());
            let (reply, waiting) = (self.reply.clone(), self.waiting.clone());
            let answered = Arc::clone(&self.answered);
            let too_soon = || {
                LinkError::Refused(kr_protocol::error::ProtocolError::new(
                    ErrorCode::RateLimited,
                    "too many requests on this connection",
                ))
            };
            Box::pin(async move {
                match reply {
                    Reply::Waiting(after) => {
                        tokio::time::sleep(after).await;
                        Ok(waiting)
                    }
                    Reply::TooSoon(after) => {
                        tokio::time::sleep(after).await;
                        Err(too_soon())
                    }
                    Reply::TooSoonAt(at) => {
                        tokio::time::sleep_until(at).await;
                        Err(too_soon())
                    }
                    Reply::Refused(code) => Err(LinkError::Refused(
                        kr_protocol::error::ProtocolError::new(code, "refused"),
                    )),
                    Reply::RefusedAt(at) => {
                        tokio::time::sleep_until(at).await;
                        answered
                            .lock()
                            .expect("the record")
                            .push(tokio::time::Instant::now());
                        Err(LinkError::Refused(kr_protocol::error::ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "refused",
                        )))
                    }
                    Reply::CommittedFrom(at) => Ok(if tokio::time::Instant::now() >= at {
                        committed_status(DeviceId::new(Uuid::from_bytes([7; 16])))
                    } else {
                        waiting
                    }),
                }
            })
        }
    }

    /// The status a host answers a device it committed with.
    fn committed_status(device_id: DeviceId) -> PairStatusResult {
        PairStatusResult {
            status: PairStatus::Committed {
                device_id,
                grant_id: kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16])),
            },
            owner: kr_protocol::scalars::Nullable::null(),
        }
    }

    /// What one scripted connection as the paired device does.
    #[derive(Clone, Debug)]
    enum Paired {
        /// The connect is refused with this code.
        Refused(ErrorCode),
        /// The connect fails as a connection lost.
        Lost,
        /// The connect fails as this device's own budget refusing it.
        Declined,
        /// The connect fails as the host's admission refusal read by the presenter.
        ConnectionRefused,
        /// The connect fails as the host holding no membership lease for this device.
        Membership,
        /// The connect never ends.
        Blocks,
        /// The host refuses the connection, as an error for request zero, and every call with it.
        RefuseConnection(ErrorCode),
        /// The host answers `pair.status` as the device the connection proved.
        Committed,
        /// The host answers `pair.status` naming this device.
        CommittedAs(DeviceId),
        /// The host answers `pair.status` with this, which is no commitment.
        Status(PairStatus),
        /// The host refuses `pair.status` with this code, as the answer to that request.
        Refuse(ErrorCode),
        /// The host never answers `pair.status`.
        Silent,
    }

    /// What the host answers to `backup.checkpoint` on every scripted connection.
    #[derive(Clone, Debug)]
    enum Checkpoint {
        /// The host of an earlier release: it refuses the method as one it does not serve.
        Unserved,
        /// The host refuses with this code.
        Refuse(ErrorCode),
        /// The host has accepted no generation.
        Null,
        /// The host names this checkpoint.
        Published(kr_protocol::backup_checkpoint::HostCheckpoint),
        /// The host names a checkpoint of generation 0, which no host publishes.
        Zero,
        /// The host never answers.
        Silent,
        /// The host closes the connection when it is asked.
        Lost,
        /// The host names this checkpoint under another request identifier than the one it was
        /// asked under.
        WrongId(kr_protocol::backup_checkpoint::HostCheckpoint),
    }

    /// What the host answers to `environment.list` on every scripted connection.
    #[derive(Clone, Debug)]
    enum Names {
        /// The host refuses it.
        Unserved,
        /// The host lists one environment, with this label.
        Label(&'static str),
        /// The host never answers.
        Silent,
    }

    /// What the device keeps of the waiting attempt when a run starts.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Attempt {
        /// Nothing is kept.
        Absent,
        /// The attempt is kept in `attempt.json`, as it is while it waits.
        Kept,
        /// A folder stands where the attempt is kept, so that the attempt cannot be cleared.
        Stuck,
    }

    /// How a scripted run begins.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Start {
        /// The waiting loop, on the connection held from the start.
        Waiting,
        /// `Pairing::resume` takes up the attempt that is kept. The host's record is written first
        /// when `recorded`, as it stands when the device stopped after the proof.
        Resumed { recorded: bool },
    }

    /// The folder, the device's keys and the host's keys of an earlier run, which the next run goes
    /// on with: the same device meets the same host again.
    struct Earlier {
        directory: tempfile::TempDir,
        keys: DeviceKeys,
        host_keys: kr_protocol::pairing::DevicePublicKeys,
    }

    /// What the device's store held when a request reached the host.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Seen {
        method: String,
        /// How many paired hosts `hosts.json` listed.
        hosts: usize,
        /// Whether `attempt.json` stood.
        attempt: bool,
        /// How many `told` entries `checkpoints.json` held.
        told: usize,
    }

    impl Seen {
        fn of(directory: &Path, method: &str) -> Self {
            let told = std::fs::read(directory.join("checkpoints.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|file| file["told"].as_array().map(Vec::len))
                .unwrap_or(0);
            Self {
                method: method.to_owned(),
                hosts: read_hosts(directory).map_or(0, |hosts| hosts.len()),
                attempt: directory.join("attempt.json").exists(),
                told,
            }
        }
    }

    /// The body of an answer that names generation 0, as a host that broke the rule would send it.
    #[derive(Serialize)]
    struct ZeroBody {
        checkpoint: ZeroEntry,
    }

    #[derive(Serialize)]
    struct ZeroEntry {
        service_origin: kr_protocol::service::GatewayOrigin,
        archive_id: kr_protocol::ids::ArchiveId,
        backup_generation: kr_protocol::ids::BackupGeneration,
        encrypted_manifest_hash: kr_protocol::scalars::Digest256,
    }

    /// Each request a scripted connection received: the connection's number and the method.
    type Requests = Arc<Mutex<Vec<(usize, String)>>>;

    /// A control connection whose host answers each request as its script says, with no socket.
    #[derive(Debug)]
    struct PairedSession {
        script: Paired,
        device_id: DeviceId,
        sender:
            std::sync::Mutex<Option<mpsc::UnboundedSender<kr_protocol::envelope::ControlFrame>>>,
        frames: tokio::sync::Mutex<mpsc::UnboundedReceiver<kr_protocol::envelope::ControlFrame>>,
        closed: Arc<Mutex<usize>>,
        checkpoint: Checkpoint,
        names: Names,
        connection: usize,
        requests: Requests,
        /// The device's store, and what it held at each request.
        watch: PathBuf,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl PairedSession {
        fn answer(
            &self,
            request: &kr_protocol::envelope::Request,
        ) -> Option<kr_protocol::envelope::Response> {
            use kr_protocol::envelope::{Outcome, ParamsValue, Response};
            self.requests
                .lock()
                .expect("the log")
                .push((self.connection, request.method.as_str().to_owned()));
            self.seen
                .lock()
                .expect("the log")
                .push(Seen::of(&self.watch, request.method.as_str()));
            if request.method.as_str() == Method::EnvironmentList.entry().name {
                let outcome = match &self.names {
                    Names::Silent => return None,
                    Names::Unserved => Outcome::Error(kr_protocol::error::ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "no environments are listed",
                    )),
                    Names::Label(label) => Outcome::Ok(
                        ParamsValue::from_typed(&EnvironmentListResult {
                            environments: vec![kr_protocol::hostinfo::EnvironmentSummary {
                                environment_id: kr_protocol::ids::EnvironmentId::new(
                                    Uuid::from_bytes([3; 16]),
                                ),
                                label: (*label).to_owned(),
                                os: "linux".to_owned(),
                                arch: "x86_64".to_owned(),
                                os_user: "a-user".to_owned(),
                                runtime_directory: "/run".to_owned(),
                                state_directory: "/state".to_owned(),
                                live_sessions: kr_protocol::scalars::U64::new(0),
                                machine: None,
                            }],
                        })
                        .expect("a value"),
                    ),
                };
                return Some(Response {
                    request_id: request.request_id,
                    outcome,
                });
            }
            if request.method.as_str() == Method::BackupCheckpoint.entry().name {
                let outcome = match &self.checkpoint {
                    Checkpoint::Silent => return None,
                    Checkpoint::Lost => {
                        crate::transport::ControlTransport::close(self);
                        return None;
                    }
                    Checkpoint::Unserved => Outcome::Error(kr_protocol::error::ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the method is not served",
                    )),
                    Checkpoint::Refuse(code) => Outcome::Error(
                        kr_protocol::error::ProtocolError::new(*code, "the question is refused"),
                    ),
                    Checkpoint::Null => Outcome::Ok(
                        ParamsValue::from_typed(
                            &kr_protocol::backup_checkpoint::BackupCheckpointResult {
                                checkpoint: kr_protocol::scalars::Nullable::null(),
                            },
                        )
                        .expect("a value"),
                    ),
                    Checkpoint::Published(held) | Checkpoint::WrongId(held) => Outcome::Ok(
                        ParamsValue::from_typed(
                            &kr_protocol::backup_checkpoint::BackupCheckpointResult {
                                checkpoint: kr_protocol::scalars::Nullable::some(held.clone()),
                            },
                        )
                        .expect("a value"),
                    ),
                    Checkpoint::Zero => Outcome::Ok(
                        ParamsValue::from_typed(&ZeroBody {
                            checkpoint: ZeroEntry {
                                service_origin: kr_protocol::service::GatewayOrigin::new(
                                    "https://reach.kala.to",
                                )
                                .expect("an origin"),
                                archive_id: kr_protocol::ids::ArchiveId::new(Uuid::from_bytes(
                                    [1; 16],
                                )),
                                backup_generation: kr_protocol::ids::BackupGeneration::new(0),
                                encrypted_manifest_hash:
                                    kr_protocol::scalars::Digest256::from_bytes([1; 32]),
                            },
                        })
                        .expect("a value"),
                    ),
                };
                let request_id = if matches!(self.checkpoint, Checkpoint::WrongId(_)) {
                    kr_protocol::ids::RequestId::new(request.request_id.get().wrapping_add(1))
                } else {
                    request.request_id
                };
                return Some(Response {
                    request_id,
                    outcome,
                });
            }
            let outcome = if request.method.as_str() != Method::PairStatus.entry().name {
                Outcome::Error(kr_protocol::error::ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "no environments are listed",
                ))
            } else {
                match &self.script {
                    Paired::Committed => Outcome::Ok(
                        ParamsValue::from_typed(&committed_status(self.device_id))
                            .expect("a value"),
                    ),
                    Paired::CommittedAs(other) => Outcome::Ok(
                        ParamsValue::from_typed(&committed_status(*other)).expect("a value"),
                    ),
                    Paired::Status(status) => Outcome::Ok(
                        ParamsValue::from_typed(&PairStatusResult {
                            status: status.clone(),
                            owner: kr_protocol::scalars::Nullable::null(),
                        })
                        .expect("a value"),
                    ),
                    Paired::Refuse(code) => Outcome::Error(kr_protocol::error::ProtocolError::new(
                        *code,
                        "the question is refused",
                    )),
                    Paired::RefuseConnection(code) => {
                        return Some(Response {
                            request_id: kr_protocol::ids::RequestId::new(0),
                            outcome: Outcome::Error(kr_protocol::error::ProtocolError::new(
                                *code,
                                "open a new connection",
                            )),
                        });
                    }
                    _ => return None,
                }
            };
            Some(Response {
                request_id: request.request_id,
                outcome,
            })
        }
    }

    impl crate::transport::ControlTransport for PairedSession {
        fn connection_id(&self) -> kr_protocol::ids::ConnectionId {
            kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([42; 16]))
        }

        fn limits(&self) -> kr_protocol::hello::ReceiveLimits {
            kr_protocol::hello::ReceiveLimits::default()
        }

        fn initial_action_window(&self) -> kr_protocol::hello::ActionWindow {
            kr_protocol::hello::ActionWindow {
                action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                    .expect("a literal window identifier"),
                connection_id: self.connection_id(),
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
            }
        }

        fn ended_by_this_device(&self) -> Option<crate::transport::DeviceEnd> {
            None
        }

        fn host_states_placement_reading(&self) -> bool {
            false
        }

        fn send<'a>(
            &'a self,
            frame: &'a kr_protocol::envelope::ControlFrame,
        ) -> crate::transport::TransportFuture<'a, ()> {
            if let kr_protocol::envelope::ControlFrame::Request(request) = frame
                && let Some(response) = self.answer(request)
                && let Some(sender) = self.sender.lock().expect("the sender").as_ref()
            {
                let _ = sender.send(kr_protocol::envelope::ControlFrame::Response(response));
            }
            Box::pin(async { Ok(()) })
        }

        fn claim_receiver(&self) -> crate::Result<()> {
            Ok(())
        }

        fn recv(
            &self,
        ) -> crate::transport::TransportFuture<'_, Option<kr_protocol::envelope::ControlFrame>>
        {
            Box::pin(async move { Ok(self.frames.lock().await.recv().await) })
        }

        fn stream_opener(&self) -> Option<Arc<dyn crate::transport::StreamOpener>> {
            None
        }

        fn revoke_streams(&self) {}

        fn close(&self) {
            if self.sender.lock().expect("the sender").take().is_some() {
                *self.closed.lock().expect("the count") += 1;
            }
        }

        fn is_closed(&self) -> bool {
            self.sender.lock().expect("the sender").is_none()
        }
    }

    /// A fresh connection a scripted network lets open: from `from` on, a dial reaches the host at
    /// once over `connection`, and the host's surface there answers as `reply` says.
    struct Opening {
        from: tokio::time::Instant,
        connection: Connection,
        reply: Reply,
    }

    /// A network that drops every new connection, each dial failing `fail_after` after it began,
    /// until `opening` lets one open.
    struct Dropping {
        fail_after: Duration,
        dials: Arc<Mutex<usize>>,
        opening: Option<Opening>,
        waiting: PairStatusResult,
        /// When the refusals waited for on fresh connections reached the device.
        fresh_answered: Arc<Mutex<Vec<tokio::time::Instant>>>,
        /// What each connection as the paired device does, in turn; past the end it is lost.
        paired: Mutex<VecDeque<Paired>>,
        /// When each such connection was tried, and how many sessions it started and had closed.
        connects: Arc<Mutex<Vec<tokio::time::Instant>>>,
        sessions: Arc<Mutex<usize>>,
        closed: Arc<Mutex<usize>>,
        checkpoint: Checkpoint,
        names: Names,
        requests: Requests,
        /// The device's store, and what it held at each request.
        watch: PathBuf,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl HostLink for Dropping {
        fn dial<'a>(
            &'a self,
            _network: &'a kr_protocol::pairing::NetworkConfig,
            _endpoint: &'a EndpointKey,
        ) -> BoxFuture<'a, Result<Connection, LinkError>> {
            *self.dials.lock().expect("the count") += 1;
            if let Some(opening) = self
                .opening
                .as_ref()
                .filter(|opening| tokio::time::Instant::now() >= opening.from)
            {
                let connection = opening.connection.clone();
                return Box::pin(async move { Ok(connection) });
            }
            let after = self.fail_after;
            Box::pin(async move {
                tokio::time::sleep(after).await;
                Err(LinkError::Lost(
                    "the network dropped the connection".to_owned(),
                ))
            })
        }

        fn open_unpaired<'a>(
            &'a self,
            _connection: &'a Connection,
            _identity: &'a LocalIdentity,
        ) -> BoxFuture<'a, Result<Box<dyn Preauth>, LinkError>> {
            let opening = self
                .opening
                .as_ref()
                .expect("only an opening dial succeeds");
            let surface = Scripted {
                reply: opening.reply.clone(),
                asked: Arc::new(Mutex::new(Vec::new())),
                answered: Arc::clone(&self.fresh_answered),
                waiting: self.waiting.clone(),
            };
            Box::pin(async move { Ok(Box::new(surface) as Box<dyn Preauth>) })
        }

        fn connect_paired_transport<'a>(
            &'a self,
            _host: &'a HostCredentials,
            identity: &'a LocalIdentity,
        ) -> BoxFuture<'a, Result<Arc<dyn crate::transport::ControlTransport>, LinkError>> {
            self.connects
                .lock()
                .expect("the record")
                .push(tokio::time::Instant::now());
            let script = self
                .paired
                .lock()
                .expect("the script")
                .pop_front()
                .unwrap_or(Paired::Lost);
            let refused = |code: ErrorCode| {
                kr_protocol::error::ProtocolError::new(code, "the connection is refused")
            };
            let session = match script {
                Paired::Refused(code) => {
                    return Box::pin(async move { Err(LinkError::Refused(refused(code))) });
                }
                Paired::Lost => {
                    return Box::pin(async {
                        Err(LinkError::Lost("the connection was lost".to_owned()))
                    });
                }
                Paired::Declined => {
                    return Box::pin(async move {
                        Err(LinkError::Declined(refused(ErrorCode::RateLimited)))
                    });
                }
                Paired::ConnectionRefused => {
                    return Box::pin(async move {
                        Err(LinkError::ConnectionRefused(refused(
                            ErrorCode::ResourceUnavailable,
                        )))
                    });
                }
                Paired::Membership => {
                    return Box::pin(async move {
                        Err(LinkError::Membership(
                            refused(ErrorCode::PermissionDenied),
                            crate::retry::user_action(ErrorCode::PermissionDenied),
                        ))
                    });
                }
                Paired::Blocks => return Box::pin(std::future::pending()),
                other => other,
            };
            let connection = {
                let mut sessions = self.sessions.lock().expect("the count");
                *sessions += 1;
                *sessions
            };
            let (sender, frames) = mpsc::unbounded_channel();
            let transport = PairedSession {
                script: session,
                device_id: identity.device_id,
                sender: std::sync::Mutex::new(Some(sender)),
                frames: tokio::sync::Mutex::new(frames),
                closed: Arc::clone(&self.closed),
                checkpoint: self.checkpoint.clone(),
                names: self.names.clone(),
                connection,
                requests: Arc::clone(&self.requests),
                watch: self.watch.clone(),
                seen: Arc::clone(&self.seen),
            };
            Box::pin(async move {
                Ok(Arc::new(transport) as Arc<dyn crate::transport::ControlTransport>)
            })
        }

        fn forget_host<'a>(&'a self, _host: &'a PairedHost) -> BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    /// A room a waiting device never opens.
    struct NoRoom;

    impl CandidateRoom for NoRoom {
        fn open<'a>(
            &'a self,
            _origin: &'a RendezvousOrigin,
            _locator: &'a Locator,
        ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
            unreachable!("a waiting device opens no room")
        }
    }

    /// A device's clock whose wall clock moves with the runtime's paused clock, from `wall_ms` at
    /// `start`.
    struct Following {
        start: tokio::time::Instant,
        wall_ms: u64,
    }

    impl PairingClock for Following {
        fn monotonic_ms(&self) -> u64 {
            u64::try_from(self.start.elapsed().as_millis()).expect("a short run")
        }

        fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
            kr_pairing::platform::BootIdentity([0; 32])
        }

        fn wall_clock_ms(&self) -> u64 {
            self.wall_ms + self.monotonic_ms()
        }
    }

    /// What a scripted run of the waiting loop faces.
    struct Script {
        /// How the host answers on the connection the device holds from the start.
        held: Reply,
        /// How long a dial that fails takes to fail.
        fail_after: Duration,
        /// A fresh connection that opens, when one does.
        opening: Option<(Duration, Connection, Reply)>,
        /// How long after the start the attempt's own deadline falls.
        deadline: Duration,
        /// What each connection as the paired device does, in turn.
        paired: Vec<Paired>,
        /// How long after the start the connection held from the start was opened: a connection
        /// opened later has its last call later, so a case that needs the device to go on asking
        /// on it past a minute has it opened as late as it needs.
        held_opened: Duration,
        /// Whether the grant the host committed lets the device manage the host.
        owner: bool,
        /// How the host answers `backup.checkpoint`.
        checkpoint: Checkpoint,
        /// What `checkpoints.json` holds before the run, when it holds anything.
        file: Option<Vec<u8>>,
        /// How the host answers `environment.list`.
        names: Names,
        /// What the device keeps of the waiting attempt when the run starts.
        attempt: Attempt,
        /// An earlier run, which this run goes on with.
        again: Option<Earlier>,
        /// How the run begins.
        start: Start,
    }

    impl Script {
        /// Answers after `answer_after`, dials failing after `fail_after`, and a deadline far off.
        fn waiting(answer_after: Duration, fail_after: Duration) -> Self {
            Self {
                held: Reply::Waiting(answer_after),
                fail_after,
                opening: None,
                deadline: Duration::from_secs(300),
                paired: Vec::new(),
                held_opened: Duration::ZERO,
                owner: false,
                checkpoint: Checkpoint::Unserved,
                file: None,
                names: Names::Unserved,
                attempt: Attempt::Absent,
                again: None,
                start: Start::Waiting,
            }
        }
    }

    /// What a scripted run of the waiting loop did.
    struct Waited {
        /// When each status question went on the connection held from the start, counted from 0 s.
        asked: Vec<Duration>,
        /// How many dials the device made.
        dials: usize,
        /// Whether the loop ended within the run.
        ended: bool,
        /// How the attempt ended, when it did within the run.
        outcome: Option<Result<PairedHost, PairingFailure>>,
        /// When each connection as the paired device was tried, counted from 0 s.
        connects: Vec<Duration>,
        /// How many sessions those connections started, and how many were closed.
        sessions: usize,
        closed: usize,
        /// How many refusals waited for on fresh connections reached the device.
        fresh_answered: usize,
        /// Whether a record of the host was written.
        record: bool,
        /// The identity the device derived for itself.
        derived: DeviceId,
        /// Each request the paired connections received: the connection's number and the method.
        requests: Vec<(usize, String)>,
        /// How long the run took on the paused clock.
        elapsed: Duration,
        /// The records the run wrote, which stay while this does.
        hosts: Arc<PairedHosts>,
        /// What the store held at each request the paired connections received.
        seen: Vec<Seen>,
        /// The folder of the store and the keys of the device and of the host, which a later run
        /// can go on with.
        directory: tempfile::TempDir,
        keys: DeviceKeys,
        host_keys: kr_protocol::pairing::DevicePublicKeys,
    }

    impl Waited {
        /// What a later run goes on with.
        fn earlier(self) -> Earlier {
            Earlier {
                directory: self.directory,
                keys: self.keys,
                host_keys: self.host_keys,
            }
        }
    }

    /// Runs the waiting loop for `run` on a paused clock, on a connection the device began to open
    /// at 0 s after a direct invitation's challenge and proof, facing `script`. The owner never
    /// decides.
    async fn waited(mut script: Script, run: Duration) -> Waited {
        let start = tokio::time::Instant::now();
        let clock = Arc::new(Following {
            start,
            wall_ms: 1_764_000_000_000,
        });
        let now_ms = clock.wall_clock_ms();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let dials = Arc::new(Mutex::new(0));
        let connects = Arc::new(Mutex::new(Vec::new()));
        let sessions = Arc::new(Mutex::new(0));
        let closed = Arc::new(Mutex::new(0));
        let fresh_answered = Arc::new(Mutex::new(Vec::new()));
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let Earlier {
            directory,
            keys,
            host_keys: host,
        } = script.again.take().unwrap_or_else(|| Earlier {
            directory: tempfile::tempdir().expect("a directory on the internal disk"),
            keys: DeviceKeys::generate().expect("keys"),
            host_keys: DeviceKeys::generate().expect("keys").public_keys(),
        });
        let watch = directory.path().join("pairing");
        let value = "f3c146fd".to_owned();
        let waiting = PairStatusResult {
            status: PairStatus::AwaitingApproval {
                attempt_id: AttemptId::new(Uuid::from_bytes([5; 16])),
                verification_value: value.clone(),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(now_ms + 240_000),
            },
            owner: kr_protocol::scalars::Nullable::null(),
        };
        let host_endpoint_id = script.opening.as_ref().map_or(host.transport, |opening| {
            ConnectionPeer::of(&opening.1).endpoint()
        });
        let pending = PendingAttempt {
            mode: AttemptMode::Direct,
            invitation_id: InvitationId::new(Uuid::from_bytes([4; 16])),
            host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            host_key_revision: DeviceKeyRevision::new(1),
            host_endpoint_id,
            host_keys: host,
            network_config: kr_protocol::pairing::NetworkConfig::empty(),
            proposed_grant: kr_protocol::pairing::ProposedGrant {
                parent_grant_id: kr_protocol::scalars::Nullable::null(),
                environment_selector: kr_protocol::grant::EnvironmentSelector::Any,
                session_selector: kr_protocol::grant::SessionSelector::Any,
                actions: if script.owner {
                    [ActionRight::HostManage].into_iter().collect()
                } else {
                    [ActionRight::SessionView].into_iter().collect()
                },
                history: kr_protocol::grant::HistoryScope {
                    lower_bound_ms: kr_protocol::scalars::Nullable::null(),
                    include_live_screen: true,
                    named_questions: kr_protocol::scalars::CanonicalSet::new(),
                    named_approvals: kr_protocol::scalars::CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: kr_protocol::scalars::Nullable::null(),
            },
            verification_value: value,
            value_confirmed: true,
            expires_at_ms: Some(now_ms + 240_000),
            recover_until_ms: now_ms
                + u64::try_from(script.deadline.as_millis()).expect("a short deadline"),
            tries_left: None,
        };
        let opening = script.opening.map(|(from, connection, reply)| Opening {
            from: start + from,
            connection,
            reply,
        });
        let pairing = Pairing {
            candidate: Candidate::new(
                keys.clone(),
                DeviceName::new("A test computer").expect("a name"),
                DevicePlatform::Macos,
                BuildId::new("kr-test/0").expect("a build identifier"),
            ),
            budget: Arc::new(kr_pairing::platform::TestClientBudgetStore::new().expect("a budget")),
            clock,
            room: Arc::new(NoRoom),
            link: Arc::new(Dropping {
                fail_after: script.fail_after,
                dials: Arc::clone(&dials),
                opening,
                waiting: waiting.clone(),
                fresh_answered: Arc::clone(&fresh_answered),
                paired: Mutex::new(script.paired.into()),
                connects: Arc::clone(&connects),
                sessions: Arc::clone(&sessions),
                closed: Arc::clone(&closed),
                checkpoint: script.checkpoint.clone(),
                names: script.names.clone(),
                requests: Arc::clone(&requests),
                watch: watch.clone(),
                seen: Arc::clone(&seen),
            }),
            hosts: Arc::new(PairedHosts::open(&watch).expect("a store")),
        };
        match script.attempt {
            Attempt::Absent => {}
            Attempt::Kept => pairing
                .hosts
                .keep_attempt(&pending)
                .expect("the attempt is kept"),
            Attempt::Stuck => {
                std::fs::create_dir(watch.join("attempt.json")).expect("a folder in its place");
            }
        }
        if let Some(bytes) = &script.file {
            kr_ipc::paths::write_owner_only_file(
                &pairing.hosts.directory().join("checkpoints.json"),
                bytes,
            )
            .expect("a file");
        }
        let held = Unpaired::scripted(
            Box::new(Scripted {
                reply: script.held,
                asked: Arc::clone(&asked),
                answered: Arc::new(Mutex::new(Vec::new())),
                waiting,
            }),
            start + script.held_opened,
            2,
        );
        let (progress, _shown) = watch::channel(AttemptState::Idle);
        let outcome = match script.start {
            Start::Waiting => {
                tokio::time::timeout(run, pairing.waiting(pending, Some(held), &progress))
                    .await
                    .ok()
            }
            Start::Resumed { recorded } => {
                if recorded {
                    pairing
                        .hosts
                        .record(PairedHost {
                            host_device_id: pending.host_device_id,
                            host_key_revision: pending.host_key_revision,
                            host_keys: pending.host_keys,
                            host_endpoint_id: pending.host_endpoint_id,
                            network_config: pending.network_config.clone(),
                            device_id: pairing
                                .candidate
                                .derived_identity(pending.invitation_id)
                                .expect("an identity")
                                .device_id,
                            grant_id: kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16])),
                            proposed_grant: pending.proposed_grant.clone(),
                            name: None,
                            paired_at_ms: now_ms,
                            device_key_revision: DeviceKeyRevision::new(1),
                        })
                        .expect("the host is recorded");
                }
                tokio::time::timeout(run, pairing.resume(&progress))
                    .await
                    .ok()
                    .flatten()
            }
        };
        let elapsed = start.elapsed();
        let asked = asked
            .lock()
            .expect("the record")
            .iter()
            .map(|sent| *sent - start)
            .collect();
        let dials = *dials.lock().expect("the count");
        let connects = connects
            .lock()
            .expect("the record")
            .iter()
            .map(|tried| *tried - start)
            .collect();
        let derived = pairing
            .candidate
            .derived_identity(InvitationId::new(Uuid::from_bytes([4; 16])))
            .expect("an identity")
            .device_id;
        let record = pairing
            .hosts
            .by_device(DeviceId::new(Uuid::from_bytes([1; 16])))
            .ok()
            .flatten()
            .is_some();
        let (sessions, closed) = (
            *sessions.lock().expect("the count"),
            *closed.lock().expect("the count"),
        );
        let fresh_answered = fresh_answered.lock().expect("the record").len();
        Waited {
            asked,
            dials,
            ended: outcome.is_some(),
            outcome,
            connects,
            sessions,
            closed,
            fresh_answered,
            record,
            derived,
            requests: requests.lock().expect("the log").clone(),
            elapsed,
            hosts: Arc::clone(&pairing.hosts),
            seen: seen.lock().expect("the log").clone(),
            directory,
            keys,
            host_keys: host,
        }
    }

    /// Checks one run of [`waited`] whose deadline is far off: nothing goes on the connection after
    /// its last call and the grace a timer is given, the kept question goes inside that second, and
    /// the device makes a bounded number of dials.
    fn kept_its_last_call(waited: &Waited, run: &str) {
        let call = UNPAIRED_LIFE - LAST_CALL_MARGIN;
        let late = call + LAST_CALL_GRACE;
        let asked = &waited.asked;
        assert!(
            !waited.ended,
            "{run}: the owner never decides, so the device is still waiting"
        );
        assert!(
            asked.iter().all(|sent| *sent <= late),
            "{run}: a question went after the last call: {asked:?}"
        );
        assert!(
            asked.iter().any(|sent| *sent >= call && *sent <= late),
            "{run}: the question kept for the last call did not go at it: {asked:?}"
        );
        assert!(waited.dials < 40, "{run}: {} dials", waited.dials);
    }

    /// KR-REQ-10.23: the waiting loop itself, on a paused clock, where every answer takes the whole
    /// ten seconds a device waits for one. Questions go at 0, 13 and 26 seconds, a look for a fresh
    /// connection at 39 seconds fails at 40, and a question then would be answered as the last call
    /// comes at 50. The device keeps that question for the call, and asks it there.
    #[tokio::test(start_paused = true)]
    async fn the_loop_keeps_a_question_whose_answer_comes_with_the_last_call() {
        let run = waited(
            Script::waiting(WAIT_STEP, Duration::from_secs(1)),
            Duration::from_secs(70),
        )
        .await;
        kept_its_last_call(&run, "answers after 10 s, dials failing after 1 s");
        assert!(
            !run.asked.contains(&Duration::from_secs(40)),
            "a question went at 40 s: {:?}",
            run.asked
        );
    }

    /// KR-REQ-10.23: the waiting loop on a paused clock, across answers that take from no time to
    /// the whole ten seconds a device waits for one, and fresh connections that fail at once or
    /// take up to longer than a dial may. On every run the question kept for the last call goes
    /// inside the second after the call, nothing goes after it, and the device never spins.
    #[tokio::test(start_paused = true)]
    async fn the_loop_is_free_for_every_last_call() {
        let millis = |value: u64| Duration::from_millis(value);
        let answers = [
            0, 1_000, 2_000, 2_500, 3_000, 4_000, 5_000, 6_000, 7_000, 7_500, 8_000, 9_000, 9_500,
            9_900, 10_000,
        ];
        let dials = [
            0, 500, 1_000, 1_500, 2_000, 3_000, 5_000, 9_500, 10_000, 12_000,
        ];
        for answer_after in answers {
            for fail_after in dials {
                let run = waited(
                    Script::waiting(millis(answer_after), millis(fail_after)),
                    Duration::from_secs(70),
                )
                .await;
                kept_its_last_call(
                    &run,
                    &format!(
                        "answers after {answer_after} ms, dials failing after {fail_after} ms"
                    ),
                );
            }
        }
    }

    /// KR-REQ-10.23: after the attempt's own last call the device keeps the pause a host that turns
    /// questions away as too soon asks for. Here the attempt ends at 30 seconds, so its last call
    /// is at 20, before the connection's at 50, and the host turns every question away a second
    /// after it went. The device asks the question kept for 20 seconds, is turned away at 21, and
    /// asks nothing more before its deadline: a pause of twenty-two seconds outlasts it. Reading the
    /// present moment as the attempt's call would ask again at 21, 22 and 23 seconds.
    #[tokio::test(start_paused = true)]
    async fn after_the_attempts_last_call_a_refusal_keeps_its_pause() {
        let run = waited(
            Script {
                held: Reply::TooSoon(Duration::from_secs(1)),
                fail_after: Duration::ZERO,
                opening: None,
                deadline: Duration::from_secs(30),
                ..Script::waiting(Duration::ZERO, Duration::ZERO)
            },
            Duration::from_secs(70),
        )
        .await;
        assert!(run.ended, "the attempt ends at its deadline");
        let call = Duration::from_secs(20);
        let after_the_call: Vec<Duration> = run
            .asked
            .iter()
            .copied()
            .filter(|sent| *sent >= call)
            .collect();
        assert_eq!(
            after_the_call,
            [call],
            "only the question kept for the attempt's last call goes after it: {:?}",
            run.asked
        );
    }

    /// A connection made to a peer on loopback and then closed, which a scripted network hands out
    /// as a fresh connection that reached the host. Nothing is sent on it.
    async fn a_finished_connection() -> Connection {
        let peer_key = kr_crypto::keys::TransportIdentityKeyPair::generate().expect("a key");
        let mut config = kr_transport::config::EndpointConfig::from_network_config(
            &kr_protocol::pairing::NetworkConfig::empty(),
        )
        .expect("a config");
        config.bind_addr = Some("127.0.0.1:0".parse().expect("loopback"));
        let peer = kr_transport::endpoint::bind_listener(&config, &peer_key)
            .await
            .expect("a peer on loopback");
        let accepting = peer.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.expect("a connection arrives");
            incoming.await.expect("the connection completes")
        });
        let mut network = kr_protocol::pairing::NetworkConfig::empty();
        network.direct_addresses =
            [
                kr_protocol::pairing::NetworkHint::new(peer.bound_sockets()[0].to_string())
                    .expect("a hint"),
            ]
            .into_iter()
            .collect();
        let pool = Arc::new(
            super::super::link::EndpointPool::new(
                kr_crypto::keys::TransportIdentityKeyPair::generate().expect("a key"),
            )
            .bound_to("127.0.0.1:0".parse().expect("loopback")),
        );
        let connection = super::super::link::IrohLink::new(Arc::clone(&pool))
            .dial(&network, peer_key.public())
            .await
            .expect("a connection to the peer");
        drop(accepted.await.expect("the peer's side"));
        pool.close().await;
        peer.close().await;
        connection
    }

    /// KR-REQ-10.23: a look for a fresh connection can end exactly as the held connection's last
    /// call comes, with the host turning the fresh connection's question away as too soon. That
    /// leaves the device a pause to keep between its questions, and the question kept for the call
    /// does not wait for it: it goes at 50 seconds. A device that slept out the pause first would
    /// come to the call eleven seconds late and let the connection go.
    #[tokio::test]
    async fn a_look_turned_away_at_the_last_call_does_not_hold_back_the_kept_question() {
        let connection = a_finished_connection().await;
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let run = waited(
            Script {
                held: Reply::Waiting(Duration::ZERO),
                fail_after: Duration::ZERO,
                opening: Some((
                    Duration::from_secs(40),
                    connection,
                    Reply::TooSoonAt(start + UNPAIRED_LIFE - LAST_CALL_MARGIN),
                )),
                deadline: Duration::from_secs(300),
                ..Script::waiting(Duration::ZERO, Duration::ZERO)
            },
            Duration::from_secs(70),
        )
        .await;
        kept_its_last_call(&run, "a fresh connection turned away at the call");
    }

    /// Runs the waiting loop on a paused clock, on a connection that answers every question as
    /// `held` says and is open for the whole run, while the paired connections go as `paired`
    /// says. The attempt's deadline falls `deadline` after the start.
    async fn recovering(
        held: Reply,
        paired: Vec<Paired>,
        deadline: Duration,
        run: Duration,
    ) -> Waited {
        waited(
            Script {
                held,
                deadline,
                paired,
                held_opened: Duration::from_secs(1000),
                ..Script::waiting(Duration::ZERO, Duration::ZERO)
            },
            run,
        )
        .await
    }

    const SECOND: Duration = Duration::from_secs(1);

    fn ended_paired(waited: &Waited) -> bool {
        matches!(waited.outcome, Some(Ok(_)))
    }

    /// The kind of failure the attempt ended with; none when it has not ended or ended paired.
    fn failure_kind(waited: &Waited) -> Option<FailureKind> {
        match &waited.outcome {
            Some(Err(failure)) => Some(failure.kind),
            _ => None,
        }
    }

    /// KR-REQ-10.37: a refusal of the status question with `PERMISSION_DENIED` starts a recovery:
    /// the device connects as the identity derived for it, the host answers it there, and it ends
    /// paired with that identity and a record.
    #[tokio::test(start_paused = true)]
    async fn a_permission_denied_status_refusal_starts_one_recovery_that_ends_paired() {
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            vec![Paired::Committed],
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .await;
        let Some(Ok(host)) = &run.outcome else {
            panic!("the attempt ends paired: {:?}", run.outcome);
        };
        assert_eq!(
            host.device_id, run.derived,
            "the device is the one derived for it"
        );
        assert!(run.record, "the record of the host was written");
        assert_eq!(
            run.connects.len(),
            1,
            "one connection was enough: {:?}",
            run.connects
        );
        assert_eq!(run.sessions, run.closed, "no session was left open");
    }

    /// KR-REQ-10.37: a recovery that loses all four of its connections does not end the attempt.
    /// The device returns to the wait, rests longer after each recovery lost in a row, and a later
    /// refusal starts another, which succeeds. The refusal that starts a recovery is a word from the
    /// host and does not reset the count: the rests are three, four and eight seconds.
    #[tokio::test(start_paused = true)]
    async fn a_recovery_that_reaches_no_host_returns_to_the_wait_and_the_rest_grows() {
        let mut paired = vec![Paired::Lost; 12];
        paired.push(Paired::Committed);
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            paired,
            Duration::from_secs(300),
            Duration::from_secs(200),
        )
        .await;
        assert!(
            ended_paired(&run),
            "the attempt ends paired: {:?}",
            run.outcome
        );
        assert_eq!(
            run.connects.len(),
            13,
            "three whole recoveries and a fourth: {:?}",
            run.connects
        );
        // The last connection of each recovery and the first of the next: the rest between them.
        let rests =
            [(3, 4), (7, 8), (11, 12)].map(|(last, next)| run.connects[next] - run.connects[last]);
        assert!(rests[0] >= 3 * SECOND, "{rests:?}");
        assert!(rests[1] >= 4 * SECOND, "{rests:?}");
        assert!(
            rests[2] >= 8 * SECOND,
            "the rest after three lost recoveries is eight seconds: {rests:?}"
        );
    }

    /// KR-REQ-10.37: a connection the host refuses with a code that permits no retry is the host's
    /// word: the attempt ends as unknown, with nothing recorded.
    #[tokio::test(start_paused = true)]
    async fn a_refused_connect_of_a_recovery_ends_the_attempt_as_unknown() {
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            vec![
                Paired::Refused(ErrorCode::PermissionDenied),
                Paired::Committed,
            ],
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .await;
        assert_eq!(
            failure_kind(&run),
            Some(FailureKind::ApprovalUnknown),
            "{:?}",
            run.outcome
        );
        assert!(!run.record, "nothing was recorded");
        assert_eq!(run.connects.len(), 1, "the refusal is not asked again");
    }

    /// KR-REQ-10.37: a connection the host refuses with a code that permits a retry is not the
    /// host's word: the recovery connects again and ends paired.
    #[tokio::test(start_paused = true)]
    async fn a_refused_connect_of_a_recovery_with_a_transient_code_is_tried_again() {
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            vec![
                Paired::Refused(ErrorCode::ResourceUnavailable),
                Paired::Committed,
            ],
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .await;
        assert!(
            ended_paired(&run),
            "the attempt ends paired: {:?}",
            run.outcome
        );
        assert_eq!(run.connects.len(), 2, "{:?}", run.connects);
        assert!(run.record, "the record of the host was written");
    }

    /// KR-REQ-10.37: this device's own budget, the host's admission refusal, a membership lease the
    /// host does not hold and a connection lost are none of them the host's word about the
    /// commitment: the recovery connects again, within its tries.
    #[tokio::test(start_paused = true)]
    async fn a_connect_that_is_not_the_hosts_word_is_not_reached_and_is_tried_again() {
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            vec![
                Paired::Declined,
                Paired::ConnectionRefused,
                Paired::Membership,
                Paired::Committed,
            ],
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .await;
        assert!(
            ended_paired(&run),
            "the attempt ends paired: {:?}",
            run.outcome
        );
        assert_eq!(run.connects.len(), 4, "{:?}", run.connects);
    }

    /// KR-REQ-10.37: a question refused as too soon starts no recovery: the device rests and asks
    /// again.
    #[tokio::test(start_paused = true)]
    async fn a_rate_limited_refusal_starts_no_recovery() {
        let run = recovering(
            Reply::Refused(ErrorCode::RateLimited),
            vec![Paired::Committed],
            Duration::from_secs(300),
            Duration::from_secs(20),
        )
        .await;
        assert!(run.connects.is_empty(), "{:?}", run.connects);
        assert!(!run.ended);
    }

    /// KR-REQ-10.37: any other refusal is the host's word about the attempt, as it always was.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_with_another_code_ends_as_the_hosts_word() {
        let run = recovering(
            Reply::Refused(ErrorCode::PairingExpired),
            vec![Paired::Committed],
            Duration::from_secs(300),
            Duration::from_secs(20),
        )
        .await;
        assert_eq!(
            failure_kind(&run),
            Some(refused_by_host(ErrorCode::PairingExpired, true)),
            "{:?}",
            run.outcome
        );
        assert!(run.connects.is_empty(), "no recovery started");
    }

    /// KR-REQ-10.37: a status question that never answers ends by the attempt's deadline, with no
    /// session left open, and no record is written before the host answers as the authorised
    /// device.
    #[tokio::test(start_paused = true)]
    async fn a_status_question_that_never_answers_ends_by_the_deadline_with_no_record() {
        let run = recovering(
            Reply::Refused(ErrorCode::PermissionDenied),
            vec![Paired::Silent; 40],
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .await;
        assert_eq!(
            failure_kind(&run),
            Some(FailureKind::ApprovalUnknown),
            "{:?}",
            run.outcome
        );
        assert!(run.sessions > 0, "the question was reached");
        assert_eq!(run.sessions, run.closed, "no session was left open");
        assert!(!run.record, "no record before the authorised answer");
    }

    /// KR-REQ-10.37: a commitment the host named whose connect is refused with a code that permits
    /// no retry ends as unknown and keeps the record, which the host committed.
    #[tokio::test(start_paused = true)]
    async fn a_told_commitment_whose_connect_is_refused_ends_as_unknown_and_keeps_its_record() {
        let run = recovering(
            Reply::CommittedFrom(tokio::time::Instant::now()),
            vec![
                Paired::Refused(ErrorCode::PermissionDenied),
                Paired::Committed,
            ],
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .await;
        assert_eq!(
            failure_kind(&run),
            Some(FailureKind::ApprovalUnknown),
            "{:?}",
            run.outcome
        );
        assert!(run.record, "the record the host committed is kept");
        assert_eq!(run.connects.len(), 1);
    }

    /// KR-REQ-10.37: a first connection the host refuses as the connection (request zero) is no
    /// word about the commitment: the device connects again and ends paired, whether the host named
    /// the commitment or the device derived it.
    #[tokio::test(start_paused = true)]
    async fn a_connection_refused_as_the_connection_is_connected_again() {
        for held in [
            Reply::CommittedFrom(tokio::time::Instant::now()),
            Reply::Refused(ErrorCode::PermissionDenied),
        ] {
            let run = recovering(
                held.clone(),
                vec![
                    Paired::RefuseConnection(ErrorCode::PermissionDenied),
                    Paired::Committed,
                ],
                Duration::from_secs(300),
                Duration::from_secs(60),
            )
            .await;
            assert!(
                ended_paired(&run),
                "the attempt ends paired: {:?}",
                run.outcome
            );
            assert_eq!(run.connects.len(), 2, "{held:?}: {:?}", run.connects);
            assert!(run.record);
        }
    }

    /// KR-REQ-10.37: no refusal of the status question on the authorised session is the host's word
    /// about the commitment, whatever its code and whether or not it is the connection's: the
    /// device asks again on a new connection and ends paired.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_of_the_status_question_is_asked_again_whatever_its_code() {
        for code in [ErrorCode::ResourceUnavailable, ErrorCode::PermissionDenied] {
            for held in [
                Reply::CommittedFrom(tokio::time::Instant::now()),
                Reply::Refused(ErrorCode::PermissionDenied),
            ] {
                let run = recovering(
                    held.clone(),
                    vec![Paired::Refuse(code), Paired::Committed],
                    Duration::from_secs(300),
                    Duration::from_secs(60),
                )
                .await;
                assert!(
                    ended_paired(&run),
                    "{code:?} {held:?}: the attempt ends paired: {:?}",
                    run.outcome
                );
                assert_eq!(
                    run.connects.len(),
                    2,
                    "{code:?} {held:?}: {:?}",
                    run.connects
                );
            }
        }
    }

    /// KR-REQ-10.37: a host that answers the authorised session with anything but the commitment
    /// the device expects is not believed. A device that derived its identity ends as unknown
    /// with no record; a device the host told keeps the mismatch it always had.
    #[tokio::test(start_paused = true)]
    async fn an_answer_that_is_not_the_expected_commitment_is_not_believed() {
        let stranger = DeviceId::new(Uuid::from_bytes([0x66; 16]));
        let awaiting = PairStatus::AwaitingApproval {
            attempt_id: AttemptId::new(Uuid::from_bytes([5; 16])),
            verification_value: "f3c146fd".to_owned(),
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        };
        for answer in [Paired::Status(awaiting), Paired::CommittedAs(stranger)] {
            let derived = recovering(
                Reply::Refused(ErrorCode::PermissionDenied),
                vec![answer.clone()],
                Duration::from_secs(300),
                Duration::from_secs(60),
            )
            .await;
            assert_eq!(
                failure_kind(&derived),
                Some(FailureKind::ApprovalUnknown),
                "{answer:?}: {:?}",
                derived.outcome
            );
            assert!(!derived.record, "{answer:?}: nothing was recorded");
            let told = recovering(
                Reply::CommittedFrom(tokio::time::Instant::now()),
                vec![answer.clone()],
                Duration::from_secs(300),
                Duration::from_secs(60),
            )
            .await;
            // The held connection names a device ([7; 16]) that the second answer repeats only for
            // the identity it was built with, so a `Told` device meets a mismatch on both.
            assert_eq!(
                failure_kind(&told),
                Some(FailureKind::HostMismatch),
                "{answer:?}: {:?}",
                told.outcome
            );
        }
    }

    /// Runs the waiting loop as [`a_look_turned_away_at_the_last_call_does_not_hold_back_the_kept_question`]
    /// does, except that the held connection answers `Committed` from its last call and the fresh
    /// connection the device looks for at 40 seconds is refused with `PERMISSION_DENIED` at
    /// `refused_at`. The recovery's connections go as `paired` says.
    async fn refused_at(refused_at: Duration) -> Waited {
        let connection = a_finished_connection().await;
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        waited(
            Script {
                held: Reply::CommittedFrom(start + UNPAIRED_LIFE - LAST_CALL_MARGIN),
                fail_after: Duration::ZERO,
                opening: Some((
                    Duration::from_secs(40),
                    connection,
                    Reply::RefusedAt(start + refused_at),
                )),
                deadline: Duration::from_secs(300),
                paired: vec![
                    Paired::Blocks,
                    Paired::Lost,
                    Paired::Lost,
                    Paired::Lost,
                    Paired::Lost,
                ],
                held_opened: Duration::ZERO,
                owner: false,
                checkpoint: Checkpoint::Unserved,
                file: None,
                names: Names::Unserved,
                attempt: Attempt::Absent,
                again: None,
                start: Start::Waiting,
            },
            Duration::from_secs(120),
        )
        .await
    }

    /// What the cases of the held connection's kept question check after the run: the question
    /// went at the call, the host's answer to it was believed, and the later failed connections
    /// left the record the host committed and ended the attempt as the host being unreachable.
    fn kept_question_was_asked_and_its_answer_kept(run: &Waited) {
        let call = UNPAIRED_LIFE - LAST_CALL_MARGIN;
        assert!(
            run.asked
                .iter()
                .any(|sent| *sent >= call && *sent <= call + LAST_CALL_GRACE),
            "the question kept for the last call did not go at it: {:?}",
            run.asked
        );
        assert_eq!(failure_kind(run), Some(FailureKind::HostUnreachable));
        assert!(run.record, "the record the host committed is kept");
    }

    /// KR-REQ-10.37: a refusal on a fresh connection that comes before the held connection's last
    /// call starts a recovery that ends by that call. The connection it makes never answers, so the
    /// recovery is abandoned at the call, the held connection's kept question goes and is answered
    /// `committed`, and the record is written. The connections made after it fail, and the attempt
    /// ends as the host being unreachable, with the record kept.
    #[tokio::test]
    async fn a_recovery_that_meets_the_last_call_leaves_the_kept_question_to_go() {
        let run = refused_at(Duration::from_secs(45)).await;
        assert_eq!(run.fresh_answered, 1, "the refusal reached the device");
        let call = UNPAIRED_LIFE - LAST_CALL_MARGIN;
        assert!(
            run.connects[0] < call,
            "the recovery started before the call: {:?}",
            run.connects
        );
        kept_question_was_asked_and_its_answer_kept(&run);
    }

    /// KR-REQ-10.37: a refusal that reaches the device at the held connection's last call, when the
    /// question that connection keeps for it has not gone, starts no recovery before that question:
    /// the device makes no connection as the paired device until the question has gone.
    #[tokio::test]
    async fn a_refusal_at_the_last_call_starts_no_recovery_before_the_kept_question() {
        let call = UNPAIRED_LIFE - LAST_CALL_MARGIN;
        let run = refused_at(call).await;
        assert_eq!(
            run.fresh_answered, 1,
            "the refusal reached the device at the call, and did not time out"
        );
        let kept = run
            .asked
            .iter()
            .copied()
            .find(|sent| *sent >= call)
            .expect("the kept question went");
        assert!(
            run.connects.iter().all(|tried| *tried >= kept),
            "a connection as the paired device was made before the kept question: {:?} / {:?}",
            run.connects,
            run.asked
        );
        kept_question_was_asked_and_its_answer_kept(&run);
    }

    fn named(generation: u64) -> kr_protocol::backup_checkpoint::HostCheckpoint {
        kr_protocol::backup_checkpoint::HostCheckpoint {
            service_origin: kr_protocol::service::GatewayOrigin::new("https://reach.kala.to")
                .expect("an origin"),
            archive_id: kr_protocol::ids::ArchiveId::new(Uuid::from_bytes([1; 16])),
            backup_generation: kr_protocol::ids::BackupGeneration::new(generation),
            encrypted_manifest_hash: kr_protocol::scalars::Digest256::from_bytes([1; 32]),
        }
    }

    fn published(generation: u64) -> Checkpoint {
        Checkpoint::Published(named(generation))
    }

    /// The script of a recovery for a device the host committed, whose host answers
    /// `backup.checkpoint` as `checkpoint` says. A `told` commitment is the one the host named,
    /// and the other is the one the device derived for itself.
    fn committing_script(
        told: bool,
        owner: bool,
        checkpoint: Checkpoint,
        file: Option<Vec<u8>>,
    ) -> Script {
        let held = if told {
            Reply::CommittedFrom(tokio::time::Instant::now())
        } else {
            Reply::Refused(ErrorCode::PermissionDenied)
        };
        Script {
            held,
            deadline: Duration::from_secs(300),
            paired: vec![Paired::Committed, Paired::Committed],
            held_opened: Duration::from_secs(1000),
            owner,
            checkpoint,
            file,
            ..Script::waiting(Duration::ZERO, Duration::ZERO)
        }
    }

    /// Runs [`committing_script`] on a paused clock.
    async fn committing(
        told: bool,
        owner: bool,
        checkpoint: Checkpoint,
        file: Option<Vec<u8>>,
    ) -> Waited {
        waited(
            committing_script(told, owner, checkpoint, file),
            Duration::from_secs(60),
        )
        .await
    }

    fn paired_host(run: &Waited) -> PairedHost {
        match &run.outcome {
            Some(Ok(host)) => host.clone(),
            other => panic!("the attempt ends paired: {other:?}"),
        }
    }

    fn methods(run: &Waited) -> Vec<(usize, &str)> {
        run.requests
            .iter()
            .map(|(connection, method)| (*connection, method.as_str()))
            .collect()
    }

    /// KR-REQ-20.12: an owner device the host committed reads the host's checkpoint once, after the
    /// name and on the connection that proved the commitment, and keeps it, whether the host named
    /// the commitment or the device derived it.
    #[tokio::test(start_paused = true)]
    async fn an_owner_reads_the_hosts_checkpoint_after_the_name_on_the_proofs_connection() {
        for told in [false, true] {
            let run = committing(told, true, published(7), None).await;
            assert!(
                ended_paired(&run),
                "the attempt ends paired: {:?}",
                run.outcome
            );
            let host = paired_host(&run);
            assert_eq!(
                methods(&run),
                vec![
                    (1, "pair.status"),
                    (1, "environment.list"),
                    (1, "backup.checkpoint")
                ],
                "told {told}"
            );
            let checkpoints = run.hosts.checkpoints();
            let held = checkpoints.held_checkpoints();
            assert!(
                matches!(&held, Held::Read { entries, owed: 0 } if entries.len() == 1
                    && entries[0].backup_generation.get() == 7),
                "told {told}: {held:?}"
            );
            assert_eq!(
                checkpoints.acquisition(&host),
                Ok(Acquisition::Told),
                "told {told}"
            );
        }
    }

    /// KR-REQ-20.12: a device that does not manage the host sends no checkpoint request and keeps
    /// no file.
    #[tokio::test(start_paused = true)]
    async fn a_device_that_does_not_manage_the_host_asks_it_nothing() {
        let run = committing(false, false, published(7), None).await;
        assert!(
            ended_paired(&run),
            "the attempt ends paired: {:?}",
            run.outcome
        );
        let host = paired_host(&run);
        assert!(
            methods(&run)
                .iter()
                .all(|(_, method)| *method != "backup.checkpoint"),
            "{:?}",
            run.requests
        );
        assert!(!run.hosts.directory().join("checkpoints.json").exists());
        assert_eq!(
            run.hosts.checkpoints().acquisition(&host),
            Ok(Acquisition::NotAnOwner)
        );
    }

    /// KR-REQ-20.12: a host that has accepted no generation says so, and is not owed an answer; the
    /// state needs another read.
    #[tokio::test(start_paused = true)]
    async fn a_host_with_nothing_published_is_not_owed_and_needs_another_read() {
        let run = committing(false, true, Checkpoint::Null, None).await;
        assert!(
            ended_paired(&run),
            "the attempt ends paired: {:?}",
            run.outcome
        );
        let host = paired_host(&run);
        let checkpoints = run.hosts.checkpoints();
        assert_eq!(
            checkpoints.acquisition(&host),
            Ok(Acquisition::NothingPublished)
        );
        assert!(matches!(
            checkpoints.held_checkpoints(),
            Held::Read { ref entries, owed: 0 } if entries.is_empty()
        ));
    }

    /// KR-REQ-20.12: a host that cannot answer, refuses, answers wrongly or answers nothing leaves
    /// the pairing complete and the host owed, the read is attempted once, and a read that gets no
    /// answer is cut at its own bound and not the longer one of a recovery step.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_gets_no_answer_leaves_the_pairing_complete_and_the_host_owed() {
        let cases = [
            ("a host of an earlier release", Checkpoint::Unserved),
            ("a refusal", Checkpoint::Refuse(ErrorCode::InvalidArgument)),
            ("generation 0", Checkpoint::Zero),
            ("no answer", Checkpoint::Silent),
            ("a connection lost", Checkpoint::Lost),
            (
                "an answer under another request identifier",
                Checkpoint::WrongId(named(7)),
            ),
        ];
        for (name, checkpoint) in cases {
            let run = committing(false, true, checkpoint, None).await;
            assert!(
                ended_paired(&run),
                "the attempt ends paired: {:?}",
                run.outcome
            );
            let host = paired_host(&run);
            let asked = methods(&run)
                .iter()
                .filter(|(_, method)| *method == "backup.checkpoint")
                .count();
            assert_eq!(asked, 1, "{name}: the read is attempted once");
            assert_eq!(
                run.hosts.checkpoints().acquisition(&host),
                Ok(Acquisition::Owed),
                "{name}"
            );
            assert!(
                !run.hosts.directory().join("checkpoints.json").exists(),
                "{name}: nothing is written"
            );
            assert!(
                run.elapsed < Duration::from_secs(8),
                "{name}: the read is cut at its own bound: {:?}",
                run.elapsed
            );
        }
    }

    /// KR-REQ-20.12: a file this release cannot read stops the checkpoint from being kept and
    /// does not fail the pairing.
    #[tokio::test(start_paused = true)]
    async fn a_checkpoint_that_cannot_be_kept_does_not_fail_the_pairing() {
        let newer = br#"{"version":2,"checkpoints":[],"told":[]}"#.to_vec();
        for told in [false, true] {
            for (name, bytes, cause) in [
                (
                    "a file that is not JSON",
                    b"{".to_vec(),
                    SnapshotCause::Unreadable,
                ),
                (
                    "a file of a newer version",
                    newer.clone(),
                    SnapshotCause::NewerVersion,
                ),
            ] {
                let run = committing(told, true, published(7), Some(bytes.clone())).await;
                assert!(
                    ended_paired(&run),
                    "told {told}, {name}: the attempt ends paired: {:?}",
                    run.outcome
                );
                let host = paired_host(&run);
                assert_eq!(
                    run.hosts.checkpoints().acquisition(&host),
                    Err(cause),
                    "told {told}, {name}"
                );
                assert_eq!(
                    std::fs::read(run.hosts.directory().join("checkpoints.json"))
                        .expect("the file"),
                    bytes,
                    "told {told}, {name}: the file is as it was"
                );
            }
        }
    }

    /// KR-REQ-20.12: a host that answered nothing published stays not owed when a later read
    /// fails, and the file is as it was.
    #[tokio::test(start_paused = true)]
    async fn a_failed_read_after_an_answer_of_nothing_published_leaves_that_answer() {
        for told in [false, true] {
            let first = committing(told, true, Checkpoint::Null, None).await;
            assert!(ended_paired(&first), "told {told}: {:?}", first.outcome);
            let kept =
                std::fs::read(first.hosts.directory().join("checkpoints.json")).expect("the file");
            let mut again = committing_script(told, true, Checkpoint::Silent, None);
            again.again = Some(first.earlier());
            let second = waited(again, Duration::from_secs(60)).await;
            assert!(ended_paired(&second), "told {told}: {:?}", second.outcome);
            assert_eq!(
                methods(&second)
                    .iter()
                    .filter(|(_, method)| *method == "backup.checkpoint")
                    .count(),
                1,
                "told {told}: a second read is made"
            );
            assert_eq!(
                second
                    .hosts
                    .checkpoints()
                    .acquisition(&paired_host(&second)),
                Ok(Acquisition::NothingPublished),
                "told {told}"
            );
            assert_eq!(
                std::fs::read(second.hosts.directory().join("checkpoints.json")).expect("the file"),
                kept,
                "told {told}: the file is as it was"
            );
        }
    }

    /// The records of paired hosts a run left.
    fn recorded(run: &Waited) -> Vec<PairedHost> {
        read_hosts(run.hosts.directory()).expect("the records are read")
    }

    /// What the store held when `method` first reached the host in `run`, as (hosts recorded,
    /// attempt kept, answers told).
    fn store_at(run: &Waited, method: &str) -> (usize, bool, usize) {
        let seen = run
            .seen
            .iter()
            .find(|seen| seen.method == method)
            .expect("the request was made");
        (seen.hosts, seen.attempt, seen.told)
    }

    /// KR-REQ-20.12: a host that gives its name and then takes no answer to the checkpoint keeps
    /// the name it gave, the read comes after the name, and the read is cut at its own bound.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_waits_leaves_the_name_the_host_gave() {
        for told in [false, true] {
            let mut script = committing_script(told, true, Checkpoint::Silent, None);
            script.names = Names::Label("a real host");
            let run = waited(script, Duration::from_secs(60)).await;
            assert!(
                ended_paired(&run),
                "told {told}: the attempt ends paired: {:?}",
                run.outcome
            );
            assert_eq!(
                paired_host(&run).name.as_deref(),
                Some("a real host"),
                "told {told}"
            );
            assert_eq!(
                recorded(&run)[0].name.as_deref(),
                Some("a real host"),
                "told {told}: the record holds it"
            );
            assert_eq!(
                methods(&run),
                vec![
                    (1, "pair.status"),
                    (1, "environment.list"),
                    (1, "backup.checkpoint")
                ],
                "told {told}"
            );
            assert!(
                run.elapsed < Duration::from_secs(8),
                "told {told}: the read is cut at its own bound: {:?}",
                run.elapsed
            );
            assert_eq!(
                run.hosts.checkpoints().acquisition(&paired_host(&run)),
                Ok(Acquisition::Owed),
                "told {told}"
            );
        }
    }

    /// KR-REQ-20.12: the host is recorded before its checkpoint is asked for, the waiting attempt
    /// stands until the answer is kept, and it is cleared after: the early record of both forms of
    /// the commitment, and the stops between the record, the read, the settle and the clear.
    #[tokio::test(start_paused = true)]
    async fn the_host_is_recorded_before_it_is_asked_and_the_attempt_stands_until_it_is_kept() {
        for told in [false, true] {
            let mut script = committing_script(told, true, published(7), None);
            script.names = Names::Label("a real host");
            script.attempt = Attempt::Kept;
            let run = waited(script, Duration::from_secs(60)).await;
            assert!(
                ended_paired(&run),
                "told {told}: the attempt ends paired: {:?}",
                run.outcome
            );
            assert_eq!(
                store_at(&run, "pair.status"),
                (usize::from(told), true, 0),
                "told {told}: at the proof"
            );
            assert_eq!(
                store_at(&run, "environment.list"),
                (1, true, 0),
                "told {told}: at the name"
            );
            assert_eq!(
                store_at(&run, "backup.checkpoint"),
                (1, true, 0),
                "told {told}: at the read"
            );
            assert!(
                !run.hosts.directory().join("attempt.json").exists(),
                "told {told}: the attempt is cleared at the end"
            );
            assert_eq!(
                run.hosts.checkpoints().acquisition(&paired_host(&run)),
                Ok(Acquisition::Told),
                "told {told}"
            );
        }
    }

    /// KR-REQ-20.12: an answer that is kept stands when the attempt cannot be cleared, and the
    /// device that goes on with the attempt asks again and changes the file by not one byte.
    #[tokio::test(start_paused = true)]
    async fn an_answer_kept_before_the_attempt_is_cleared_stands_and_a_second_read_changes_nothing()
    {
        for told in [false, true] {
            let mut script = committing_script(told, true, published(7), None);
            script.attempt = Attempt::Stuck;
            let first = waited(script, Duration::from_secs(60)).await;
            assert_eq!(
                failure_kind(&first),
                Some(FailureKind::StoreFailed),
                "told {told}: {:?}",
                first.outcome
            );
            assert!(
                matches!(first.hosts.checkpoints().held_checkpoints(),
                    Held::Read { ref entries, owed: 0 } if entries.len() == 1),
                "told {told}: the answer is kept and the host is not owed"
            );
            assert_eq!(
                recorded(&first).len(),
                1,
                "told {told}: the host is recorded"
            );
            assert!(
                first.hosts.directory().join("attempt.json").is_dir(),
                "told {told}: the attempt stands"
            );
            let kept =
                std::fs::read(first.hosts.directory().join("checkpoints.json")).expect("the file");
            std::fs::remove_dir(first.hosts.directory().join("attempt.json"))
                .expect("the folder this case made");

            let mut again = committing_script(told, true, published(7), None);
            again.attempt = Attempt::Kept;
            again.again = Some(first.earlier());
            let second = waited(again, Duration::from_secs(60)).await;
            assert!(
                ended_paired(&second),
                "told {told}: the attempt ends paired: {:?}",
                second.outcome
            );
            assert_eq!(
                methods(&second)
                    .iter()
                    .filter(|(_, method)| *method == "backup.checkpoint")
                    .count(),
                1,
                "told {told}: the device asks again"
            );
            assert_eq!(
                std::fs::read(second.hosts.directory().join("checkpoints.json")).expect("the file"),
                kept,
                "told {told}: the same answer changes nothing"
            );
            assert!(
                !second.hosts.directory().join("attempt.json").exists(),
                "told {told}: the attempt is cleared"
            );
        }
    }

    /// KR-REQ-20.12: an owner device that resumes the attempt it kept asks the host for its
    /// checkpoint as a first run does, through the host's record when the device wrote one before it
    /// stopped and as the device it derived when it did not, and clears the attempt once the answer
    /// is kept.
    #[tokio::test]
    async fn a_resumed_attempt_reads_the_hosts_checkpoint_and_clears_the_attempt() {
        let connection = a_finished_connection().await;
        tokio::time::pause();
        for recorded in [false, true] {
            let mut script = committing_script(true, true, published(7), None);
            script.names = Names::Label("a real host");
            script.attempt = Attempt::Kept;
            script.start = Start::Resumed { recorded };
            if !recorded {
                script.opening = Some((
                    Duration::ZERO,
                    connection.clone(),
                    Reply::Refused(ErrorCode::PermissionDenied),
                ));
            }
            let run = waited(script, Duration::from_secs(60)).await;
            assert!(
                ended_paired(&run),
                "recorded {recorded}: the attempt ends paired: {:?}",
                run.outcome
            );
            assert_eq!(
                methods(&run),
                vec![
                    (1, "pair.status"),
                    (1, "environment.list"),
                    (1, "backup.checkpoint")
                ],
                "recorded {recorded}"
            );
            assert_eq!(
                store_at(&run, "pair.status"),
                (usize::from(recorded), true, 0),
                "recorded {recorded}: at the proof"
            );
            assert_eq!(
                store_at(&run, "backup.checkpoint"),
                (1, true, 0),
                "recorded {recorded}: at the read"
            );
            let checkpoints = run.hosts.checkpoints();
            assert_eq!(
                checkpoints.acquisition(&paired_host(&run)),
                Ok(Acquisition::Told),
                "recorded {recorded}"
            );
            assert!(
                matches!(checkpoints.held_checkpoints(),
                    Held::Read { ref entries, owed: 0 } if entries.len() == 1
                        && entries[0].backup_generation.get() == 7),
                "recorded {recorded}: the checkpoint is kept"
            );
            assert!(
                !run.hosts.directory().join("attempt.json").exists(),
                "recorded {recorded}: the attempt is cleared"
            );
        }
    }

    /// KR-REQ-20.12: an attempt that stood after its answer was kept is resumed through the host's
    /// record, the host is asked again, the file does not change by one byte and the attempt is
    /// cleared.
    #[tokio::test(start_paused = true)]
    async fn a_resumed_attempt_whose_answer_was_kept_changes_nothing_and_is_cleared() {
        for told in [false, true] {
            let mut script = committing_script(told, true, published(7), None);
            script.attempt = Attempt::Stuck;
            let first = waited(script, Duration::from_secs(60)).await;
            assert_eq!(
                failure_kind(&first),
                Some(FailureKind::StoreFailed),
                "told {told}: {:?}",
                first.outcome
            );
            let kept =
                std::fs::read(first.hosts.directory().join("checkpoints.json")).expect("the file");
            std::fs::remove_dir(first.hosts.directory().join("attempt.json"))
                .expect("the folder this case made");

            let mut again = committing_script(told, true, published(7), None);
            again.attempt = Attempt::Kept;
            again.start = Start::Resumed { recorded: false };
            again.again = Some(first.earlier());
            let second = waited(again, Duration::from_secs(60)).await;
            assert!(
                ended_paired(&second),
                "told {told}: the attempt ends paired: {:?}",
                second.outcome
            );
            assert_eq!(
                methods(&second),
                vec![
                    (1, "pair.status"),
                    (1, "environment.list"),
                    (1, "backup.checkpoint")
                ],
                "told {told}"
            );
            assert_eq!(
                store_at(&second, "pair.status"),
                (1, true, 1),
                "told {told}: the record and the answer stand at the proof"
            );
            assert_eq!(
                std::fs::read(second.hosts.directory().join("checkpoints.json")).expect("the file"),
                kept,
                "told {told}: the same answer changes nothing"
            );
            assert_eq!(
                second
                    .hosts
                    .checkpoints()
                    .acquisition(&paired_host(&second)),
                Ok(Acquisition::Told),
                "told {told}"
            );
            assert!(
                !second.hosts.directory().join("attempt.json").exists(),
                "told {told}: the attempt is cleared"
            );
        }
    }

    /// KR-REQ-20.12: an attempt resumed after its time has passed makes no connection and no read,
    /// and the host stays recorded and owed.
    #[tokio::test(start_paused = true)]
    async fn a_resumed_attempt_past_its_time_asks_nothing_and_leaves_the_host_owed() {
        let mut script = committing_script(true, true, published(7), None);
        script.deadline = Duration::ZERO;
        script.attempt = Attempt::Kept;
        script.start = Start::Resumed { recorded: true };
        let run = waited(script, Duration::from_secs(60)).await;
        assert_eq!(
            failure_kind(&run),
            Some(FailureKind::HostUnreachable),
            "{:?}",
            run.outcome
        );
        assert!(run.connects.is_empty(), "{:?}", run.connects);
        assert!(run.requests.is_empty(), "{:?}", run.requests);
        let hosts = recorded(&run);
        assert_eq!(hosts.len(), 1, "the host stays recorded");
        assert_eq!(
            run.hosts.checkpoints().acquisition(&hosts[0]),
            Ok(Acquisition::Owed)
        );
        assert!(!run.hosts.directory().join("checkpoints.json").exists());
        assert!(
            !run.hosts.directory().join("attempt.json").exists(),
            "the attempt is cleared"
        );
    }

    /// KR-REQ-20.12: a recovery that has no time left before its reserve makes no read, and the
    /// host stays recorded and owed.
    #[tokio::test]
    async fn a_recovery_with_no_time_left_makes_no_read_and_leaves_the_host_owed() {
        let connection = a_finished_connection().await;
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let run = waited(
            Script {
                held: Reply::CommittedFrom(start + UNPAIRED_LIFE - LAST_CALL_MARGIN),
                fail_after: Duration::ZERO,
                opening: Some((
                    Duration::from_secs(40),
                    connection,
                    Reply::RefusedAt(start + Duration::from_secs(45)),
                )),
                deadline: Duration::from_secs(300),
                paired: vec![Paired::Committed, Paired::Committed],
                held_opened: Duration::ZERO,
                owner: true,
                checkpoint: published(7),
                file: None,
                names: Names::Silent,
                attempt: Attempt::Absent,
                again: None,
                start: Start::Waiting,
            },
            Duration::from_secs(120),
        )
        .await;
        assert!(
            methods(&run)
                .iter()
                .any(|(_, method)| *method == "environment.list"),
            "the recovery reached the name, which the host never gave: {:?}",
            run.requests
        );
        assert!(
            methods(&run)
                .iter()
                .all(|(_, method)| *method != "backup.checkpoint"),
            "{:?}",
            run.requests
        );
        let hosts = recorded(&run);
        assert_eq!(hosts.len(), 1, "the host is recorded");
        assert_eq!(
            run.hosts.checkpoints().acquisition(&hosts[0]),
            Ok(Acquisition::Owed)
        );
        assert!(!run.hosts.directory().join("checkpoints.json").exists());
    }

    /// KR-REQ-20.12: a recovery that has less time before its reserve than the read's own bound
    /// ends the read by the reserve: a host that never answers does not keep it past that, and the
    /// host stays recorded and owed.
    #[tokio::test]
    async fn a_read_with_less_time_left_than_its_bound_ends_by_the_reserve() {
        let connection = a_finished_connection().await;
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let reserve = UNPAIRED_LIFE - LAST_CALL_MARGIN;
        let run = waited(
            Script {
                held: Reply::CommittedFrom(start + reserve),
                fail_after: Duration::ZERO,
                // The recovery starts when the refusal arrives, two seconds before the reserve.
                opening: Some((
                    Duration::from_secs(40),
                    connection,
                    Reply::RefusedAt(start + reserve - Duration::from_secs(2)),
                )),
                deadline: Duration::from_secs(300),
                paired: vec![Paired::Committed, Paired::Committed],
                held_opened: Duration::ZERO,
                owner: true,
                checkpoint: Checkpoint::Silent,
                file: None,
                names: Names::Label("a real host"),
                attempt: Attempt::Absent,
                again: None,
                start: Start::Waiting,
            },
            Duration::from_secs(120),
        )
        .await;
        assert!(
            methods(&run)
                .iter()
                .any(|(_, method)| *method == "backup.checkpoint"),
            "the read was made: {:?}",
            run.requests
        );
        // `CHECKPOINT_WITHIN` is a second longer than the time the recovery has left.
        assert!(
            run.elapsed < reserve + Duration::from_millis(500),
            "the read ends by the reserve, not at its own bound: {:?}",
            run.elapsed
        );
        let hosts = recorded(&run);
        assert_eq!(hosts.len(), 1, "the host is recorded");
        assert_eq!(
            run.hosts.checkpoints().acquisition(&hosts[0]),
            Ok(Acquisition::Owed)
        );
    }

    /// KR-REQ-20.12: a proof that fails, because the host names another device or refuses the
    /// question, is followed by no read of the checkpoint and by no file.
    #[tokio::test(start_paused = true)]
    async fn a_proof_that_fails_is_followed_by_no_read_and_no_file() {
        let other = DeviceId::new(Uuid::from_bytes([77; 16]));
        for told in [false, true] {
            for (name, step) in [
                ("another device is named", Paired::CommittedAs(other)),
                (
                    "the question is refused",
                    Paired::Refuse(ErrorCode::PermissionDenied),
                ),
            ] {
                let mut script = committing_script(told, true, published(7), None);
                script.paired = vec![step.clone(), step.clone(), step.clone(), step.clone()];
                let run = waited(script, Duration::from_secs(60)).await;
                assert!(
                    methods(&run)
                        .iter()
                        .any(|(_, method)| *method == "pair.status"),
                    "told {told}, {name}: the proof was asked for"
                );
                assert!(
                    methods(&run)
                        .iter()
                        .all(|(_, method)| *method != "backup.checkpoint"),
                    "told {told}, {name}: {:?}",
                    run.requests
                );
                assert!(
                    !run.hosts.directory().join("checkpoints.json").exists(),
                    "told {told}, {name}"
                );
            }
        }
    }

    /// An answer of an earlier pairing of the host, left in the file.
    fn earlier_pairings_answer() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "checkpoints": [],
            "told": [{
                "host_device_id": DeviceId::new(Uuid::from_bytes([1; 16])),
                "device_id": DeviceId::new(Uuid::from_bytes([9; 16])),
                "answer": "checkpoint",
                "at_ms": 5
            }]
        }))
        .expect("bytes")
    }

    /// KR-REQ-20.12: an answer of an earlier pairing, left in the file, does not stop the read for
    /// the new one and does not stand for it.
    #[tokio::test(start_paused = true)]
    async fn an_answer_of_an_earlier_pairing_does_not_stop_the_read() {
        let stale = earlier_pairings_answer();
        let run = committing(false, true, Checkpoint::Unserved, Some(stale.clone())).await;
        assert!(ended_paired(&run), "{:?}", run.outcome);
        assert_eq!(
            methods(&run)
                .iter()
                .filter(|(_, method)| *method == "backup.checkpoint")
                .count(),
            1,
            "the host is asked"
        );
        assert_eq!(
            run.hosts.checkpoints().acquisition(&paired_host(&run)),
            Ok(Acquisition::Owed),
            "the earlier pairing's answer is not this pairing's"
        );

        let run = committing(false, true, published(7), Some(stale)).await;
        assert!(ended_paired(&run), "{:?}", run.outcome);
        assert_eq!(
            run.hosts.checkpoints().acquisition(&paired_host(&run)),
            Ok(Acquisition::Told)
        );
        let file: serde_json::Value = serde_json::from_slice(
            &std::fs::read(run.hosts.directory().join("checkpoints.json")).expect("the file"),
        )
        .expect("a file");
        assert_eq!(
            file["told"].as_array().map(Vec::len),
            Some(1),
            "the earlier pairing's answer is dropped"
        );
    }

    /// Every log event written while it is the default subscriber, as the text of its fields.
    #[derive(Clone, Default)]
    struct Logged(Arc<Mutex<Vec<String>>>);

    struct FieldText(String);

    impl tracing::field::Visit for FieldText {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={value:?} ", field.name()));
        }
    }

    impl tracing::Subscriber for Logged {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = FieldText(String::new());
            event.record(&mut fields);
            self.0.lock().expect("the record").push(fields.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Every event that a scripted owner recovery writes, for a host that answers `checkpoint` and
    /// a file that holds `file`.
    async fn events_of(checkpoint: Checkpoint, file: Option<Vec<u8>>) -> Vec<String> {
        let logged = Logged::default();
        // With one registered dispatcher a rebuild of the log calls' interest on another thread reads
        // that thread's default alone, which drops this thread's events: a second one ends that.
        let dispatch = tracing::Dispatch::new(logged.clone());
        let _second = tracing::Dispatch::new(Logged::default());
        let guard = tracing::dispatcher::set_default(&dispatch);
        let run = committing(false, true, checkpoint, file).await;
        drop(guard);
        assert!(ended_paired(&run), "{:?}", run.outcome);
        logged.0.lock().expect("the record").clone()
    }

    /// A checkpoints file that holds the checkpoint `named` makes for `generation`, with a manifest
    /// of `manifest` bytes.
    fn holding(generation: u64, manifest: u8) -> Vec<u8> {
        let given = named(generation);
        let held = PairedCheckpoint {
            service_origin: given.service_origin,
            archive_id: given.archive_id,
            backup_generation: given.backup_generation,
            encrypted_manifest_hash: kr_protocol::scalars::Digest256::from_bytes([manifest; 32]),
            taken_at_ms: 5,
        };
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "checkpoints": [held],
            "told": []
        }))
        .expect("bytes")
    }

    /// KR-REQ-20.12: the log of a read the host refused holds the cause and not the host's words.
    #[tokio::test(start_paused = true)]
    async fn the_log_of_a_refused_read_holds_its_cause_and_not_the_hosts_words() {
        let events = events_of(Checkpoint::Refuse(ErrorCode::InvalidArgument), None).await;
        assert!(
            events
                .iter()
                .any(|event| event.contains("could not be read")
                    && event.contains("Refused(InvalidArgument)")),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .all(|event| !event.contains("the question is refused")),
            "{events:?}"
        );
    }

    /// KR-REQ-20.12: the log names why a read gave no answer, and what a settle left standing or
    /// could not save, with no word of the host's.
    #[tokio::test(start_paused = true)]
    async fn the_log_names_the_cause_of_a_read_and_what_a_settle_left_standing() {
        let rows = [
            (
                "a host that does not serve the method",
                Checkpoint::Unserved,
                None,
                vec!["could not be read", "cause=HostLacksIt"],
            ),
            (
                "a connection lost",
                Checkpoint::Lost,
                None,
                vec!["could not be read", "cause=Lost"],
            ),
            (
                "a lower generation",
                published(7),
                Some(holding(9, 1)),
                vec!["named a lower backup generation than this device holds"],
            ),
            (
                "another manifest",
                published(7),
                Some(holding(7, 2)),
                vec!["named another manifest than this device holds"],
            ),
            (
                "a file that cannot be read",
                published(7),
                Some(b"{".to_vec()),
                vec![
                    "could not be saved, and the pairing stands",
                    "cause=Unreadable(Unreadable)",
                ],
            ),
        ];
        for (name, checkpoint, file, texts) in rows {
            let events = events_of(checkpoint, file).await;
            for text in texts {
                assert!(
                    events.iter().any(|event| event.contains(text)),
                    "{name}: no event holds {text:?}: {events:?}"
                );
            }
            assert!(
                events
                    .iter()
                    .all(|event| !event.contains("the method is not served")),
                "{name}: {events:?}"
            );
        }
    }

    /// An attempt says its stage and when it expires, and never the verification value, a host's
    /// name or what the host said.
    #[test]
    fn an_attempt_says_its_stage_and_never_what_it_was_told() {
        const MARKER: &str = "kr-marker-7c1e";
        assert_eq!(format!("{:?}", AttemptState::Idle), "Idle");
        assert_eq!(
            format!(
                "{:?}",
                AttemptState::Working {
                    stage: Stage::ReachingService
                }
            ),
            "Working { stage: ReachingService }"
        );
        let awaiting = AttemptState::AwaitingApproval {
            value: MARKER.to_owned(),
            expires_at_ms: Some(1),
            rights: Vec::new(),
            authority: MARKER.to_owned(),
            grant_expires_at_ms: None,
        };
        assert_eq!(
            format!("{awaiting:?}"),
            "AwaitingApproval { expires_at_ms: Some(1), rights: [], grant_expires_at_ms: None, .. }"
        );
        let reconnecting = AttemptState::Reconnecting {
            value: Some(MARKER.to_owned()),
            expires_at_ms: None,
        };
        assert_eq!(
            format!("{reconnecting:?}"),
            "Reconnecting { expires_at_ms: None, .. }"
        );
        let paired = AttemptState::Paired {
            host: HostView {
                name: Some(MARKER.to_owned()),
                owner: true,
                authority: MARKER.to_owned(),
                grant_expires_at_ms: None,
            },
        };
        assert_eq!(format!("{paired:?}"), "Paired { .. }");
    }
}
