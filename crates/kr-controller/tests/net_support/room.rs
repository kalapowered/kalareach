//! An in-process rendezvous room, and a candidate that pairs through it.
//!
//! The room keeps the service's contract where a host and a candidate can both be watched: a
//! reservation is atomic per locator and names its invitation, the host attaches by proving the
//! control token, a candidate is served the record and declares its attempt, every relayed frame
//! reaches the other side of its own attempt unread, the host closing an attempt ends that
//! candidate, and a release ends every socket on the record. Every frame either side sends crosses
//! the room's wire encoding on the way, so a frame the service could not read fails here too. The
//! service's admission budgets are its own suite's to prove.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use iroh::EndpointAddr;
use kr_client::pairing::room::RoomSocket;
use kr_controller::service::net::pairing::HostPairingClock;
use kr_controller::service::net::rendezvous::Rendezvous;
use kr_crypto::secret::SymmetricKey;
use kr_pairing::PairingError;
use kr_pairing::bundles::BundleFrame;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::platform::{LocatorRecord, RendezvousHost, TestClient, TestClientBudgetStore};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, ClientBundle, Locator, NetworkConfig, RendezvousOrigin,
    SignedHostBundle,
};
use kr_protocol::preauth::PairFinishResult;
use kr_protocol::rendezvous::{
    ClientFrame, CloseReason, ServiceFrame, decode_client_frame, decode_message, encode_frame,
    encode_message,
};
use kr_protocol::scalars::{Bytes, Digest256, EndpointKey, Mac256, TimestampMs};
use kr_transport::handshake::{self, CandidateConnection};
use kr_transport::listener::BoxFuture;
use tokio::sync::mpsc;

use super::pairing::{Candidate, HostPeer};

/// How many frames wait on one socket before its sender waits.
const DEPTH: usize = 64;

/// How long a test waits for the room to deliver one frame.
const FRAME_WAIT: Duration = Duration::from_secs(10);

/// How long a test waits for a host to hold its room: it fails a wait that never ends, and is not
/// a measurement.
const HOSTING_DEADLINE: Duration = Duration::from_secs(120);

/// An in-process rendezvous service with one room per reserved locator.
#[derive(Clone, Debug)]
pub struct TestRoom {
    rooms: Arc<Mutex<Rooms>>,
    /// True while the room holds back what hosts send, as a slow service does.
    held: Arc<tokio::sync::watch::Sender<bool>>,
    /// Woken each time a host attaches to a record, each time a record is released and each time
    /// the room takes a frame from a host to hold it back.
    hosting: Arc<tokio::sync::Notify>,
}

impl Default for TestRoom {
    fn default() -> Self {
        Self {
            rooms: Arc::default(),
            held: Arc::new(tokio::sync::watch::channel(false).0),
            hosting: Arc::default(),
        }
    }
}

#[derive(Debug, Default)]
struct Rooms {
    records: BTreeMap<String, Record>,
    released: Vec<String>,
    release_requests: Vec<String>,
    unreachable: bool,
    /// How many frames the room has taken from a host and held back since it last began to.
    withheld: usize,
}

#[derive(Debug)]
struct Record {
    invitation_id: InvitationId,
    expires_at_ms: u64,
    token_hash: Digest256,
    host: Option<mpsc::Sender<ServiceFrame>>,
    /// Whether a host has attached to this record, now or earlier.
    hosted: bool,
    attempts: BTreeMap<AttemptId, mpsc::Sender<ServiceFrame>>,
}

fn hash(token: &SymmetricKey) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(token.expose()))
}

impl TestRoom {
    /// Creates a service with no reservations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds back, or lets through, every frame hosts send, in the order they were sent.
    ///
    /// A control request is not held, which is how a release could overtake frames a host sent
    /// before it if the host did not wait for the room to acknowledge them.
    pub fn hold_hosts(&self, held: bool) {
        if held {
            self.rooms().withheld = 0;
        }
        self.held.send_replace(held);
    }

    /// Makes every control request fail, as an unreachable service does.
    pub fn set_unreachable(&self, unreachable: bool) {
        self.rooms().unreachable = unreachable;
    }

    /// Returns the locators this service holds a record for.
    #[must_use]
    pub fn reserved(&self) -> Vec<String> {
        self.rooms().records.keys().cloned().collect()
    }

    /// Returns the locators released, in order.
    #[must_use]
    pub fn released(&self) -> Vec<String> {
        self.rooms().released.clone()
    }

    /// Returns the locator of every release a host asked for, in order, including one refused
    /// because the record was already gone.
    #[must_use]
    pub fn release_requests(&self) -> Vec<String> {
        self.rooms().release_requests.clone()
    }

    /// Waits until the host that reserved `locator` has attached to its room for the first time.
    ///
    /// A host reserves a locator and attaches to the room a moment later, on a task of its own, and
    /// a frame a candidate relays before then ends its attempt, as the service ends one that has no
    /// host to carry its frame. An invitation is on offer once its host holds the room, so a
    /// candidate that starts from the invitation's answer starts after this. A locator nobody holds
    /// a record for has no host to wait for, and neither has one whose record was released, or
    /// released and reserved again for another invitation, while the wait lasted. A host that
    /// attached once and went is not waited for again: what a candidate meets then is the room's
    /// own answer.
    ///
    /// # Panics
    ///
    /// Panics when no host attaches within [`HOSTING_DEADLINE`].
    pub async fn until_hosted(&self, locator: &str) {
        let waited = tokio::time::timeout(HOSTING_DEADLINE, async {
            // The invitation whose host is waited for, which is the one the record names when the
            // wait begins.
            let mut invitation = None;
            loop {
                // Asked to be woken before the record is read, so a change between the read and
                // the wait is not missed.
                let changed = self.hosting.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let pending = self.rooms().records.get(locator).is_some_and(|record| {
                    *invitation.get_or_insert(record.invitation_id) == record.invitation_id
                        && !record.hosted
                });
                if !pending {
                    return;
                }
                changed.await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "no host attached to the room of {locator} within {HOSTING_DEADLINE:?}"
        );
    }

    /// Waits until the host attached to `locator` has handed the room a frame that the room holds
    /// back, and waits on the room for what it sent.
    ///
    /// A host that has sent its last frames and waits for the room to confirm them reads whatever
    /// the room sends it, and a host that does not wait leaves its socket. So a frame the room sends
    /// after the one it holds is read only by a host that is still there and waiting, and this
    /// returns once it has been read: a host that ended an invitation has nothing left to do before
    /// it releases the locator but wait for the room, so the release has not been asked for and
    /// cannot be until the room speaks or the host's own limit on that wait
    /// (`rendezvous::CLOSE_ACKNOWLEDGEMENT`) runs out. The count of held frames is the room's, not
    /// the locator's: it is for a room with one host held back.
    ///
    /// # Panics
    ///
    /// Panics when the host leaves its socket or releases the locator first, and when nothing is
    /// held back or read within [`HOSTING_DEADLINE`].
    pub async fn until_host_waits(&self, locator: &str) {
        const LEFT: &str = "the host left its socket without waiting for the room";
        let waited = tokio::time::timeout(HOSTING_DEADLINE, async {
            loop {
                // Asked to be woken before the count is read, so a frame taken in between is not
                // missed.
                let changed = self.hosting.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.rooms().withheld > 0 {
                    break;
                }
                changed.await;
            }
            let (host, probe) = {
                let rooms = self.rooms();
                let record = rooms.records.get(locator).expect(LEFT);
                (
                    record.host.clone().expect(LEFT),
                    ServiceFrame::Attached {
                        invitation_id: record.invitation_id,
                        expires_at_ms: record.expires_at_ms,
                    },
                )
            };
            // A frame a host that waits ignores, sent behind everything the room has sent it. The
            // socket holds DEPTH frames, so all of its places are free again once the host has read
            // the probe.
            assert!(host.send(probe).await.is_ok(), "{LEFT}");
            tokio::select! {
                read = host.reserve_many(DEPTH) => assert!(read.is_ok(), "{LEFT}"),
                () = host.closed() => panic!("{LEFT}"),
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "the host of {locator} was not waiting on the room within {HOSTING_DEADLINE:?}"
        );
    }

    /// Opens a candidate socket in the room of `locator`.
    ///
    /// A locator with a record is served the record first; an unknown one is held and served
    /// nothing, as the service does.
    pub fn candidate(&self, locator: &str) -> RoomSocket {
        let (to_candidate, incoming) = mpsc::channel(DEPTH);
        let (outgoing, from_candidate) = mpsc::channel(DEPTH);
        if let Some(record) = self.rooms().records.get(locator) {
            let _ = to_candidate.try_send(ServiceFrame::Record {
                invitation_id: record.invitation_id,
                expires_at_ms: record.expires_at_ms,
            });
        }
        tokio::spawn(
            self.clone()
                .pump_candidate(locator.to_owned(), to_candidate, from_candidate),
        );
        RoomSocket { outgoing, incoming }
    }

    fn rooms(&self) -> MutexGuard<'_, Rooms> {
        self.rooms.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn attach_host(
        &self,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> kr_pairing::Result<RoomSocket> {
        let (to_host, incoming) = mpsc::channel(DEPTH);
        let (outgoing, from_host) = mpsc::channel(DEPTH);
        {
            let mut rooms = self.rooms();
            let record = rooms
                .records
                .get_mut(locator.as_str())
                .filter(|record| record.token_hash == hash(control_token))
                .ok_or_else(|| PairingError::RendezvousUnavailable {
                    reason: "the room did not accept this host".to_owned(),
                })?;
            if let Some(previous) = record.host.replace(to_host.clone()) {
                let _ = previous.try_send(ServiceFrame::Closed {
                    reason: CloseReason::Superseded,
                });
            }
            record.hosted = true;
            let _ = to_host.try_send(ServiceFrame::Attached {
                invitation_id: record.invitation_id,
                expires_at_ms: record.expires_at_ms,
            });
            for attempt_id in record.attempts.keys() {
                let _ = to_host.try_send(ServiceFrame::AttemptOpened {
                    attempt_id: *attempt_id,
                });
            }
        }
        self.hosting.notify_waiters();
        tokio::spawn(
            self.clone()
                .pump_host(locator.as_str().to_owned(), to_host, from_host),
        );
        Ok(RoomSocket { outgoing, incoming })
    }

    /// Carries what the host sends to the candidate of each attempt, and detaches the host when
    /// its socket ends.
    async fn pump_host(
        self,
        locator: String,
        to_host: mpsc::Sender<ServiceFrame>,
        mut from_host: mpsc::Receiver<ClientFrame>,
    ) {
        self.carry_host(&locator, &mut from_host).await;
        if let Some(record) = self.rooms().records.get_mut(&locator)
            && record
                .host
                .as_ref()
                .is_some_and(|host| host.same_channel(&to_host))
        {
            record.host = None;
        }
    }

    async fn carry_host(&self, locator: &str, from_host: &mut mpsc::Receiver<ClientFrame>) {
        let mut held = self.held.subscribe();
        while let Some(frame) = from_host.recv().await {
            let holding = *held.borrow();
            if holding {
                self.rooms().withheld += 1;
                self.hosting.notify_waiters();
            }
            if held.wait_for(|held| !*held).await.is_err() {
                return;
            }
            match on_the_wire(&frame) {
                ClientFrame::Relay {
                    attempt_id,
                    payload,
                } => {
                    let candidate = self.candidate_of(locator, attempt_id);
                    if let Some(candidate) = candidate {
                        let _ = candidate
                            .send(ServiceFrame::Relay {
                                attempt_id,
                                payload,
                            })
                            .await;
                    }
                }
                ClientFrame::CloseAttempt { attempt_id } => {
                    // The service's closing sequence: the host is told the attempt closed, and
                    // the candidate is sent its last frame.
                    let (candidate, host) = {
                        let mut rooms = self.rooms();
                        let record = rooms.records.get_mut(locator);
                        let host = record.as_ref().and_then(|record| record.host.clone());
                        (
                            record.and_then(|record| record.attempts.remove(&attempt_id)),
                            host,
                        )
                    };
                    if let Some(candidate) = candidate {
                        if let Some(host) = host {
                            let _ = host
                                .send(ServiceFrame::AttemptClosed {
                                    attempt_id,
                                    reason: CloseReason::Cancelled,
                                })
                                .await;
                        }
                        let _ = candidate
                            .send(ServiceFrame::Closed {
                                reason: CloseReason::Cancelled,
                            })
                            .await;
                    }
                }
                // Not a host's frame. The service would end the socket as invalid.
                ClientFrame::Attempt { .. } => return,
            }
        }
    }

    /// Carries what one candidate sends to the host, and tells the host when it ends.
    async fn pump_candidate(
        self,
        locator: String,
        to_candidate: mpsc::Sender<ServiceFrame>,
        mut from_candidate: mpsc::Receiver<ClientFrame>,
    ) {
        let mut declared = None;
        while let Some(frame) = from_candidate.recv().await {
            match on_the_wire(&frame) {
                ClientFrame::Attempt { attempt_id } if declared.is_none() => {
                    declared = Some(attempt_id);
                    let host = {
                        let mut rooms = self.rooms();
                        let Some(record) = rooms.records.get_mut(&locator) else {
                            continue;
                        };
                        record.attempts.insert(attempt_id, to_candidate.clone());
                        record.host.clone()
                    };
                    if let Some(host) = host {
                        let _ = host.send(ServiceFrame::AttemptOpened { attempt_id }).await;
                    }
                }
                ClientFrame::Relay {
                    attempt_id,
                    payload,
                } if declared == Some(attempt_id) => {
                    let (served, host) = {
                        let rooms = self.rooms();
                        let record = rooms.records.get(&locator);
                        (
                            record.is_some_and(|record| record.attempts.contains_key(&attempt_id)),
                            record.and_then(|record| record.host.clone()),
                        )
                    };
                    match (served, host) {
                        (true, Some(host)) => {
                            let carried = host
                                .send(ServiceFrame::Relay {
                                    attempt_id,
                                    payload,
                                })
                                .await;
                            if carried.is_err() {
                                let _ = to_candidate
                                    .send(ServiceFrame::Closed {
                                        reason: CloseReason::HostGone,
                                    })
                                    .await;
                            }
                        }
                        (true, None) => {
                            let _ = to_candidate
                                .send(ServiceFrame::Closed {
                                    reason: CloseReason::HostGone,
                                })
                                .await;
                        }
                        // The host closed this attempt; its later frames reach nobody.
                        (false, _) => {}
                    }
                }
                _ => {
                    let _ = to_candidate
                        .send(ServiceFrame::Closed {
                            reason: CloseReason::Invalid,
                        })
                        .await;
                    break;
                }
            }
        }
        let Some(attempt_id) = declared else {
            return;
        };
        let host = {
            let mut rooms = self.rooms();
            let Some(record) = rooms.records.get_mut(&locator) else {
                return;
            };
            record.attempts.remove(&attempt_id).and(record.host.clone())
        };
        if let Some(host) = host {
            let _ = host
                .send(ServiceFrame::AttemptClosed {
                    attempt_id,
                    reason: CloseReason::Cancelled,
                })
                .await;
        }
    }

    fn candidate_of(
        &self,
        locator: &str,
        attempt_id: AttemptId,
    ) -> Option<mpsc::Sender<ServiceFrame>> {
        self.rooms()
            .records
            .get(locator)
            .and_then(|record| record.attempts.get(&attempt_id).cloned())
    }
}

/// Sends a frame through the room's own encoding, which is what the service reads.
fn on_the_wire(frame: &ClientFrame) -> ClientFrame {
    let bytes = encode_frame(frame).expect("a frame the room can carry");
    decode_client_frame(&bytes).expect("and the room reads it back")
}

impl RendezvousHost for TestRoom {
    fn reserve_locator(
        &self,
        _origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
    ) -> kr_pairing::Result<bool> {
        let mut rooms = self.rooms();
        if rooms.unreachable {
            return Err(PairingError::RendezvousUnavailable {
                reason: "the test service is unreachable".to_owned(),
            });
        }
        if rooms.records.contains_key(locator.as_str()) {
            return Ok(false);
        }
        rooms.records.insert(
            locator.as_str().to_owned(),
            Record {
                invitation_id,
                expires_at_ms: advertised_expires_at_ms.get(),
                token_hash: control_token_hash,
                host: None,
                hosted: false,
                attempts: BTreeMap::new(),
            },
        );
        Ok(true)
    }

    fn release_locator(
        &self,
        _origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> kr_pairing::Result<()> {
        let mut rooms = self.rooms();
        rooms.release_requests.push(locator.as_str().to_owned());
        if rooms.unreachable {
            return Err(PairingError::RendezvousUnavailable {
                reason: "the test service is unreachable".to_owned(),
            });
        }
        let proven = rooms
            .records
            .get(locator.as_str())
            .is_some_and(|record| record.token_hash == hash(control_token));
        if !proven {
            return Err(PairingError::RendezvousUnavailable {
                reason: "no reservation is held for that locator and token".to_owned(),
            });
        }
        let record = rooms
            .records
            .remove(locator.as_str())
            .expect("the record was just read");
        rooms.released.push(locator.as_str().to_owned());
        self.hosting.notify_waiters();
        // Every socket attached to the record ends with it: each candidate's, which the host is
        // told about, and then the host's own.
        let closed = ServiceFrame::Closed {
            reason: CloseReason::Cancelled,
        };
        for (attempt_id, candidate) in record.attempts {
            if let Some(host) = &record.host {
                let _ = host.try_send(ServiceFrame::AttemptClosed {
                    attempt_id,
                    reason: CloseReason::Cancelled,
                });
            }
            let _ = candidate.try_send(closed.clone());
        }
        if let Some(host) = record.host {
            let _ = host.try_send(closed);
        }
        Ok(())
    }
}

impl kr_client::pairing::candidate::CandidateRoom for TestRoom {
    fn open<'a>(
        &'a self,
        _origin: &'a RendezvousOrigin,
        locator: &'a Locator,
    ) -> kr_client::pairing::BoxFuture<'a, Result<RoomSocket, kr_client::pairing::room::RoomError>>
    {
        Box::pin(async move {
            self.until_hosted(locator.as_str()).await;
            Ok(self.candidate(locator.as_str()))
        })
    }
}

impl Rendezvous for TestRoom {
    fn attach(
        &self,
        _origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>> {
        let attached = self.attach_host(locator, control_token);
        Box::pin(async move { attached })
    }
}

/// What the host answered a candidate with, when it did not go on.
#[derive(Debug, PartialEq, Eq)]
pub enum Stopped {
    /// The host refused the attempt with this code.
    Refused {
        /// The code.
        code: ErrorCode,
        /// The failed confirmations the invitation still allows.
        remaining: Option<u32>,
    },
    /// The room ended the socket.
    Closed(CloseReason),
    /// The candidate's own state machine refused a step.
    Local(ErrorCode),
}

/// One candidate running a short-code attempt through the room.
pub struct CodeCandidate<'a> {
    device: Candidate<'a>,
    socket: RoomSocket,
    client: ClientAttempt,
    clock: HostPairingClock,
    attempt_id: AttemptId,
    /// The confirmation tag computed from the host's PAKE message, not yet sent.
    pending_tag: Option<Mac256>,
    host_bundle: Option<SignedHostBundle>,
}

impl std::fmt::Debug for CodeCandidate<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeCandidate")
            .field("attempt_id", &self.attempt_id)
            .finish_non_exhaustive()
    }
}

impl<'a> CodeCandidate<'a> {
    /// Enters `code` for `origin`, reaches the room and runs the exchange up to the candidate's
    /// confirmation tag, which it has not sent yet.
    ///
    /// # Panics
    ///
    /// Panics when the room serves no record for the code's locator.
    pub async fn start(
        room: &TestRoom,
        device: Candidate<'a>,
        origin: &RendezvousOrigin,
        code: &str,
    ) -> Result<Self, Stopped> {
        let entered = EnteredCode::parse(code).map_err(|error| Stopped::Local(error.code()))?;
        room.until_hosted(entered.locator().as_str()).await;
        let mut socket = room.candidate(entered.locator().as_str());
        let ServiceFrame::Record {
            invitation_id,
            expires_at_ms,
        } = next(&mut socket).await?
        else {
            panic!("a candidate is served the record first");
        };
        let clock =
            HostPairingClock::new(&kr_ipc::identity::boot_identity().expect("a boot identity"));
        let budget = TestClientBudgetStore::new().expect("a budget store");
        let lookup = TestClient::new(LocatorRecord {
            invitation_id,
            advertised_expires_at_ms: TimestampMs::new(expires_at_ms),
        });
        let (client, admission, _) =
            ClientAttempt::start(&budget, &clock, &lookup, origin, &entered)
                .map_err(|error| Stopped::Local(error.code()))?;
        let attempt_id = admission.attempt_id;
        let mut candidate = Self {
            device,
            socket,
            client,
            clock,
            attempt_id,
            pending_tag: None,
            host_bundle: None,
        };
        candidate
            .socket
            .outgoing
            .send(ClientFrame::Attempt { attempt_id })
            .await
            .expect("the room takes the attempt");
        candidate
            .send(&RendezvousMessage::Admit {
                client_nonce: admission.client_nonce,
            })
            .await;
        let RendezvousMessage::HostPake {
            host_nonce,
            message,
        } = candidate.receive().await?
        else {
            panic!("an admitted candidate is answered with the host's PAKE message");
        };
        let client_pake = candidate
            .client
            .with_host_nonce(host_nonce, &candidate.clock)
            .map_err(|error| Stopped::Local(error.code()))?;
        candidate
            .send(&RendezvousMessage::ClientPake {
                message: Bytes::new(client_pake),
            })
            .await;
        // The candidate's tag is computed now and sent by `confirm`, so a test can hold several
        // candidates at this point and decide who goes first.
        let tag = candidate
            .client
            .receive_host_pake(message.as_slice(), &candidate.clock)
            .map_err(|error| Stopped::Local(error.code()))?;
        candidate.pending_tag = Some(tag);
        Ok(candidate)
    }

    /// Returns the attempt this candidate made.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Sends the confirmation tag and takes the host's answer: its own tag and its sealed bundle,
    /// which the candidate verifies and opens.
    pub async fn confirm(&mut self) -> Result<(), Stopped> {
        let tag = self.pending_tag.take().expect("an attempt confirms once");
        self.send(&RendezvousMessage::ClientConfirmation { tag })
            .await;
        let RendezvousMessage::HostConfirmation { tag } = self.receive().await? else {
            panic!("a confirmed candidate is answered with the host's tag");
        };
        self.client
            .verify_host_confirmation(&tag, &self.clock)
            .map_err(|error| Stopped::Local(error.code()))?;
        let RendezvousMessage::Bundle {
            sequence,
            nonce,
            ciphertext,
        } = self.receive().await?
        else {
            panic!("the host's tag is followed by its bundle");
        };
        let opened = self
            .client
            .open_host_bundle(
                &BundleFrame {
                    direction: BundleDirection::HostToClient,
                    sequence,
                    message_type: BundleMessageType::HostBundle,
                    nonce,
                    ciphertext: ciphertext.into_vec(),
                },
                &self.clock,
            )
            .map_err(|error| Stopped::Local(error.code()))?;
        self.host_bundle = Some(opened);
        Ok(())
    }

    /// Sends the candidate's sealed bundle and waits for the host to accept it.
    pub async fn send_bundle(&mut self) -> Result<(), Stopped> {
        let bundle = ClientBundle {
            endpoint_id: self.device.declared.endpoint_id,
            keys: self.device.declared.keys,
            device_key_revision: self.device.declared.device_key_revision,
            device_name: self.device.declared.device_name.clone(),
            platform: self.device.declared.platform,
        };
        let frame = self
            .client
            .seal_client_bundle(&self.device.keys.authorisation, bundle, &self.clock)
            .map_err(|error| Stopped::Local(error.code()))?;
        self.send(&RendezvousMessage::Bundle {
            sequence: frame.sequence,
            nonce: frame.nonce,
            ciphertext: Bytes::new(frame.ciphertext),
        })
        .await;
        match self.receive().await? {
            RendezvousMessage::BundleAccepted => Ok(()),
            other => panic!("a sealed bundle is acknowledged, not answered with {other:?}"),
        }
    }

    /// Reaches the host over iroh at the endpoint its authenticated bundle pinned, and binds the
    /// transcript to both live endpoints with `pair.finish`.
    ///
    /// Returns the connection, the candidate's unpaired session on it and the host's answer.
    pub async fn finish(
        &mut self,
    ) -> (
        iroh::endpoint::Connection,
        CandidateConnection,
        PairFinishResult,
    ) {
        let host = self
            .host_bundle
            .as_ref()
            .expect("the host's bundle was opened")
            .bundle
            .clone();
        let connection = self
            .device
            .endpoint
            .connect(
                bundle_addr(&host.endpoint_id, &host.network_config),
                kr_protocol::hello::ALPN,
            )
            .await
            .expect("the candidate reaches the host it authenticated");
        let mut session = handshake::connect_unpaired(&connection, self.device.identity)
            .await
            .expect("an unpaired connection");
        let request = self
            .client
            .finish_request(
                &HostPeer(*host.endpoint_id.as_bytes()),
                &self.device.declared.endpoint_id,
                &self.clock,
            )
            .expect("a finish request");
        let finished: PairFinishResult = session
            .call(Method::PairFinish, &request)
            .await
            .expect("the host binds the transcript");
        (connection, session, finished)
    }

    /// Returns the value this candidate displays once both bundles are exchanged.
    #[must_use]
    pub fn verification_value(&self) -> String {
        self.client
            .verification_value()
            .expect("both bundles were exchanged")
    }

    /// Sends a relay payload that is not a pairing message, as a broken or hostile candidate
    /// might.
    pub async fn send_malformed(&self) {
        self.socket
            .outgoing
            .send(ClientFrame::Relay {
                attempt_id: self.attempt_id,
                payload: Bytes::new(vec![0xff, 0x00, 0x13]),
            })
            .await
            .expect("the room takes the frame");
    }

    async fn send(&self, message: &RendezvousMessage) {
        let payload = encode_message(message).expect("a message encodes");
        self.socket
            .outgoing
            .send(ClientFrame::Relay {
                attempt_id: self.attempt_id,
                payload,
            })
            .await
            .expect("the room takes the frame");
    }

    /// Receives the host's next message for this attempt, or how the attempt stopped.
    async fn receive(&mut self) -> Result<RendezvousMessage, Stopped> {
        let ServiceFrame::Relay {
            attempt_id,
            payload,
        } = next(&mut self.socket).await?
        else {
            panic!("a candidate is sent relay frames once it has its record");
        };
        assert_eq!(attempt_id, self.attempt_id, "and only its own attempt's");
        let message = decode_message(payload.as_slice()).expect("a pairing message");
        if let RendezvousMessage::Refused {
            code,
            remaining_confirmations,
        } = message
        {
            return Err(Stopped::Refused {
                code,
                remaining: remaining_confirmations.0,
            });
        }
        Ok(message)
    }
}

/// Waits for the next frame on a socket; a closed socket is how the attempt stopped.
async fn next(socket: &mut RoomSocket) -> Result<ServiceFrame, Stopped> {
    let frame = tokio::time::timeout(FRAME_WAIT, socket.incoming.recv())
        .await
        .expect("the room answers in time")
        .ok_or(Stopped::Closed(CloseReason::Cancelled))?;
    if let ServiceFrame::Closed { reason } = frame {
        return Err(Stopped::Closed(reason));
    }
    Ok(frame)
}

/// Returns where a candidate dials the host, from the host's authenticated bundle alone.
#[must_use]
pub fn bundle_addr(endpoint_id: &EndpointKey, network_config: &NetworkConfig) -> EndpointAddr {
    let endpoint_id = iroh::PublicKey::from_bytes(endpoint_id.as_bytes())
        .expect("the bundle pins a usable endpoint identity");
    let mut addr = EndpointAddr::new(endpoint_id);
    for hint in &network_config.direct_addresses {
        if let Ok(socket) = hint.as_str().parse::<std::net::SocketAddr>() {
            addr = addr.with_ip_addr(socket);
        }
    }
    addr
}
