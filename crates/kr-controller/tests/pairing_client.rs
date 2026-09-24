//! The product's pairing client against the daemon a host runs.
//!
//! The candidate here is kr-client's pairing module, the code a companion application calls: it
//! enters a code through the host's room and finishes over iroh, or redeems a direct invitation,
//! and then waits for the owner and connects as what it became. The owner device is kr-client's
//! confirmation service, answering the challenges the local owner asks for. The daemon is the same
//! network service and controller the binary runs, with its room in this process.

#![cfg(unix)]

mod net_support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use iroh::endpoint::Connection;
use kr_client::ClientError;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::{AttemptState, Candidate, CandidateRoom, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::invitation::{Invitation, read_invitation};
use kr_client::pairing::link::{EndpointPool, HostLink, IrohLink, LinkError, Preauth};
use kr_client::pairing::owner::{
    CannotCheck, Ceremony, CeremonyKind, CeremonyOutcome, Listed, OwnerChannel, OwnerConfirmations,
    ReviewOutcome, SessionChannel, Subject,
};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_client::pairing::room::{RoomConnector, RoomError, RoomSocket};
use kr_client::session::Session;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_ipc::client::LocalClient;
use kr_pairing::budget::DurableClientBudgetStore;
use kr_pairing::code::EnteredCode;
use kr_pairing::platform::{BootIdentity, ClientBudgetStore, PairingClock};
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, DescribedAction, OwnerConfirmationCompleteParams,
    OwnerConfirmationPendingResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::GrantExpiry;
use kr_protocol::hello::HostSelection;
use kr_protocol::ids::{BuildId, DeviceKeyRevision, EnvironmentId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams, PairInviteResult,
    RendezvousMessage, default_rendezvous_origin,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    DeviceName, DevicePlatform, Locator, MAX_CLIENT_ATTEMPTS, MAX_CONFIRMATION_FAILURES,
    NetworkConfig, NetworkHint, PairFinishRequest, PairStatus, ProposedGrant, QrPayload,
    RendezvousOrigin, SensitiveAction, group_verification_value,
};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rendezvous::{
    ClientFrame, ServiceFrame, decode_client_frame, decode_message, encode_frame, encode_message,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, EndpointKey, Nullable, SecretBytes32};
use kr_transport::handshake::LocalIdentity;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_websockets::{Message, ServerBuilder};

/// How long a test waits for a pairing step before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(60);

fn keys() -> DeviceKeys {
    DeviceKeys::generate().expect("keys")
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// How far past its start a short-code attempt's own deadline lies: the invitation's five minutes
/// and the device's margin, and then some.
const PAST_THE_DEADLINE: Duration = Duration::from_secs(7 * 60);

/// A device's clock, which a test can move forward.
struct MovableClock {
    clock: DeviceClock,
    ahead_ms: AtomicU64,
}

impl MovableClock {
    fn advance(&self, by: Duration) {
        self.ahead_ms.fetch_add(
            u64::try_from(by.as_millis()).expect("a short time"),
            Ordering::SeqCst,
        );
    }
}

impl PairingClock for MovableClock {
    fn monotonic_ms(&self) -> u64 {
        self.clock.monotonic_ms()
    }

    fn boot_identity(&self) -> BootIdentity {
        self.clock.boot_identity()
    }

    fn wall_clock_ms(&self) -> u64 {
        self.clock.wall_clock_ms() + self.ahead_ms.load(Ordering::SeqCst)
    }
}

/// A device running the product's pairing client, with its records on the internal disk.
struct ProductDevice {
    pairing: Arc<Pairing>,
    budget: Arc<DurableClientBudgetStore>,
    clock: Arc<MovableClock>,
    keys: DeviceKeys,
    room: Arc<dyn CandidateRoom>,
    directory: tempfile::TempDir,
}

impl ProductDevice {
    /// A device that pairs through `room` and reaches hosts through the link `link` makes of the
    /// product's own.
    fn new(room: Arc<dyn CandidateRoom>, link: impl FnOnce(IrohLink) -> Arc<dyn HostLink>) -> Self {
        Self::with_keys(keys(), room, link)
    }

    fn with_keys(
        keys: DeviceKeys,
        room: Arc<dyn CandidateRoom>,
        link: impl FnOnce(IrohLink) -> Arc<dyn HostLink>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let budget = Arc::new(
            DurableClientBudgetStore::open(
                directory.path().join("budget"),
                Arc::new(MemoryStore::new()),
                "device",
            )
            .expect("a durable budget"),
        );
        let clock = Arc::new(MovableClock {
            clock: DeviceClock::current().expect("a clock"),
            ahead_ms: AtomicU64::new(0),
        });
        Self {
            pairing: running(&keys, &budget, &clock, &room, directory.path(), link),
            budget,
            clock,
            keys,
            room,
            directory,
        }
    }

    /// The same device started again: its keys, budget, clock and records, and a link of its own.
    fn restarted(&self, link: impl FnOnce(IrohLink) -> Arc<dyn HostLink>) -> Arc<Pairing> {
        running(
            &self.keys,
            &self.budget,
            &self.clock,
            &self.room,
            self.directory.path(),
            link,
        )
    }

    /// Enters `code` for `origin`, and returns the running attempt and what it shows.
    fn enter(
        &self,
        origin: &RendezvousOrigin,
        code: &str,
    ) -> (
        tokio::task::JoinHandle<Result<PairedHost, kr_client::pairing::PairingFailure>>,
        watch::Receiver<AttemptState>,
    ) {
        let (progress, shown) = watch::channel(AttemptState::Idle);
        let pairing = Arc::clone(&self.pairing);
        let origin = origin.clone();
        let code = EnteredCode::parse(code).expect("a code");
        let attempt =
            tokio::spawn(async move { pairing.pair_by_code(&origin, &code, &progress).await });
        (attempt, shown)
    }

    /// Redeems `text`, a direct invitation's QR text, and returns the running attempt.
    fn redeem(
        &self,
        text: &str,
    ) -> (
        tokio::task::JoinHandle<Result<PairedHost, kr_client::pairing::PairingFailure>>,
        watch::Receiver<AttemptState>,
    ) {
        let Invitation::Direct(payload) =
            read_invitation(text, &default_rendezvous_origin()).expect("an invitation")
        else {
            panic!("a direct invitation's text reads as a direct invitation");
        };
        let (progress, shown) = watch::channel(AttemptState::Idle);
        let pairing = Arc::clone(&self.pairing);
        let attempt = tokio::spawn(async move { pairing.pair_directly(&payload, &progress).await });
        (attempt, shown)
    }
}

/// The product's pairing client, running as a device with these keys, budget, clock and records.
fn running(
    keys: &DeviceKeys,
    budget: &Arc<DurableClientBudgetStore>,
    clock: &Arc<MovableClock>,
    room: &Arc<dyn CandidateRoom>,
    directory: &std::path::Path,
    link: impl FnOnce(IrohLink) -> Arc<dyn HostLink>,
) -> Arc<Pairing> {
    let pool = EndpointPool::new(keys.transport.clone())
        .bound_to("127.0.0.1:0".parse().expect("loopback"));
    Arc::new(Pairing {
        candidate: Candidate::new(
            keys.clone(),
            DeviceName::new("A test computer").expect("a name"),
            DevicePlatform::Macos,
            build(),
        ),
        budget: budget.clone(),
        clock: clock.clone(),
        room: Arc::clone(room),
        link: link(IrohLink::new(Arc::new(pool))),
        hosts: Arc::new(PairedHosts::open(directory.join("pairing")).expect("a store")),
    })
}

/// Waits until an attempt shows the value both devices display, and returns it.
async fn awaiting_value(shown: &mut watch::Receiver<AttemptState>) -> String {
    let state = tokio::time::timeout(
        WATCHDOG,
        shown.wait_for(|state| {
            matches!(
                state,
                AttemptState::AwaitingApproval { .. } | AttemptState::Ended { .. }
            )
        }),
    )
    .await
    .expect("the attempt reaches the owner")
    .expect("the attempt runs")
    .clone();
    let AttemptState::AwaitingApproval { value, .. } = state else {
        panic!("the attempt waits for the owner, and did not: {state:?}");
    };
    value
}

/// Waits for an attempt to end and returns how.
async fn outcome(
    attempt: tokio::task::JoinHandle<Result<PairedHost, kr_client::pairing::PairingFailure>>,
) -> Result<PairedHost, kr_client::pairing::PairingFailure> {
    tokio::time::timeout(WATCHDOG, attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
}

/// Records every state an attempt shows, as far as a watcher sees them.
fn record(mut shown: watch::Receiver<AttemptState>) -> Arc<Mutex<Vec<AttemptState>>> {
    let seen = Arc::new(Mutex::new(vec![shown.borrow().clone()]));
    let kept = Arc::clone(&seen);
    tokio::spawn(async move {
        while shown.changed().await.is_ok() {
            let state = shown.borrow_and_update().clone();
            kept.lock().expect("the record").push(state);
        }
    });
    seen
}

/// True when a state shows the value both devices display.
fn shows_a_value(state: &AttemptState) -> bool {
    matches!(
        state,
        AttemptState::AwaitingApproval { .. } | AttemptState::Reconnecting { value: Some(_), .. }
    )
}

fn showed_a_value(seen: &Arc<Mutex<Vec<AttemptState>>>) -> bool {
    seen.lock().expect("the record").iter().any(shows_a_value)
}

/// Issues a code invitation at `origin`, or this host's default origin, once `signer` has
/// confirmed it.
async fn invite_code(
    environment: EnvironmentId,
    client: &mut LocalClient,
    grant: &ProposedGrant,
    origin: Option<&RendezvousOrigin>,
    signer: &Signer<'_>,
) -> PairInviteResult {
    let origin = origin.map_or_else(Nullable::null, |origin| Nullable::some(origin.clone()));
    calls::confirm_subject(
        environment,
        client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Code,
            rendezvous_origin: origin.clone(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
        signer,
    )
    .await
    .expect("answered");
    calls::mutate(
        environment,
        client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Code {
                rendezvous_origin: origin,
            },
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
    )
    .await
    .expect("a code invitation")
}

/// The origin, the code and the QR text a code invitation's answer shows.
fn code_of(invited: &PairInviteResult) -> (RendezvousOrigin, String, String) {
    let InviteEntry::Code {
        rendezvous_origin,
        code,
        qr_text,
    } = &invited.entry
    else {
        panic!("a code invitation is offered as a code");
    };
    (
        rendezvous_origin.clone(),
        code.as_str().to_owned(),
        qr_text.as_str().to_owned(),
    )
}

/// Issues a direct invitation for a viewer, once `signer` has confirmed it.
async fn issue_direct(
    environment: EnvironmentId,
    client: &mut LocalClient,
    signer: &Signer<'_>,
) -> PairInviteResult {
    calls::invite_direct(
        environment,
        client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        signer,
    )
    .await
    .expect("a direct invitation")
}

/// The QR text a direct invitation's answer shows.
fn direct_text(invited: &PairInviteResult) -> String {
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation is offered as a QR");
    };
    qr_text.as_str().to_owned()
}

/// The owner's view of an invitation's status.
async fn owner_status(client: &mut LocalClient, invited: &PairInviteResult) -> PairStatus {
    calls::owner_status(client, invited.invitation_id)
        .await
        .expect("the owner reads its invitation")
        .status
}

/// The confirmation failures an invitation still allows, as its owner sees them.
async fn allowance(client: &mut LocalClient, invited: &PairInviteResult) -> u32 {
    calls::owner_status(client, invited.invitation_id)
        .await
        .expect("the owner reads its invitation")
        .owner
        .0
        .expect("the owner's view")
        .remaining_confirmations
}

/// A room that carries a candidate's frames through the host's room, altering or recording them.
struct TamperedRoom {
    inner: net_support::room::TestRoom,
    flip_host_tag: bool,
    sent: Arc<Mutex<Vec<RendezvousMessage>>>,
}

impl CandidateRoom for TamperedRoom {
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
        Box::pin(async move {
            let inner = CandidateRoom::open(&self.inner, origin, locator).await?;
            let (to_device, incoming) = mpsc::channel(64);
            let (outgoing, mut from_device) = mpsc::channel::<ClientFrame>(64);
            let flip = self.flip_host_tag;
            let RoomSocket {
                outgoing: to_room,
                incoming: mut from_room,
            } = inner;
            tokio::spawn(async move {
                while let Some(mut frame) = from_room.recv().await {
                    if let ServiceFrame::Relay {
                        attempt_id,
                        payload,
                    } = &frame
                        && flip
                        && let Ok(RendezvousMessage::HostConfirmation { tag }) =
                            decode_message(payload.as_slice())
                    {
                        let mut bytes = *tag.as_bytes();
                        bytes[0] ^= 1;
                        frame = ServiceFrame::Relay {
                            attempt_id: *attempt_id,
                            payload: encode_message(&RendezvousMessage::HostConfirmation {
                                tag: kr_protocol::scalars::Mac256::from_bytes(bytes),
                            })
                            .expect("a message"),
                        };
                    }
                    if to_device.send(frame).await.is_err() {
                        return;
                    }
                }
            });
            let sent = Arc::clone(&self.sent);
            tokio::spawn(async move {
                while let Some(frame) = from_device.recv().await {
                    if let ClientFrame::Relay { payload, .. } = &frame
                        && let Ok(message) = decode_message(payload.as_slice())
                    {
                        sent.lock().expect("the record").push(message);
                    }
                    if to_room.send(frame).await.is_err() {
                        return;
                    }
                }
            });
            Ok(RoomSocket { outgoing, incoming })
        })
    }
}

/// A link that counts what the client asks of the network, and can reach another host, alter
/// what the host answers, lose an answer, or stop reaching the host.
struct WatchedLink {
    inner: IrohLink,
    /// Dial this host instead of the one asked for.
    elsewhere: Option<(NetworkConfig, EndpointKey)>,
    /// Alter the verification value the host answers a finish or a redemption with.
    alter_value: bool,
    /// Let the host take a finish, and lose its answer as a response stream that ended would.
    lose_finish_answer: bool,
    /// Once the host has answered a finish, reach it no more.
    sever_after_finish: bool,
    /// Answer this many status questions, and then none, with the connection held open.
    answers_before_silence: Option<usize>,
    severed: Arc<AtomicBool>,
    statuses: Arc<AtomicUsize>,
    dials: AtomicUsize,
    opened: AtomicUsize,
}

impl WatchedLink {
    fn new(inner: IrohLink) -> Self {
        Self {
            inner,
            elsewhere: None,
            alter_value: false,
            lose_finish_answer: false,
            sever_after_finish: false,
            answers_before_silence: None,
            severed: Arc::new(AtomicBool::new(false)),
            statuses: Arc::new(AtomicUsize::new(0)),
            dials: AtomicUsize::new(0),
            opened: AtomicUsize::new(0),
        }
    }
}

fn severed() -> LinkError {
    LinkError::Lost("the test cut the host off".to_owned())
}

impl HostLink for WatchedLink {
    fn dial<'a>(
        &'a self,
        network: &'a NetworkConfig,
        endpoint: &'a EndpointKey,
    ) -> BoxFuture<'a, Result<Connection, LinkError>> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        if self.severed.load(Ordering::SeqCst) {
            return Box::pin(async { Err(severed()) });
        }
        match &self.elsewhere {
            Some((network, endpoint)) => self.inner.dial(network, endpoint),
            None => self.inner.dial(network, endpoint),
        }
    }

    fn open_unpaired<'a>(
        &'a self,
        connection: &'a Connection,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Box<dyn Preauth>, LinkError>> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let inner = self.inner.open_unpaired(connection, identity).await?;
            Ok(Box::new(Watched {
                inner,
                alter_value: self.alter_value,
                lose_finish_answer: self.lose_finish_answer,
                sever_after_finish: self.sever_after_finish,
                answers_before_silence: self.answers_before_silence,
                severed: Arc::clone(&self.severed),
                statuses: Arc::clone(&self.statuses),
            }) as Box<dyn Preauth>)
        })
    }

    fn connect_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Session, LinkError>> {
        if self.severed.load(Ordering::SeqCst) {
            return Box::pin(async { Err(severed()) });
        }
        self.inner.connect_paired(host, identity)
    }
}

/// A pre-authorisation surface that does to the host's answers what its link says.
struct Watched {
    inner: Box<dyn Preauth>,
    alter_value: bool,
    lose_finish_answer: bool,
    sever_after_finish: bool,
    answers_before_silence: Option<usize>,
    severed: Arc<AtomicBool>,
    statuses: Arc<AtomicUsize>,
}

fn altered(value: &str) -> String {
    let mut altered: Vec<char> = value.chars().collect();
    altered[0] = if altered[0] == '0' { '1' } else { '0' };
    altered.into_iter().collect()
}

impl Preauth for Watched {
    fn selection(&self) -> &HostSelection {
        self.inner.selection()
    }

    fn finish<'a>(
        &'a mut self,
        request: &'a PairFinishRequest,
    ) -> BoxFuture<'a, Result<PairFinishResult, LinkError>> {
        Box::pin(async move {
            let mut finished = self.inner.finish(request).await?;
            if self.sever_after_finish {
                self.severed.store(true, Ordering::SeqCst);
            }
            if self.lose_finish_answer {
                // What the transport reports when the response stream ends without an answer.
                return Err(LinkError::from(kr_transport::TransportError::handshake(
                    ErrorCode::ResourceUnavailable,
                    "the host answered nothing",
                )));
            }
            if self.alter_value {
                finished.verification_value = altered(&finished.verification_value);
            }
            Ok(finished)
        })
    }

    fn redeem<'a>(
        &'a mut self,
        params: &'a PairRedeemParams,
    ) -> BoxFuture<'a, Result<PairRedeemResult, LinkError>> {
        Box::pin(async move {
            Ok(match self.inner.redeem(params).await? {
                PairRedeemResult::Locked {
                    attempt_id,
                    verification_value,
                } if self.alter_value => PairRedeemResult::Locked {
                    attempt_id,
                    verification_value: altered(&verification_value),
                },
                other => other,
            })
        })
    }

    fn status<'a>(
        &'a mut self,
        params: &'a PairStatusParams,
    ) -> BoxFuture<'a, Result<PairStatusResult, LinkError>> {
        Box::pin(async move {
            if self.severed.load(Ordering::SeqCst) {
                return Err(severed());
            }
            let asked = self.statuses.fetch_add(1, Ordering::SeqCst);
            if self
                .answers_before_silence
                .is_some_and(|answers| asked >= answers)
            {
                std::future::pending::<()>().await;
            }
            self.inner.status(params).await
        })
    }
}

/// KR-REQ-10.23, KR-REQ-10.27, KR-REQ-10.32: a device running the product client pairs by code
/// through the host's room with its durable budget, shows the value the owner sees, and once the
/// owner approves connects as the device it became and reads its own status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_by_code_through_the_product_client() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, mut shown) = device.enter(&origin, &code);
    let value = awaiting_value(&mut shown).await;
    let PairStatus::AwaitingApproval {
        verification_value, ..
    } = owner_status(&mut client, &invited).await
    else {
        panic!("the owner is asked to approve the device");
    };
    assert_eq!(value, group_verification_value(&verification_value));
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");
    assert_eq!(paired.device_id, confirmed.device_id);
    assert_eq!(paired.grant_id, confirmed.grant_id);
    assert!(matches!(
        &*shown.borrow(),
        AttemptState::Paired { host } if !host.owner
    ));
    assert_eq!(
        device.pairing.hosts.list().expect("readable"),
        vec![paired.clone()],
        "the paired host is recorded"
    );

    // The device reaches the host again as what it became, and the host knows it.
    let session = device
        .pairing
        .link
        .connect_paired(
            &paired,
            &device.pairing.candidate.paired_identity(paired.device_id),
        )
        .await
        .expect("the paired device connects");
    let status: PairStatusResult = session
        .read(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        )
        .await
        .expect("the paired device reads its own status");
    assert_eq!(
        status.status,
        PairStatus::Committed {
            device_id: paired.device_id,
            grant_id: paired.grant_id
        }
    );

    // One try was charged, in the durable budget the device keeps.
    let key = kr_pairing::client::budget_key(
        &*device.budget,
        &origin,
        &EnteredCode::parse(&code).expect("a code"),
    )
    .expect("the budget's key");
    assert_eq!(
        device
            .budget
            .load(&key)
            .expect("readable")
            .map(|record| record.attempts),
        Some(1)
    );
}

/// KR-REQ-10.23: a device checks the host's confirmation tag before it trusts anything the host
/// sent. A room that flips one bit of the host's tag leaves the attempt ambiguous; the device sends
/// no bundle and never dials the host, and the host's allowance of failed confirmations is what it
/// was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_tag_that_does_not_verify_ends_the_attempt_before_anything_is_trusted() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let sent = Arc::new(Mutex::new(Vec::new()));
    let watched = Arc::new(Mutex::new(None::<Arc<WatchedLink>>));
    let kept = Arc::clone(&watched);
    let device = ProductDevice::new(
        Arc::new(TamperedRoom {
            inner: host.room.clone(),
            flip_host_tag: true,
            sent: Arc::clone(&sent),
        }),
        move |link| {
            let link = Arc::new(WatchedLink::new(link));
            *kept.lock().expect("the link") = Some(Arc::clone(&link));
            link
        },
    );
    let (attempt, shown) = device.enter(&origin, &code);
    let seen = record(shown);
    let failure = outcome(attempt).await.expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::NotAuthenticated);
    assert!(
        !sent
            .lock()
            .expect("the record")
            .iter()
            .any(|message| matches!(message, RendezvousMessage::Bundle { .. })),
        "no bundle left the device"
    );
    let link = watched.lock().expect("the link").clone().expect("the link");
    assert_eq!(
        link.dials.load(Ordering::SeqCst),
        0,
        "the host was never dialled"
    );
    assert!(!showed_a_value(&seen));
    assert_eq!(
        allowance(&mut client, &invited).await,
        MAX_CONFIRMATION_FAILURES,
        "the device's own tag was right, so the host charged no failed confirmation"
    );
}

/// KR-REQ-10.37: a device shows the value only when the host's value is the one it computed. A
/// layer that alters `pair.finish`'s value ends the attempt as a host that did not match, and no
/// value is shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finish_answered_with_another_value_shows_no_value() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| {
        let mut watched = WatchedLink::new(link);
        watched.alter_value = true;
        Arc::new(watched)
    });
    let (attempt, shown) = device.enter(&origin, &code);
    let seen = record(shown);
    let failure = outcome(attempt).await.expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::HostMismatch);
    assert_eq!(
        failure.tries_left,
        Some(MAX_CLIENT_ATTEMPTS - 1),
        "the attempt was charged, so its ending says how many tries are left"
    );
    assert!(!showed_a_value(&seen), "no value was shown");
    assert!(
        device
            .pairing
            .hosts
            .waiting_attempt()
            .expect("readable")
            .is_none(),
        "nothing is left waiting"
    );
}

/// KR-REQ-10.27: the live peer the device checks is its connection's own. A dialler that reaches
/// a second host ends the attempt before the device offers anything on that connection: no
/// unpaired surface is opened on it and no `pair.finish` is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_finish_is_bound_to_the_endpoint_the_client_authenticated() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let other = Host::start(&keys()).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let elsewhere = (
        other
            .network()
            .network_config()
            .expect("the other host's configuration"),
        other.network().endpoint_id(),
    );
    let watched = Arc::new(Mutex::new(None::<Arc<WatchedLink>>));
    let kept = Arc::clone(&watched);
    let device = ProductDevice::new(Arc::new(host.room.clone()), move |link| {
        let mut link = WatchedLink::new(link);
        link.elsewhere = Some(elsewhere);
        let link = Arc::new(link);
        *kept.lock().expect("the link") = Some(Arc::clone(&link));
        link
    });
    let (attempt, _) = device.enter(&origin, &code);
    let failure = outcome(attempt).await.expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::HostMismatch);
    assert_eq!(failure.tries_left, Some(MAX_CLIENT_ATTEMPTS - 1));
    let link = watched.lock().expect("the link").clone().expect("the link");
    assert_eq!(link.dials.load(Ordering::SeqCst), 1, "the device dialled");
    assert_eq!(
        link.opened.load(Ordering::SeqCst),
        0,
        "and opened nothing on a connection to another host"
    );
}

/// A link maker that configures a watched link, and a handle to the link it made.
#[allow(clippy::type_complexity)]
fn watching(
    configure: impl FnOnce(&mut WatchedLink),
) -> (
    Arc<Mutex<Option<Arc<WatchedLink>>>>,
    impl FnOnce(IrohLink) -> Arc<dyn HostLink>,
) {
    let made = Arc::new(Mutex::new(None));
    let kept = Arc::clone(&made);
    let make = move |link| {
        let mut watched = WatchedLink::new(link);
        configure(&mut watched);
        let watched = Arc::new(watched);
        *kept.lock().expect("the link") = Some(Arc::clone(&watched));
        watched as Arc<dyn HostLink>
    };
    (made, make)
}

fn made(handle: &Arc<Mutex<Option<Arc<WatchedLink>>>>) -> Arc<WatchedLink> {
    handle
        .lock()
        .expect("the link")
        .clone()
        .expect("the device made its link")
}

/// KR-REQ-10.32, KR-REQ-10.37: a finish whose answer never arrived is not a refusal. The host
/// took it, so the device keeps its record of the attempt, asks again on a connection of its own,
/// shows the value only once the host has answered with it, and pairs when the owner approves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finish_whose_answer_was_lost_is_asked_about_again() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let (link, making) = watching(|link| link.lose_finish_answer = true);
    let device = ProductDevice::new(Arc::new(host.room.clone()), making);
    let (attempt, mut shown) = device.enter(&origin, &code);
    let seen = record(shown.clone());
    awaiting_value(&mut shown).await;
    assert!(
        device
            .pairing
            .hosts
            .waiting_attempt()
            .expect("readable")
            .is_some(),
        "the device kept its record of the attempt"
    );
    {
        let seen = seen.lock().expect("the record");
        let first = seen
            .iter()
            .position(shows_a_value)
            .expect("a value was shown");
        assert!(
            matches!(seen[first], AttemptState::AwaitingApproval { .. }),
            "the first value shown is the one the host answered with: {seen:?}"
        );
        assert!(
            seen[..first]
                .iter()
                .any(|state| matches!(state, AttemptState::Reconnecting { value: None, .. })),
            "the device asked again, showing no value yet: {seen:?}"
        );
    }
    assert!(
        made(&link).opened.load(Ordering::SeqCst) >= 2,
        "the device asked on a connection of its own"
    );
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");
    assert_eq!(paired.device_id, confirmed.device_id);
}

/// KR-REQ-10.32: a device that stopped after it recorded its host, and before it let the waiting
/// attempt go, finds both when it starts again. It reaches the host through the record, as the
/// device it became, checks that the host reports it so, and never offers itself as a candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_stopped_after_recording_its_host_resumes_through_the_record() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, mut shown) = device.enter(&origin, &code);
    awaiting_value(&mut shown).await;
    let waiting = device
        .pairing
        .hosts
        .waiting_attempt()
        .expect("readable")
        .expect("the attempt is kept while the owner decides");
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");

    // What a stop between the two writes leaves: the host's record and the attempt it answered.
    device.pairing.hosts.keep_attempt(&waiting).expect("kept");
    let (link, making) = watching(|_| {});
    let restarted = device.restarted(making);
    let (progress, shown) = watch::channel(AttemptState::Idle);
    let resumed = tokio::time::timeout(WATCHDOG, restarted.resume(&progress))
        .await
        .expect("the resumed attempt ends")
        .expect("an attempt was waiting")
        .expect("paired");
    assert_eq!(resumed.device_id, paired.device_id);
    assert!(matches!(&*shown.borrow(), AttemptState::Paired { .. }));
    let link = made(&link);
    assert_eq!(link.dials.load(Ordering::SeqCst), 0, "no candidate dialled");
    assert_eq!(
        link.opened.load(Ordering::SeqCst),
        0,
        "and no unpaired offer was made"
    );
    assert!(
        restarted
            .hosts
            .waiting_attempt()
            .expect("readable")
            .is_none(),
        "the attempt is let go once the host reports the device"
    );
}

/// KR-REQ-10.32, KR-REQ-10.19: a device that loses the host before its first status answer,
/// while the owner approves it, cannot learn as a candidate what it became. It asks until the
/// deadline it set when the attempt began, whatever the service advertised, and then says that
/// the approval is unknown, with the tries it has left, and lets the attempt go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_the_device_cannot_learn_by_its_deadline_is_unknown() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let (link, making) = watching(|link| link.sever_after_finish = true);
    let device = ProductDevice::new(Arc::new(host.room.clone()), making);
    let (attempt, mut shown) = device.enter(&origin, &code);
    // The host is lost as soon as it answered the finish, so the value may already be shown as
    // reconnecting by the time this looks.
    let state = tokio::time::timeout(
        WATCHDOG,
        shown.wait_for(|state| shows_a_value(state) || matches!(state, AttemptState::Ended { .. })),
    )
    .await
    .expect("the host answers the finish")
    .expect("the attempt runs")
    .clone();
    assert!(shows_a_value(&state), "the value is shown: {state:?}");
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the owner approves");
    device.clock.advance(PAST_THE_DEADLINE);
    let failure = outcome(attempt).await.expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::ApprovalUnknown);
    assert_eq!(failure.tries_left, Some(MAX_CLIENT_ATTEMPTS - 1));
    assert_eq!(
        made(&link).statuses.load(Ordering::SeqCst),
        0,
        "no status answer ever arrived"
    );
    assert!(
        device
            .pairing
            .hosts
            .waiting_attempt()
            .expect("readable")
            .is_none(),
        "the attempt is let go"
    );
    assert!(
        matches!(
            owner_status(&mut client, &invited).await,
            PairStatus::Committed { .. }
        ),
        "the host did commit it, which is why the device says it does not know"
    );
}

/// KR-REQ-10.32: a host that holds the connection open and stops answering does not hold the
/// device past its deadline. Each question has a bound, and once the deadline has passed the
/// device says the approval is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_answering_is_not_waited_on_past_the_deadline() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let (link, making) = watching(|link| link.answers_before_silence = Some(1));
    let device = ProductDevice::new(Arc::new(host.room.clone()), making);
    let (attempt, mut shown) = device.enter(&origin, &code);
    awaiting_value(&mut shown).await;
    let link = made(&link);
    tokio::time::timeout(WATCHDOG, async {
        while link.statuses.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the host answered once and was asked again");
    device.clock.advance(PAST_THE_DEADLINE);
    let failure = outcome(attempt).await.expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::ApprovalUnknown);
    assert_eq!(failure.tries_left, Some(MAX_CLIENT_ATTEMPTS - 1));
}

/// KR-REQ-10.19: an attempt taken up again after a restart still says how many tries the device
/// has left when it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resumed_attempt_says_how_many_tries_are_left() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, _) = code_of(&invited);

    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, mut shown) = device.enter(&origin, &code);
    awaiting_value(&mut shown).await;
    attempt.abort();
    let _ = attempt.await;

    // The device starts again past its deadline, and cannot reach the host.
    device.clock.advance(PAST_THE_DEADLINE);
    let (_, making) = watching(|link| link.severed.store(true, Ordering::SeqCst));
    let restarted = device.restarted(making);
    let (progress, _shown) = watch::channel(AttemptState::Idle);
    let failure = tokio::time::timeout(WATCHDOG, restarted.resume(&progress))
        .await
        .expect("the resumed attempt ends")
        .expect("an attempt was waiting")
        .expect_err("not paired");
    assert_eq!(failure.kind, FailureKind::ApprovalUnknown);
    assert_eq!(failure.tries_left, Some(MAX_CLIENT_ATTEMPTS - 1));
    assert!(
        restarted
            .hosts
            .waiting_attempt()
            .expect("readable")
            .is_none()
    );
}

/// A certificate authority a test trusts, which issues a room's certificate.
struct Authority {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Authority {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("certificate parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, name.to_owned());
        let key = KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("a certificate");
        Self {
            der: certificate.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    /// The product's room connector, trusting this authority alone.
    fn connector(&self) -> RoomConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).expect("a root");
        RoomConnector::with_tls(
            ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    fn acceptor(&self) -> TlsAcceptor {
        let key = KeyPair::generate().expect("a key pair");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters")
            .signed_by(&key, &self.issuer)
            .expect("a certificate");
        TlsAcceptor::from(Arc::new(
            ServerConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), self.der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("a server configuration"),
        ))
    }
}

/// The host's room behind TLS on loopback, as the service serves it: each candidate socket at
/// `/api/pair/room/<locator>/candidate` is carried into `room`. Returns the origin it answers at.
async fn room_behind_tls(
    authority: &Authority,
    room: net_support::room::TestRoom,
) -> RendezvousOrigin {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    let acceptor = authority.acceptor();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, room) = (acceptor.clone(), room.clone());
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Ok((request, end)) = ServerBuilder::new().accept(stream).await else {
                    return;
                };
                let Some(locator) = request
                    .uri()
                    .path()
                    .strip_prefix("/api/pair/room/")
                    .and_then(|rest| rest.strip_suffix("/candidate"))
                else {
                    return;
                };
                let socket = room.candidate(locator);
                let (mut to_device, mut from_device) = end.split();
                let RoomSocket {
                    outgoing,
                    mut incoming,
                } = socket;
                let down = async move {
                    while let Some(frame) = incoming.recv().await {
                        let frame = Message::binary(encode_frame(&frame).expect("a frame"));
                        if to_device.send(frame).await.is_err() {
                            return;
                        }
                    }
                    let _ = to_device.close().await;
                };
                let up = async move {
                    while let Some(Ok(message)) = from_device.next().await {
                        if message.is_close() {
                            return;
                        }
                        if !message.is_binary() {
                            continue;
                        }
                        let Ok(frame) = decode_client_frame(message.as_payload()) else {
                            return;
                        };
                        if outgoing.send(frame).await.is_err() {
                            return;
                        }
                    }
                };
                tokio::join!(down, up);
            });
        }
    });
    RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin")
}

/// KR-REQ-10.23, KR-REQ-10.19: the room socket the product opens over TLS pairs when a host
/// answers in the room, so the endings the scripted room behind TLS plays are the room's, not the
/// socket's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_through_a_room_behind_tls() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let authority = Authority::new("rendezvous test authority");
    let origin = room_behind_tls(&authority, host.room.clone()).await;
    let invited = invite_code(environment, &mut client, &viewer(), Some(&origin), &owner).await;
    let (named, code, _) = code_of(&invited);
    assert_eq!(named, origin, "the invitation names the room behind TLS");

    let device = ProductDevice::new(Arc::new(authority.connector()), |link| Arc::new(link));
    let (attempt, mut shown) = device.enter(&origin, &code);
    awaiting_value(&mut shown).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");
    assert_eq!(paired.device_id, confirmed.device_id);
}

/// KR-REQ-10.36, KR-REQ-10.37: a device running the product client redeems a direct invitation,
/// shows the value the host locked it with, which is the one the owner sees, and pairs once the
/// owner approves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_directly_through_the_product_client() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");

    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, mut shown) = device.redeem(&direct_text(&invited));
    let value = awaiting_value(&mut shown).await;
    let PairStatus::AwaitingApproval {
        verification_value, ..
    } = owner_status(&mut client, &invited).await
    else {
        panic!("the owner is asked to approve the device");
    };
    assert_eq!(value, group_verification_value(&verification_value));
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");
    assert_eq!(paired.device_id, confirmed.device_id);
    assert_eq!(paired.host_endpoint_id, host.network().endpoint_id());
}

/// KR-REQ-10.36: a direct invitation whose secret is wrong locks nothing; one redeemed at another
/// host sends no proof; and a lock answered with another value shows no value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_redemption_proves_nothing_to_the_wrong_host_and_shows_no_wrong_value() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let other = Host::start(&keys()).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);

    // One bit of the secret flipped: the host refuses the proof, and nothing is locked.
    let invited = issue_direct(environment, &mut client, &owner).await;
    let QrPayload::Direct(mut payload) =
        QrPayload::from_text(&direct_text(&invited)).expect("a payload")
    else {
        panic!("a direct payload");
    };
    let mut secret = *payload.secret.expose();
    secret[0] ^= 1;
    payload.secret = SecretBytes32::from_bytes(secret);
    let flipped = QrPayload::Direct(payload)
        .to_text()
        .expect("the payload's text");
    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, _) = device.redeem(&flipped);
    assert_eq!(
        outcome(attempt).await.expect_err("refused").kind,
        FailureKind::NotAuthenticated
    );
    assert!(
        matches!(
            owner_status(&mut client, &invited).await,
            PairStatus::Open { .. }
        ),
        "nothing was locked"
    );
    calls::cancel(environment, &mut client, invited.invitation_id, false)
        .await
        .expect("withdrawn");

    // A dialler that reaches another host: the device refuses before it opens anything there.
    let invited = issue_direct(environment, &mut client, &owner).await;
    let elsewhere = (
        other
            .network()
            .network_config()
            .expect("the other host's configuration"),
        other.network().endpoint_id(),
    );
    let watched = Arc::new(Mutex::new(None::<Arc<WatchedLink>>));
    let kept = Arc::clone(&watched);
    let device = ProductDevice::new(Arc::new(host.room.clone()), move |link| {
        let mut link = WatchedLink::new(link);
        link.elsewhere = Some(elsewhere);
        let link = Arc::new(link);
        *kept.lock().expect("the link") = Some(Arc::clone(&link));
        link
    });
    let (attempt, _) = device.redeem(&direct_text(&invited));
    assert_eq!(
        outcome(attempt).await.expect_err("refused").kind,
        FailureKind::HostMismatch
    );
    let link = watched.lock().expect("the link").clone().expect("the link");
    assert_eq!(
        link.opened.load(Ordering::SeqCst),
        0,
        "no proof left the device"
    );
    calls::cancel(environment, &mut client, invited.invitation_id, false)
        .await
        .expect("withdrawn");

    // A lock answered with another value: the device shows none.
    let invited = issue_direct(environment, &mut client, &owner).await;
    let device = ProductDevice::new(Arc::new(host.room.clone()), |link| {
        let mut watched = WatchedLink::new(link);
        watched.alter_value = true;
        Arc::new(watched)
    });
    let (attempt, shown) = device.redeem(&direct_text(&invited));
    let seen = record(shown);
    assert_eq!(
        outcome(attempt).await.expect_err("refused").kind,
        FailureKind::HostMismatch
    );
    assert!(!showed_a_value(&seen), "no value was shown");
}

/// KR-REQ-10.38: what `pair.invite` issues in both modes reads back, through the one reader a
/// device has, as the same invitation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_invitation_reads_back_in_the_companion_reader() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);

    let invited = invite_code(environment, &mut client, &viewer(), None, &owner).await;
    let (origin, code, text) = code_of(&invited);
    let Invitation::Code(read) = read_invitation(&text, &origin).expect("an invitation") else {
        panic!("a code invitation reads as a code");
    };
    assert_eq!(read.origin, origin);
    assert_eq!(read.code.normalised(), code.replace('-', ""));
    assert!(!read.names_another_origin);
    let Invitation::Code(elsewhere) = read_invitation(
        &text,
        &RendezvousOrigin::new("https://pair.example.org").expect("an origin"),
    )
    .expect("an invitation") else {
        panic!("a code invitation reads as a code");
    };
    assert!(elsewhere.names_another_origin);
    calls::cancel(environment, &mut client, invited.invitation_id, false)
        .await
        .expect("withdrawn");

    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let Invitation::Direct(read) =
        read_invitation(&direct_text(&invited), &origin).expect("an invitation")
    else {
        panic!("a direct invitation reads as direct");
    };
    assert_eq!(*read, calls::direct_payload(&invited));
}

/// A ceremony that answers the same way every time, and counts what it was asked.
struct StubCeremony {
    answer: CeremonyOutcome,
    asked: Mutex<Vec<String>>,
}

impl StubCeremony {
    fn answering(answer: CeremonyOutcome) -> Self {
        Self {
            answer,
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl Ceremony for StubCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.asked
            .lock()
            .expect("the record")
            .push(reason.to_owned());
        Box::pin(async move { self.answer })
    }
}

/// A change a test makes to what a host listed, before the owner device reads it.
type Alteration = Box<dyn Fn(&mut OwnerConfirmationPendingResult) + Send>;

/// An owner channel that counts completions, and can alter what the host listed.
struct WatchedChannel {
    inner: SessionChannel,
    alter: Mutex<Option<Alteration>>,
    completions: AtomicUsize,
}

impl OwnerChannel for WatchedChannel {
    fn pending(&self) -> BoxFuture<'_, Result<OwnerConfirmationPendingResult, ClientError>> {
        Box::pin(async move {
            let mut listed = self.inner.pending().await?;
            if let Some(alter) = self.alter.lock().expect("the alteration").as_ref() {
                alter(&mut listed);
            }
            Ok(listed)
        })
    }

    fn complete<'a>(
        &'a self,
        params: &'a OwnerConfirmationCompleteParams,
    ) -> BoxFuture<'a, Result<(), ClientError>> {
        self.completions.fetch_add(1, Ordering::SeqCst);
        self.inner.complete(params)
    }
}

/// The owner device a host was started with, as the product client knows its host.
async fn owner_device(
    host: &Host,
    owner_keys: &DeviceKeys,
) -> (OwnerConfirmations, Arc<WatchedChannel>, ProductDevice) {
    let record = host.owner.clone().expect("the owner device");
    let identity = host.network().pairing().identity();
    let paired = PairedHost {
        host_device_id: identity.device_id,
        host_key_revision: DeviceKeyRevision::new(1),
        host_keys: identity.keys,
        host_endpoint_id: host.network().endpoint_id(),
        network_config: host.network().network_config().expect("the configuration"),
        device_id: record.device_id,
        grant_id: record.grant.grant_id,
        proposed_grant: kr_pairing::grants::personal_owner_grant(),
        name: Some("the test host".to_owned()),
        paired_at_ms: record.paired_at_ms.get(),
    };
    let device =
        ProductDevice::with_keys(owner_keys.clone(), Arc::new(host.room.clone()), |link| {
            Arc::new(link)
        });
    let session = device
        .pairing
        .link
        .connect_paired(
            &paired,
            &device.pairing.candidate.paired_identity(record.device_id),
        )
        .await
        .expect("the owner device connects");
    let channel = Arc::new(WatchedChannel {
        inner: SessionChannel::open(Arc::new(session))
            .await
            .expect("the channel"),
        alter: Mutex::new(None),
        completions: AtomicUsize::new(0),
    });
    (
        OwnerConfirmations::new(
            paired,
            owner_keys.authorisation.clone(),
            channel.clone(),
            Arc::new(DeviceClock::current().expect("a clock")),
        ),
        channel,
        device,
    )
}

/// Lists the owner's challenges until the one `request` names appears.
async fn listed(
    confirmations: &OwnerConfirmations,
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
) -> Listed {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let listed = confirmations.pending().await.expect("the challenges");
            if let Some(found) = listed
                .into_iter()
                .find(|listed| listed.request.confirmation_id == request.confirmation_id)
            {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the challenge is listed")
}

fn issue_subject(grant: &ProposedGrant) -> ConfirmationSubject {
    ConfirmationSubject::IssueInvitation {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: grant.clone(),
    }
}

/// KR-REQ-10.05, KR-REQ-10.06, KR-REQ-10.52: an owner device running the product's confirmation
/// service answers the challenges the local owner asked for, after its ceremony and only then: the
/// host records `owner_device_presence` and spends the answer on the effect it confirmed. The host
/// has no terminal, so a separately paired owner device is its route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_answers_through_the_product_client() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let (confirmations, channel, _device) = owner_device(&host, &owner_keys).await;
    let confirming = StubCeremony::answering(CeremonyOutcome::Confirmed);

    // Issuing an invitation.
    let grant = viewer();
    let challenge = calls::request(environment, &mut client, issue_subject(&grant))
        .await
        .expect("the local owner asks");
    let found = listed(&confirmations, &challenge.request).await;
    assert!(matches!(found.subject, Ok(Subject::IssueInvitation { .. })));
    assert_eq!(
        confirmations.review(&found, &confirming).await,
        ReviewOutcome::Confirmed
    );
    assert_eq!(channel.completions.load(Ordering::SeqCst), 1);
    let invited: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Direct,
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
    )
    .await
    .expect("the answer is spent on the invitation it confirmed");
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(challenge.request.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert_eq!(acceptance.channel, "owner_device_presence");
    assert!(acceptance.consumed_at_ms.is_some());

    // Adding the device that answered it.
    let candidate = ProductDevice::new(Arc::new(host.room.clone()), |link| Arc::new(link));
    let (attempt, mut shown) = candidate.redeem(&direct_text(&invited));
    let value = awaiting_value(&mut shown).await;
    let challenge = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::ConfirmDevice {
            invitation_id: invited.invitation_id,
        },
    )
    .await
    .expect("the local owner asks");
    let found = listed(&confirmations, &challenge.request).await;
    let Ok(Subject::ConfirmDevice {
        candidate: shown_candidate,
        ..
    }) = &found.subject
    else {
        panic!(
            "a device confirmation is described as one: {:?}",
            found.subject
        );
    };
    assert_eq!(
        group_verification_value(&shown_candidate.verification_value),
        value,
        "the owner device shows the value the candidate shows"
    );
    assert_eq!(
        confirmations.review(&found, &confirming).await,
        ReviewOutcome::Confirmed
    );
    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let approval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("an approval");
    let _: kr_protocol::invitation::PairConfirmResult = calls::mutate(
        environment,
        &mut client,
        Method::PairConfirm,
        &kr_protocol::invitation::PairConfirmParams {
            invitation_id: invited.invitation_id,
            approval,
        },
    )
    .await
    .expect("the answer is spent on the device it confirmed");
    outcome(attempt).await.expect("the device paired");
    let reasons = confirming.asked.lock().expect("the record").clone();
    assert_eq!(reasons.len(), 2);
    assert!(
        reasons[1].contains(&value),
        "the ceremony shows the value: {}",
        reasons[1]
    );
}

/// KR-REQ-10.05, KR-REQ-10.06: nothing is sent without the ceremony, and nothing is signed that the
/// device cannot check. A declined ceremony sends no completion, the host still lists the challenge
/// as unanswered, and the effect is refused; a challenge whose display disagrees with what it would
/// authorise, with the action and rights unchanged, is never signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_signs_nothing_it_did_not_confirm_or_could_not_check() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let (confirmations, channel, _device) = owner_device(&host, &owner_keys).await;

    // Declined.
    let grant = viewer();
    let challenge = calls::request(environment, &mut client, issue_subject(&grant))
        .await
        .expect("the local owner asks");
    let found = listed(&confirmations, &challenge.request).await;
    let declining = StubCeremony::answering(CeremonyOutcome::NotConfirmed);
    assert_eq!(
        confirmations.review(&found, &declining).await,
        ReviewOutcome::NotConfirmed
    );
    assert_eq!(channel.completions.load(Ordering::SeqCst), 0);
    let still = listed(&confirmations, &challenge.request).await;
    assert!(
        !still.answered,
        "the host still holds the challenge unanswered"
    );
    let refused = calls::mutate::<_, PairInviteResult>(
        environment,
        &mut client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Direct,
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
    )
    .await
    .expect_err("no confirmation, no invitation");
    assert_eq!(refused.code, ErrorCode::OwnerConfirmationRequired);

    // Displays that disagree with what the challenge would authorise.
    let confirming = StubCeremony::answering(CeremonyOutcome::Confirmed);
    let described = DescribedAction {
        action: SensitiveAction::EnlargeGrant,
        action_digest: Digest256::from_bytes([7; 32]),
        destination_keys: Nullable::null(),
        destination_rights: [ActionRight::SessionView]
            .into_iter()
            .collect::<CanonicalSet<_>>(),
    };
    let described_challenge = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::Described(described),
    )
    .await
    .expect("the local owner asks");
    let alterations: Vec<(&str, Alteration, CannotCheck)> = vec![
        (
            "another origin",
            Box::new(|listed| {
                for pending in &mut listed.pending {
                    if let ConfirmationDisplay::IssueInvitation {
                        rendezvous_origin, ..
                    } = &mut pending.display
                    {
                        *rendezvous_origin = Nullable::some(
                            RendezvousOrigin::new("https://pair.example.org").expect("an origin"),
                        );
                    }
                }
            }),
            CannotCheck::DigestMismatch,
        ),
        (
            "another grant expiry",
            Box::new(|listed| {
                for pending in &mut listed.pending {
                    if let ConfirmationDisplay::IssueInvitation { proposed_grant, .. } =
                        &mut pending.display
                    {
                        proposed_grant.expiry = GrantExpiry::Never;
                    }
                }
            }),
            CannotCheck::DigestMismatch,
        ),
        (
            "destination keys where none belong",
            Box::new(|listed| {
                for pending in &mut listed.pending {
                    if matches!(pending.display, ConfirmationDisplay::IssueInvitation { .. }) {
                        pending.request.destination_keys =
                            Nullable::some(DeviceKeys::generate().expect("keys").public_keys());
                    }
                }
            }),
            CannotCheck::Destination,
        ),
        (
            "another described digest",
            Box::new(|listed| {
                for pending in &mut listed.pending {
                    if let ConfirmationDisplay::Described(described) = &mut pending.display {
                        described.action_digest = Digest256::from_bytes([8; 32]);
                    }
                }
            }),
            CannotCheck::DigestMismatch,
        ),
    ];
    for (what, alteration, why) in alterations {
        *channel.alter.lock().expect("the alteration") = Some(alteration);
        let request = if what == "another described digest" {
            &described_challenge.request
        } else {
            &challenge.request
        };
        let found = listed(&confirmations, request).await;
        assert_eq!(found.subject.clone().err(), Some(why), "{what}");
        assert_eq!(
            confirmations.review(&found, &confirming).await,
            ReviewOutcome::CannotCheck,
            "{what}"
        );
    }
    assert_eq!(
        channel.completions.load(Ordering::SeqCst),
        0,
        "nothing was sent for any of them"
    );
    assert!(
        confirming.asked.lock().expect("the record").is_empty(),
        "no challenge that could not be checked reached the ceremony"
    );
}

/// A local Pkarr relay: it keeps the record each endpoint publishes, answers a resolver with it,
/// and remembers every endpoint it was asked about.
struct Resolver {
    url: String,
    records: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Resolver {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let url = format!(
            "http://127.0.0.1:{}/pkarr",
            listener.local_addr().expect("an address").port()
        );
        let records = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (kept, recorded) = (Arc::clone(&records), Arc::clone(&asked));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_pkarr(
                    stream,
                    Arc::clone(&kept),
                    Arc::clone(&recorded),
                ));
            }
        });
        Self {
            url,
            records,
            asked,
        }
    }

    fn key(endpoint: &EndpointKey) -> String {
        iroh::PublicKey::from_bytes(endpoint.as_bytes())
            .expect("an endpoint key")
            .to_z32()
    }

    /// True when a resolver asked this relay about `endpoint`.
    fn asked_about(&self, endpoint: &EndpointKey) -> bool {
        let key = Self::key(endpoint);
        self.asked.lock().expect("the record").contains(&key)
    }

    /// Waits until `endpoint` has published its record here.
    async fn published(&self, endpoint: &EndpointKey) {
        let key = Self::key(endpoint);
        tokio::time::timeout(WATCHDOG, async {
            while !self.records.lock().expect("the records").contains_key(&key) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the host published its record");
    }

    /// The network configuration of a host that publishes its direct addresses here and resolves
    /// through here.
    fn host_endpoint(&self) -> kr_transport::config::EndpointConfig {
        kr_transport::config::EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            discovery: kr_transport::config::DiscoveryConfig {
                pkarr_publisher_url: Some(self.url.parse().expect("the relay's URL")),
                pkarr_resolver_url: Some(self.url.parse().expect("the relay's URL")),
                publisher: kr_transport::config::PublisherPolicy {
                    published_addresses: kr_transport::config::PublishedAddresses::RelayAndDirect,
                    ..kr_transport::config::PublisherPolicy::default()
                },
                ..kr_transport::config::DiscoveryConfig::default()
            },
            ..kr_transport::config::EndpointConfig::default()
        }
    }
}

/// Serves one connection of the local Pkarr relay: `PUT /pkarr/<key>` keeps a record, and
/// `GET /pkarr/<key>` answers with it.
async fn serve_pkarr(
    stream: tokio::net::TcpStream,
    records: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    asked: Arc<Mutex<Vec<String>>>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut request = String::new();
        if reader.read_line(&mut request).await.unwrap_or(0) == 0 {
            return;
        }
        let mut length = 0_usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).await.unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0_u8; length];
        if reader.read_exact(&mut body).await.is_err() {
            return;
        }
        let mut parts = request.split_whitespace();
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let key = path.rsplit('/').next().unwrap_or("").to_owned();
        let answer = match method {
            "PUT" => {
                records.lock().expect("the records").insert(key, body);
                b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec()
            }
            "GET" => {
                asked.lock().expect("the record").push(key.clone());
                match records.lock().expect("the records").get(&key) {
                    Some(record) => {
                        let mut answer = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                            record.len()
                        )
                        .into_bytes();
                        answer.extend_from_slice(record);
                        answer
                    }
                    None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
                }
            }
            _ => b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n".to_vec(),
        };
        if write.write_all(&answer).await.is_err() {
            return;
        }
    }
}

/// The record a device keeps of `host`, whose owner it is, with its address hints gone stale.
fn stale_record(host: &Host, network_config: NetworkConfig) -> PairedHost {
    let owner = host.owner.clone().expect("the owner device");
    let identity = host.network().pairing().identity();
    PairedHost {
        host_device_id: identity.device_id,
        host_key_revision: DeviceKeyRevision::new(1),
        host_keys: identity.keys,
        host_endpoint_id: host.network().endpoint_id(),
        network_config: NetworkConfig {
            direct_addresses: vec![NetworkHint::new("127.0.0.1:9").expect("a hint")],
            ..network_config
        },
        device_id: owner.device_id,
        grant_id: owner.grant.grant_id,
        proposed_grant: kr_pairing::grants::personal_owner_grant(),
        name: None,
        paired_at_ms: owner.paired_at_ms.get(),
    }
}

/// KR-REQ-10.27, KR-REQ-10.02: a device reaches each host it is paired with through the discovery
/// service that host's own configuration selects. Two hosts publish to two different servers, the
/// device's address hints for both have gone stale, and it reaches both; an endpoint bound from
/// the first host's configuration does not reach the second, and while the device reaches the
/// first host the second host's server is never asked about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_host_is_reached_through_its_own_network_configuration() {
    let first_resolver = Resolver::start().await;
    let second_resolver = Resolver::start().await;
    let device_keys = keys();
    let first = Host::start_with_endpoint(&device_keys, first_resolver.host_endpoint()).await;
    let second = Host::start_with_endpoint(&device_keys, second_resolver.host_endpoint()).await;
    first_resolver
        .published(&first.network().endpoint_id())
        .await;
    second_resolver
        .published(&second.network().endpoint_id())
        .await;
    let first_config = first.network().network_config().expect("a configuration");
    let second_config = second.network().network_config().expect("a configuration");

    let device = ProductDevice::with_keys(device_keys, Arc::new(first.room.clone()), |link| {
        Arc::new(link)
    });
    let reach = |host: &PairedHost| {
        let pairing = Arc::clone(&device.pairing);
        let host = host.clone();
        async move {
            let identity = pairing.candidate.paired_identity(host.device_id);
            let session = pairing.link.connect_paired(&host, &identity).await?;
            let info: kr_protocol::hostinfo::HostInfoResult = session
                .read(Method::HostInfo, &EmptyParams {})
                .await
                .map_err(|error| LinkError::Lost(error.to_string()))?;
            session.close();
            Ok::<_, LinkError>(info.environment_id)
        }
    };

    let first_record = stale_record(&first, first_config.clone());
    let reached_first = tokio::time::timeout(WATCHDOG, reach(&first_record)).await;
    assert_eq!(
        reached_first
            .expect("in time")
            .expect("the first host is reached"),
        first.environment_id
    );
    assert!(
        first_resolver.asked_about(&first.network().endpoint_id()),
        "the first host was found through its own server"
    );
    assert!(
        !second_resolver.asked_about(&first.network().endpoint_id()),
        "the second host's server was never asked about the first"
    );

    let second_record = stale_record(&second, second_config);
    assert_eq!(
        tokio::time::timeout(WATCHDOG, reach(&second_record))
            .await
            .expect("in time")
            .expect("the second host is reached"),
        second.environment_id
    );

    // The second host, through the first host's configuration: nothing there can find it.
    let misconfigured = stale_record(&second, first_config);
    let reached = tokio::time::timeout(Duration::from_secs(20), reach(&misconfigured)).await;
    assert!(
        !matches!(reached, Ok(Ok(_))),
        "a host is not reached through another host's services"
    );
}

/// A method that takes no parameters.
#[derive(serde::Serialize)]
struct EmptyParams {}
