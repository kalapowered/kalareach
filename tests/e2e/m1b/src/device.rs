//! The paired device: this repository's native client library over iroh, with kr-pairing's client
//! half.
//!
//! A device makes fresh keys for the run and an iroh endpoint on loopback to dial from. It pairs
//! the two ways section 10 offers:
//!
//! * **By short code.** It sends only the four locator characters to the rendezvous origin it is
//!   configured with, through a candidate socket in the room the host reserved, runs the SPAKE2
//!   exchange and both confirmation tags through that room, exchanges sealed bundles, and binds the
//!   transcript to both live endpoints with `pair.finish` over iroh.
//! * **By direct QR.** It reads the payload the host printed, dials the pinned endpoint over iroh,
//!   takes the host's challenge and redeems it with its own proof.
//!
//! Either way it learns everything it pins about the host from what it authenticated, and then
//! connects with `kr-connect/1`: each side proves its key over one transcript and checks the
//! other's proof against the record it holds. What a device then does over that connection goes
//! through [`Remote`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::cursors::StreamCursors;
use kr_client::error::ClientError;
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_controller::service::net::pairing::HostPairingClock;
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_pairing::budget::DurableClientBudgetStore;
use kr_pairing::bundles::BundleFrame;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::direct::{CandidateIdentity, redeem_proof};
use kr_pairing::platform::{LivePeer, LocatorRecord, RendezvousClient};
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, DescribedAction, OwnerConfirmationCompleteParams,
    OwnerConfirmationCompleteResult, OwnerConfirmationPendingParams,
    OwnerConfirmationPendingResult, OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::{
    BuildId, DeviceId, DeviceKeyRevision, EnvironmentId, GrantId, InvitationId,
};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, ClientBundle, ConfirmationChannel, DeviceName,
    DevicePlatform, DirectQrPayload, NetworkConfig, OwnerConfirmationProof, PairStatus, QrPayload,
    RendezvousOrigin, SensitiveAction,
};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rendezvous::{ClientFrame, ServiceFrame, decode_message, encode_message};
use kr_protocol::scalars::{Bytes, CanonicalSet, Digest256, DurationMs, EndpointKey, Nullable};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, CandidateConnection, LocalIdentity};
use kr_transport::scheduler::SendLimits;

use crate::room::{CandidateSocket, FRAME_DEADLINE, Stopped};

/// How long a mutation this device submits asks to live.
pub const LIFETIME: DurationMs = DurationMs::new(120_000);

/// How long a device waits for the owner's challenge it is to answer to appear.
pub const CHALLENGE_WAIT: Duration = Duration::from_secs(60);

/// How long one exchange a device makes with the host is given: a connection, a handshake, or one
/// request and its answer.
///
/// A host that keeps a connection open and never answers must not hold a leg for ever.
pub const REQUEST: Duration = Duration::from_secs(60);

/// Waits for `exchange` within [`REQUEST`], and says which exchange did not finish when it does
/// not.
pub(crate) async fn bounded<T>(
    what: &str,
    exchange: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    tokio::time::timeout(REQUEST, exchange)
        .await
        .map_err(|_| format!("{what} was not answered within {REQUEST:?}"))
}

/// Why a request over the paired connection produced no result.
#[derive(Debug)]
pub enum RequestError {
    /// The host or the connection answered with a failure.
    Client(ClientError),
    /// Nothing answered within [`REQUEST`].
    Unanswered(String),
}

impl RequestError {
    /// The code the host refused with, when it was the host that refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<ErrorCode> {
        match self {
            Self::Client(ClientError::Host(error)) => Some(error.code),
            Self::Client(_) | Self::Unanswered(_) => None,
        }
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(error) => write!(formatter, "{error}"),
            Self::Unanswered(why) => formatter.write_str(why),
        }
    }
}

/// The build this device reports.
fn build() -> BuildId {
    BuildId::new(concat!("kr-e2e-m1b/", env!("CARGO_PKG_VERSION"))).expect("a build identifier")
}

/// How a pairing attempt ended when it did not go on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingStopped {
    /// The host refused the attempt, with the confirmations the invitation still allows.
    Refused {
        /// The code the host refused with.
        code: ErrorCode,
        /// The failed confirmations the invitation still allows, when the host said.
        remaining: Option<u32>,
    },
    /// The room ended the attempt.
    Room(String),
    /// This device's own state machine refused a step.
    Local(String),
}

impl std::fmt::Display for PairingStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { code, remaining } => write!(
                formatter,
                "the host refused the attempt with {} ({remaining:?} confirmations remain)",
                code.as_str()
            ),
            Self::Room(why) => write!(formatter, "the room ended the attempt: {why}"),
            Self::Local(why) => write!(formatter, "the device refused a step: {why}"),
        }
    }
}

/// What a device holds about a host it paired with.
#[derive(Clone, Debug)]
pub struct PairedHost {
    /// The identity the host gave this device.
    pub device_id: DeviceId,
    /// The grant the host issued.
    pub grant_id: GrantId,
    /// The host as this device's record holds it, which its proof is checked against.
    pub record: PairedPeer,
    /// Where the host is dialled.
    pub address: EndpointAddr,
}

/// One device.
pub struct Device {
    name: String,
    keys: DeviceKeys,
    endpoint: Endpoint,
    unpaired: LocalIdentity,
    budget: DurableClientBudgetStore,
    clock: HostPairingClock,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Device")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Makes a device with fresh keys, an endpoint on loopback and its attempt budget in
    /// `directory`.
    ///
    /// # Panics
    ///
    /// Panics when keys, the endpoint or the budget cannot be made.
    pub async fn create(name: &str, directory: &Path) -> Self {
        let keys = DeviceKeys::generate().expect("fresh device keys");
        let config = EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        };
        let endpoint = kr_transport::endpoint::bind_dialer(&config, &keys.transport)
            .await
            .expect("an endpoint to dial from");
        // The identity a device presents before it is paired. The host gives it the identity it
        // is known by when it commits the pairing.
        let unpaired = LocalIdentity::new(
            DeviceId::new(kr_ipc::new_uuid()),
            DeviceKeyRevision::new(1),
            *keys.transport.public(),
            keys.authorisation.clone(),
            build(),
        );
        let secrets = directory.join("secrets");
        let store = kr_crypto::store::open_store_in(&secrets).expect("the device's own store");
        let budget = DurableClientBudgetStore::open(
            directory.join("pairing-budget"),
            Arc::from(store.store),
            "device",
        )
        .expect("the device's attempt budget");
        let clock = HostPairingClock::new(&kr_ipc::identity::boot_identity().expect("a boot"));
        Self {
            name: name.to_owned(),
            keys,
            endpoint,
            unpaired,
            budget,
            clock,
        }
    }

    /// The name this device declares.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The device's own keys.
    #[must_use]
    pub const fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// What this device's bundle declares.
    #[must_use]
    pub fn declared(&self) -> CandidateIdentity {
        CandidateIdentity {
            keys: self.keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            device_name: DeviceName::new(self.name.clone()).expect("a device name"),
            platform: if cfg!(target_os = "macos") {
                DevicePlatform::Macos
            } else {
                DevicePlatform::Linux
            },
            endpoint_id: *self.keys.transport.public(),
        }
    }

    /// Enters a short code for `origin` and runs the exchange through the room up to the device's
    /// own sealed bundle, which the host has accepted.
    ///
    /// # Errors
    ///
    /// Returns how the attempt stopped: the host's refusal, the room ending it, or this device's
    /// own state machine refusing a step.
    pub async fn enter_code(
        &self,
        origin: &RendezvousOrigin,
        code: &str,
    ) -> Result<CodeExchange, PairingStopped> {
        let entered = EnteredCode::parse(code).map_err(|error| local(&error))?;
        let mut socket = CandidateSocket::open(origin, entered.locator())
            .await
            .map_err(PairingStopped::Room)?;
        let ServiceFrame::Record {
            invitation_id,
            expires_at_ms,
        } = socket.next(FRAME_DEADLINE).await.map_err(room)?
        else {
            return Err(PairingStopped::Room(
                "the room did not serve the record first".to_owned(),
            ));
        };
        let lookup = Served(LocatorRecord {
            invitation_id,
            advertised_expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
        });
        let (mut client, admission, _) =
            ClientAttempt::start(&self.budget, &self.clock, &lookup, origin, &entered)
                .map_err(|error| local(&error))?;
        let attempt_id = admission.attempt_id;
        let mut exchange = Exchange { socket, attempt_id };
        exchange
            .socket
            .send(&ClientFrame::Attempt { attempt_id })
            .await
            .map_err(PairingStopped::Room)?;
        exchange
            .send(&RendezvousMessage::Admit {
                client_nonce: admission.client_nonce,
            })
            .await?;
        let RendezvousMessage::HostPake {
            host_nonce,
            message,
        } = exchange.receive().await?
        else {
            return Err(PairingStopped::Room(
                "the host did not answer with its PAKE message".to_owned(),
            ));
        };
        let client_pake = client
            .with_host_nonce(host_nonce, &self.clock)
            .map_err(|error| local(&error))?;
        exchange
            .send(&RendezvousMessage::ClientPake {
                message: Bytes::new(client_pake),
            })
            .await?;
        let tag = client
            .receive_host_pake(message.as_slice(), &self.clock)
            .map_err(|error| local(&error))?;
        exchange
            .send(&RendezvousMessage::ClientConfirmation { tag })
            .await?;
        let RendezvousMessage::HostConfirmation { tag } = exchange.receive().await? else {
            return Err(PairingStopped::Room(
                "the host did not answer with its confirmation tag".to_owned(),
            ));
        };
        client
            .verify_host_confirmation(&tag, &self.clock)
            .map_err(|error| local(&error))?;
        let RendezvousMessage::Bundle {
            sequence,
            nonce,
            ciphertext,
        } = exchange.receive().await?
        else {
            return Err(PairingStopped::Room(
                "the host's tag was not followed by its bundle".to_owned(),
            ));
        };
        let host_bundle = client
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
            .map_err(|error| local(&error))?;
        let declared = self.declared();
        let frame = client
            .seal_client_bundle(
                &self.keys.authorisation,
                ClientBundle {
                    endpoint_id: declared.endpoint_id,
                    keys: declared.keys,
                    device_key_revision: declared.device_key_revision,
                    device_name: declared.device_name,
                    platform: declared.platform,
                },
                &self.clock,
            )
            .map_err(|error| local(&error))?;
        exchange
            .send(&RendezvousMessage::Bundle {
                sequence: frame.sequence,
                nonce: frame.nonce,
                ciphertext: Bytes::new(frame.ciphertext),
            })
            .await?;
        match exchange.receive().await? {
            RendezvousMessage::BundleAccepted => {}
            other => {
                return Err(PairingStopped::Room(format!(
                    "the host answered the device's bundle with {other:?}"
                )));
            }
        }
        // Everything after this goes over iroh, to the endpoint the authenticated bundle pinned.
        exchange.socket.close().await;
        Ok(CodeExchange {
            client,
            invitation_id: host_bundle.bundle.invitation_id,
            host: host_bundle.bundle,
        })
    }

    /// Binds a code exchange's transcript to both live endpoints with `pair.finish` over iroh.
    ///
    /// Returns the unpaired connection the device asks about its pairing on, and the value it
    /// displays for the owner to compare.
    ///
    /// # Errors
    ///
    /// Returns why the host could not be reached or refused the binding.
    pub async fn finish(&self, exchange: &mut CodeExchange) -> Result<Candidate, String> {
        let address = address_of(&exchange.host.endpoint_id, &exchange.host.network_config);
        let connection = bounded(
            "the connection to the pinned host",
            self.endpoint.connect(address, kr_protocol::hello::ALPN),
        )
        .await?
        .map_err(|error| format!("the pinned host could not be reached: {error}"))?;
        let mut unpaired = bounded(
            "the unpaired handshake",
            handshake::connect_unpaired(&connection, &self.unpaired),
        )
        .await?
        .map_err(|error| format!("the host did not answer an unpaired device: {error}"))?;
        let request = exchange
            .client
            .finish_request(
                &Pinned(exchange.host.endpoint_id),
                &self.declared().endpoint_id,
                &self.clock,
            )
            .map_err(|error| format!("no finish request: {error}"))?;
        let finished: PairFinishResult =
            bounded("pair.finish", unpaired.call(Method::PairFinish, &request))
                .await?
                .map_err(|error| format!("pair.finish: {error}"))?;
        // The value this device displays is its own, from the transcript it holds. The host's is
        // compared with it rather than taken in its place.
        let verification_value = exchange
            .client
            .verification_value()
            .map_err(|error| format!("no verification value: {error}"))?;
        if !kr_pairing::direct::verification_values_match(
            &verification_value,
            &finished.verification_value,
        ) {
            return Err(
                "the host's verification value is not the one this device derives".to_owned(),
            );
        }
        let host = &exchange.host;
        Ok(Candidate {
            connection,
            unpaired,
            invitation_id: exchange.invitation_id,
            verification_value,
            host: PairedPeer {
                device_id: host.device_id,
                device_key_revision: host.device_key_revision,
                authorisation: host.keys.authorisation,
                endpoint_id: host.endpoint_id,
            },
            address: address_of(&host.endpoint_id, &host.network_config),
        })
    }

    /// Redeems the direct invitation `qr_text` names, over loopback iroh to the pinned endpoint.
    ///
    /// # Errors
    ///
    /// Returns why the payload could not be read, the host reached, or the redemption made.
    pub async fn redeem(&self, qr_text: &str) -> Result<Candidate, String> {
        let QrPayload::Direct(payload) = QrPayload::from_text(qr_text)
            .map_err(|error| format!("the QR text is not a payload: {error}"))?
        else {
            return Err("the QR is not a direct invitation".to_owned());
        };
        let payload: DirectQrPayload = *payload;
        let address = address_of(&payload.endpoint_id, &payload.network_config);
        let connection = bounded(
            "the connection to the pinned host",
            self.endpoint
                .connect(address.clone(), kr_protocol::hello::ALPN),
        )
        .await?
        .map_err(|error| format!("the pinned host could not be reached: {error}"))?;
        let mut unpaired = bounded(
            "the unpaired handshake",
            handshake::connect_unpaired(&connection, &self.unpaired),
        )
        .await?
        .map_err(|error| format!("the host did not answer an unpaired device: {error}"))?;
        let challenge: PairRedeemResult = bounded(
            "the redemption's challenge",
            unpaired.call(
                Method::PairRedeem,
                &PairRedeemParams::Challenge {
                    invitation_id: payload.invitation_id,
                },
            ),
        )
        .await?
        .map_err(|error| format!("the challenge: {error}"))?;
        let PairRedeemResult::Challenge(challenge) = challenge else {
            return Err("the first redemption step did not answer with a challenge".to_owned());
        };
        let (proof, transcript) = redeem_proof(
            &payload,
            &challenge,
            &self.keys.authorisation,
            &self.declared(),
            &Pinned(challenge.endpoint_id),
        )
        .map_err(|error| format!("no redemption proof: {error}"))?;
        // The value this device displays is its own, from the transcript it signed. The host's is
        // compared with it rather than taken in its place.
        let verification_value = kr_protocol::pairing::direct_verification_value(&transcript);
        let locked: PairRedeemResult = bounded(
            "the redemption",
            unpaired.call(
                Method::PairRedeem,
                &PairRedeemParams::Direct(Box::new(proof)),
            ),
        )
        .await?
        .map_err(|error| format!("the redemption: {error}"))?;
        let PairRedeemResult::Locked {
            verification_value: shown,
            ..
        } = locked
        else {
            return Err("the redemption did not lock the invitation".to_owned());
        };
        if !kr_pairing::direct::verification_values_match(&verification_value, &shown) {
            return Err(
                "the host's verification value is not the one this device derives".to_owned(),
            );
        }
        // The host's own identity comes from the connection pinned to the endpoint the QR named,
        // and its keys from the challenge on that connection. The paired connection then checks
        // the host's proof against both.
        let host = PairedPeer {
            device_id: unpaired.selection.device_id,
            device_key_revision: challenge.device_key_revision,
            authorisation: challenge.host_keys.authorisation,
            endpoint_id: challenge.endpoint_id,
        };
        Ok(Candidate {
            connection,
            unpaired,
            invitation_id: payload.invitation_id,
            verification_value,
            host,
            address,
        })
    }

    /// Connects to a host this device paired with, proving its key and checking the host's.
    ///
    /// # Errors
    ///
    /// Returns the transport's failure, including the host's refusal of the proof.
    pub async fn connect(&self, paired: &PairedHost) -> Result<Remote, String> {
        self.reconnect(paired, StreamCursors::new()).await
    }

    /// Connects again, carrying the content positions an earlier connection had reached.
    ///
    /// A new connection has its own identity and its own input stream; what it carries is how far
    /// each stream's content had been applied, which is what its subscriptions resume from.
    ///
    /// # Errors
    ///
    /// As [`Self::connect`].
    pub async fn reconnect(
        &self,
        paired: &PairedHost,
        cursors: StreamCursors,
    ) -> Result<Remote, String> {
        let identity = LocalIdentity::new(
            paired.device_id,
            DeviceKeyRevision::new(1),
            *self.keys.transport.public(),
            self.keys.authorisation.clone(),
            build(),
        );
        let transport = bounded(
            "the paired connection",
            NetworkTransport::connect(
                &self.endpoint,
                paired.address.clone(),
                &identity,
                &paired.record,
                SendLimits::default(),
            ),
        )
        .await?
        .map_err(|error| format!("the paired connection: {error}"))?;
        let connection_id = kr_client::transport::ControlTransport::connection_id(&transport);
        let session = Session::resume(Arc::new(transport), cursors)
            .map_err(|error| format!("a session on the connection: {error}"))?;
        let info: HostInfoResult = bounded("host.info", session.read(Method::HostInfo, &()))
            .await?
            .map_err(|error| format!("host.info over the paired connection: {error}"))?;
        Ok(Remote {
            session,
            environment_id: info.environment_id,
            keys: self.keys.clone(),
            connection: connection_id.to_string(),
        })
    }

    /// Closes the device's endpoint.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// A code exchange that has reached the host's acceptance of the device's bundle.
pub struct CodeExchange {
    client: ClientAttempt,
    invitation_id: InvitationId,
    host: kr_protocol::pairing::HostBundle,
}

impl std::fmt::Debug for CodeExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeExchange")
            .field("invitation_id", &self.invitation_id)
            .finish_non_exhaustive()
    }
}

/// A candidate that has bound itself to an invitation and waits for the owner's approval.
pub struct Candidate {
    connection: iroh::endpoint::Connection,
    unpaired: CandidateConnection,
    /// The invitation it answered.
    pub invitation_id: InvitationId,
    /// The value this device displays for the owner to compare.
    pub verification_value: String,
    host: PairedPeer,
    address: EndpointAddr,
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Candidate")
            .field("invitation_id", &self.invitation_id)
            .finish_non_exhaustive()
    }
}

impl Candidate {
    /// Asks the host, on the unpaired connection, what became of this candidate, and returns the
    /// paired host once the owner has approved it.
    ///
    /// # Errors
    ///
    /// Returns the status when the pairing did not commit within `within`.
    pub async fn committed(mut self, within: Duration) -> Result<PairedHost, String> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let status: PairStatusResult = bounded(
                "pair.status",
                self.unpaired.call(
                    Method::PairStatus,
                    &PairStatusParams {
                        invitation_id: self.invitation_id,
                    },
                ),
            )
            .await?
            .map_err(|error| format!("pair.status: {error}"))?;
            if let PairStatus::Committed {
                device_id,
                grant_id,
            } = status.status
            {
                self.connection.close(0_u32.into(), b"paired");
                return Ok(PairedHost {
                    device_id,
                    grant_id,
                    record: self.host,
                    address: self.address,
                });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "the pairing did not commit within {within:?}: {:?}",
                    status.status
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// A paired connection to a host, and what a device does over it.
pub struct Remote {
    session: Session,
    environment_id: EnvironmentId,
    keys: DeviceKeys,
    connection: String,
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Remote")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// The client session on the connection.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The environment the host serves, as it said over this connection.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// The connection identity the host allocated.
    #[must_use]
    pub fn connection(&self) -> &str {
        &self.connection
    }

    /// Calls a read and parses its result.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or the connection's failure.
    pub async fn read<P, R>(&self, method: Method, params: &P) -> Result<R, RequestError>
    where
        P: serde::Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        bounded(method.as_str(), self.session.read(method, params))
            .await
            .map_err(RequestError::Unanswered)?
            .map_err(RequestError::Client)
    }

    /// Submits a mutation about `target` and parses the result it settled with.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or the connection's failure.
    pub async fn mutate<P, R>(
        &self,
        method: Method,
        target: ActionTarget,
        params: &P,
    ) -> Result<R, RequestError>
    where
        P: serde::Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        bounded(
            method.as_str(),
            self.session.mutate(
                method,
                target,
                None,
                &ParamsValue::empty(),
                params,
                LIFETIME,
            ),
        )
        .await
        .map_err(RequestError::Unanswered)?
        .and_then(|settled| settled.to_typed())
        .map_err(RequestError::Client)
    }

    /// Submits a mutation about this host's environment.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or the connection's failure.
    pub async fn mutate_environment<P, R>(
        &self,
        method: Method,
        params: &P,
    ) -> Result<R, RequestError>
    where
        P: serde::Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        self.mutate(
            method,
            ActionTarget::environment(self.environment_id),
            params,
        )
        .await
    }

    /// Waits for a challenge the owner has still to answer whose display `wanted` accepts, answers
    /// it in this owner device's own ceremony, and returns the host's record of the answer.
    ///
    /// # Errors
    ///
    /// Returns why no such challenge was answered within [`CHALLENGE_WAIT`].
    pub async fn confirm_pending(
        &self,
        wanted: impl Fn(&ConfirmationDisplay) -> bool,
    ) -> Result<OwnerConfirmationCompleteResult, String> {
        let deadline = tokio::time::Instant::now() + CHALLENGE_WAIT;
        loop {
            let pending: OwnerConfirmationPendingResult = self
                .read(
                    Method::OwnerConfirmationPending,
                    &OwnerConfirmationPendingParams {},
                )
                .await
                .map_err(|error| format!("owner.confirmation.pending: {error}"))?;
            if let Some(challenge) = pending
                .pending
                .iter()
                .find(|challenge| !challenge.answered && wanted(&challenge.display))
            {
                let proof = self.sign(&challenge.request)?;
                return self
                    .mutate_environment(
                        Method::OwnerConfirmationComplete,
                        &OwnerConfirmationCompleteParams {
                            proof,
                            bootstrap_signer: Nullable::null(),
                        },
                    )
                    .await
                    .map_err(|error| format!("owner.confirmation.complete: {error}"));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "no challenge the owner could answer appeared within {CHALLENGE_WAIT:?}: {:?}",
                    pending.pending
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Asks the host for a challenge about an action it describes by its digest, and answers it in
    /// this owner device's own ceremony, returning the proof the effect then carries.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn confirm_described(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
    ) -> Result<OwnerConfirmationProof, String> {
        let asked: OwnerConfirmationRequestResult = self
            .mutate_environment(
                Method::OwnerConfirmationRequest,
                &OwnerConfirmationRequestParams {
                    subject: ConfirmationSubject::Described(DescribedAction {
                        action,
                        action_digest,
                        destination_keys: Nullable::null(),
                        destination_rights: CanonicalSet::new(),
                    }),
                },
            )
            .await
            .map_err(|error| format!("owner.confirmation.request: {error}"))?;
        self.sign(&asked.request)
    }

    fn sign(
        &self,
        request: &kr_protocol::pairing::OwnerConfirmationRequest,
    ) -> Result<OwnerConfirmationProof, String> {
        kr_pairing::confirm::sign_confirmation(
            &self.keys.authorisation,
            request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .map_err(|error| format!("the owner's proof: {error}"))
    }

    /// Ends the connection.
    pub fn close(&self) {
        self.session.close();
    }
}

/// The record the room served, as the lookup this device's state machine asks for.
struct Served(LocatorRecord);

impl RendezvousClient for Served {
    fn lookup(
        &self,
        _origin: &RendezvousOrigin,
        _locator: &kr_protocol::pairing::Locator,
    ) -> kr_pairing::Result<LocatorRecord> {
        Ok(self.0.clone())
    }
}

/// The host as this device sees it: the endpoint its authenticated material pinned.
struct Pinned(EndpointKey);

impl LivePeer for Pinned {
    fn live_endpoint(&self) -> kr_pairing::Result<EndpointKey> {
        Ok(self.0)
    }

    fn arrived_in_early_data(&self) -> bool {
        false
    }
}

/// One attempt's frames through the room.
struct Exchange {
    socket: CandidateSocket,
    attempt_id: kr_protocol::ids::AttemptId,
}

impl Exchange {
    async fn send(&mut self, message: &RendezvousMessage) -> Result<(), PairingStopped> {
        let payload = encode_message(message).map_err(PairingStopped::Local)?;
        self.socket
            .send(&ClientFrame::Relay {
                attempt_id: self.attempt_id,
                payload,
            })
            .await
            .map_err(PairingStopped::Room)
    }

    async fn receive(&mut self) -> Result<RendezvousMessage, PairingStopped> {
        loop {
            match self.socket.next(FRAME_DEADLINE).await.map_err(room)? {
                ServiceFrame::Relay {
                    attempt_id,
                    payload,
                } if attempt_id == self.attempt_id => {
                    let message =
                        decode_message(payload.as_slice()).map_err(PairingStopped::Room)?;
                    if let RendezvousMessage::Refused {
                        code,
                        remaining_confirmations,
                    } = message
                    {
                        return Err(PairingStopped::Refused {
                            code,
                            remaining: remaining_confirmations.0,
                        });
                    }
                    return Ok(message);
                }
                ServiceFrame::AttemptClosed { reason, .. } => {
                    return Err(PairingStopped::Room(format!(
                        "the attempt closed: {reason:?}"
                    )));
                }
                // Anything else a candidate may be sent is not about this attempt's messages.
                _ => {}
            }
        }
    }
}

fn room(stopped: Stopped) -> PairingStopped {
    PairingStopped::Room(stopped.to_string())
}

fn local(error: &kr_pairing::PairingError) -> PairingStopped {
    PairingStopped::Local(error.to_string())
}

/// Where a device dials a host, from the endpoint and the hints its authenticated material names.
#[must_use]
pub fn address_of(endpoint_id: &EndpointKey, network_config: &NetworkConfig) -> EndpointAddr {
    let key = iroh::PublicKey::from_bytes(endpoint_id.as_bytes())
        .expect("the host's material pins a usable endpoint identity");
    let mut address = EndpointAddr::new(key);
    for hint in &network_config.direct_addresses {
        if let Ok(socket) = hint.as_str().parse::<std::net::SocketAddr>() {
            address = address.with_ip_addr(socket);
        }
    }
    address
}
