//! Pairing through the methods the daemon serves, as the owner's own client and a candidate do.
//!
//! Nothing here reaches inside the daemon. The owner asks for a confirmation, answers it, issues
//! the invitation, reads what the candidate bound and confirms it, each over the owner's local
//! socket; the candidate redeems over its own unpaired iroh connection. A suite that pairs a
//! device therefore exercises exactly the path a person's pairing takes.

use iroh::{Endpoint, EndpointAddr};
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_ipc::client::LocalClient;
use kr_pairing::confirm::sign_confirmation;
use kr_pairing::direct::{CandidateIdentity, redeem_proof};
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationPendingParams, OwnerConfirmationPendingResult, OwnerConfirmationRequestParams,
    OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, EnvironmentId, InvitationId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairCancelParams, PairConfirmParams,
    PairConfirmResult, PairInviteParams, PairInviteResult, PairingApproval,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, DirectQrPayload, OwnerConfirmationProof, OwnerConfirmationRequest,
    ProposedGrant, QrPayload,
};
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::scalars::{AuthorisationKey, Nullable};
use kr_transport::handshake::{self, CandidateConnection, LocalIdentity};

/// The host as the candidate sees it: the endpoint identity the invitation pinned.
#[derive(Debug)]
pub struct HostPeer(pub [u8; 32]);

impl kr_pairing::platform::LivePeer for HostPeer {
    fn live_endpoint(&self) -> kr_pairing::Result<kr_protocol::scalars::EndpointKey> {
        Ok(kr_protocol::scalars::EndpointKey::from_bytes(self.0))
    }

    fn arrived_in_early_data(&self) -> bool {
        false
    }
}

/// Returns where a candidate dials the host, from the invitation alone.
#[must_use]
pub fn host_addr(payload: &DirectQrPayload) -> EndpointAddr {
    let endpoint_id = iroh::PublicKey::from_bytes(payload.endpoint_id.as_bytes())
        .expect("the invitation pins a usable endpoint identity");
    let mut addr = EndpointAddr::new(endpoint_id);
    if let Some(relay) = payload
        .network_config
        .relay_urls
        .first()
        .and_then(|hint| hint.as_str().parse::<iroh::RelayUrl>().ok())
    {
        addr = addr.with_relay_url(relay);
    }
    for hint in &payload.network_config.direct_addresses {
        if let Ok(socket) = hint.as_str().parse::<std::net::SocketAddr>() {
            addr = addr.with_ip_addr(socket);
        }
    }
    addr
}

/// A candidate: its endpoint, the identity it presents before pairing and what it declares.
pub struct Candidate<'a> {
    /// The endpoint it dials from.
    pub endpoint: &'a Endpoint,
    /// The identity it presents on an unpaired connection.
    pub identity: &'a LocalIdentity,
    /// Its keys.
    pub keys: &'a DeviceKeys,
    /// What its bundle declares.
    pub declared: CandidateIdentity,
}

/// Sends one read on the owner's own socket.
pub async fn read<P, T>(
    client: &mut LocalClient,
    method: Method,
    params: &P,
) -> Result<T, ProtocolError>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let answer = client
        .request(method, params)
        .await
        .expect("the daemon answers")?;
    Ok(answer.to_typed().expect("the answer decodes"))
}

/// Sends one mutation on the owner's own socket, under a fresh action identity.
pub async fn mutate<P, T>(
    environment: EnvironmentId,
    client: &mut LocalClient,
    method: Method,
    params: &P,
) -> Result<T, ProtocolError>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    mutate_as(
        environment,
        client,
        ActionId::new(kr_ipc::new_uuid()),
        method,
        params,
    )
    .await
}

/// Sends one mutation under the action identity given, which is how a suite submits a retry.
pub async fn mutate_as<P, T>(
    environment: EnvironmentId,
    client: &mut LocalClient,
    action: ActionId,
    method: Method,
    params: &P,
) -> Result<T, ProtocolError>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let answer = client
        .mutate(
            method,
            action,
            ActionTarget::environment(environment),
            params,
        )
        .await
        .expect("the daemon answers")?;
    Ok(answer.to_typed().expect("the answer decodes"))
}

/// Asks for the challenge that confirms `subject`.
pub async fn request(
    environment: EnvironmentId,
    client: &mut LocalClient,
    subject: ConfirmationSubject,
) -> Result<OwnerConfirmationRequestResult, ProtocolError> {
    mutate(
        environment,
        client,
        Method::OwnerConfirmationRequest,
        &OwnerConfirmationRequestParams { subject },
    )
    .await
}

/// Answers a challenge with a proof.
pub async fn complete(
    environment: EnvironmentId,
    client: &mut LocalClient,
    proof: OwnerConfirmationProof,
    bootstrap_signer: Option<AuthorisationKey>,
) -> Result<OwnerConfirmationCompleteResult, ProtocolError> {
    mutate(
        environment,
        client,
        Method::OwnerConfirmationComplete,
        &OwnerConfirmationCompleteParams {
            proof,
            bootstrap_signer: bootstrap_signer.map_or_else(Nullable::null, Nullable::some),
        },
    )
    .await
}

/// Lists the challenges an owner can still answer.
pub async fn pending(
    client: &mut LocalClient,
) -> Result<OwnerConfirmationPendingResult, ProtocolError> {
    read(
        client,
        Method::OwnerConfirmationPending,
        &OwnerConfirmationPendingParams {},
    )
    .await
}

/// How an owner answers a challenge.
pub enum Signer<'a> {
    /// A paired owner device's own ceremony.
    OwnerDevice(&'a DeviceKeys),
    /// The initial bootstrap at an interactive terminal, with a key made for it.
    Bootstrap(&'a AuthorisationKeyPair),
}

/// Asks for the challenge for `subject`, signs it as `signer` and answers it.
pub async fn confirm_subject(
    environment: EnvironmentId,
    client: &mut LocalClient,
    subject: ConfirmationSubject,
    signer: &Signer<'_>,
) -> Result<OwnerConfirmationRequest, ProtocolError> {
    let challenge = request(environment, client, subject).await?;
    let (proof, presented) = sign(&challenge.request, signer);
    complete(environment, client, proof, presented).await?;
    Ok(challenge.request)
}

/// Signs one challenge as `signer`.
#[must_use]
pub fn sign(
    request: &OwnerConfirmationRequest,
    signer: &Signer<'_>,
) -> (OwnerConfirmationProof, Option<AuthorisationKey>) {
    match signer {
        Signer::OwnerDevice(keys) => (
            sign_confirmation(
                &keys.authorisation,
                request,
                ConfirmationChannel::OwnerDevicePresence,
            )
            .expect("a proof"),
            None,
        ),
        Signer::Bootstrap(key) => (
            sign_confirmation(key, request, ConfirmationChannel::LocalBootstrapTerminal)
                .expect("a proof"),
            Some(*key.public()),
        ),
    }
}

/// Issues a direct invitation for `proposal`, once `signer` has confirmed issuing it.
pub async fn invite_direct(
    environment: EnvironmentId,
    client: &mut LocalClient,
    grant_kind: InviteGrantKind,
    proposal: &ProposedGrant,
    signer: &Signer<'_>,
) -> Result<PairInviteResult, ProtocolError> {
    confirm_subject(
        environment,
        client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind,
            proposed_grant: proposal.clone(),
        },
        signer,
    )
    .await?;
    mutate(
        environment,
        client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Direct,
            grant_kind,
            proposed_grant: proposal.clone(),
        },
    )
    .await
}

/// Returns the direct QR payload an invitation's answer carries.
#[must_use]
pub fn direct_payload(invited: &PairInviteResult) -> DirectQrPayload {
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation is offered as a direct QR");
    };
    let QrPayload::Direct(payload) = QrPayload::from_text(qr_text.as_str()).expect("a payload")
    else {
        panic!("a direct QR carries a direct payload");
    };
    *payload
}

/// Redeems a direct invitation as `device`, over the unpaired surface an unpaired endpoint reaches.
///
/// Returns the candidate's connection, which it asks about its pairing on afterwards.
pub async fn redeem(
    device: &Candidate<'_>,
    invited: &PairInviteResult,
) -> (iroh::endpoint::Connection, CandidateConnection, String) {
    let payload = direct_payload(invited);
    let connection = device
        .endpoint
        .connect(host_addr(&payload), kr_protocol::hello::ALPN)
        .await
        .expect("the candidate reaches the host");
    let mut candidate = handshake::connect_unpaired(&connection, device.identity)
        .await
        .expect("an unpaired connection");
    let challenge: PairRedeemResult = candidate
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Challenge {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("the host issues a challenge");
    let PairRedeemResult::Challenge(challenge) = challenge else {
        panic!("the first redemption step answers with a challenge");
    };
    let live_host = HostPeer(*challenge.endpoint_id.as_bytes());
    let (proof, _transcript) = redeem_proof(
        &payload,
        &challenge,
        &device.keys.authorisation,
        &device.declared,
        &live_host,
    )
    .expect("a redemption proof");
    let locked: PairRedeemResult = candidate
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Direct(Box::new(proof)),
        )
        .await
        .expect("the host accepts the redemption");
    let PairRedeemResult::Locked {
        verification_value, ..
    } = locked
    else {
        panic!("a redemption locks the invitation");
    };
    (connection, candidate, verification_value)
}

/// Reads the owner's view of one invitation.
pub async fn owner_status(
    client: &mut LocalClient,
    invitation_id: InvitationId,
) -> Result<PairStatusResult, ProtocolError> {
    read(
        client,
        Method::PairStatus,
        &PairStatusParams { invitation_id },
    )
    .await
}

/// Confirms the candidate bound to `invitation_id`, once `signer` has confirmed that device.
pub async fn confirm_candidate(
    environment: EnvironmentId,
    client: &mut LocalClient,
    invitation_id: InvitationId,
    signer: &Signer<'_>,
) -> Result<PairConfirmResult, ProtocolError> {
    let status = owner_status(client, invitation_id).await?;
    let approval: PairingApproval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("a bound candidate the owner can approve");
    confirm_subject(
        environment,
        client,
        ConfirmationSubject::ConfirmDevice { invitation_id },
        signer,
    )
    .await?;
    mutate(
        environment,
        client,
        Method::PairConfirm,
        &PairConfirmParams {
            invitation_id,
            approval,
        },
    )
    .await
}

/// Withdraws or denies one invitation.
pub async fn cancel(
    environment: EnvironmentId,
    client: &mut LocalClient,
    invitation_id: InvitationId,
    deny: bool,
) -> Result<PairStatusResult, ProtocolError> {
    mutate(
        environment,
        client,
        Method::PairCancel,
        &PairCancelParams {
            invitation_id,
            deny,
        },
    )
    .await
}
