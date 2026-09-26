//! A notification the push gateway holds, and the ways it is asked about and removed.
//!
//! An installation registers a push token and authorises a host to send it notifications; the host
//! delivers one through its own gateway client and asks what became of it through its own status
//! reader. On a local deployment every provider send fails before anything leaves this machine, so
//! the gateway keeps the notification queued, retrying, for as long as a leg needs it held there.
//!
//! The gateway's forget is the separately authorised deletion section 24 asks for. The host has no
//! client for it, because the choice is a person's, so this module sends it as the gateway's own
//! contract writes it, with the delivery credential the installation issued or with none at all.

use std::sync::Arc;

use base64::Engine as _;
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_controller::push::client::GatewayClient;
use kr_controller::push::status::{GatewayStatus, StatusAllowance};
use kr_controller::push::transport::DeliveryTransports;
use kr_delivery::preview::{PreviewBody, PreviewTarget, seal_preview};
use kr_delivery::push::{DeliveryStatus as _, PushSender as _, SendOutcome, StatusAnswer};
use kr_protocol::ids::{
    CollapseId, EnvelopeId, NotificationId, PushRegistrationId, PushSenderRecordId,
};
use kr_protocol::push::{
    PUSH_REGISTRATION_ANSWER_DOMAIN, PushAlert, PushDeliveryCredential, PushDeliveryRequest,
    PushPlatform, PushPlatformHints, PushRegistrationAnswer, PushRegistrationAnswerPayload,
    PushRegistrationProposal, PushRegistrationRequest, PushRequest, PushSenderIssueRequest,
    PushUrgency, RegistrationToken, token_digest,
};
use kr_protocol::scalars::{EndpointKey, Nonce256, Nullable, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, installation_id,
};
use kr_sync_integration::{Deployment, RunKey, fresh_uuid, now_ms};

use crate::local::{Answer, LocalStack};

/// The route a registration is proposed and answered on.
const REGISTER_ROUTE: &str = "/api/push/installation/register";

/// The route an installation authorises a host on.
const ISSUE_ROUTE: &str = "/api/push/sender/issue";

/// The route a host asks the gateway to delete what it holds for named notifications on.
pub const FORGET_ROUTE: &str = "/api/push/deliver/forget";

/// One deployment's push gateway, reached over the deployment's transport.
#[derive(Debug)]
pub struct Gateway {
    origin: GatewayOrigin,
    transport: Arc<dyn ServiceHttp>,
}

/// Every delivery reaches the one gateway a leg runs against.
#[derive(Debug)]
struct Only(Arc<dyn ServiceHttp>);

impl DeliveryTransports for Only {
    fn to(&self, _origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String> {
        Ok(Arc::clone(&self.0))
    }
}

impl Gateway {
    /// The gateway of `deployment`.
    #[must_use]
    pub fn of(deployment: &Deployment) -> Self {
        Self {
            origin: deployment.origin().clone(),
            transport: deployment.transport(),
        }
    }

    async fn post(&self, route: &str, body: &[u8], headers: &[(&str, &str)]) -> Answer {
        let url = format!("{}{route}", self.origin.as_str());
        let answer = self
            .transport
            .post_json(&url, body, headers)
            .await
            .expect("the gateway answered");
        Answer {
            status: answer.status,
            body: serde_json::from_slice(&answer.body).unwrap_or(serde_json::Value::Null),
        }
    }

    /// One push request, signed by `key` with the one signature every managed-service request
    /// carries, over the push request digest the gateway recomputes.
    fn signed(&self, key: &RunKey, body: &PushRequest) -> Vec<u8> {
        let mut nonce = [0_u8; 32];
        kr_crypto::random_bytes(&mut nonce).expect("a nonce");
        let payload = ServiceRequestPayload {
            body_digest: body.digest().expect("a digest"),
            gateway_origin: self.origin.clone(),
            method: body.method(),
            nonce: Nonce256::from_bytes(nonce),
            signed_at_ms: TimestampMs::new(now_ms()),
        };
        let input = payload
            .signing_input(body.signer())
            .expect("a signing input");
        let signature = ServiceRequestSignature {
            signature: key.sign(&input).expect("a signature"),
            payload,
            signer: body.signer(),
            public_key: key.public_key(),
        };
        serde_json::to_vec(&serde_json::json!({ "body": body, "signature": signature }))
            .expect("a request")
    }

    /// Registers a push token for `installation` and answers the challenge the gateway sent to it.
    ///
    /// The challenge is read beside the local deployment, standing in for the device that received
    /// it through the provider.
    ///
    /// # Panics
    ///
    /// Panics when the gateway refuses either step or keeps no challenge for the registration.
    pub async fn register(&self, installation: &RunKey, stack: &LocalStack) {
        let registration = PushRegistrationId::new(fresh_uuid());
        let token = RegistrationToken::new(format!("local-{}", fresh_uuid())).expect("a token");
        let proposal = PushRequest::InstallationRegister {
            request: PushRegistrationRequest::Propose {
                proposal: PushRegistrationProposal {
                    installation_key: installation.public_key(),
                    platform: PushPlatform::Ios,
                    registration_id: registration,
                    registration_token: token.clone(),
                },
            },
        };
        let proposed = self
            .post(REGISTER_ROUTE, &self.signed(installation, &proposal), &[])
            .await;
        assert_eq!(
            proposed.status, 200,
            "the registration was proposed: {proposed:?}"
        );
        // Nothing reached a provider, so nothing reached a device: the challenge is still pending.
        assert_eq!(proposed.body["data"]["challenge_sent"], false);

        let named = installation_id(&installation.public_key());
        let challenge = stack
            .pending_challenge(named, registration)
            .expect("the gateway keeps the challenge for this registration");
        let payload: PushRegistrationAnswerPayload = serde_json::from_value(serde_json::json!({
            "challenge": challenge,
            "expires_at_ms": proposed.body["data"]["challenge_expires_at_ms"],
            "gateway_origin": self.origin.as_str(),
            "installation_id": named,
            "platform": PushPlatform::Ios,
            "registration_id": registration,
            "token_digest": token_digest(&token),
        }))
        .expect("the challenge's answer");
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            PUSH_REGISTRATION_ANSWER_DOMAIN,
            payload.signing_input().expect("the answer's signing input"),
        )
        .expect("a transcript");
        let answer = PushRequest::InstallationRegister {
            request: PushRegistrationRequest::Answer {
                answer: PushRegistrationAnswer {
                    payload,
                    installation_key: installation.public_key(),
                    signature: kr_crypto::sign::sign(installation.pair(), &transcript)
                        .expect("a signature"),
                },
            },
        };
        let answered = self
            .post(REGISTER_ROUTE, &self.signed(installation, &answer), &[])
            .await;
        assert_eq!(
            answered.status, 200,
            "the challenge was answered: {answered:?}"
        );
        assert_eq!(answered.body["data"]["state"], "active");
    }

    /// Authorises `host` to send `installation` notifications, and hands back the host's credential.
    ///
    /// # Panics
    ///
    /// Panics when the gateway refuses.
    pub async fn authorise(&self, installation: &RunKey, host: &RunKey) -> PushDeliveryCredential {
        let mut endpoint = [0_u8; 32];
        kr_crypto::random_bytes(&mut endpoint).expect("an endpoint key");
        let issue = PushRequest::SenderIssue {
            request: PushSenderIssueRequest {
                host_endpoint_key: EndpointKey::from_bytes(endpoint),
                host_signing_key: host.public_key(),
                sender_record_id: PushSenderRecordId::new(fresh_uuid()),
            },
        };
        let issued = self
            .post(ISSUE_ROUTE, &self.signed(installation, &issue), &[])
            .await;
        assert_eq!(issued.status, 200, "the host was authorised: {issued:?}");
        serde_json::from_value(issued.body["data"]["credential"].clone())
            .expect("a delivery credential")
    }

    /// Delivers `request` through the host's own gateway client.
    ///
    /// # Panics
    ///
    /// Panics when the blocking task the client runs on cannot be joined.
    pub async fn deliver(
        &self,
        credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        let client = GatewayClient::new(
            Arc::new(Only(Arc::clone(&self.transport))),
            tokio::runtime::Handle::current(),
        );
        let (credential, request) = (credential.clone(), request.clone());
        // The client is synchronous and drives the exchange on the runtime it was given, as a
        // delivery pass does on its blocking thread.
        tokio::task::spawn_blocking(move || client.send(&credential, &request))
            .await
            .expect("the delivery ran")
    }

    /// What the gateway says became of one notification, through the host's own status reader.
    ///
    /// # Panics
    ///
    /// Panics when the blocking task the reader runs on cannot be joined.
    pub async fn status(
        &self,
        credential: &PushDeliveryCredential,
        notification: NotificationId,
    ) -> StatusAnswer {
        let reader = GatewayStatus::new(
            Arc::new(Only(Arc::clone(&self.transport))),
            tokio::runtime::Handle::current(),
            StatusAllowance::RECEIPTS,
        );
        let credential = credential.clone();
        tokio::task::spawn_blocking(move || reader.status(&credential, notification))
            .await
            .expect("the question ran")
    }

    /// Asks the gateway to delete what it holds for `notifications`, presenting `credential`, or no
    /// credential at all.
    pub async fn forget(
        &self,
        credential: Option<&PushDeliveryCredential>,
        notifications: &[NotificationId],
    ) -> Answer {
        let body = serde_json::to_vec(&serde_json::json!({ "notification_ids": notifications }))
            .expect("a deletion");
        match credential {
            Some(credential) => {
                let bearer = format!(
                    "Bearer {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(credential.secret.expose())
                );
                self.post(FORGET_ROUTE, &body, &[("authorization", bearer.as_str())])
                    .await
            }
            None => self.post(FORGET_ROUTE, &body, &[]).await,
        }
    }
}

/// One notification for `sender`, expiring at `expires_at_ms`, with a preview sealed the way the
/// host seals one, to a device key made for the run.
///
/// # Panics
///
/// Panics when a key cannot be made or the preview cannot be sealed.
#[must_use]
pub fn notification(sender: PushSenderRecordId, expires_at_ms: u64) -> PushDeliveryRequest {
    let host = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a sending key");
    let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a device key");
    let now = TimestampMs::new(now_ms());
    let expires = TimestampMs::new(expires_at_ms);
    let sealed = seal_preview(
        &host,
        &PreviewTarget {
            recipient: *device.public(),
            revision: 1,
        },
        EnvelopeId::new(fresh_uuid()),
        &PreviewBody {
            alert: PushAlert::ApprovalWaiting,
            rule: "an approval is waiting".to_owned(),
            summary: "a request is waiting for your approval".to_owned(),
            session_id: Nullable::null(),
            environment_id: Nullable::null(),
            detail_object: Nullable::null(),
            observed_at_ms: now,
        },
        now,
        expires,
    )
    .expect("a sealed preview");
    PushDeliveryRequest {
        collapse_id: CollapseId::new(fresh_uuid()),
        expires_at_ms: expires,
        hints: PushPlatformHints {
            alert: PushAlert::ApprovalWaiting,
            urgency: PushUrgency::Attention,
        },
        notification_id: NotificationId::new(fresh_uuid()),
        preview: Nullable::some(sealed.envelope),
        sender_record_id: sender,
    }
}
