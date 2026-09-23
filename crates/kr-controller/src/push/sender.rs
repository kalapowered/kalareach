//! Renewing the authorisation this host delivers under, at the gateway that issued it.
//!
//! `push.sender.renew` is two requests, because the proof answers a nonce the gateway chose. The
//! host asks for the nonce, and then returns it signed with the host key the installation named,
//! and the gateway answers the second with a fresh credential. A captured renewal therefore
//! answers a question that has already been asked and closed.
//!
//! Both requests are managed-service requests and carry the one signature every such request
//! carries, a [`ServiceRequestSignature`] over the gateway's origin, the method, a fresh nonce,
//! the time and the digest of the body. The digest is [`PushRequest::digest`], the push request
//! digest the gateway recomputes from the body it received, so a signature covers this body and
//! this method and no other.
//!
//! The gateway is the one the held credential names. A renewal proof covers that origin, and a
//! gateway checks the origin it is asked under, so a renewal could not be carried to any other.
//!
//! # What the host key signs
//!
//! [`HostSigner`] holds the host's authorisation key for delivery and signs exactly two kinds of
//! transcript with it: a managed-service request and a renewal proof. Anything else it is handed is
//! refused, so the seam cannot be used to sign a pairing bundle or a grant.

use std::sync::Arc;

use kr_client::services::{ServiceHttpAnswer, ServiceSigner};
use kr_protocol::push::{
    PUSH_SENDER_RENEWAL_DOMAIN, PushDeliveryCredential, PushRequest, PushSenderNonceRequest,
    PushSenderRecord, PushSenderRenewRequest, PushSenderRenewal, PushSenderRenewalPayload,
    PushSenderState,
};
use kr_protocol::scalars::{AuthorisationKey, Nonce256, Signature64, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, ServiceRequestSigner,
};

use super::credentials::CredentialRenewal;
use super::transport::DeliveryTransports;

/// The route both steps of a renewal are presented on.
pub const RENEW_ROUTE: &str = "/api/push/sender/renew";

/// The most bytes this client reads from an answer.
///
/// A renewal's answer is an authorisation record and a credential, a few hundred bytes. An answer
/// past this is one this host does not trust.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The host key a sender authorisation is proven with.
pub struct HostSigner {
    key: kr_crypto::keys::AuthorisationKeyPair,
}

impl HostSigner {
    /// Signs with this host's authorisation key.
    #[must_use]
    pub const fn new(key: kr_crypto::keys::AuthorisationKeyPair) -> Self {
        Self { key }
    }
}

impl std::fmt::Debug for HostSigner {
    /// The public key, which is what names this signer to a gateway. Never the private half.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostSigner")
            .field("public_key", self.key.public())
            .finish_non_exhaustive()
    }
}

impl ServiceSigner for HostSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Host
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = [
            ServiceRequestSigner::Host.domain(),
            PUSH_SENDER_RENEWAL_DOMAIN,
        ]
        .into_iter()
        .find_map(|domain| {
            kr_crypto::sign::SigningTranscript::from_canonical_bytes(domain, message.to_vec()).ok()
        })
        .ok_or_else(|| {
            refused("the delivery key signs a managed-service request or a renewal proof")
        })?;
        kr_crypto::sign::sign(&self.key, &transcript)
            .map_err(|error| refused(format!("the renewal could not be signed: {error}")))
    }
}

/// The gateways this host renews its delivery credentials at.
#[derive(Clone, Debug)]
pub struct GatewaySenders {
    transports: Arc<dyn DeliveryTransports>,
    signer: Arc<dyn ServiceSigner>,
    runtime: tokio::runtime::Handle,
}

impl GatewaySenders {
    /// Builds the client over the transports this host reaches its gateways through.
    #[must_use]
    pub fn new(
        transports: Arc<dyn DeliveryTransports>,
        signer: Arc<dyn ServiceSigner>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            transports,
            signer,
            runtime,
        }
    }

    /// Presents one signed request and returns the `data` of the gateway's answer.
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        origin: &GatewayOrigin,
        body: &PushRequest,
    ) -> Result<T, String> {
        let mut nonce = [0_u8; 32];
        kr_crypto::random_bytes(&mut nonce)
            .map_err(|error| format!("no fresh nonce could be drawn: {error}"))?;
        let payload = ServiceRequestPayload {
            body_digest: body
                .digest()
                .map_err(|error| format!("the request could not be digested: {error}"))?,
            gateway_origin: origin.clone(),
            method: body.method(),
            nonce: Nonce256::from_bytes(nonce),
            signed_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
        };
        let input = payload
            .signing_input(ServiceRequestSigner::Host)
            .map_err(|error| format!("the request could not be encoded: {error}"))?;
        let signature = ServiceRequestSignature {
            signature: self
                .signer
                .sign(&input)
                .map_err(|error| error.to_string())?,
            payload,
            signer: ServiceRequestSigner::Host,
            public_key: self.signer.public_key(),
        };
        let request = serde_json::to_vec(&SignedRequest { body, signature })
            .map_err(|error| format!("the request could not be encoded: {error}"))?;
        let transport = self.transports.to(origin)?;
        let url = format!("{}{RENEW_ROUTE}", origin.as_str());
        let answer = self
            .runtime
            .block_on(async { transport.post_json(&url, &request, &[]).await })
            .map_err(|error| format!("the gateway did not answer: {error}"))?;
        data_of(&answer)
    }
}

impl CredentialRenewal for GatewaySenders {
    fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
        let origin = &held.gateway_origin;
        let challenge: SenderChallenge = self.call(
            origin,
            &PushRequest::SenderRenew {
                request: PushSenderRenewRequest::Begin {
                    request: PushSenderNonceRequest {
                        sender_record_id: held.sender_record_id,
                    },
                },
            },
        )?;
        let now_ms = kr_ipc::now_ms().get();
        if challenge.expires_at_ms.get() <= now_ms {
            return Err("the gateway's nonce expired before it could be answered".to_owned());
        }
        let payload = PushSenderRenewalPayload {
            gateway_origin: origin.clone(),
            gateway_nonce: challenge.gateway_nonce,
            requested_at_ms: TimestampMs::new(now_ms),
            sender_record_id: held.sender_record_id,
        };
        let proof = payload
            .signing_input()
            .map_err(|error| format!("the renewal could not be encoded: {error}"))?;
        let signature = self
            .signer
            .sign(&proof)
            .map_err(|error| error.to_string())?;
        let result: SenderResult = self.call(
            origin,
            &PushRequest::SenderRenew {
                request: PushSenderRenewRequest::Complete {
                    renewal: PushSenderRenewal { payload, signature },
                },
            },
        )?;
        let renewed = result.credential;
        // What came back has to be the same authorisation, at the same gateway, for the same
        // destination: a credential for anything else is not a renewal of this one, and holding it
        // would put this host's deliveries under an authority nobody gave it.
        if renewed.sender_record_id != held.sender_record_id
            || renewed.gateway_origin != held.gateway_origin
            || renewed.installation_id != held.installation_id
            || result.record.binding.sender_record_id != held.sender_record_id
            || result.record.binding.host_signing_key != self.signer.public_key()
        {
            return Err(
                "the gateway answered with a credential for another authorisation".to_owned(),
            );
        }
        if result.record.state != PushSenderState::Active || !renewed.lifetime_within_maximum() {
            return Err(
                "the gateway answered with a credential this host may not deliver under".to_owned(),
            );
        }
        Ok(renewed)
    }
}

/// A signed request, as the gateway reads it.
#[derive(serde::Serialize)]
struct SignedRequest<'a> {
    body: &'a PushRequest,
    signature: ServiceRequestSignature,
}

/// What the first step answers: the nonce the proof has to cover.
#[derive(serde::Deserialize)]
struct SenderChallenge {
    gateway_nonce: Nonce256,
    expires_at_ms: TimestampMs,
}

/// What the second step answers: the authorisation as it now stands, and the new credential.
#[derive(serde::Deserialize)]
struct SenderResult {
    record: PushSenderRecord,
    credential: PushDeliveryCredential,
}

/// The standard envelope the gateway answers with.
#[derive(serde::Deserialize)]
struct Envelope<T> {
    ok: bool,
    data: Option<T>,
    error: Option<Refusal>,
}

/// What a refusal says, for a person reading why a renewal did not happen.
#[derive(serde::Deserialize)]
struct Refusal {
    message: String,
}

/// The `data` of one answer, or why there is none.
fn data_of<T: serde::de::DeserializeOwned>(answer: &ServiceHttpAnswer) -> Result<T, String> {
    if answer.body.len() > MAX_ANSWER_BYTES {
        return Err(format!(
            "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host reads",
            answer.body.len()
        ));
    }
    match serde_json::from_slice::<Envelope<T>>(&answer.body) {
        Ok(Envelope {
            ok: true,
            data: Some(data),
            ..
        }) if answer.status == 200 => Ok(data),
        Ok(Envelope {
            error: Some(refusal),
            ..
        }) => Err(format!(
            "the gateway refused the renewal ({}): {}",
            answer.status, refusal.message
        )),
        Ok(_) => Err(format!(
            "the gateway answered {} without a renewal",
            answer.status
        )),
        Err(error) => Err(format!(
            "the gateway's answer ({}) could not be read: {error}",
            answer.status
        )),
    }
}

/// A request this host would not send. Nothing left it.
fn refused(what: impl Into<String>) -> kr_client::ClientError {
    kr_client::ClientError::Host(kr_protocol::error::ProtocolError::new(
        kr_protocol::error::ErrorCode::InvalidArgument,
        what.into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_client::services::{ServiceFuture, ServiceHttp};
    use kr_protocol::ids::{InstallationId, PushSenderRecordId, PushSenderRevision};
    use kr_protocol::push::{PushRatePolicy, PushSenderBinding};
    use kr_protocol::scalars::{EndpointKey, SecretBytes32, Uuid};

    use super::*;

    const NOW_OFFSET_MS: u64 = 60_000;

    /// One exchange the recorder was asked to make.
    #[derive(Clone, Debug)]
    struct Asked {
        url: String,
        body: serde_json::Value,
    }

    /// Answers from a script and records what it was asked.
    #[derive(Debug, Default)]
    struct Recorder {
        answers: Mutex<Vec<(u16, serde_json::Value)>>,
        asked: Mutex<Vec<Asked>>,
    }

    impl ServiceHttp for Recorder {
        fn post_json<'a>(
            &'a self,
            url: &'a str,
            body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.asked.lock().expect("not poisoned").push(Asked {
                url: url.to_owned(),
                body: serde_json::from_slice(body).expect("a JSON request"),
            });
            let (status, answer) = self.answers.lock().expect("not poisoned").remove(0);
            Box::pin(async move {
                Ok(ServiceHttpAnswer {
                    status,
                    body: serde_json::to_vec(&answer).expect("an answer"),
                })
            })
        }
    }

    /// Every origin through the one recorder.
    #[derive(Debug)]
    struct Through(Arc<Recorder>);

    impl DeliveryTransports for Through {
        fn to(&self, _origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String> {
            Ok(Arc::clone(&self.0) as Arc<dyn ServiceHttp>)
        }
    }

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.invalid").expect("an origin")
    }

    fn now() -> u64 {
        kr_ipc::now_ms().get()
    }

    fn credential(byte: u8, expires_at_ms: u64) -> PushDeliveryCredential {
        PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(expires_at_ms),
            gateway_origin: origin(),
            installation_id: InstallationId::new(uuid(2)),
            issued_at_ms: TimestampMs::new(expires_at_ms - 29 * 24 * 60 * 60 * 1000),
            revision: PushSenderRevision::new(1),
            secret: SecretBytes32::from_bytes([byte; 32]),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
        }
    }

    fn record(
        host: &kr_crypto::keys::AuthorisationKeyPair,
        renewed: &PushDeliveryCredential,
    ) -> PushSenderRecord {
        PushSenderRecord {
            binding: PushSenderBinding {
                gateway_origin: origin(),
                host_endpoint_key: EndpointKey::from_bytes([4; 32]),
                host_signing_key: *host.public(),
                installation_id: renewed.installation_id,
                rate_policy: PushRatePolicy::FREE,
                sender_record_id: renewed.sender_record_id,
            },
            credential_expires_at_ms: renewed.expires_at_ms,
            issued_at_ms: renewed.issued_at_ms,
            revision: renewed.revision,
            state: PushSenderState::Active,
        }
    }

    fn challenge(nonce: [u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "data": {
                "gateway_nonce": Nonce256::from_bytes(nonce),
                "expires_at_ms": TimestampMs::new(now() + NOW_OFFSET_MS),
            },
        })
    }

    fn renewed_answer(
        record: &PushSenderRecord,
        credential: &PushDeliveryCredential,
    ) -> serde_json::Value {
        serde_json::json!({ "ok": true, "data": { "record": record, "credential": credential } })
    }

    fn senders(
        recorder: &Arc<Recorder>,
        host: &kr_crypto::keys::AuthorisationKeyPair,
        runtime: &tokio::runtime::Runtime,
    ) -> GatewaySenders {
        GatewaySenders::new(
            Arc::new(Through(Arc::clone(recorder))),
            Arc::new(HostSigner::new(host.clone())),
            runtime.handle().clone(),
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
    }

    /// Verifies one signature the way a gateway does: over the exact transcript, under the
    /// domain it claims.
    fn verifies(
        public: &AuthorisationKey,
        domain: &str,
        input: Vec<u8>,
        signature: &Signature64,
    ) -> bool {
        kr_crypto::sign::SigningTranscript::from_canonical_bytes(domain, input)
            .and_then(|transcript| kr_crypto::sign::verify(public, &transcript, signature))
            .is_ok()
    }

    #[test]
    fn a_renewal_asks_for_a_nonce_and_answers_it_under_the_host_key() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let held = credential(9, now() + 2 * 24 * 60 * 60 * 1000);
        let fresh = credential(10, now() + 30 * 24 * 60 * 60 * 1000 - 1_000);
        let recorder = Arc::new(Recorder::default());
        *recorder.answers.lock().expect("not poisoned") = vec![
            (200, challenge([7; 32])),
            (200, renewed_answer(&record(&host, &fresh), &fresh)),
        ];
        let runtime = runtime();
        let renewed = senders(&recorder, &host, &runtime)
            .renew(&held)
            .expect("a renewal");
        assert_eq!(renewed, fresh);

        let asked = recorder.asked.lock().expect("not poisoned").clone();
        assert_eq!(asked.len(), 2, "two steps");
        let mut nonces = Vec::new();
        for (step, Asked { url, body }) in asked.iter().enumerate() {
            assert_eq!(url, "https://reach.invalid/api/push/sender/renew");
            let signed: PushRequest =
                serde_json::from_value(body["body"].clone()).expect("a push request body");
            let signature: ServiceRequestSignature =
                serde_json::from_value(body["signature"].clone()).expect("a signature");
            assert_eq!(signature.signer, ServiceRequestSigner::Host);
            assert_eq!(signature.public_key, *host.public());
            assert_eq!(
                signature.payload.method,
                kr_protocol::method::Method::PushSenderRenew
            );
            assert_eq!(signature.payload.gateway_origin, origin());
            assert_eq!(
                signature.payload.body_digest,
                signed.digest().expect("a digest"),
                "the signature covers the push request digest of this body"
            );
            assert!(verifies(
                host.public(),
                ServiceRequestSigner::Host.domain(),
                signature
                    .payload
                    .signing_input(ServiceRequestSigner::Host)
                    .expect("an input"),
                &signature.signature,
            ));
            nonces.push(signature.payload.nonce);
            match (step, signed) {
                (
                    0,
                    PushRequest::SenderRenew {
                        request: PushSenderRenewRequest::Begin { request },
                    },
                ) => assert_eq!(request.sender_record_id, held.sender_record_id),
                (
                    1,
                    PushRequest::SenderRenew {
                        request: PushSenderRenewRequest::Complete { renewal },
                    },
                ) => {
                    assert_eq!(
                        renewal.payload.gateway_nonce,
                        Nonce256::from_bytes([7; 32]),
                        "the proof answers the nonce the gateway handed out"
                    );
                    assert_eq!(renewal.payload.sender_record_id, held.sender_record_id);
                    assert_eq!(renewal.payload.gateway_origin, origin());
                    assert!(verifies(
                        host.public(),
                        PUSH_SENDER_RENEWAL_DOMAIN,
                        renewal.payload.signing_input().expect("an input"),
                        &renewal.signature,
                    ));
                }
                (step, other) => panic!("step {step} sent {other:?}"),
            }
        }
        assert_ne!(nonces[0], nonces[1], "each request carries a fresh nonce");
    }

    #[test]
    fn a_refused_renewal_says_why() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let held = credential(9, now() + 2 * 24 * 60 * 60 * 1000);
        let recorder = Arc::new(Recorder::default());
        *recorder.answers.lock().expect("not poisoned") = vec![(
            403,
            serde_json::json!({
                "ok": false,
                "error": { "code": "FORBIDDEN", "message": "There is no such authorisation." },
            }),
        )];
        let runtime = runtime();
        let refused = senders(&recorder, &host, &runtime)
            .renew(&held)
            .expect_err("no renewal");
        assert!(
            refused.contains("There is no such authorisation."),
            "{refused}"
        );
    }

    #[test]
    fn a_credential_for_another_authorisation_is_not_a_renewal() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let held = credential(9, now() + 2 * 24 * 60 * 60 * 1000);
        let mut other = credential(10, now() + 30 * 24 * 60 * 60 * 1000 - 1_000);
        other.sender_record_id = PushSenderRecordId::new(uuid(4));
        let recorder = Arc::new(Recorder::default());
        *recorder.answers.lock().expect("not poisoned") = vec![
            (200, challenge([7; 32])),
            (200, renewed_answer(&record(&host, &other), &other)),
        ];
        let runtime = runtime();
        assert!(senders(&recorder, &host, &runtime).renew(&held).is_err());
    }

    #[test]
    fn the_host_key_signs_a_request_or_a_renewal_proof_and_nothing_else() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let signer = HostSigner::new(host);
        let revocation = kr_protocol::push::PushSenderRevocationPayload {
            gateway_origin: origin(),
            gateway_nonce: Nonce256::from_bytes([7; 32]),
            reason: kr_protocol::push::PushRevocationReason::Unpaired,
            requested_at_ms: TimestampMs::new(1_000),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
        };
        assert!(
            signer
                .sign(&revocation.signing_input().expect("an input"))
                .is_err(),
            "a revocation is not a transcript this seam signs"
        );
        assert!(signer.sign(b"not a transcript").is_err());
    }
}
