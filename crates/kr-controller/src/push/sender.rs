//! Renewing and revoking the authorisation this host delivers under, at the gateway that issued it.
//!
//! `push.sender.renew` is two requests, because the proof answers a nonce the gateway chose. The
//! host asks for the nonce, and then returns it signed with the host key the installation named,
//! and the gateway answers the second with a fresh credential. A captured renewal therefore
//! answers a question that has already been asked and closed. `push.sender.revoke` is built the
//! same way and ends the authorisation when its device is unpaired.
//!
//! Both requests of either are managed-service requests and carry the one signature every such
//! request carries, a [`ServiceRequestSignature`] over the gateway's origin, the method, a fresh
//! nonce, the time and the digest of the body. The digest is [`PushRequest::digest`], the push
//! request digest the gateway recomputes from the body it received, so a signature covers this
//! body and this method and no other.
//!
//! The gateway is the one the held credential names. A renewal proof covers that origin, and a
//! gateway checks the origin it is asked under, so a renewal could not be carried to any other.
//!
//! # What the host key signs
//!
//! [`HostSigner`] holds the host's authorisation key for delivery and signs exactly three kinds of
//! transcript with it: a managed-service request, a renewal proof and a revocation. Anything else
//! it is handed is refused, so the seam cannot be used to sign a pairing bundle or a grant.

use std::sync::Arc;

use kr_client::services::{ServiceHttpAnswer, ServiceSigner};
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::push::{
    PUSH_SENDER_RENEWAL_DOMAIN, PUSH_SENDER_REVOCATION_DOMAIN, PushDeliveryCredential, PushRequest,
    PushRevocationReason, PushSenderNonceRequest, PushSenderRecord, PushSenderRenewRequest,
    PushSenderRenewal, PushSenderRenewalPayload, PushSenderRevocation, PushSenderRevocationPayload,
    PushSenderRevokeRequest, PushSenderState,
};
use kr_protocol::scalars::{AuthorisationKey, Nonce256, Signature64, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, ServiceRequestSigner,
};

use super::Confirmation;
use super::credentials::CredentialRenewal;
use super::transport::DeliveryTransports;

/// The route both steps of a renewal are presented on.
pub const RENEW_ROUTE: &str = "/api/push/sender/renew";

/// The route both steps of a revocation are presented on.
pub const REVOKE_ROUTE: &str = "/api/push/sender/revoke";

/// The most bytes this client reads from an answer.
///
/// A renewal's answer is an authorisation record and a credential, a few hundred bytes. An answer
/// past this is one this host does not trust.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The codes a gateway names a refusal by, which are the only words of a refusal this host
/// repeats.
///
/// A gateway's own words are the gateway's, and one that repeats what it was sent repeats the
/// bearer credential. So a refusal's body is read by the envelope decoder and never turned into
/// text: a renewal's refusal is recorded by its status and, when it names one of these codes
/// exactly, by that code, as this host's own constant. The list is the one the managed service
/// client keeps for the same gateway's answers, which that crate does not export.
const GATEWAY_CODES: [&str; 20] = [
    "UNAUTHENTICATED",
    "REAUTHENTICATION_REQUIRED",
    "FORBIDDEN",
    "RATE_LIMITED",
    "QUOTA_EXHAUSTED",
    "NOT_CONFIGURED",
    "INTERNAL",
    "INVALID_REQUEST",
    "INVALID_ARGUMENT",
    "NOT_FOUND",
    "METHOD_NOT_ALLOWED",
    "ID_CONFLICT",
    "CONFLICT",
    "REQUEST_FENCED",
    "COLLECTION_ABSENT",
    "KEY_EPOCH_RETIRED",
    "SIGNED_BEFORE_CUTOFF",
    "COLLECTION_DELETED",
    "SERVICE_UNAVAILABLE",
    "OUTCOME_UNKNOWN",
];

/// The code of [`GATEWAY_CODES`] that `named` is exactly, as this host's own constant.
fn known_code(named: &str) -> Option<&'static str> {
    GATEWAY_CODES.iter().copied().find(|code| *code == named)
}

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
            PUSH_SENDER_REVOCATION_DOMAIN,
        ]
        .into_iter()
        .find_map(|domain| {
            kr_crypto::sign::SigningTranscript::from_canonical_bytes(domain, message.to_vec()).ok()
        })
        .ok_or_else(|| {
            refused(
                "the delivery key signs a managed-service request, a renewal proof or a revocation",
            )
        })?;
        kr_crypto::sign::sign(&self.key, &transcript)
            .map_err(|error| refused(format!("the renewal could not be signed: {error}")))
    }
}

/// The gateways this host renews its delivery credentials at, and revokes authorisations at.
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

    /// Presents one signed request to one route and returns the gateway's answer as it came.
    fn post(
        &self,
        origin: &GatewayOrigin,
        route: &str,
        body: &PushRequest,
    ) -> Result<ServiceHttpAnswer, String> {
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
        let url = format!("{}{route}", origin.as_str());
        self.runtime
            .block_on(async { transport.post_json(&url, &request, &[]).await })
            .map_err(|error| format!("the gateway did not answer: {error}"))
    }

    /// Asks the gateway for the nonce a renewal would answer, and nothing more.
    ///
    /// The gateway hands a nonce out at any time, but only for an authorisation that names this
    /// host's signing key. So an answer says the gateway holds the authorisation and that this
    /// host is the one it names, which renewing cannot show before the last week of a credential's
    /// life. The nonce is never answered and lapses on its own; the gateway counts the request
    /// against this host's allowance for renewing and revoking.
    ///
    /// # Errors
    ///
    /// Returns [`Confirmation::Refused`] for the gateway's own refusal, `FORBIDDEN`, which says it
    /// holds no such authorisation for this host's key, and [`Confirmation::NotAsked`] for
    /// everything else that is not a nonce.
    pub fn begin_renewal(
        &self,
        origin: &GatewayOrigin,
        sender_record_id: PushSenderRecordId,
    ) -> Result<(), Confirmation> {
        let answer = self
            .post(
                origin,
                RENEW_ROUTE,
                &PushRequest::SenderRenew {
                    request: PushSenderRenewRequest::Begin {
                        request: PushSenderNonceRequest { sender_record_id },
                    },
                },
            )
            .map_err(Confirmation::NotAsked)?;
        if answer.status == 403 && refusal_code(&answer) == Some("FORBIDDEN") {
            return Err(Confirmation::Refused(
                "the gateway holds no such authorisation for this host".to_owned(),
            ));
        }
        data_of::<SenderChallenge>(&answer, "renewal")
            .map(drop)
            .map_err(Confirmation::NotAsked)
    }

    /// Presents one signed renewal request and returns the `data` of the gateway's answer.
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        origin: &GatewayOrigin,
        body: &PushRequest,
    ) -> Result<T, String> {
        data_of(&self.post(origin, RENEW_ROUTE, body)?, "renewal")
    }
}

/// What asking a gateway to revoke an authorisation came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationAnswer {
    /// The gateway ended the authorisation.
    Revoked,
    /// The gateway knows no authorisation for this host's key under that identifier, so there is
    /// nothing for this host to end and no use in asking again. It says why, in this host's own
    /// words.
    Gone(String),
    /// The revocation did not complete and may be asked for again: nobody answered, the answer was
    /// not one this host reads, or the gateway refused for a reason that may pass.
    Later(String),
}

/// How an authorisation this host no longer delivers under is ended at its gateway.
pub trait SenderRevocation: std::fmt::Debug + Send + Sync {
    /// Revokes one authorisation at the gateway that issued it, proven by this host's key. Blocks.
    fn revoke(
        &self,
        origin: &GatewayOrigin,
        sender_record_id: PushSenderRecordId,
    ) -> RevocationAnswer;
}

impl SenderRevocation for GatewaySenders {
    fn revoke(
        &self,
        origin: &GatewayOrigin,
        sender_record_id: PushSenderRecordId,
    ) -> RevocationAnswer {
        let begin = match self.post(
            origin,
            REVOKE_ROUTE,
            &PushRequest::SenderRevoke {
                request: PushSenderRevokeRequest::Begin {
                    request: PushSenderNonceRequest { sender_record_id },
                },
            },
        ) {
            Ok(answer) => answer,
            Err(error) => return RevocationAnswer::Later(error),
        };
        // The gateway refuses the first step with FORBIDDEN when it holds no authorisation under
        // that identifier for this host's key, and asking again cannot change that. A bare status
        // says nothing of the kind: a proxy, a deployment without the route and a refusal to
        // authenticate answer 403 as well, and the authorisation is then still active.
        if begin.status == 403 && refusal_code(&begin) == Some("FORBIDDEN") {
            return RevocationAnswer::Gone(
                "the gateway holds no such authorisation for this host".to_owned(),
            );
        }
        let challenge: SenderChallenge = match data_of(&begin, "revocation") {
            Ok(challenge) => challenge,
            Err(error) => return RevocationAnswer::Later(error),
        };
        let now_ms = kr_ipc::now_ms().get();
        if challenge.expires_at_ms.get() <= now_ms {
            return RevocationAnswer::Later(
                "the gateway's nonce expired before it could be answered".to_owned(),
            );
        }
        let payload = PushSenderRevocationPayload {
            gateway_origin: origin.clone(),
            gateway_nonce: challenge.gateway_nonce,
            reason: PushRevocationReason::Unpaired,
            requested_at_ms: TimestampMs::new(now_ms),
            sender_record_id,
        };
        let proof = match payload.signing_input() {
            Ok(proof) => proof,
            Err(error) => {
                return RevocationAnswer::Later(format!(
                    "the revocation could not be encoded: {error}"
                ));
            }
        };
        let signature = match self.signer.sign(&proof) {
            Ok(signature) => signature,
            Err(error) => return RevocationAnswer::Later(error.to_string()),
        };
        let complete = match self.post(
            origin,
            REVOKE_ROUTE,
            &PushRequest::SenderRevoke {
                request: PushSenderRevokeRequest::Complete {
                    revocation: PushSenderRevocation { payload, signature },
                },
            },
        ) {
            Ok(answer) => answer,
            Err(error) => return RevocationAnswer::Later(error),
        };
        // Only an answer that reads as the gateway's success settles the debt; whatever else came
        // back, the authorisation may still be active and the revocation is asked for again.
        match data_of::<Revoked>(&complete, "revocation") {
            Ok(Revoked { record })
                if record.state == PushSenderState::Revoked
                    && record.binding.sender_record_id == sender_record_id =>
            {
                RevocationAnswer::Revoked
            }
            Ok(_) => RevocationAnswer::Later(
                "the gateway answered with a record that is not this authorisation's, revoked"
                    .to_owned(),
            ),
            Err(error) => RevocationAnswer::Later(error),
        }
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

/// What the gateway answers a completed revocation with: the authorisation as it now stands.
#[derive(serde::Deserialize)]
struct Revoked {
    record: PushSenderRecord,
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

/// What a refusal says that this host repeats: the code the gateway named. Its message is the
/// gateway's own words and is never read, so nothing it holds can reach a record or a log.
#[derive(serde::Deserialize)]
struct Refusal {
    code: String,
}

/// The code of the gateway's refusal, when the answer is one of its refusals and the code is one
/// this host knows.
fn refusal_code(answer: &ServiceHttpAnswer) -> Option<&'static str> {
    if answer.body.len() > MAX_ANSWER_BYTES {
        return None;
    }
    match kr_client::services::json::read::<Envelope<serde::de::IgnoredAny>>(&answer.body) {
        Ok(Envelope {
            ok: false,
            error: Some(refusal),
            ..
        }) => known_code(&refusal.code),
        _ => None,
    }
}

/// The `data` of one answer, or why there is none.
///
/// The answer is read through the client's one reader, so a text that names a member twice is not
/// a renewal, and what a failure says is where the text failed, never what it held.
fn data_of<T: serde::de::DeserializeOwned>(
    answer: &ServiceHttpAnswer,
    what: &str,
) -> Result<T, String> {
    if answer.body.len() > MAX_ANSWER_BYTES {
        return Err(format!(
            "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host reads",
            answer.body.len()
        ));
    }
    match kr_client::services::json::read::<Envelope<T>>(&answer.body) {
        Ok(Envelope {
            ok: true,
            data: Some(data),
            error: None,
        }) if answer.status == 200 => Ok(data),
        Ok(Envelope {
            error: Some(refusal),
            ..
        }) => Err(match known_code(&refusal.code) {
            Some(code) => format!("the gateway refused the {what} ({}, {code})", answer.status),
            None => format!("the gateway refused the {what} ({})", answer.status),
        }),
        Ok(_) => Err(format!(
            "the gateway answered {} without a {what}",
            answer.status
        )),
        Err(fault) => Err(format!(
            "the gateway's answer ({}) could not be read: {fault}",
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

    /// KR-REQ-04.19: the gateway's answer is read through the client's one reader. One that names
    /// a member twice is not a renewal, whichever member it is, and no failure repeats what the
    /// answer held.
    #[test]
    fn an_answer_that_names_a_member_twice_is_not_a_renewal_and_no_failure_quotes_one() {
        const MARKER: &str = "a-marker-nobody-should-see";
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let fresh = credential(10, now() + 30 * 24 * 60 * 60 * 1000 - 1_000);
        let answer = renewed_answer(&record(&host, &fresh), &fresh).to_string();
        let read = |text: String| {
            data_of::<SenderResult>(
                &ServiceHttpAnswer {
                    status: 200,
                    body: text.into_bytes(),
                },
                "renewal",
            )
        };

        // A member the renewal reads, and one nothing reads.
        for repeated in [
            answer.replacen(r#""ok":true"#, r#""ok":true,"ok":true"#, 1),
            answer.replacen(r#""ok":true"#, r#""ok":true,"note":1,"note":2"#, 1),
        ] {
            assert_ne!(
                repeated, answer,
                "the answer names its members once to begin with"
            );
            let refused = read(repeated).err().expect("not a renewal");
            assert!(
                refused.contains("names one member of an object twice"),
                "{refused}"
            );
        }

        // An answer this host cannot read is described by where it failed, not by what it held.
        let refused = read(format!(r#"{{"ok":true,"data":{{"record":"{MARKER}"}}}}"#))
            .err()
            .expect("not a renewal");
        assert!(!refused.contains(MARKER), "{refused}");
        assert!(
            refused.contains("is not the shape this client reads"),
            "{refused}"
        );

        // The control: the same answer naming its members once is the renewal.
        assert!(read(answer).is_ok());
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

    /// A refused renewal names the status and, when the gateway's code is one this host knows, the
    /// code. Nothing else the gateway said is repeated: not its message, and not a code this host
    /// does not know, which can be anything the gateway chose to put there.
    #[test]
    fn a_refused_renewal_names_its_code_and_never_the_gateways_words() {
        const WORDS: &str = "There is no such authorisation.";
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let held = credential(9, now() + 2 * 24 * 60 * 60 * 1000);
        let refusal = |code: &str| {
            let recorder = Arc::new(Recorder::default());
            *recorder.answers.lock().expect("not poisoned") = vec![(
                403,
                serde_json::json!({
                    "ok": false,
                    "error": { "code": code, "message": WORDS },
                }),
            )];
            let runtime = runtime();
            senders(&recorder, &host, &runtime)
                .renew(&held)
                .expect_err("no renewal")
        };

        let known = refusal("FORBIDDEN");
        assert!(
            known.contains("403") && known.contains("FORBIDDEN"),
            "{known}"
        );
        assert!(!known.contains(WORDS), "{known}");

        let unknown = refusal("a-code-nobody-should-see");
        assert!(unknown.contains("403"), "{unknown}");
        assert!(
            !unknown.contains("a-code-nobody-should-see") && !unknown.contains(WORDS),
            "{unknown}"
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
    fn the_host_key_signs_a_request_a_renewal_proof_or_a_revocation_and_nothing_else() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let signer = HostSigner::new(host);
        let revocation = kr_protocol::push::PushSenderRevocationPayload {
            gateway_origin: origin(),
            gateway_nonce: Nonce256::from_bytes([7; 32]),
            reason: kr_protocol::push::PushRevocationReason::Unpaired,
            requested_at_ms: TimestampMs::new(1_000),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
        };
        let input = revocation.signing_input().expect("an input");
        let signature = signer.sign(&input).expect("a revocation is signed");
        assert!(verifies(
            &signer.public_key(),
            PUSH_SENDER_REVOCATION_DOMAIN,
            input,
            &signature
        ));
        assert!(signer.sign(b"not a transcript").is_err());
    }

    /// A revocation asks for a nonce and answers it under the host key, on its own route, and a
    /// gateway that holds no such authorisation is told apart from one that did not answer.
    #[test]
    fn a_revocation_asks_for_a_nonce_and_answers_it_under_the_host_key() {
        let host = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
        let id = PushSenderRecordId::new(uuid(3));
        let recorder = Arc::new(Recorder::default());
        let revoked = |state: PushSenderState, id: PushSenderRecordId| {
            let mut stands = record(&host, &credential(10, now() + 29 * 24 * 60 * 60 * 1000));
            stands.binding.sender_record_id = id;
            stands.state = state;
            serde_json::json!({ "ok": true, "data": { "record": stands } })
        };
        *recorder.answers.lock().expect("not poisoned") = vec![
            (200, challenge([7; 32])),
            (200, revoked(PushSenderState::Revoked, id)),
        ];
        let runtime = runtime();
        let revoker = senders(&recorder, &host, &runtime);
        assert_eq!(revoker.revoke(&origin(), id), RevocationAnswer::Revoked);
        let asked = recorder.asked.lock().expect("not poisoned").clone();
        assert_eq!(asked.len(), 2);
        let signed: PushRequest =
            serde_json::from_value(asked[1].body["body"].clone()).expect("a push request body");
        let PushRequest::SenderRevoke {
            request: PushSenderRevokeRequest::Complete { revocation },
        } = signed
        else {
            panic!("the second step is the revocation");
        };
        assert_eq!(asked[1].url, "https://reach.invalid/api/push/sender/revoke");
        assert_eq!(
            revocation.payload.gateway_nonce,
            Nonce256::from_bytes([7; 32])
        );
        assert_eq!(revocation.payload.sender_record_id, id);
        assert!(verifies(
            host.public(),
            PUSH_SENDER_REVOCATION_DOMAIN,
            revocation.payload.signing_input().expect("an input"),
            &revocation.signature,
        ));

        // The gateway's own refusal of the first step, FORBIDDEN, says it holds no such
        // authorisation for this host's key: nothing is owed.
        let ask = |answers: Vec<(u16, serde_json::Value)>| {
            let recorder = Arc::new(Recorder::default());
            *recorder.answers.lock().expect("not poisoned") = answers;
            senders(&recorder, &host, &runtime).revoke(&origin(), id)
        };
        let refusal = |status: u16, code: &str| {
            (
                status,
                serde_json::json!({ "ok": false, "error": { "code": code, "message": "no" } }),
            )
        };
        assert!(matches!(
            ask(vec![refusal(403, "FORBIDDEN")]),
            RevocationAnswer::Gone(_)
        ));

        // A status alone says nothing of the kind: a proxy, a deployment without the route and a
        // refusal to authenticate answer 403 as well, and the authorisation is still active.
        for unsaid in [
            (403, serde_json::json!("forbidden")),
            (403, serde_json::json!({})),
            refusal(403, "REAUTHENTICATION_REQUIRED"),
            (404, serde_json::json!({})),
            refusal(503, "SERVICE_UNAVAILABLE"),
        ] {
            assert!(
                matches!(ask(vec![unsaid.clone()]), RevocationAnswer::Later(_)),
                "{unsaid:?} leaves it owed"
            );
        }

        // The second step settles the debt only as the gateway's success: anything else, a
        // success that carries nothing included, leaves it owed.
        for unsaid in [
            refusal(403, "FORBIDDEN"),
            refusal(503, "SERVICE_UNAVAILABLE"),
            (200, serde_json::json!({ "ok": true })),
            (200, serde_json::json!({ "ok": true, "data": {} })),
            (200, serde_json::json!("done")),
            (200, serde_json::json!({ "ok": false })),
            // A record that is not revoked, and one that is another authorisation's.
            (200, revoked(PushSenderState::Active, id)),
            (
                200,
                revoked(PushSenderState::Revoked, PushSenderRecordId::new(uuid(9))),
            ),
        ] {
            assert!(
                matches!(
                    ask(vec![(200, challenge([8; 32])), unsaid.clone()]),
                    RevocationAnswer::Later(_)
                ),
                "{unsaid:?} leaves it owed"
            );
        }
    }
}
