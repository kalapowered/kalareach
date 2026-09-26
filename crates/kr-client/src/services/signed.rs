//! One signed managed-service call, and what its answer means.
//!
//! The mailbox, the authority feed and settings sync are three services with one way in. Each
//! method is a POST of a JSON document to a path, authenticated by one credential per method: a
//! signature over the gateway origin, the method, a fresh nonce, the time and the digest of the
//! canonical request body. So the call is written once here and each adapter supplies its path,
//! its method and its body.
//!
//! # What the digest covers
//!
//! These bodies are JSON documents rather than protocol objects, so
//! [`kr_protocol::service::canonical_body_digest`] is what the signature carries: the KR-CBOR-1
//! encoding of the document, with text keys in canonical order and an exact count as an unsigned
//! integer. The document that is digested is the document that is sent, so the service recomputes
//! the digest from the bytes it received and neither half depends on how the other wrote its JSON.
//!
//! # A second authorisation
//!
//! Some resources belong to an account rather than to the key that asks for them: the storage an
//! account pays for, and the recovery bundle an account keeps. A request for one carries two
//! proofs. The credential above says which installation or host is asking and nothing about an
//! account; an account token says which account is signed in and nothing about the key that holds
//! it. [`AccountAuthorisation`] is the second proof: where the token comes from, and the scope the
//! resource reads. The token is taken from its source for each request, before the request is
//! signed, because a token expires and is replaced, and it travels as the request's
//! `authorization` header. The signature covers none of it: a service checks the two proofs apart
//! and binds them to one request itself.
//!
//! # Content
//!
//! Managed storage carries ciphertext in both directions, and ciphertext is content rather than a
//! document. A part's body is the ciphertext, so its signed request travels in a header beside it
//! ([`Carriage::Header`]), and a read is answered with the ciphertext itself on a success
//! ([`Content`]). Both go through the one call: the same token, the same credential, the same bound
//! on the signed request and the same boundary between a request that left and one that did not.
//!
//! # Whether a request left
//!
//! A caller whose request came back without an answer has one question: can the request have run?
//! This module answers it exactly, with [`Unanswered`]. Everything it refuses before the transport
//! is given the request is [`Unanswered::NotSent`]: a body it cannot write, a token its source will
//! not give, a credential it cannot make or that falls outside the service's clock window, and a
//! request larger than the method admits. Nothing left this device, so nothing can run. From the
//! moment the transport is given the request, whatever goes wrong is [`Unanswered::Sent`], an
//! answer this client cannot read included, because the service may have received the request and
//! acted on it.
//!
//! # What is never rendered
//!
//! A request body carries a credential and an answer carries whatever answered, so the types here
//! write their own [`std::fmt::Debug`] under this module's rule: the method, the signer kind and
//! the gateway, and nothing that travelled. A second authorisation renders its scope and never its
//! source or a token, and content renders its length and never its bytes.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use kr_protocol::authority::IdempotencyBehaviour;
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::scalars::{AuthorisationKey, Nonce256, TimestampMs};
use kr_protocol::service::{
    BodyError, GatewayOrigin, SERVICE_REQUEST_FRESHNESS_MS, ServiceRequestPayload,
    ServiceRequestSignature, ServiceRequestSigner, canonical_body_digest,
};
use serde::{Deserialize, Serialize};

use super::account::AccountTokenSource;
use super::json::Unreadable;
use super::relay::{ServiceHttp, ServiceHttpAnswer, ServiceSigner};
use crate::error::{ClientError, Result};
use crate::retry::UserAction;
use crate::shown::{ServiceMessage, Shown};

/// A request's second authorisation: the account token for one scope.
///
/// It names where the token comes from and the scope the resource reads, and holds no token itself:
/// each request takes the one its source holds at that moment. A source that holds none for the
/// scope refuses, and the request is not sent.
#[derive(Clone)]
pub struct AccountAuthorisation {
    tokens: Arc<dyn AccountTokenSource>,
    scope: &'static str,
}

impl fmt::Debug for AccountAuthorisation {
    /// The scope. Never the source or a token.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountAuthorisation")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl AccountAuthorisation {
    /// The token `tokens` holds for `scope`, presented with each request made under this.
    #[must_use]
    pub fn new(tokens: Arc<dyn AccountTokenSource>, scope: &'static str) -> Self {
        Self { tokens, scope }
    }

    /// The scope the token is asked for.
    #[must_use]
    pub const fn scope(&self) -> &'static str {
        self.scope
    }
}

/// Why one signed request came back without an answer, and whether it left this device.
///
/// A refusal the service named is an answer, so it is not one of these.
#[derive(Debug)]
pub enum Unanswered {
    /// Refused on this device before the transport was given the request. Nothing left, so
    /// nothing can run.
    NotSent(ClientError),
    /// The transport was given the request, and no answer this client reads came back. The
    /// service may have received the request and acted on it.
    Sent(ClientError),
}

impl From<Unanswered> for ClientError {
    /// The error either way, for a caller that does not ask whether the request left.
    fn from(unanswered: Unanswered) -> Self {
        match unanswered {
            Unanswered::NotSent(error) | Unanswered::Sent(error) => error,
        }
    }
}

/// How one signed request travels.
///
/// Every managed-service method sends its signed request as its body, a JSON document, but one: a
/// storage part, whose body is the ciphertext itself. Its signed request travels in a header
/// instead, as unpadded base64url of the same JSON, so the signature covers the part's declared
/// length and hash rather than its bytes, and the service bounds what it reads before it reads any.
#[derive(Clone, Copy)]
pub(crate) enum Carriage<'a> {
    /// The signed request is the body.
    Body,
    /// The signed request travels in `header`, and `content` is the body.
    Header {
        /// The header's name, lower-cased.
        header: &'static str,
        /// The bytes the signed request describes.
        content: &'a [u8],
    },
}

/// How one request leaves: the instant it is signed at, its second authorisation, and how it
/// travels.
struct Sending<'a> {
    signed_at_ms: Option<u64>,
    account: Option<&'a AccountAuthorisation>,
    carriage: Carriage<'a>,
}

/// What a request whose success is content was answered: the bytes, or the refusal the service
/// named.
pub(crate) enum Content {
    /// The bytes a success carried, as they arrived.
    Bytes(Vec<u8>),
    /// The refusal the service named.
    Refused(Refusal),
}

impl fmt::Debug for Content {
    /// How many bytes came back, or the refusal's code and status. Never the bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("length", &bytes.len())
                .finish(),
            Self::Refused(refusal) => formatter.debug_tuple("Refused").field(refusal).finish(),
        }
    }
}

/// The exchange a managed-service adapter makes its calls through.
///
/// One gateway, one signer, one transport. An adapter holds this and knows nothing about
/// credentials, envelopes or status codes.
#[derive(Clone)]
pub struct SignedService {
    origin: GatewayOrigin,
    http: Arc<dyn ServiceHttp>,
    signer: Arc<dyn ServiceSigner>,
}

impl fmt::Debug for SignedService {
    /// The gateway and which kind of key signs for it. Never the key and never a request.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedService")
            .field("gateway_origin", &self.origin.as_str())
            .field("signer", &self.signer.signer())
            .finish_non_exhaustive()
    }
}

impl SignedService {
    /// Builds the exchange one adapter uses.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            origin,
            http,
            signer,
        }
    }

    /// The gateway these calls are addressed to.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// Whether an installation or a host signs for this caller.
    #[must_use]
    pub fn signer_kind(&self) -> ServiceRequestSigner {
        self.signer.signer()
    }

    /// The public half of the key that signs.
    #[must_use]
    pub fn public_key(&self) -> AuthorisationKey {
        self.signer.public_key()
    }

    /// Sends one signed request, signed now, and returns the `data` of the service's envelope.
    ///
    /// `request_limit` is the most bytes the service admits for the whole signed request, which
    /// each method states for itself. A request past it is refused here rather than sent, because
    /// a service that stops reading at its own limit answers a request it never saw whole, and a
    /// caller told "too large" by this client knows it was this client that said so.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Refused`] for a refusal the service named, and
    /// [`ClientError::Host`] for a request this client would not send, a transport failure and an
    /// answer this client cannot read.
    pub async fn call<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
    ) -> Result<serde_json::Value> {
        self.answer(path, method, body, request_limit).await?.data()
    }

    /// Sends one signed request under the instant its caller states, and returns the `data` of the
    /// service's envelope.
    ///
    /// For a call whose signing time is part of what the caller records: an attempt the caller
    /// wrote down as signed at one instant is signed at exactly that instant, never at a reading
    /// taken here, because the record and the credential have to be the one value.
    ///
    /// The instant is still held to the window the service admits a signature in, against this
    /// device's clock, and an attempt outside it is refused here rather than sent. The service
    /// would refuse it either side of the window, so sending it would spend a request to learn what
    /// this device can already see; and an attempt signed a while ago is one this client does not
    /// carry to the service late, because nothing re-dates an attempt.
    ///
    /// # Errors
    ///
    /// As [`Self::call`], and [`ErrorCode::ClockUntrusted`] for an instant outside the window.
    pub async fn call_at<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        signed_at_ms: u64,
    ) -> Result<serde_json::Value> {
        self.answer_at(path, method, body, request_limit, signed_at_ms)
            .await?
            .data()
    }

    /// Sends one signed request, signed now, and returns what the service answered: its `data`, or
    /// the refusal it named, whole.
    ///
    /// For an adapter that reads a refusal as an answer: one whose code says something about the
    /// request that the caller acts on, such as a collection that does not admit it, and one that
    /// carries members beside its code.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Host`] for a request this client would not send, a transport failure
    /// and an answer this client cannot read. A refusal is not an error here.
    pub(crate) async fn answer<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
    ) -> Result<Answer> {
        Ok(self
            .dispatch(path, method, body, request_limit, None, None)
            .await?)
    }

    /// Sends one signed request under the instant its caller states, and returns what the service
    /// answered: its `data`, or the refusal it named, whole.
    ///
    /// # Errors
    ///
    /// As [`Self::answer`], and [`ErrorCode::ClockUntrusted`] for an instant outside the window.
    pub(crate) async fn answer_at<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        signed_at_ms: u64,
    ) -> Result<Answer> {
        Ok(self
            .dispatch(path, method, body, request_limit, Some(signed_at_ms), None)
            .await?)
    }

    /// Sends one signed request, and returns what the service answered, its `data` or the refusal
    /// it named, or why nothing was answered and whether the request left this device.
    ///
    /// `signed_at_ms` is the instant the caller recorded for this attempt, or none to sign it now.
    /// `account` is the request's second authorisation, for a resource that reads one. Its token is
    /// taken first, before the request is signed, so the clock window is checked after any wait for
    /// the token and an attempt that has aged out of it meanwhile is refused here.
    ///
    /// # Errors
    ///
    /// Returns [`Unanswered::NotSent`] for a request this client would not send, whatever the
    /// reason, and [`Unanswered::Sent`] for a transport failure and an answer this client cannot
    /// read. A refusal is not an error here.
    pub(crate) async fn dispatch<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        signed_at_ms: Option<u64>,
        account: Option<&AccountAuthorisation>,
    ) -> std::result::Result<Answer, Unanswered> {
        let sending = Sending {
            signed_at_ms,
            account,
            carriage: Carriage::Body,
        };
        let answer = self
            .send(path, method, body, request_limit, sending)
            .await?;
        answer_of(&answer).map_err(|error| unanswered(method, answer.status, error))
    }

    /// Sends one signed request, signed now, that travels as `carriage` says, and returns what the
    /// service answered: its `data`, or the refusal it named.
    ///
    /// For the one request whose body is content rather than a document. Everything else about it
    /// is [`Self::dispatch`]'s: the second authorisation, the clock window, the bound on the signed
    /// request, and whether a request that went unanswered left this device.
    ///
    /// # Errors
    ///
    /// As [`Self::dispatch`].
    pub(crate) async fn dispatch_carried<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        account: Option<&AccountAuthorisation>,
        carriage: Carriage<'_>,
    ) -> std::result::Result<Answer, Unanswered> {
        let sending = Sending {
            signed_at_ms: None,
            account,
            carriage,
        };
        let answer = self
            .send(path, method, body, request_limit, sending)
            .await?;
        answer_of(&answer).map_err(|error| unanswered(method, answer.status, error))
    }

    /// Sends one signed request, signed now, whose success is content rather than a document, and
    /// returns the content or the refusal the service named.
    ///
    /// # Errors
    ///
    /// As [`Self::dispatch`]. A success envelope where the status says the request failed is an
    /// answer this client cannot read.
    pub(crate) async fn dispatch_for_content<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        account: Option<&AccountAuthorisation>,
    ) -> std::result::Result<Content, Unanswered> {
        let sending = Sending {
            signed_at_ms: None,
            account,
            carriage: Carriage::Body,
        };
        let answer = self
            .send(path, method, body, request_limit, sending)
            .await?;
        let status = answer.status;
        content_of(answer).map_err(|error| unanswered(method, status, error))
    }

    /// The one path every request takes: the document, the token, the credential, the bound, and
    /// then the transport, which is where a request starts to leave this device.
    async fn send<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
        sending: Sending<'_>,
    ) -> std::result::Result<ServiceHttpAnswer, Unanswered> {
        let Sending {
            signed_at_ms,
            account,
            carriage,
        } = sending;
        let document = serde_json::to_value(body).map_err(|error| {
            Unanswered::NotSent(malformed(crate::shown!(
                "a request could not be written: {}",
                Shown::json(&error)
            )))
        })?;
        let authorisation = match account {
            Some(account) => {
                let token = account
                    .tokens
                    .token(account.scope)
                    .await
                    .map_err(Unanswered::NotSent)?;
                Some(format!("Bearer {}", token.expose()))
            }
            None => None,
        };
        let request = self
            .signed(method, document, signed_at_ms.unwrap_or_else(now_ms))
            .map_err(Unanswered::NotSent)?;
        if request.len() > request_limit {
            return Err(Unanswered::NotSent(malformed(crate::shown!(
                "a {} request is at most {} bytes and this one is {}",
                method,
                request_limit,
                request.len()
            ))));
        }
        let url = format!("{}{path}", self.origin.as_str());
        let token = authorisation
            .iter()
            .map(|value| ("authorization", value.as_str()));
        // From here the transport holds the request, so whatever goes wrong may have happened after
        // the service received it.
        match carriage {
            Carriage::Body => {
                let headers: Vec<(&str, &str)> = token.collect();
                self.http.post_json(&url, &request, &headers).await
            }
            Carriage::Header { header, content } => {
                let carried = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&request);
                let headers: Vec<(&str, &str)> = std::iter::once((header, carried.as_str()))
                    .chain(token)
                    .collect();
                self.http.post_bytes(&url, content, &headers).await
            }
        }
        .map_err(Unanswered::Sent)
    }

    /// The bytes of one signed request: the document, and the credential over its digest.
    fn signed(
        &self,
        method: Method,
        document: serde_json::Value,
        signed_at_ms: u64,
    ) -> Result<Vec<u8>> {
        let payload = ServiceRequestPayload {
            // The failure names which rule the body broke and nothing of the body: a count it
            // cannot carry, or members that are not canonical and distinct.
            body_digest: canonical_body_digest(&document).map_err(|error| {
                malformed(match error {
                    BodyError::Number => {
                        "a request body carries no number that is not an exact count"
                    }
                    BodyError::Members(_) => "a request body's members are canonical and distinct",
                })
            })?,
            gateway_origin: self.origin.clone(),
            method,
            nonce: Nonce256::from_bytes(fresh_nonce()?),
            signed_at_ms: TimestampMs::new(signed_at_ms),
        };
        // The credential names the method it authorises, and the set it may name is the managed
        // surface. A credential for a host method would be a credential aimed at something no
        // service holds the authority to run.
        if !payload.names_a_service_method() {
            return Err(malformed(crate::shown!(
                "{} is not a method a managed service serves",
                method
            )));
        }
        // The service's own rule for when a signature may be admitted, applied against this
        // device's clock before anything is sent. It names the instant and the window, and not
        // the reading it was compared with, because that reading is this device's and says
        // nothing the caller can act on that the instant does not.
        if !payload.is_fresh_at(now_ms()) {
            return Err(ClientError::refusal(
                ErrorCode::ClockUntrusted,
                crate::shown!(
                    "an attempt signed at {} is outside the {} ms a service admits a signature in, by this device's clock",
                    signed_at_ms,
                    SERVICE_REQUEST_FRESHNESS_MS
                ),
            ));
        }

        let signer = self.signer.signer();
        let signature = ServiceRequestSignature {
            signature: self.signer.sign(&payload.signing_input(signer)?)?,
            payload,
            signer,
            public_key: self.signer.public_key(),
        };

        serde_json::to_vec(&SignedServiceRequest {
            body: document,
            signature,
        })
        .map_err(|error| {
            malformed(crate::shown!(
                "a request could not be written: {}",
                Shown::json(&error)
            ))
        })
    }
}

/// A signed request, as the service receives it.
#[derive(Serialize)]
struct SignedServiceRequest {
    /// The document the digest covers.
    body: serde_json::Value,
    /// The proof that a key the service will check made this request.
    signature: ServiceRequestSignature,
}

impl fmt::Debug for SignedServiceRequest {
    /// The method and which kind of key signed. Never the body, the credential or the signature.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedServiceRequest")
            .field("method", &self.signature.payload.method)
            .field("signer", &self.signature.signer)
            .finish_non_exhaustive()
    }
}

/// What one signed call was answered.
pub(crate) enum Answer {
    /// The `data` of the service's envelope.
    Data(serde_json::Value),
    /// The refusal the service named.
    Refused(Refusal),
}

impl fmt::Debug for Answer {
    /// Which answer it is, and a refusal's code and status. Never the data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(_) => formatter.write_str("Data(..)"),
            Self::Refused(refusal) => formatter.debug_tuple("Refused").field(refusal).finish(),
        }
    }
}

impl Answer {
    /// The `data`, or the refusal as the error the service named.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Refused`] for a refusal, classified by [`classify`].
    pub(crate) fn data(self) -> Result<serde_json::Value> {
        match self {
            Self::Data(data) => Ok(data),
            Self::Refused(refusal) => Err(refusal.into_error()),
        }
    }
}

/// A refusal the service named, whole: its code, the status it came with, and the answer it
/// arrived in, for an adapter that reads the members its contract gives that code.
///
/// Most adapters want only the error it becomes. One that reads a refusal as an answer, because
/// the code says something about the request the caller acts on, reads the code, and then those
/// members as the shape its contract gives them. The answer was read through
/// [`super::json::read`], so an answer that names any member twice, the code's and the ones an
/// adapter reads among them, is not a refusal this client reads.
pub(crate) struct Refusal {
    status: u16,
    code: String,
    message: ServiceMessage,
    retry_after_seconds: Option<u64>,
    /// The whole answer the refusal arrived in, which [`Self::members`] reads again.
    answer: Vec<u8>,
}

impl fmt::Debug for Refusal {
    /// The code and the status. Never the message or the answer, which are the service's.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Refusal")
            .field("code", &self.code)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Refusal {
    /// The service's own code for the refusal.
    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    /// The members the refusal carried beside its code, read as the shape `T` gives them.
    ///
    /// # Errors
    ///
    /// Returns an unknown outcome when the refusal does not carry them in that shape.
    pub(crate) fn members<T: for<'de> Deserialize<'de>>(&self, what: &'static str) -> Result<T> {
        #[derive(Deserialize)]
        struct Carried<T> {
            error: T,
        }
        super::json::read::<Carried<T>>(&self.answer)
            .map(|carried| carried.error)
            .map_err(|fault| unreadable_answer(what, fault))
    }

    /// The error the service named, with the delay it asked for when it named one.
    pub(crate) fn into_error(self) -> ClientError {
        let (code, action) = classify(&self.code, self.status);
        ClientError::Refused {
            error: crate::error::refusal(code, plain_message(&self.code, &self.message)),
            retry_after_seconds: self.retry_after_seconds,
            action,
        }
    }
}

/// What a person is told about one refusal: the service's own message, except where the code says
/// more about this request than the service's words do.
///
/// `SIGNED_BEFORE_CUTOFF` is that exception. The service words it for a write that may have run
/// before, and an exchange reads it as an answer before it could become an error. Every other
/// request reaches it as an error, and for those what matters is what the refusal means: nothing
/// ran, nothing was recorded, and asking again can succeed only once the service's cutoff falls
/// behind the clocks.
fn plain_message(code: &str, message: &ServiceMessage) -> Shown {
    match code {
        "SIGNED_BEFORE_CUTOFF" => Shown::said(
            "nothing ran and nothing was recorded: the service holds this request as signed \
             before its collection's cutoff, which runs ahead of the clocks, and asking again can \
             succeed only once the cutoff falls behind them",
        ),
        _ => Shown::service(message),
    }
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A refusal is the service's answer about the request rather than a transport failure, so it
/// arrives whole, and becomes the error the service named when an adapter asks for the `data`.
///
/// A body that is not this service's envelope is not a refusal at all: it is something in front of
/// the service, a truncated answer, or something that is not this service. [`unreadable`] is what
/// those become, classified by the status that carried them. A text that names one member twice,
/// in the envelope or anywhere inside it, is one of them: [`super::json::read`] refuses it before
/// any member is read.
///
/// So is an envelope that is not exactly the service's. It writes `ok` with `data`, or `ok` with
/// `error`, and nothing else, so another member beside them, or a success and a refusal at once,
/// says the answer is not the service's own. Inside `data` and `error` the members are each
/// adapter's to read, and a member it does not read is one a newer service may add.
fn answer_of(answer: &ServiceHttpAnswer) -> Result<Answer> {
    /// The two members beside `ok` are each absent (`None`) or present, and a present one may be
    /// `null` (`Some(None)`), so a member that is there with nothing in it is still there.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        ok: bool,
        #[serde(default, deserialize_with = "present")]
        data: Option<Option<serde_json::Value>>,
        #[serde(default, deserialize_with = "present")]
        error: Option<Option<Named>>,
    }

    /// Reads a member that is there, `null` included.
    fn present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: Deserialize<'de>,
    {
        T::deserialize(deserializer).map(Some)
    }

    /// The members every refusal carries, read directly: a field named twice is refused here.
    #[derive(Deserialize)]
    struct Named {
        code: String,
        message: String,
        /// The service names this in camel case, as its whole envelope does.
        #[serde(default, rename = "retryAfterSeconds")]
        retry_after_seconds: Option<u64>,
    }

    let envelope = super::json::read::<Envelope>(&answer.body).map_err(|fault| {
        unreadable(
            answer.status,
            crate::shown!("its answer is not one this client reads: {}", fault),
        )
    })?;

    if envelope.ok {
        if envelope.error.is_some() {
            return Err(unreadable(
                answer.status,
                "its answer is a success and a refusal at once",
            ));
        }
        return envelope
            .data
            .flatten()
            .map(Answer::Data)
            .ok_or_else(|| unreadable(answer.status, "its answer carries no data"));
    }

    if envelope.data.is_some() {
        return Err(unreadable(answer.status, "its refusal carries data"));
    }
    let Some(named) = envelope.error.flatten() else {
        return Err(unreadable(answer.status, "its refusal names no error"));
    };
    Ok(Answer::Refused(Refusal {
        status: answer.status,
        code: named.code,
        message: ServiceMessage::from_refusal(named.message),
        retry_after_seconds: named.retry_after_seconds,
        answer: answer.body.clone(),
    }))
}

/// The bytes a success carried, or the refusal a failure carried.
///
/// A request whose success is content is answered with the content itself on a success status and
/// with the service's envelope otherwise. So a success is its bytes, whatever they are: they are
/// content, and nothing here reads them. Anything else is read as an envelope, and a refusal is the
/// one thing it may be, because a success envelope under a status that says the request failed is
/// not this service's answer.
fn content_of(answer: ServiceHttpAnswer) -> Result<Content> {
    if (200..300).contains(&answer.status) {
        return Ok(Content::Bytes(answer.body));
    }
    match answer_of(&answer)? {
        Answer::Refused(refusal) => Ok(Content::Refused(refusal)),
        Answer::Data(_) => Err(unreadable(
            answer.status,
            "its answer is a success under a status that says the request failed",
        )),
    }
}

/// The protocol code one service error code means, and what a person does about it.
///
/// The status decides the codes this service does not name, because a body carrying an unknown code
/// is either a newer service or something in front of it.
///
/// Two of the service's codes map to one protocol code and mean different things to a person, and
/// section 23's required set has one `PERMISSION_DENIED`, so the difference is carried as the
/// action beside it rather than as a code the protocol does not define.
///
/// Neither of them is a sign-in. These methods are proven by a credential this device mints for
/// itself, not by an account, so a credential the service would not admit is a wrong origin, a
/// method the signature does not name, a body it does not cover, a clock outside the freshness
/// window or a nonce already spent. Signing in changes none of those: what does is this device's
/// own configuration, so `UNAUTHENTICATED` asks for that and `FORBIDDEN` says this key may not do
/// this, which is a matter for the host's records rather than for a login.
///
/// Settings sync answers three codes of its own about a request identity rather than about the
/// caller. `ID_CONFLICT` is section 23's own code: another request already wore the identity,
/// which is a client fault. `REQUEST_FENCED` has none, because nothing in section 23 is a request
/// identity that was ended before it ran: it is the refusal of that identity, so it is reported as
/// the permission it is, and with nothing for a person to do, because the device that ended the
/// request settles it from the fence's own answer. `INVALID_ARGUMENT` is a value this client
/// should not have sent, as `INVALID_REQUEST` is.
///
/// And two about a shared collection, which its adapter reads as answers before they ever become
/// errors. `COLLECTION_ABSENT` is a collection that does not exist or does not list the caller,
/// one answer for both, reported as the unknown object it is to this device. `KEY_EPOCH_RETIRED` is
/// a write sealed under a key the collection no longer writes with: this device's view has fallen
/// behind the collection's key records, which a refresh brings up to date.
///
/// `SIGNED_BEFORE_CUTOFF` refuses a request signed before the collection's cutoff, running nothing
/// and recording nothing. An exchange reads it as an answer about its attempt. Every other request
/// is signed when it is sent, or, for a key-record offer, at the instant its caller recorded, which
/// this client sends only while it is fresh. The service checks freshness first, so a refusal of
/// one says that the collection's record of what it swept runs ahead of the clocks. Nothing on this
/// device can correct that, and the request as sent is not at fault, so it is `CLOCK_UNTRUSTED`,
/// which retries nothing by itself, and the person waits: asking again can succeed only once the
/// cutoff falls behind the clocks.
///
/// Managed storage and the backup manifest answer two more. `COLLECTION_DELETED` is a backup
/// collection its owner deleted from the account console: its archive takes no upload and its
/// manifest no publication again, whoever sends them, and backing up again means enrolling a new
/// collection. That is a change of configuration and never an update of this client, so it is the
/// permission it refuses, with that action, and the service's own message names the new
/// collection. `SERVICE_UNAVAILABLE` is a service with no room for this request now: a write fence,
/// a tenant being moved, or a part the isolate cannot hold yet. It is capacity rather than a
/// fault, and it names the delay to wait.
///
/// An upload that spends an account's storage without the account's proof is answered
/// `QUOTA_EXHAUSTED`, the same code an exhausted allowance is, with a message that says where
/// backup storage comes from. The ledger's own `PAYMENT_REQUIRED` never reaches this client.
///
/// `CONFLICT` is a request made against something that changed after the caller read it. Nothing
/// was done, and the request was not wrong when it was sent, so it is the subject changing under
/// the request, and refreshing the view is what a person does. A storage retention change reads
/// its conflict as an answer carrying the retention as it stands; one whose members that adapter
/// cannot read, and a conflict from any other method, reach a caller as this.
fn classify(code: &str, status: u16) -> (ErrorCode, UserAction) {
    match code {
        "UNAUTHENTICATED" => (ErrorCode::PermissionDenied, UserAction::FixConfiguration),
        "REAUTHENTICATION_REQUIRED" => (ErrorCode::PermissionDenied, UserAction::SignIn),
        "FORBIDDEN" => (ErrorCode::PermissionDenied, UserAction::FixConfiguration),
        "RATE_LIMITED" => (ErrorCode::RateLimited, UserAction::Wait),
        "QUOTA_EXHAUSTED" => (ErrorCode::QuotaExceeded, UserAction::Wait),
        "NOT_CONFIGURED" => (ErrorCode::HostNotConfigured, UserAction::FixConfiguration),
        "INTERNAL" => (ErrorCode::UpstreamUnavailable, UserAction::Wait),
        "INVALID_REQUEST" | "INVALID_ARGUMENT" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" => {
            (ErrorCode::InvalidArgument, UserAction::Update)
        }
        "ID_CONFLICT" => (ErrorCode::IdConflict, UserAction::Update),
        "CONFLICT" => (ErrorCode::DraftConflict, UserAction::Resync),
        "REQUEST_FENCED" => (ErrorCode::PermissionDenied, UserAction::Nothing),
        "COLLECTION_ABSENT" => (ErrorCode::UnknownSession, UserAction::Nothing),
        "KEY_EPOCH_RETIRED" => (ErrorCode::ResyncRequired, UserAction::Resync),
        "SIGNED_BEFORE_CUTOFF" => (ErrorCode::ClockUntrusted, UserAction::Wait),
        "COLLECTION_DELETED" => (ErrorCode::PermissionDenied, UserAction::FixConfiguration),
        "SERVICE_UNAVAILABLE" => (ErrorCode::ServiceCapacity, UserAction::Wait),
        _ if status >= 500 => (ErrorCode::UpstreamUnavailable, UserAction::Wait),
        _ => (ErrorCode::InvalidArgument, UserAction::Update),
    }
}

/// An answer this client could not read, classified by the status that carried it.
///
/// What a caller may do about it turns on one question: whether the request may have been carried
/// out. A success status with an unreadable body is the dangerous case, because the service acted
/// and this client cannot see what it did, so it is an unknown outcome and never retried
/// automatically. A fault or a rate limit is transient. A gateway's 502 or 504 is too, here: it can
/// follow the service acting on the request, and [`unanswered`] decides by the method whether that
/// makes the outcome unknown. Anything else without an envelope never reached this service's own
/// routes, which is a configuration between here and it.
fn unreadable(status: u16, what: impl Into<Shown>) -> ClientError {
    let code = if (200..300).contains(&status) {
        ErrorCode::OutcomeUnknown
    } else if status >= 500 || status == 408 || status == 429 {
        ErrorCode::UpstreamUnavailable
    } else {
        ErrorCode::HostNotConfigured
    };

    ClientError::refusal(
        code,
        crate::shown!("the service answered {} and {}", status, what.into()),
    )
}

/// Why a request that left this device went unanswered, for a request of `method`.
///
/// A gateway in front of the service answers 502 or 504 when the service's answer did not reach it,
/// which it can do after the service acted on the request. So an answer of either with no envelope
/// of the service's is an unknown outcome, never sent again, unless a request of `method` is safe
/// to send again ([`repeat_is_safe`]).
fn unanswered(method: Method, status: u16, error: ClientError) -> Unanswered {
    if matches!(status, 502 | 504) && !repeat_is_safe(method) {
        return Unanswered::Sent(ClientError::refusal(
            ErrorCode::OutcomeUnknown,
            crate::shown!(
                "a gateway answered with status {} and the service's own answer was lost, so \
                 whether the service carried the request out is unknown",
                status
            ),
        ));
    }
    Unanswered::Sent(error)
}

/// Whether a request of `method` may be sent again, signed afresh, after its answer was lost.
///
/// A read changes nothing. A write qualifies when every operation its method carries is answered,
/// on a repeat under a fresh signature, without a second effect or a different one: a delivery by
/// its envelope identifier, an acknowledgement by its position, a settings-sync request by the
/// identity it carries and the receipt kept for it, a manifest by its generation and its enrolment
/// revision, a retention change by its revision, and an upload by its part numbers and its upload
/// identifier. A creation signed afresh meets the object the first may have made and makes nothing
/// more while that object is live; after its hold is released, it makes a new upload in place of
/// the one that lapsed. A deletion does not qualify, because the service keeps a deletion's first
/// target only for the signature that asked for it and a later object may hold the identity by
/// then; nor does the authority feed, whose delegation replaces the removal keys with nothing to
/// tell a repeat from a later change. A method added later does not either, until it is shown to.
fn repeat_is_safe(method: Method) -> bool {
    matches!(
        method.entry().idempotency,
        IdempotencyBehaviour::IdempotentRead
    ) || matches!(
        method,
        Method::MailboxDeliver
            | Method::MailboxAcknowledge
            | Method::SyncCompareExchange
            | Method::BackupManifest
            | Method::StorageRetentionSet
            | Method::StorageUploadCreate
            | Method::StorageUploadPart
            | Method::StorageUploadComplete
            | Method::StorageUploadAbort
    )
}

/// An answer that was read and is not the shape this client expected.
///
/// The service answered, so whatever it did is done; what this client lacks is the answer. It is
/// therefore an unknown outcome, like any other answer that could not be read.
///
/// What it says about the answer is [`super::json::Unreadable`] and nothing else: an answer
/// carries whatever answered, and `serde_json`'s own message would quote the part it rejected.
pub(crate) fn unreadable_answer(
    what: impl Into<Shown>,
    fault: impl Into<Unreadable>,
) -> ClientError {
    let fault: Unreadable = fault.into();
    ClientError::refusal(
        ErrorCode::OutcomeUnknown,
        crate::shown!("this client cannot read {}: {}", what.into(), fault),
    )
}

/// A request this client would not send. Nothing left this device.
pub(crate) fn malformed(message: impl Into<Shown>) -> ClientError {
    ClientError::refusal(ErrorCode::InvalidArgument, message.into())
}

/// This machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A fresh nonce from the operating system's generator.
fn fresh_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    kr_crypto::random_bytes(&mut nonce).map_err(|error| {
        malformed(crate::shown!(
            "a nonce could not be drawn: {}",
            Shown::crypto(&error)
        ))
    })?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn credential() -> ServiceRequestSignature {
        let payload = ServiceRequestPayload {
            body_digest: canonical_body_digest(&serde_json::json!({})).expect("a digest"),
            gateway_origin: origin(),
            method: Method::AuthoritySync,
            nonce: Nonce256::from_bytes([0x3c; 32]),
            signed_at_ms: TimestampMs::new(1_800_000_000_000),
        };
        ServiceRequestSignature {
            payload,
            signer: ServiceRequestSigner::Host,
            public_key: AuthorisationKey::from_bytes([0x11; 32]),
            signature: kr_protocol::scalars::Signature64::from_bytes([0x22; 64]),
        }
    }

    #[test]
    fn a_rendering_of_a_signed_request_carries_neither_its_body_nor_its_credential() {
        let request = SignedServiceRequest {
            body: serde_json::json!({ "note": NEVER_RENDERED }),
            signature: credential(),
        };
        renders_only(
            &request,
            r#"SignedServiceRequest{method:AuthoritySync,signer:Host,..}"#,
        );
    }

    #[test]
    fn a_refusal_carries_the_services_own_message_and_nothing_else_of_the_answer() {
        let error = answer_of(&ServiceHttpAnswer {
            status: 403,
            body: format!(
                r#"{{"ok":false,"error":{{"code":"FORBIDDEN","message":"Only the host issues its own revisions.","detail":"{NEVER_RENDERED}"}}}}"#
            )
            .into_bytes(),
        })
        .and_then(Answer::data)
        .expect_err("a refusal");

        assert!(
            error
                .to_string()
                .contains("Only the host issues its own revisions.")
        );
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn an_answer_this_client_cannot_read_is_reported_without_quoting_it() {
        let error = answer_of(&ServiceHttpAnswer {
            status: 200,
            body: NEVER_RENDERED.as_bytes().to_vec(),
        })
        .expect_err("that is not this service's envelope");
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    }

    #[test]
    fn a_refusal_that_names_one_of_its_members_twice_is_not_one_this_client_reads() {
        // The code, the message and the retry delay: whichever of two values a reader kept, it
        // would be acting on an answer the service did not give once.
        for body in [
            r#"{"ok":false,"error":{"code":"COLLECTION_ABSENT","code":"INVALID_ARGUMENT","message":"refused"}}"#,
            r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"wait","message":"now"}}"#,
            r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"wait","retryAfterSeconds":1,"retryAfterSeconds":900}}"#,
        ] {
            let error = answer_of(&ServiceHttpAnswer {
                status: 409,
                body: body.as_bytes().to_vec(),
            })
            .expect_err("not a refusal this client reads");
            assert!(matches!(error, ClientError::Host(_)), "{body}");
        }

        // A member an adapter reads beside the code is held to the same rule, and so is one that
        // nothing reads: the whole answer is refused before any member of it is read.
        for body in [
            r#"{"ok":false,"error":{"code":"KEY_EPOCH_RETIRED","message":"retired","key_epoch":"1","key_epoch":"2"}}"#,
            r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"wait","detail":"a","detail":"b"}}"#,
        ] {
            let error = answer_of(&ServiceHttpAnswer {
                status: 409,
                body: body.as_bytes().to_vec(),
            })
            .expect_err("not a refusal this client reads");
            assert!(matches!(error, ClientError::Host(_)), "{body}");
            assert!(
                error
                    .to_string()
                    .contains("names one member of an object twice"),
                "{error}"
            );
        }

        // The control: the same refusal naming its epoch once carries it to the adapter.
        #[derive(Deserialize)]
        struct Epoch {
            key_epoch: String,
        }
        let answer = answer_of(&ServiceHttpAnswer {
            status: 409,
            body: br#"{"ok":false,"error":{"code":"KEY_EPOCH_RETIRED","message":"retired","key_epoch":"1"}}"#.to_vec(),
        })
        .expect("a refusal");
        let Answer::Refused(refusal) = answer else {
            panic!("a refusal: {answer:?}");
        };
        assert_eq!(refusal.code(), "KEY_EPOCH_RETIRED");
        assert_eq!(
            refusal
                .members::<Epoch>("an epoch")
                .expect("an epoch")
                .key_epoch,
            "1"
        );
    }

    /// KR-REQ-04.19: a success whose `data` names a member twice, at any depth, is an answer this
    /// client cannot read, which after a success is an unknown outcome; and what it says names the
    /// rule and the place, not the text.
    #[test]
    fn a_success_that_names_a_member_twice_anywhere_is_an_unknown_outcome() {
        for body in [
            format!(
                r#"{{"ok":true,"data":{{"note":"{NEVER_RENDERED}","note":"{NEVER_RENDERED}"}}}}"#
            ),
            format!(r#"{{"ok":true,"data":{{"pages":[{{"at":"1","at":"{NEVER_RENDERED}"}}]}}}}"#),
            format!(r#"{{"ok":true,"ok":true,"data":{{"note":"{NEVER_RENDERED}"}}}}"#),
        ] {
            let error = answer_of(&ServiceHttpAnswer {
                status: 200,
                body: body.clone().into_bytes(),
            })
            .expect_err("a member named twice");
            assert_eq!(error.code(), ErrorCode::OutcomeUnknown, "{body}");
            for rendering in [
                error.to_string(),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
            }
            assert!(
                error
                    .to_string()
                    .contains("names one member of an object twice at line 1"),
                "{error}"
            );
        }
    }

    /// KR-REQ-04.19: the envelope is `ok` with `data`, or `ok` with `error`, and nothing else. The
    /// service writes no other member and never both, so an answer that carries another member, or
    /// is a success and a refusal at once, is not its envelope, and the status decides what that
    /// is, as it does for any answer this client cannot read.
    #[test]
    fn an_envelope_that_carries_any_other_member_is_not_one_this_client_reads() {
        for (status, body, expected) in [
            (
                200,
                r#"{"ok":true,"data":{"note":"x"},"extra":1}"#,
                ErrorCode::OutcomeUnknown,
            ),
            (
                200,
                r#"{"ok":true,"data":{"note":"x"},"error":{"code":"FORBIDDEN","message":"no"}}"#,
                ErrorCode::OutcomeUnknown,
            ),
            (
                403,
                r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"no"},"retryAfterSeconds":5}"#,
                ErrorCode::HostNotConfigured,
            ),
            (
                403,
                r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"no"},"data":{"note":"x"}}"#,
                ErrorCode::HostNotConfigured,
            ),
            // A member that is there with nothing in it is there all the same.
            (
                200,
                r#"{"ok":true,"data":{},"error":null}"#,
                ErrorCode::OutcomeUnknown,
            ),
            (
                429,
                r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"wait"},"data":null}"#,
                ErrorCode::UpstreamUnavailable,
            ),
        ] {
            let error = answer_of(&ServiceHttpAnswer {
                status,
                body: body.as_bytes().to_vec(),
            })
            .expect_err(body);
            assert!(matches!(error, ClientError::Host(_)), "{body}");
            assert_eq!(error.code(), expected, "{body}");
        }

        // The controls: the two envelopes the service writes are read as they always were, and the
        // members a refusal carries beside its code stay the adapter's to read.
        let answer = answer_of(&ServiceHttpAnswer {
            status: 200,
            body: br#"{"ok":true,"data":{"note":"x","more":1}}"#.to_vec(),
        })
        .expect("an answer");
        assert!(matches!(answer, Answer::Data(_)), "{answer:?}");
        let answer = answer_of(&ServiceHttpAnswer {
            status: 409,
            body: br#"{"ok":false,"error":{"code":"KEY_EPOCH_RETIRED","message":"retired","key_epoch":"1","missing":["x"]}}"#.to_vec(),
        })
        .expect("a refusal");
        let Answer::Refused(refusal) = answer else {
            panic!("a refusal: {answer:?}");
        };
        assert_eq!(refusal.code(), "KEY_EPOCH_RETIRED");
    }

    #[test]
    fn a_success_with_no_data_is_an_unknown_outcome_rather_than_an_empty_answer() {
        let error = answer_of(&ServiceHttpAnswer {
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
        })
        .expect_err("an envelope with no data");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    }

    /* ---------------------------------------------------------------------- */
    /* A second authorisation, and whether a request left                      */
    /* ---------------------------------------------------------------------- */

    use std::sync::Mutex;

    use crate::services::ServiceFuture;
    use crate::services::account::{AccountToken, AccountTokenSource};

    /// The account token the scripted source hands out.
    const TOKEN: &str = "an-account-token";

    /// One request as the transport was given it.
    struct Sent {
        body: Vec<u8>,
        headers: Vec<(String, String)>,
        /// Whether it was given content to send rather than a document.
        content: bool,
    }

    /// A transport that keeps every request it is given, headers included, and answers each one
    /// alike: with an answer, or with a failure of its own.
    struct Wire {
        sent: Mutex<Vec<Sent>>,
        answer: std::result::Result<ServiceHttpAnswer, ErrorCode>,
    }

    impl fmt::Debug for Wire {
        /// How many requests it was given. Never one of them.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("Wire")
                .field("requests", &self.requests())
                .finish_non_exhaustive()
        }
    }

    impl Wire {
        fn answering(answer: std::result::Result<ServiceHttpAnswer, ErrorCode>) -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                answer,
            })
        }

        fn data() -> Arc<Self> {
            Self::answering(Ok(ServiceHttpAnswer {
                status: 200,
                body: br#"{"ok":true,"data":{"note":"answered"}}"#.to_vec(),
            }))
        }

        fn requests(&self) -> usize {
            self.sent.lock().expect("the requests").len()
        }

        fn headers(&self) -> Vec<Vec<(String, String)>> {
            self.sent
                .lock()
                .expect("the requests")
                .iter()
                .map(|sent| sent.headers.clone())
                .collect()
        }

        fn bodies(&self) -> Vec<Vec<u8>> {
            self.sent
                .lock()
                .expect("the requests")
                .iter()
                .map(|sent| sent.body.clone())
                .collect()
        }

        /// Whether each request was sent as content rather than as a document.
        fn contents(&self) -> Vec<bool> {
            self.sent
                .lock()
                .expect("the requests")
                .iter()
                .map(|sent| sent.content)
                .collect()
        }

        /// Keeps one request and answers it as this wire answers every request.
        fn take(
            &self,
            body: &[u8],
            headers: &[(&str, &str)],
            content: bool,
        ) -> ServiceFuture<'static, ServiceHttpAnswer> {
            self.sent.lock().expect("the requests").push(Sent {
                body: body.to_vec(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
                content,
            });
            let answer = self
                .answer
                .clone()
                .map_err(|code| ClientError::refusal(code, Shown::said("the connection dropped")));
            Box::pin(async move { answer })
        }
    }

    impl ServiceHttp for Wire {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.take(body, headers, false)
        }

        fn post_bytes<'a>(
            &'a self,
            _url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.take(body, headers, true)
        }
    }

    /// An installation's key, signing as a client signs.
    #[derive(Debug)]
    struct Key(kr_crypto::keys::AuthorisationKeyPair);

    impl ServiceSigner for Key {
        fn signer(&self) -> ServiceRequestSigner {
            ServiceRequestSigner::Installation
        }

        fn public_key(&self) -> AuthorisationKey {
            *self.0.public()
        }

        fn sign(&self, message: &[u8]) -> Result<kr_protocol::scalars::Signature64> {
            let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
                ServiceRequestSigner::Installation.domain(),
                message.to_vec(),
            )
            .expect("a domain-tagged transcript");
            Ok(kr_crypto::sign::sign(&self.0, &transcript).expect("a signature"))
        }
    }

    /// Where account tokens come from: one token for any scope, or none at all, and a record of
    /// every scope it was asked for.
    #[derive(Debug)]
    struct Tokens {
        token: Option<&'static str>,
        asked: Mutex<Vec<String>>,
    }

    impl Tokens {
        fn holding(token: Option<&'static str>) -> Arc<Self> {
            Arc::new(Self {
                token,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("the scopes").clone()
        }
    }

    impl AccountTokenSource for Tokens {
        fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
            self.asked
                .lock()
                .expect("the scopes")
                .push(scope.to_owned());
            let token = match self.token {
                Some(token) => AccountToken::new(token),
                None => Err(ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    Shown::said("no account is signed in on this device"),
                )),
            };
            Box::pin(async move { token })
        }
    }

    fn service(wire: &Arc<Wire>) -> SignedService {
        SignedService::new(
            origin(),
            Arc::clone(wire) as Arc<dyn ServiceHttp>,
            Arc::new(Key(
                kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key pair")
            )),
        )
    }

    fn presenting(tokens: &Arc<Tokens>) -> AccountAuthorisation {
        AccountAuthorisation::new(
            Arc::clone(tokens) as Arc<dyn AccountTokenSource>,
            "backup.write",
        )
    }

    /// One request, signed now, with or without a second authorisation.
    async fn send(
        service: &SignedService,
        account: Option<&AccountAuthorisation>,
    ) -> std::result::Result<Answer, Unanswered> {
        service
            .dispatch(
                "/api/sync/exchange",
                Method::SyncCompareExchange,
                &serde_json::json!({ "note": "a request" }),
                256 * 1024,
                None,
                account,
            )
            .await
    }

    /// The body digest the credential of one sent request covers.
    fn digest_of(body: &[u8]) -> kr_protocol::scalars::Digest256 {
        let request: serde_json::Value = serde_json::from_slice(body).expect("a signed request");
        let signature: ServiceRequestSignature =
            serde_json::from_value(request["signature"].clone()).expect("a credential");
        signature.payload.body_digest
    }

    /// A second authorisation is the account token for the scope it names, carried as the
    /// request's `authorization` header and nowhere else: not in the body, and not in what the
    /// signature covers, which is the same with it as without it.
    #[tokio::test]
    async fn a_second_authorisation_travels_as_the_authorization_header_and_nowhere_else() {
        let wire = Wire::data();
        let service = service(&wire);
        let tokens = Tokens::holding(Some(TOKEN));
        let account = presenting(&tokens);

        let answer = send(&service, Some(&account)).await.expect("an answer");
        assert!(matches!(answer, Answer::Data(_)), "{answer:?}");
        send(&service, None).await.expect("an answer");

        assert_eq!(tokens.asked(), ["backup.write"], "one token, for its scope");
        assert_eq!(
            wire.headers(),
            [
                vec![("authorization".to_owned(), format!("Bearer {TOKEN}"))],
                Vec::new(),
            ],
            "the token beside the request that presents it, and no header beside the one that does not"
        );
        let bodies = wire.bodies();
        assert!(
            bodies
                .iter()
                .all(|body| !String::from_utf8_lossy(body).contains(TOKEN)),
            "the token is never in a body"
        );
        assert_eq!(
            digest_of(&bodies[0]),
            digest_of(&bodies[1]),
            "the signature covers the document, which is the same document either way"
        );
    }

    /// A token its source will not give is a request this client does not send: nothing reaches
    /// the transport, and the refusal is the source's own.
    #[tokio::test]
    async fn a_request_whose_token_its_source_will_not_give_is_not_sent() {
        let wire = Wire::data();
        let tokens = Tokens::holding(None);
        let refused = send(&service(&wire), Some(&presenting(&tokens)))
            .await
            .expect_err("no token");
        let Unanswered::NotSent(error) = refused else {
            panic!("nothing was sent: {refused:?}");
        };
        assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        assert_eq!(wire.requests(), 0);
        assert_eq!(tokens.asked(), ["backup.write"]);
    }

    /// Every other refusal this client makes before the transport is given the request is not
    /// sent either: an attempt outside the service's clock window, a request larger than the
    /// method admits, and a method no managed service serves.
    #[tokio::test]
    async fn a_request_this_client_refuses_is_not_sent_whatever_the_reason() {
        let wire = Wire::data();
        let service = service(&wire);
        let tokens = Tokens::holding(Some(TOKEN));
        let account = presenting(&tokens);
        let document = serde_json::json!({ "note": "a request" });
        let long_ago = now_ms() - 2 * SERVICE_REQUEST_FRESHNESS_MS;

        for (what, refused, code) in [
            (
                "an attempt signed outside the window",
                service
                    .dispatch(
                        "/api/sync/exchange",
                        Method::SyncCompareExchange,
                        &document,
                        256 * 1024,
                        Some(long_ago),
                        Some(&account),
                    )
                    .await,
                ErrorCode::ClockUntrusted,
            ),
            (
                "a request past its limit",
                service
                    .dispatch(
                        "/api/sync/exchange",
                        Method::SyncCompareExchange,
                        &document,
                        64,
                        None,
                        Some(&account),
                    )
                    .await,
                ErrorCode::InvalidArgument,
            ),
            (
                "a method no managed service serves",
                service
                    .dispatch(
                        "/api/sync/exchange",
                        Method::SessionList,
                        &document,
                        256 * 1024,
                        None,
                        None,
                    )
                    .await,
                ErrorCode::InvalidArgument,
            ),
        ] {
            match refused {
                Err(Unanswered::NotSent(error)) => assert_eq!(error.code(), code, "{what}"),
                other => panic!("{what} is not sent: {other:?}"),
            }
        }
        assert_eq!(wire.requests(), 0, "nothing reached the transport");
    }

    /// Sends one request of `method` with no second authorisation, as an adapter of that method does.
    async fn dispatched(
        service: &SignedService,
        method: Method,
    ) -> std::result::Result<Answer, Unanswered> {
        service
            .dispatch(
                "/api/a-method",
                method,
                &serde_json::json!({ "note": "a request" }),
                256 * 1024,
                None,
                None,
            )
            .await
    }

    /// KR-REQ-23.57: a gateway's 502 or 504 with no envelope of the service's can follow the
    /// service acting on the request, so a deletion or an authority feed request it answers has an
    /// unknown outcome, which nothing sends again: the service holds a deletion's first target only
    /// for the signature that asked for it, and a delegation has nothing to tell a repeat from a
    /// later change. The controls: the service's own refusal on a 502 is an answer, and a request
    /// that is safe to send again (a keyed delivery, an upload part, a read) stays transient on a
    /// 503 and on a gateway's 502 or 504 alike.
    #[tokio::test]
    async fn kr_req_23_57_a_gateway_that_lost_a_deletion_or_an_authority_request_leaves_its_outcome_unknown()
     {
        let page = b"<html><body>Bad Gateway</body></html>".to_vec();
        for method in [Method::StorageObjectDelete, Method::AuthoritySync] {
            for status in [502, 504] {
                let wire = Wire::answering(Ok(ServiceHttpAnswer {
                    status,
                    body: page.clone(),
                }));
                match dispatched(&service(&wire), method).await {
                    Err(Unanswered::Sent(error)) => {
                        assert_eq!(
                            error.code(),
                            ErrorCode::OutcomeUnknown,
                            "{method:?} {status}"
                        );
                        assert_eq!(
                            error
                                .decision(crate::retry::RequestClass::IdempotentRead)
                                .recovery,
                            crate::retry::Recovery::QueryOutcome
                        );
                    }
                    other => panic!("{method:?} {status} may have run: {other:?}"),
                }
            }
            let wire = Wire::answering(Ok(ServiceHttpAnswer {
                status: 502,
                body: br#"{"ok":false,"error":{"code":"INTERNAL","message":"Not now."}}"#.to_vec(),
            }));
            match dispatched(&service(&wire), method).await {
                Ok(Answer::Refused(refusal)) => assert_eq!(refusal.code(), "INTERNAL"),
                other => panic!("{method:?}: the service's refusal is an answer: {other:?}"),
            }
        }
        for method in [
            Method::MailboxDeliver,
            Method::StorageUploadPart,
            Method::StorageObjectRead,
        ] {
            for status in [502, 503, 504] {
                let wire = Wire::answering(Ok(ServiceHttpAnswer {
                    status,
                    body: page.clone(),
                }));
                match dispatched(&service(&wire), method).await {
                    Err(Unanswered::Sent(error)) => assert_eq!(
                        error.code(),
                        ErrorCode::UpstreamUnavailable,
                        "{method:?} {status}"
                    ),
                    other => panic!("{method:?} {status} may have run: {other:?}"),
                }
            }
        }
    }

    /// From the moment the transport is given a request, whatever goes wrong may have happened
    /// after the service received it: a transport that fails, and an answer this client cannot
    /// read. A refusal the service named is an answer, sent and answered.
    #[tokio::test]
    async fn a_request_the_transport_was_given_may_have_run_whatever_comes_back() {
        let tokens = Tokens::holding(Some(TOKEN));
        let account = presenting(&tokens);
        for (what, answer, code) in [
            (
                "a transport that failed",
                Err(ErrorCode::UpstreamUnavailable),
                ErrorCode::UpstreamUnavailable,
            ),
            (
                "a fault with no envelope",
                Ok(ServiceHttpAnswer {
                    status: 502,
                    body: b"<html>Bad Gateway</html>".to_vec(),
                }),
                ErrorCode::UpstreamUnavailable,
            ),
            (
                "a success this client cannot read",
                Ok(ServiceHttpAnswer {
                    status: 200,
                    body: b"not an envelope".to_vec(),
                }),
                ErrorCode::OutcomeUnknown,
            ),
        ] {
            let wire = Wire::answering(answer);
            match send(&service(&wire), Some(&account)).await {
                Err(Unanswered::Sent(error)) => assert_eq!(error.code(), code, "{what}"),
                other => panic!("{what} may have run: {other:?}"),
            }
            assert_eq!(wire.requests(), 1, "{what}");
        }

        let wire = Wire::answering(Ok(ServiceHttpAnswer {
            status: 404,
            body: br#"{"ok":false,"error":{"code":"COLLECTION_ABSENT","message":"absent"}}"#
                .to_vec(),
        }));
        match send(&service(&wire), Some(&account)).await {
            Ok(Answer::Refused(refusal)) => assert_eq!(refusal.code(), "COLLECTION_ABSENT"),
            other => panic!("a refusal is an answer: {other:?}"),
        }
    }

    /// A token source that holds each caller until the test lets one through, as a refresh in
    /// flight does.
    #[derive(Debug)]
    struct Refreshing {
        through: tokio::sync::Semaphore,
    }

    impl Refreshing {
        fn holding() -> Arc<Self> {
            Arc::new(Self {
                through: tokio::sync::Semaphore::new(0),
            })
        }

        fn let_one_through(&self) {
            self.through.add_permits(1);
        }
    }

    impl AccountTokenSource for Refreshing {
        fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
            Box::pin(async move {
                self.through
                    .acquire()
                    .await
                    .expect("the source stays open")
                    .forget();
                AccountToken::new(TOKEN)
            })
        }
    }

    /// Whether a request left is decided by the path each call takes, so two calls in flight at
    /// once through one exchange each say their own. One waits for its token, as a refresh makes
    /// it wait, while the other's request leaves and its answer is lost: that one may have run.
    /// Meanwhile the instant the first was to be signed at, inside the service's window when the
    /// call began, falls out of it, and the first is refused here when its token arrives: nothing
    /// of it ever reached the transport.
    #[tokio::test]
    async fn two_calls_in_flight_at_once_each_say_whether_their_own_request_left() {
        let wire = Wire::answering(Err(ErrorCode::UpstreamUnavailable));
        let service = service(&wire);
        let refreshing = Refreshing::holding();
        let waits = AccountAuthorisation::new(
            Arc::clone(&refreshing) as Arc<dyn AccountTokenSource>,
            "backup.write",
        );
        let held = presenting(&Tokens::holding(Some(TOKEN)));
        let signed_at_ms = now_ms() + 1_000 - SERVICE_REQUEST_FRESHNESS_MS;
        assert!(
            now_ms().abs_diff(signed_at_ms) <= SERVICE_REQUEST_FRESHNESS_MS,
            "inside the window when the call begins"
        );
        let document = serde_json::json!({ "note": "a request" });
        let waiting = service.dispatch(
            "/api/sync/exchange",
            Method::SyncCompareExchange,
            &document,
            256 * 1024,
            Some(signed_at_ms),
            Some(&waits),
        );
        let meanwhile = async {
            let lost = send(&service, Some(&held)).await;
            assert_eq!(
                wire.requests(),
                1,
                "the call waiting for its token has sent nothing"
            );
            tokio::time::sleep(std::time::Duration::from_millis(2_000)).await;
            refreshing.let_one_through();
            lost
        };
        let (refused, lost) = tokio::join!(waiting, meanwhile);
        match refused {
            Err(Unanswered::NotSent(error)) => assert_eq!(error.code(), ErrorCode::ClockUntrusted),
            other => panic!("aged out while it waited, and not sent: {other:?}"),
        }
        assert!(matches!(lost, Err(Unanswered::Sent(_))), "{lost:?}");
        assert_eq!(
            wire.requests(),
            1,
            "only the lost request reached the transport"
        );
    }

    /// A caller that does not ask whether its request left gets the error it always got.
    #[test]
    fn an_unanswered_request_is_the_error_it_carries_to_a_caller_that_does_not_ask() {
        for unanswered in [
            Unanswered::NotSent(malformed("refused here")),
            Unanswered::Sent(malformed("refused there")),
        ] {
            let expected = match &unanswered {
                Unanswered::NotSent(error) | Unanswered::Sent(error) => error.to_string(),
            };
            assert_eq!(ClientError::from(unanswered).to_string(), expected);
        }
    }

    #[test]
    fn a_rendering_of_a_second_authorisation_names_its_scope_and_nothing_else() {
        renders_only(
            &presenting(&Tokens::holding(Some(NEVER_RENDERED))),
            r#"AccountAuthorisation{scope:"backup.write",..}"#,
        );
    }

    /* ---------------------------------------------------------------------- */
    /* What a failure says of a request and its answer                          */
    /* ---------------------------------------------------------------------- */

    /// A refusal a service names becomes an error that says the service's message, through the
    /// door kept for words a service writes to be shown to a person, and nothing else its answer
    /// carried: the marker planted in each other member, name and value of the answer in turn is
    /// in no rendering of what comes back. A refusal whose code says more than its words is said in
    /// this program's words, whatever the service wrote.
    #[test]
    fn a_service_refusal_says_its_own_message_and_nothing_else_it_carried() {
        use crate::shown::marker::{
            MARKER, NEUTRAL, assert_unmarked, failure_renderings, json_plantings,
        };

        let refusal = |code: &str, message: &str| {
            serde_json::json!({
                "ok": false,
                "error": {
                    "code": code,
                    "message": message,
                    "retryAfterSeconds": 5,
                    "detail": { "note": "a note", "items": ["an item", 7] },
                },
            })
        };
        let read = |document: &serde_json::Value| {
            answer_of(&ServiceHttpAnswer {
                status: 403,
                body: serde_json::to_vec(document).expect("an answer"),
            })
            .and_then(Answer::data)
            .expect_err("a refusal, or an answer this client cannot read")
        };

        // The neutral control: the code as this client classifies it, the service's message and
        // the delay it asked for.
        assert_eq!(
            read(&refusal("FORBIDDEN", NEUTRAL)).to_string(),
            "PERMISSION_DENIED: neutral-value (retry after 5s)"
        );
        // The negative control: the message is the one member said whole.
        let said = read(&refusal("FORBIDDEN", MARKER)).to_string();
        assert!(said.contains(MARKER), "{said}");

        let mut plantings = 0;
        for planted in json_plantings(&refusal("FORBIDDEN", "the service's own words"), MARKER) {
            if planted.at == "Text at /error/message" {
                continue;
            }
            plantings += 1;
            assert_unmarked(&planted.at, &failure_renderings(read(&planted.input)));
        }
        assert!(plantings > 10, "{plantings} plantings");

        let cutoff = read(&refusal("SIGNED_BEFORE_CUTOFF", MARKER));
        assert!(
            cutoff
                .to_string()
                .starts_with("CLOCK_UNTRUSTED: nothing ran and nothing was recorded"),
            "{cutoff}"
        );
        assert_unmarked(
            "a refusal signed before a cutoff",
            &failure_renderings(cutoff),
        );
    }

    /// A request that went unanswered says why in this program's words, and nothing it carried:
    /// not the account token beside it, not a body whose writer failed, which is said by the kind
    /// of fault, and not a body past its method's bound, which is said by its length. What an
    /// answer this client cannot read held is said by its kind too.
    #[tokio::test]
    async fn an_unanswered_request_says_nothing_of_its_body_or_its_account_token() {
        use crate::shown::marker::{MARKER, NEUTRAL, assert_unmarked, failure_renderings};

        /// A body whose writer fails with the words it is given.
        struct Unwritable(&'static str);

        impl Serialize for Unwritable {
            fn serialize<S: serde::Serializer>(
                &self,
                _serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(self.0))
            }
        }

        let account = presenting(&Tokens::holding(Some(MARKER)));
        let wire = Wire::data();
        let client = service(&wire);

        for planted in [MARKER, NEUTRAL] {
            // The negative control: the writer's own failure says the words it was given.
            let own = serde_json::to_value(Unwritable(planted)).expect_err("the writer fails");
            assert!(own.to_string().contains(planted), "{own}");
            let refused = client
                .dispatch(
                    "/api/sync/exchange",
                    Method::SyncCompareExchange,
                    &Unwritable(planted),
                    256 * 1024,
                    None,
                    Some(&account),
                )
                .await;
            let Err(Unanswered::NotSent(error)) = refused else {
                panic!("a body its writer cannot write is not sent: {refused:?}");
            };
            // The neutral control: the class of the fault and where it is.
            assert_eq!(
                error.to_string(),
                "INVALID_ARGUMENT: a request could not be written: it is not the shape this client \
                 reads at line 0 column 0"
            );
            assert_unmarked("a body its writer cannot write", &failure_renderings(error));
        }

        let document = serde_json::json!({ "note": MARKER.repeat(8) });
        let refused = client
            .dispatch(
                "/api/sync/exchange",
                Method::SyncCompareExchange,
                &document,
                64,
                None,
                Some(&account),
            )
            .await;
        let Err(Unanswered::NotSent(error)) = refused else {
            panic!("a request past its bound is not sent: {refused:?}");
        };
        let said = error.to_string();
        assert!(
            said.starts_with(
                "INVALID_ARGUMENT: a sync.compare_exchange request is at most 64 bytes and this one \
                 is "
            ),
            "{said}"
        );
        assert_unmarked("a request past its bound", &failure_renderings(error));
        assert_eq!(wire.requests(), 0, "nothing reached the transport");

        for answer in [
            Err(ErrorCode::UpstreamUnavailable),
            Ok(ServiceHttpAnswer {
                status: 200,
                body: MARKER.as_bytes().to_vec(),
            }),
        ] {
            let wire = Wire::answering(answer);
            let unanswered = send(&service(&wire), Some(&account)).await;
            let Err(Unanswered::Sent(error)) = unanswered else {
                panic!("a request the transport was given may have run: {unanswered:?}");
            };
            // The negative control: the token travelled beside the request.
            assert_eq!(
                wire.headers(),
                [vec![(
                    "authorization".to_owned(),
                    format!("Bearer {MARKER}")
                )]]
            );
            assert_unmarked("a request that may have run", &failure_renderings(error));
        }
    }

    /* ---------------------------------------------------------------------- */
    /* A request whose body is content, and an answer that is content          */
    /* ---------------------------------------------------------------------- */

    /// The content a carried request describes, as a storage part would be.
    const CONTENT: &[u8] = &[0x00, 0xff, 0x7b, 0x22, 0x0a, 0xc3, 0x28];

    /// One request carried in a header beside `CONTENT`, signed now.
    async fn carry(
        service: &SignedService,
        account: Option<&AccountAuthorisation>,
    ) -> std::result::Result<Answer, Unanswered> {
        service
            .dispatch_carried(
                "/api/storage/upload/part",
                Method::StorageUploadPart,
                &serde_json::json!({ "note": "a part" }),
                8 * 1024,
                account,
                Carriage::Header {
                    header: "kr-service-request",
                    content: CONTENT,
                },
            )
            .await
    }

    /// A request carried in a header is the same signed request, as unpadded base64url of its
    /// JSON, and the body is the content and nothing else. The account token goes beside it, as it
    /// goes beside every request that presents one, and neither the header nor the body holds it.
    #[tokio::test]
    async fn a_request_carried_in_a_header_travels_beside_its_content_and_its_token() {
        use base64::Engine as _;

        let wire = Wire::data();
        let service = service(&wire);
        let tokens = Tokens::holding(Some(TOKEN));
        let answer = carry(&service, Some(&presenting(&tokens)))
            .await
            .expect("an answer");
        assert!(matches!(answer, Answer::Data(_)), "{answer:?}");

        assert_eq!(wire.contents(), [true], "sent as content");
        assert_eq!(
            wire.bodies(),
            [CONTENT.to_vec()],
            "the content, byte for byte"
        );
        let headers = wire.headers();
        assert_eq!(headers[0].len(), 2, "{:?}", headers[0]);
        assert_eq!(headers[0][0].0, "kr-service-request");
        assert_eq!(
            headers[0][1],
            ("authorization".to_owned(), format!("Bearer {TOKEN}"))
        );
        let document = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&headers[0][0].1)
            .expect("unpadded base64url");
        assert!(
            !String::from_utf8_lossy(&document).contains(TOKEN),
            "the token is never in the signed request"
        );
        let request: serde_json::Value =
            serde_json::from_slice(&document).expect("a signed request");
        assert_eq!(request["body"], serde_json::json!({ "note": "a part" }));
        assert_eq!(
            digest_of(&document),
            canonical_body_digest(&request["body"]).expect("a digest"),
            "the signature covers the document, and not the content beside it"
        );
        assert_eq!(
            request["signature"]["payload"]["method"],
            "storage.upload.part"
        );
    }

    /// The boundary is the same one: a request carried in a header whose token its source will
    /// not give is not sent, and nothing reaches the transport.
    #[tokio::test]
    async fn a_request_carried_in_a_header_is_not_sent_without_its_token() {
        let wire = Wire::data();
        let refused = carry(&service(&wire), Some(&presenting(&Tokens::holding(None))))
            .await
            .expect_err("no token");
        assert!(matches!(refused, Unanswered::NotSent(_)), "{refused:?}");
        assert_eq!(wire.requests(), 0);
    }

    /// A success whose answer is content is the bytes, whatever they are, because nothing here
    /// reads content. A failure is read as the envelope it is, and a success envelope where a
    /// failure status says otherwise is not an answer this client reads.
    #[tokio::test]
    async fn a_success_whose_answer_is_content_comes_back_as_its_bytes() {
        let read = |wire: &Arc<Wire>| {
            let service = service(wire);
            async move {
                service
                    .dispatch_for_content(
                        "/api/storage/object/read",
                        Method::StorageObjectRead,
                        &serde_json::json!({ "note": "a read" }),
                        8 * 1024,
                        None,
                    )
                    .await
            }
        };

        // Bytes that happen to look like an envelope are still the bytes.
        for body in [
            CONTENT.to_vec(),
            br#"{"ok":false,"error":{"code":"FORBIDDEN","message":"no"}}"#.to_vec(),
            Vec::new(),
        ] {
            let wire = Wire::answering(Ok(ServiceHttpAnswer {
                status: 200,
                body: body.clone(),
            }));
            match read(&wire).await {
                Ok(Content::Bytes(bytes)) => assert_eq!(bytes, body),
                other => panic!("the bytes: {other:?}"),
            }
            assert_eq!(wire.contents(), [false], "the request is a document");
        }

        let wire = Wire::answering(Ok(ServiceHttpAnswer {
            status: 404,
            body:
                br#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No such stored object."}}"#
                    .to_vec(),
        }));
        match read(&wire).await {
            Ok(Content::Refused(refusal)) => assert_eq!(refusal.code(), "NOT_FOUND"),
            other => panic!("a refusal: {other:?}"),
        }

        for (status, body, code) in [
            (
                404,
                br#"{"ok":true,"data":{"note":"x"}}"#.to_vec(),
                ErrorCode::HostNotConfigured,
            ),
            (
                502,
                b"<html>Bad Gateway</html>".to_vec(),
                ErrorCode::UpstreamUnavailable,
            ),
        ] {
            let wire = Wire::answering(Ok(ServiceHttpAnswer { status, body }));
            match read(&wire).await {
                Err(Unanswered::Sent(error)) => assert_eq!(error.code(), code, "{status}"),
                other => panic!("not an answer this client reads: {other:?}"),
            }
        }
    }

    #[test]
    fn a_rendering_of_content_carries_its_length_and_never_its_bytes() {
        renders_only(
            &Content::Bytes(NEVER_RENDERED.as_bytes().to_vec()),
            &format!("Bytes{{length:{}}}", NEVER_RENDERED.len()),
        );
    }

    /// The storage and backup services' own refusals say what a person does. A collection deleted
    /// from the account console takes nothing again, whoever asks, which a new collection is the
    /// way round: a change of configuration, and never an update. A service with no room for the
    /// request now is a capacity to wait for, with the delay it named.
    #[test]
    fn a_storage_refusal_says_what_a_person_does_about_it() {
        for (status, code, message, expected, action) in [
            (
                410,
                "COLLECTION_DELETED",
                "That backup collection was deleted from the account console. Enrol a new collection to back up again.",
                ErrorCode::PermissionDenied,
                UserAction::FixConfiguration,
            ),
            (
                503,
                "SERVICE_UNAVAILABLE",
                "This service has no room for that part at the moment. Send it again shortly.",
                ErrorCode::ServiceCapacity,
                UserAction::Wait,
            ),
        ] {
            let error = answer_of(&ServiceHttpAnswer {
                status,
                body: serde_json::to_vec(&serde_json::json!({
                    "ok": false,
                    "error": { "code": code, "message": message, "retryAfterSeconds": 2 },
                }))
                .expect("a refusal"),
            })
            .and_then(Answer::data)
            .expect_err("a refusal");
            assert_eq!(error.code(), expected, "{code}");
            assert_eq!(error.user_action(), action, "{code}");
            assert!(error.to_string().contains(message), "{error}");
            let ClientError::Refused {
                retry_after_seconds,
                ..
            } = error
            else {
                panic!("a refusal the service named: {error:?}");
            };
            assert_eq!(retry_after_seconds, Some(2));
        }
    }
}
