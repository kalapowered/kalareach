//! Signing in to a managed account through the system browser, and the tokens that come of it.
//!
//! Section 17: native applications are registered public OAuth clients. They use the system
//! browser, the authorisation-code flow with S256 PKCE, exact registered redirect addresses, state
//! and issuer and audience checks, associated HTTPS app links on mobile and a registered loopback
//! redirect on desktop, and no client secret. Access tokens last ten minutes, refresh tokens rotate
//! on every use, presenting a rotated one again revokes the whole family, and tokens are kept in
//! native secure storage.
//!
//! This module is the client's half of that, with no platform code in it:
//!
//! * [`AuthorisationRequest`] builds the one address the browser is handed.
//! * [`PendingAuthorisation`] checks what comes back, in a fixed order, and consumes the request so
//!   that no second answer can use it.
//! * [`AccountService`] is the service's token, revocation, identity and usage endpoints, and
//!   [`ManagedAccountService`] is the managed implementation, over the narrow [`AccountHttp`].
//! * [`SignedInAccount`] keeps the grant in a [`SecretStore`] under one lock and is the
//!   [`AccountTokenSource`] every managed resource asks for a token.
//!
//! The browser, the delivery of the redirect and the store itself are the embedder's: the
//! companion carries them per platform.
//!
//! # What is pinned
//!
//! The origin, the issuer, the endpoints and the two registered clients with their redirects are
//! constants here rather than something discovered. The registry on the service is closed and
//! exact, and the issuer is the value every answer is checked against, so reading it from the
//! service would have the answer vouch for itself. A self-hosted deployment supplies its own
//! [`AccountService`].
//!
//! # One lock
//!
//! Every change to what is stored happens under one lock: a sign-in's commit, a refresh, a
//! sign-out, the removal of an acknowledged revocation and the recovery at start. A refresh holds it
//! across its request, so nothing can write a grant back after a sign-out removed it, and two
//! callers never present the same refresh token. Across processes on one machine the embedder names
//! a lock file, which is taken after the in-process lock and released before it.
//!
//! # What is never rendered
//!
//! [`AccountToken`], [`RefreshToken`], [`AuthorisationRequest`], [`AuthorisationGrant`],
//! [`IssuedGrant`] and [`StoredGrant`] hold a token, a code, a verifier, a state or a nonce. Each
//! writes its own [`fmt::Debug`] naming what it is and nothing that travelled, under this crate's
//! rule for service types; `a_rendering_of_a_request_a_grant_or_a_token_carries_none_of_them` holds
//! them to it. An address or a name read from the service is not a credential, but a rendering
//! does not print those either: it says whether one is there.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use kr_crypto::store::{SecretName, SecretStore};
use kr_protocol::error::{ErrorCode, ProtocolError};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use url::Url;

use super::{ServiceFuture, ServiceHttpAnswer};
use crate::error::{ClientError, Result};

/* -------------------------------------------------------------------------- */
/* What is pinned                                                              */
/* -------------------------------------------------------------------------- */

/// The website's fixed origin, where the passkey ceremony runs.
pub const ACCOUNT_ORIGIN: &str = "https://reach.kala.to";

/// The passkey relying party: the origin's host, which is how the service derives it.
pub const RELYING_PARTY_ID: &str = "reach.kala.to";

/// The issuer every answer is checked against.
pub const ISSUER: &str = "https://reach.kala.to/auth";

/// Where the browser is sent to sign in.
pub const AUTHORIZE_PATH: &str = "/auth/oauth2/authorize";

/// Where a code and a refresh token are exchanged.
pub const TOKEN_PATH: &str = "/auth/oauth2/token";

/// Where a grant is revoked.
pub const REVOKE_PATH: &str = "/auth/oauth2/revoke";

/// Where the signed-in account's address and name are read.
pub const USERINFO_PATH: &str = "/auth/oauth2/userinfo";

/// Where the account's usage is read.
pub const USAGE_PATH: &str = "/api/billing/summary";

/// The scope a membership lease request needs.
pub const LEASE_SCOPE: &str = "organisation.lease";

/// The scope reading usage needs.
pub const USAGE_SCOPE: &str = "billing.read";

/// Every scope an application sign-in asks for, in the order the request states them.
///
/// The identity claims, a refresh token that survives a restart, the member's lease fetch, the
/// call this device holds and the answers it asks for, and usage. Not `backup.write`: the
/// application writes no archives.
pub const REQUESTED_SCOPES: [&str; 8] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    LEASE_SCOPE,
    super::voice::VOICE_SCOPE,
    "reasoning",
    USAGE_SCOPE,
];

/// How long before its stated end an access token is replaced rather than presented.
const ACCESS_MARGIN_MS: u64 = 30_000;

/// How far a token's clock may be from this device's, in seconds, either way.
const CLOCK_SKEW_SECONDS: u64 = 300;

/// The most revocations kept waiting for the service.
const PENDING_LIMIT: usize = 16;

/// How long a revocation is kept waiting: a grant ends by itself after this.
const PENDING_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The stored item that holds the grant.
const SESSION_ITEM: &str = "account/session";

/// The stored item that holds the revocations the service has not acknowledged.
const PENDING_ITEM: &str = "account/revoke";

/// Where the answer to an authorisation comes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Redirect {
    /// `https://reach.kala.to/app/oauth/callback`: an associated HTTPS app link.
    AppLink,
    /// `to.kala.reach:/oauth/callback`: a private-use scheme, for a browser-backed session that
    /// catches the navigation itself and cannot take an HTTPS callback.
    PrivateUse,
    /// `http://127.0.0.1:8765/oauth/callback`: a loopback listener on this machine.
    Loopback,
}

impl Redirect {
    /// The registered address, byte for byte.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::AppLink => "https://reach.kala.to/app/oauth/callback",
            Self::PrivateUse => "to.kala.reach:/oauth/callback",
            Self::Loopback => "http://127.0.0.1:8765/oauth/callback",
        }
    }

    /// Whether `url` is this address: the same scheme, host, port and path, with no user
    /// information and no fragment. The query is the answer and is not compared.
    #[must_use]
    pub fn matches(self, url: &Url) -> bool {
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return false;
        }
        let Ok(registered) = Url::parse(self.uri()) else {
            return false;
        };
        url.scheme() == registered.scheme()
            && url.host() == registered.host()
            && url.port_or_known_default() == registered.port_or_known_default()
            && url.path() == registered.path()
    }
}

/// A registered public client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Client {
    /// The iOS and Android application.
    Mobile,
    /// The macOS, Windows and Linux application.
    Desktop,
}

impl Client {
    /// The identifier the service registered.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Mobile => "kalareach-mobile",
            Self::Desktop => "kalareach-desktop",
        }
    }

    /// The redirects registered for this client.
    #[must_use]
    pub const fn redirects(self) -> &'static [Redirect] {
        match self {
            Self::Mobile => &[Redirect::AppLink, Redirect::PrivateUse],
            Self::Desktop => &[Redirect::Loopback],
        }
    }

    /// Whether `redirect` is registered for this client.
    #[must_use]
    pub fn owns(self, redirect: Redirect) -> bool {
        self.redirects().contains(&redirect)
    }

    /// The client a registered identifier names.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        [Self::Mobile, Self::Desktop]
            .into_iter()
            .find(|client| client.id() == id)
    }
}

/* -------------------------------------------------------------------------- */
/* Tokens                                                                      */
/* -------------------------------------------------------------------------- */

/// Checks a bearer value: not empty, at most 8192 bytes, and printable ASCII.
fn bearer_value(value: &str, what: &str) -> Result<()> {
    if value.is_empty() {
        return Err(local(&format!("{what} is not empty")));
    }
    if value.len() > 8192 {
        return Err(local(&format!("{what} is at most 8192 bytes")));
    }
    if !value
        .bytes()
        .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ')
    {
        return Err(local(&format!(
            "{what} is printable ASCII, as an authorisation header value is"
        )));
    }
    Ok(())
}

/// An account access token, held so it cannot reach a log by accident.
///
/// The value is never in a [`fmt::Debug`] rendering and there is no [`fmt::Display`]. A caller
/// that needs the bytes asks for them by name, which is one line to find in a review rather than
/// an interpolation to notice.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountToken(String);

impl AccountToken {
    /// Wraps an access token, rejecting one that cannot be sent as a header value.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is empty or carries a character an HTTP header may not.
    /// The refusal never quotes the token.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        bearer_value(&value, "an account token")?;
        Ok(Self(value))
    }

    /// Returns the token itself, for the one caller that has to send it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountToken(<not printed>)")
    }
}

/// A refresh token: the grant itself, for as long as it lasts.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken(String);

impl RefreshToken {
    /// Wraps a refresh token.
    ///
    /// # Errors
    ///
    /// Returns an error when the value could not be sent in a form body as this client sends it.
    /// The refusal never quotes the value.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        bearer_value(&value, "a refresh token")?;
        Ok(Self(value))
    }

    /// Returns the token itself, for the request that has to send it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RefreshToken(<not printed>)")
    }
}

/// Where the current account token comes from, for the scope the caller needs.
///
/// A token expires and is replaced, so a client handed one at construction would keep presenting
/// a dead one. The source answers with whatever it holds now, for the resource the caller names,
/// and refuses when what it holds was not issued with that scope, so a request never goes out
/// with a token the resource would turn away.
pub trait AccountTokenSource: Send + Sync + fmt::Debug {
    /// Returns the token to present for `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when no account is available, when what is held was not issued with
    /// `scope`, or when it could not be read or replaced. The error never carries the token.
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken>;
}

/* -------------------------------------------------------------------------- */
/* The request                                                                 */
/* -------------------------------------------------------------------------- */

/// 32 random bytes, base64url without padding: 43 characters.
fn fresh_secret() -> Result<String> {
    let mut bytes = [0_u8; 32];
    kr_crypto::random_bytes(&mut bytes).map_err(|error| {
        ClientError::Host(ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            format!("this device could not produce random bytes: {error}"),
        ))
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The S256 challenge for a verifier: BASE64URL(SHA-256(verifier)), RFC 7636 section 4.2.
#[must_use]
pub fn code_challenge(verifier: &str) -> String {
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..])
}

/// One sign-in attempt, named so that a late answer from an earlier one is told apart.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    /// A new attempt identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when this device could not produce random bytes.
    pub fn fresh() -> Result<Self> {
        let mut bytes = [0_u8; 8];
        kr_crypto::random_bytes(&mut bytes).map_err(|error| {
            ClientError::Host(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                format!("this device could not produce random bytes: {error}"),
            ))
        })?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }

    /// The identifier as a number, which is how a native carrier is told it.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The identifier a native carrier reported.
    #[must_use]
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for AttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}", self.0)
    }
}

impl fmt::Debug for AttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AttemptId({self})")
    }
}

/// The authorisation request one attempt hands the browser.
///
/// Its state, verifier and nonce are fresh for every attempt, live in this process for as long as
/// the attempt does, and are never stored; the nonce is kept with the grant once the sign-in
/// succeeds, because a refresh's ID token is checked against it.
pub struct AuthorisationRequest {
    client: Client,
    redirect: Redirect,
    attempt: AttemptId,
    state: String,
    verifier: String,
    nonce: String,
}

impl fmt::Debug for AuthorisationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorisationRequest")
            .field("client", &self.client)
            .field("redirect", &self.redirect)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

impl AuthorisationRequest {
    /// A request for `client`, answered on `redirect`.
    ///
    /// # Errors
    ///
    /// Returns an error when `redirect` is not registered for `client`, or when this device could
    /// not produce random bytes.
    pub fn new(client: Client, redirect: Redirect) -> Result<Self> {
        if !client.owns(redirect) {
            return Err(local(&format!(
                "{} is not a redirect registered for {}",
                redirect.uri(),
                client.id()
            )));
        }
        Ok(Self {
            client,
            redirect,
            attempt: AttemptId::fresh()?,
            state: fresh_secret()?,
            verifier: fresh_secret()?,
            nonce: fresh_secret()?,
        })
    }

    /// The address the browser opens: the authorisation endpoint on the fixed origin, with each
    /// parameter once and nothing else.
    ///
    /// # Panics
    ///
    /// Panics only when the pinned origin does not parse, which is a build-time mistake.
    #[must_use]
    pub fn url(&self) -> String {
        let mut url = Url::parse(ACCOUNT_ORIGIN)
            .and_then(|origin| origin.join(AUTHORIZE_PATH))
            .expect("the pinned origin and path parse");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client.id())
            .append_pair("redirect_uri", self.redirect.uri())
            .append_pair("scope", &REQUESTED_SCOPES.join(" "))
            .append_pair("state", &self.state)
            .append_pair("code_challenge", &code_challenge(&self.verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", &self.nonce)
            .append_pair("prompt", "login");
        url.into()
    }

    /// The client this request is for.
    #[must_use]
    pub const fn client(&self) -> Client {
        self.client
    }

    /// The redirect this attempt's answer comes back on.
    #[must_use]
    pub const fn redirect(&self) -> Redirect {
        self.redirect
    }

    /// The attempt this request belongs to.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }
}

/* -------------------------------------------------------------------------- */
/* The answer                                                                  */
/* -------------------------------------------------------------------------- */

/// What delivered an answer, which decides what refusing it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// It delivers one result and ends: a browser-backed session's completion, or an Auth Tab's
    /// result. Refusing its answer ends the attempt, because nothing else can arrive.
    Terminal,
    /// It can deliver more: a loopback listener, or links the system hands the application. A
    /// request or intent refused at the address, repetition or state checks is dropped and the
    /// attempt goes on waiting, so a stray request cannot end a real sign-in.
    Continuing,
}

/// Why an answer was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnswerFault {
    /// It came back on an address other than the attempt's redirect.
    OtherAddress,
    /// It carried `state`, `code`, `iss` or `error` more than once.
    Repeated,
    /// Its state is not this attempt's, or no attempt is waiting.
    WrongState,
    /// It named another issuer, or none.
    OtherIssuer,
    /// The service answered with an error other than a refusal.
    ServiceFailure,
    /// It carried neither a code nor an error.
    NoCode,
}

/// What became of one answer.
pub enum Answer {
    /// The attempt produced a code to exchange.
    Granted(AuthorisationGrant),
    /// The person or the service said no (`access_denied`).
    Refused,
    /// The attempt is over and failed.
    Failed(AnswerFault),
    /// This answer was not for the attempt and was set aside; the attempt goes on waiting.
    Dropped(AnswerFault),
}

impl fmt::Debug for Answer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted(grant) => formatter.debug_tuple("Granted").field(grant).finish(),
            Self::Refused => formatter.write_str("Refused"),
            Self::Failed(fault) => formatter.debug_tuple("Failed").field(fault).finish(),
            Self::Dropped(fault) => formatter.debug_tuple("Dropped").field(fault).finish(),
        }
    }
}

/// A code, with everything its exchange needs.
pub struct AuthorisationGrant {
    client: Client,
    redirect: Redirect,
    attempt: AttemptId,
    code: String,
    verifier: String,
    nonce: String,
}

impl fmt::Debug for AuthorisationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorisationGrant")
            .field("client", &self.client)
            .field("redirect", &self.redirect)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

impl AuthorisationGrant {
    /// The client the code was issued to.
    #[must_use]
    pub const fn client(&self) -> Client {
        self.client
    }

    /// The redirect the code came back on, which the exchange names again.
    #[must_use]
    pub const fn redirect(&self) -> Redirect {
        self.redirect
    }

    /// The attempt the code belongs to.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// The code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The PKCE verifier the code is bound to.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The nonce the ID token has to carry.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// What checks 1 to 3 leave of an answer.
struct Inspected {
    code: Option<String>,
    issuer: Option<String>,
    error: Option<String>,
}

/// The attempt waiting for its answer.
///
/// It holds the request until an answer whose state matches takes it out, so a second answer,
/// whether a repeat of the first or anything later with the same state, finds nothing to take:
/// that is the client's half of "a code is used once".
#[derive(Debug)]
pub struct PendingAuthorisation {
    request: Option<AuthorisationRequest>,
}

impl PendingAuthorisation {
    /// An attempt waiting for the answer to `request`.
    #[must_use]
    pub const fn new(request: AuthorisationRequest) -> Self {
        Self {
            request: Some(request),
        }
    }

    /// The attempt that is waiting, if one is.
    #[must_use]
    pub fn attempt(&self) -> Option<AttemptId> {
        self.request.as_ref().map(AuthorisationRequest::attempt)
    }

    /// Whether an answer can still be accepted.
    #[must_use]
    pub const fn is_waiting(&self) -> bool {
        self.request.is_some()
    }

    /// Ends the attempt without an answer.
    pub fn abandon(&mut self) {
        self.request = None;
    }

    /// Checks one answer, in this order: the address is the attempt's redirect; `state`, `code`,
    /// `iss` and `error` appear at most once; the state is this attempt's; the request is consumed;
    /// the issuer is the pinned one; an `error` is a refusal or a failure; a code becomes a grant.
    pub fn answer(&mut self, url: &str, carrier: Carrier) -> Answer {
        let inspected = match self.request.as_ref() {
            None => Err(AnswerFault::WrongState),
            Some(request) => inspect(request, url),
        };
        let inspected = match inspected {
            Ok(inspected) => inspected,
            Err(fault) => {
                return match carrier {
                    Carrier::Continuing => Answer::Dropped(fault),
                    Carrier::Terminal => {
                        self.request = None;
                        Answer::Failed(fault)
                    }
                };
            }
        };
        let Some(request) = self.request.take() else {
            return Answer::Failed(AnswerFault::WrongState);
        };
        if inspected.issuer.as_deref() != Some(ISSUER) {
            return Answer::Failed(AnswerFault::OtherIssuer);
        }
        if let Some(error) = inspected.error {
            return if error == "access_denied" {
                Answer::Refused
            } else {
                Answer::Failed(AnswerFault::ServiceFailure)
            };
        }
        match inspected.code {
            Some(code) if !code.is_empty() => Answer::Granted(AuthorisationGrant {
                client: request.client,
                redirect: request.redirect,
                attempt: request.attempt,
                code,
                verifier: request.verifier,
                nonce: request.nonce,
            }),
            _ => Answer::Failed(AnswerFault::NoCode),
        }
    }
}

/// Checks 1 to 3 against the waiting request, without consuming it.
fn inspect(
    request: &AuthorisationRequest,
    url: &str,
) -> std::result::Result<Inspected, AnswerFault> {
    let parsed = Url::parse(url).map_err(|_| AnswerFault::OtherAddress)?;
    if !request.redirect.matches(&parsed) {
        return Err(AnswerFault::OtherAddress);
    }
    let mut state: Option<String> = None;
    let mut code = None;
    let mut issuer = None;
    let mut error = None;
    for (name, value) in parsed.query_pairs() {
        let slot = match name.as_ref() {
            "state" => &mut state,
            "code" => &mut code,
            "iss" => &mut issuer,
            "error" => &mut error,
            _ => continue,
        };
        if slot.is_some() {
            return Err(AnswerFault::Repeated);
        }
        *slot = Some(value.into_owned());
    }
    let matches = state
        .as_ref()
        .is_some_and(|state| bool::from(state.as_bytes().ct_eq(request.state.as_bytes())));
    if !matches {
        return Err(AnswerFault::WrongState);
    }
    Ok(Inspected {
        code,
        issuer,
        error,
    })
}

/* -------------------------------------------------------------------------- */
/* The service                                                                 */
/* -------------------------------------------------------------------------- */

/// Tokens the service issued, checked.
pub struct IssuedGrant {
    /// The access token.
    pub access_token: AccountToken,
    /// How many seconds the access token lasts.
    pub expires_in_seconds: u64,
    /// The refresh token that replaces it.
    pub refresh_token: RefreshToken,
    /// The scopes granted, which may be fewer than asked for.
    pub scopes: Vec<String>,
    /// The account the ID token names.
    pub subject: String,
}

impl fmt::Debug for IssuedGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedGrant")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// What a code's exchange came to.
#[derive(Debug)]
pub enum Exchanged {
    /// Tokens that passed every check.
    Issued(IssuedGrant),
    /// The service refused, or answered with something that failed a check. Nothing is kept; a
    /// refresh token the answer carried is handed back so it can be revoked rather than left to
    /// last thirty days.
    Refused {
        /// A refresh token the refused answer carried.
        leftover: Option<RefreshToken>,
    },
}

/// What a refresh came to.
#[derive(Debug)]
pub enum Refreshed {
    /// New tokens that passed every check. The stored grant is replaced with them.
    Rotated(IssuedGrant),
    /// The service says the grant is gone: expired, revoked or replayed, which it will not tell
    /// apart.
    Ended,
    /// The service answered after spending the old token, with something that failed a check. The
    /// grant is over; a refresh token the answer carried is handed back to be revoked.
    Refused {
        /// A refresh token the refused answer carried.
        leftover: Option<RefreshToken>,
    },
}

/// Who is signed in, as the service reports it.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountIdentity {
    /// The account's stable identifier.
    pub subject: String,
    /// The address it signs in with, when the service says.
    pub email: Option<String>,
    /// The name on the account, when it has one.
    pub name: Option<String>,
}

impl fmt::Debug for AccountIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountIdentity")
            .field("email", &self.email.as_ref().map(|_| "<present>"))
            .field("name", &self.name.as_ref().map(|_| "<present>"))
            .finish_non_exhaustive()
    }
}

/// One resource the account's usage covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageResource {
    /// Relay bytes forwarded, counted per calendar month.
    Relay,
    /// Encrypted backup storage held.
    Storage,
    /// Settings-sync bytes held.
    Sync,
}

/// One line of usage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageLine {
    /// What it measures.
    pub resource: UsageResource,
    /// Bytes used in the current period.
    pub used_bytes: u64,
    /// Bytes allowed in the current period.
    pub allowance_bytes: u64,
    /// The calendar month for a monthly resource, or none for a standing total.
    pub period: Option<String>,
}

/// What the account has used, and nothing about money.
///
/// Read from the usage route's allowances and nothing else: the catalogue, the balance and the
/// currency are not parsed, so they cannot reach an interface through this type.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AccountUsage {
    /// One line per resource the service reported, in the order it reported them.
    pub lines: Vec<UsageLine>,
}

/// Where a managed or self-hosted account is signed in.
///
/// Account tokens authorise managed resources only. Nothing here can grant host authority.
pub trait AccountService: Send + Sync + fmt::Debug {
    /// Exchanges a code for tokens, and checks them.
    fn exchange<'a>(&'a self, grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged>;

    /// Replaces a stored grant's tokens, and checks what comes back against what is stored.
    fn refresh<'a>(&'a self, stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed>;

    /// Revokes the grant a refresh token belongs to.
    fn revoke<'a>(&'a self, refresh: &'a RefreshToken) -> ServiceFuture<'a, ()>;

    /// Reads who is signed in.
    fn identity<'a>(&'a self, access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity>;

    /// Reads what the account has used.
    fn usage<'a>(&'a self, access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage>;
}

/// The exchange the account client is written against: a form post and a read.
///
/// Narrower than [`super::ServiceHttp`], which posts JSON and which fourteen other clients
/// implement or use; the account endpoints take forms and bearer reads, and nothing else needs
/// them.
pub trait AccountHttp: Send + Sync + fmt::Debug {
    /// Posts `body` as `application/x-www-form-urlencoded` and returns what came back.
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer>;

    /// Reads `url` with `headers` and returns what came back.
    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer>;
}

/// Seconds since the Unix epoch, by this device's clock.
fn system_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Milliseconds since the Unix epoch, by this device's clock.
fn system_milliseconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The managed account service.
#[derive(Clone)]
pub struct ManagedAccountService {
    origin: String,
    http: Arc<dyn AccountHttp>,
    client: Client,
    clock: fn() -> u64,
}

impl fmt::Debug for ManagedAccountService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedAccountService")
            .field("origin", &self.origin)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

/// What the ID token's payload has to say, and what it said.
struct Expected<'a> {
    client: Client,
    subject: Option<&'a str>,
    nonce: Option<&'a str>,
}

impl ManagedAccountService {
    /// The managed service on its fixed origin, for one client.
    #[must_use]
    pub fn new(http: Arc<dyn AccountHttp>, client: Client) -> Self {
        Self::at_origin(ACCOUNT_ORIGIN, http, client)
    }

    /// The same service answering on another origin, such as a test server. The issuer every
    /// answer is checked against stays the pinned one.
    #[must_use]
    pub fn at_origin(
        origin: impl Into<String>,
        http: Arc<dyn AccountHttp>,
        client: Client,
    ) -> Self {
        Self {
            origin: origin.into(),
            http,
            client,
            clock: system_seconds,
        }
    }

    /// Reads the time in seconds since the Unix epoch from `clock`, for a test.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    /// Reads a token answer's fields, and checks them all.
    ///
    /// The refresh token is read first, so that an answer which fails any later check still hands
    /// it back to be revoked.
    fn issued(
        &self,
        answer: &serde_json::Value,
        expected: &Expected<'_>,
        stored_scopes: Option<&[String]>,
    ) -> std::result::Result<IssuedGrant, Option<RefreshToken>> {
        let refresh = answer
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| RefreshToken::new(value).ok());
        let fail = || refresh.clone();
        let refresh_token = refresh.clone().ok_or(None)?;
        let bearer = answer
            .get("token_type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"));
        if !bearer {
            return Err(fail());
        }
        let access_token = answer
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| AccountToken::new(value).ok())
            .ok_or_else(fail)?;
        let expires_in_seconds = answer
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .filter(|seconds| *seconds > 0)
            .ok_or_else(fail)?;
        let scopes: Vec<String> = match (answer.get("scope"), stored_scopes) {
            (Some(scope), _) => scope
                .as_str()
                .ok_or_else(fail)?
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect(),
            // A refresh answer that states no scope keeps what the grant had (RFC 6749 section 5.1).
            (None, Some(stored)) => stored.to_vec(),
            (None, None) => return Err(fail()),
        };
        if scopes.is_empty() {
            return Err(fail());
        }
        if let Some(stored) = stored_scopes
            && scopes.iter().any(|scope| !stored.contains(scope))
        {
            return Err(fail());
        }
        let subject = match answer.get("id_token") {
            Some(token) => {
                let token = token.as_str().ok_or_else(fail)?;
                self.checked_subject(token, expected).ok_or_else(fail)?
            }
            // An exchange carries an ID token; a refresh may leave it out (OpenID Connect Core
            // section 12.2), and then the stored subject stands.
            None => match expected.subject {
                Some(subject) if stored_scopes.is_some() => subject.to_owned(),
                _ => return Err(fail()),
            },
        };
        Ok(IssuedGrant {
            access_token,
            expires_in_seconds,
            refresh_token,
            scopes,
            subject,
        })
    }

    /// Checks an ID token's payload and returns its subject.
    ///
    /// Its signature is not checked: it came over TLS straight from the pinned token endpoint,
    /// which OpenID Connect Core section 3.1.3.7 accepts in place of one.
    fn checked_subject(&self, token: &str, expected: &Expected<'_>) -> Option<String> {
        let claims = id_token_claims(token)?;
        let text = |name: &str| claims.get(name).and_then(serde_json::Value::as_str);
        if text("iss") != Some(ISSUER) {
            return None;
        }
        let client = expected.client.id();
        let audience = claims.get("aud")?;
        let audience_names_client = match audience {
            serde_json::Value::String(single) => single == client,
            serde_json::Value::Array(several) => {
                several.iter().any(|entry| entry.as_str() == Some(client))
            }
            _ => false,
        };
        if !audience_names_client {
            return None;
        }
        if let Some(party) = claims.get("azp")
            && party.as_str() != Some(client)
        {
            return None;
        }
        let now = (self.clock)();
        let expires = claims.get("exp").and_then(serde_json::Value::as_u64)?;
        if expires.saturating_add(CLOCK_SKEW_SECONDS) <= now {
            return None;
        }
        let issued_at = claims.get("iat").and_then(serde_json::Value::as_u64)?;
        if issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
            return None;
        }
        match (expected.nonce, text("nonce")) {
            // An exchange's token carries the attempt's nonce.
            (Some(nonce), Some(said)) if bool::from(said.as_bytes().ct_eq(nonce.as_bytes())) => {}
            (Some(_), _) if expected.subject.is_none() => return None,
            // A refresh's token may carry none; if it carries one, it is the stored one.
            (Some(_), Some(_)) => return None,
            (Some(_) | None, None) => {}
            (None, Some(_)) => return None,
        }
        let subject = text("sub").filter(|subject| !subject.is_empty())?;
        if let Some(stored) = expected.subject
            && stored != subject
        {
            return None;
        }
        Some(subject.to_owned())
    }

    /// Reads a JSON answer.
    fn json(answer: &ServiceHttpAnswer) -> Option<serde_json::Value> {
        serde_json::from_slice(&answer.body).ok()
    }

    /// Whether a refused answer names an OAuth error.
    fn names_error(answer: &ServiceHttpAnswer) -> bool {
        Self::json(answer)
            .and_then(|value| value.get("error").map(serde_json::Value::is_string))
            .unwrap_or(false)
    }
}

/// The payload of a compact JWT, as a JSON object.
fn id_token_claims(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        serde_json::Value::Object(claims) => Some(claims),
        _ => None,
    }
}

/// A form body, encoded.
fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish().into_bytes()
}

/// A service that could not be reached or answered in a way this client cannot read.
fn upstream(what: &str, status: u16) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::UpstreamUnavailable,
        format!("the account service answered {what} with status {status}"),
    ))
}

impl AccountService for ManagedAccountService {
    fn exchange<'a>(&'a self, grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async move {
            let body = form(&[
                ("grant_type", "authorization_code"),
                ("code", grant.code()),
                ("redirect_uri", grant.redirect().uri()),
                ("client_id", grant.client().id()),
                ("code_verifier", grant.verifier()),
            ]);
            let answer = self.http.post_form(&self.url(TOKEN_PATH), &body).await?;
            if answer.status != 200 {
                if (400..500).contains(&answer.status) {
                    return Ok(Exchanged::Refused { leftover: None });
                }
                return Err(upstream("the exchange", answer.status));
            }
            let Some(value) = Self::json(&answer) else {
                return Ok(Exchanged::Refused { leftover: None });
            };
            let expected = Expected {
                client: grant.client(),
                subject: None,
                nonce: Some(grant.nonce()),
            };
            Ok(match self.issued(&value, &expected, None) {
                Ok(issued) => Exchanged::Issued(issued),
                Err(leftover) => Exchanged::Refused { leftover },
            })
        })
    }

    fn refresh<'a>(&'a self, stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        Box::pin(async move {
            let body = form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", stored.refresh_token.expose()),
                ("client_id", stored.client.id()),
            ]);
            let answer = self.http.post_form(&self.url(TOKEN_PATH), &body).await?;
            if answer.status != 200 {
                if (400..500).contains(&answer.status) && Self::names_error(&answer) {
                    return Ok(Refreshed::Ended);
                }
                return Err(upstream("the refresh", answer.status));
            }
            let Some(value) = Self::json(&answer) else {
                return Ok(Refreshed::Refused { leftover: None });
            };
            let expected = Expected {
                client: stored.client,
                subject: Some(&stored.subject),
                nonce: Some(&stored.nonce),
            };
            Ok(
                match self.issued(&value, &expected, Some(stored.scopes.as_slice())) {
                    Ok(issued) => Refreshed::Rotated(issued),
                    Err(leftover) => Refreshed::Refused { leftover },
                },
            )
        })
    }

    fn revoke<'a>(&'a self, refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async move {
            let body = form(&[
                ("token", refresh.expose()),
                ("token_type_hint", "refresh_token"),
                ("client_id", self.client.id()),
            ]);
            let answer = self.http.post_form(&self.url(REVOKE_PATH), &body).await?;
            if answer.status == 200 {
                Ok(())
            } else {
                Err(upstream("the revocation", answer.status))
            }
        })
    }

    fn identity<'a>(&'a self, access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        Box::pin(async move {
            let authorisation = format!("Bearer {}", access.expose());
            let answer = self
                .http
                .get(
                    &self.url(USERINFO_PATH),
                    &[("authorization", authorisation.as_str())],
                )
                .await?;
            if answer.status != 200 {
                return Err(upstream("the identity read", answer.status));
            }
            let value = Self::json(&answer).ok_or_else(|| upstream("the identity read", 200))?;
            let text = |name: &str| {
                value
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .filter(|text| !text.is_empty())
                    .map(str::to_owned)
            };
            let subject = text("sub").ok_or_else(|| upstream("the identity read", 200))?;
            Ok(AccountIdentity {
                subject,
                email: text("email"),
                name: text("name"),
            })
        })
    }

    fn usage<'a>(&'a self, access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async move {
            let authorisation = format!("Bearer {}", access.expose());
            let answer = self
                .http
                .get(
                    &self.url(USAGE_PATH),
                    &[("authorization", authorisation.as_str())],
                )
                .await?;
            if answer.status != 200 {
                return Err(upstream("the usage read", answer.status));
            }
            let value = Self::json(&answer).ok_or_else(|| upstream("the usage read", 200))?;
            // The service answers `{ok, data}` around the summary; a refusal is `ok: false`.
            if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                return Err(upstream("the usage read", 200));
            }
            let allowances = value
                .get("data")
                .and_then(|summary| summary.get("allowances"))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| upstream("the usage read", 200))?;
            let bytes = |entry: &serde_json::Value, name: &str| {
                entry
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| text.parse::<u64>().ok())
            };
            let lines = allowances
                .iter()
                .filter_map(|entry| {
                    let resource = match entry.get("resource")?.as_str()? {
                        "relay_bytes" => UsageResource::Relay,
                        "storage_bytes" => UsageResource::Storage,
                        "sync_bytes" => UsageResource::Sync,
                        _ => return None,
                    };
                    Some(UsageLine {
                        resource,
                        used_bytes: bytes(entry, "used")?,
                        allowance_bytes: bytes(entry, "allowance")?,
                        period: entry
                            .get("period")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                    })
                })
                .collect();
            Ok(AccountUsage { lines })
        })
    }
}

/* -------------------------------------------------------------------------- */
/* What is stored                                                              */
/* -------------------------------------------------------------------------- */

/// The grant as this device keeps it: one item, so a rotation writes one item and can never leave
/// half a grant behind.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredGrant {
    grant_id: String,
    revision: u64,
    client: Client,
    subject: String,
    email: Option<String>,
    name: Option<String>,
    nonce: String,
    refresh_token: RefreshToken,
    access_token: AccountToken,
    access_expires_at_ms: u64,
    scopes: Vec<String>,
}

impl fmt::Debug for StoredGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredGrant")
            .field("grant_id", &self.grant_id)
            .field("revision", &self.revision)
            .field("client", &self.client)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// What the item holds.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantDocument {
    grant_id: String,
    revision: u64,
    issuer: String,
    client_id: String,
    subject: String,
    email: Option<String>,
    name: Option<String>,
    nonce: String,
    refresh_token: String,
    access_token: String,
    access_expires_at_ms: u64,
    scopes: Vec<String>,
}

impl StoredGrant {
    /// A new grant from an exchange's tokens, with an identifier of its own.
    ///
    /// # Errors
    ///
    /// Returns an error when this device could not produce random bytes.
    pub fn new(issued: IssuedGrant, client: Client, nonce: &str, now_ms: u64) -> Result<Self> {
        Ok(Self {
            grant_id: fresh_secret()?,
            revision: 0,
            client,
            subject: issued.subject,
            email: None,
            name: None,
            nonce: nonce.to_owned(),
            refresh_token: issued.refresh_token,
            access_token: issued.access_token,
            access_expires_at_ms: now_ms
                .saturating_add(issued.expires_in_seconds.saturating_mul(1000)),
            scopes: issued.scopes,
        })
    }

    /// The same grant with a refresh's tokens.
    fn rotated(&self, issued: IssuedGrant, now_ms: u64) -> Self {
        Self {
            grant_id: self.grant_id.clone(),
            revision: self.revision.saturating_add(1),
            client: self.client,
            subject: self.subject.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            nonce: self.nonce.clone(),
            refresh_token: issued.refresh_token,
            access_token: issued.access_token,
            access_expires_at_ms: now_ms
                .saturating_add(issued.expires_in_seconds.saturating_mul(1000)),
            scopes: issued.scopes,
        }
    }

    /// The identifier fixed at sign-in, which a pending revocation names.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// How many times the grant has been rotated.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The client the grant was issued to.
    #[must_use]
    pub const fn client(&self) -> Client {
        self.client
    }

    /// The account the grant belongs to.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The account's address, once read.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// The name on the account, once read.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The nonce the sign-in's ID token carried.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The refresh token.
    #[must_use]
    pub const fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }

    /// The scopes granted.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether the grant carries `scope`.
    #[must_use]
    pub fn carries(&self, scope: &str) -> bool {
        self.scopes.iter().any(|held| held == scope)
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let document: GrantDocument = serde_json::from_slice(bytes).map_err(|error| {
            storage(&format!(
                "the stored sign-in could not be read: {}",
                super::json_fault(&error)
            ))
        })?;
        if document.issuer != ISSUER {
            return Err(storage("the stored sign-in names another issuer"));
        }
        let client = Client::from_id(&document.client_id)
            .ok_or_else(|| storage("the stored sign-in names a client this build does not know"))?;
        Ok(Self {
            grant_id: document.grant_id,
            revision: document.revision,
            client,
            subject: document.subject,
            email: document.email,
            name: document.name,
            nonce: document.nonce,
            refresh_token: RefreshToken::new(document.refresh_token)?,
            access_token: AccountToken::new(document.access_token)?,
            access_expires_at_ms: document.access_expires_at_ms,
            scopes: document.scopes,
        })
    }

    fn write(&self) -> Result<Vec<u8>> {
        let document = GrantDocument {
            grant_id: self.grant_id.clone(),
            revision: self.revision,
            issuer: ISSUER.to_owned(),
            client_id: self.client.id().to_owned(),
            subject: self.subject.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            nonce: self.nonce.clone(),
            refresh_token: self.refresh_token.expose().to_owned(),
            access_token: self.access_token.expose().to_owned(),
            access_expires_at_ms: self.access_expires_at_ms,
            scopes: self.scopes.clone(),
        };
        serde_json::to_vec(&document).map_err(|error| {
            storage(&format!(
                "the sign-in could not be written: {}",
                super::json_fault(&error)
            ))
        })
    }
}

/// One revocation the service has not acknowledged.
#[derive(Clone, PartialEq, Eq)]
struct PendingRevocation {
    grant_id: String,
    refresh_token: RefreshToken,
    queued_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingDocument {
    entries: Vec<PendingEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingEntry {
    grant_id: String,
    refresh_token: String,
    queued_at_ms: u64,
}

/// A store failure, which a caller reports as this device being unable to keep the sign-in.
fn storage(message: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::StorageUnavailable,
        message.to_owned(),
    ))
}

/// A request this client would not make.
fn local(message: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::InvalidArgument,
        message.to_owned(),
    ))
}

/* -------------------------------------------------------------------------- */
/* The signed-in account                                                       */
/* -------------------------------------------------------------------------- */

/// Where this device stands with an account.
#[derive(Clone, PartialEq, Eq)]
pub enum AccountStatus {
    /// No account is signed in on this device.
    SignedOut,
    /// An account is signed in.
    SignedIn {
        /// Its address, once read.
        email: Option<String>,
        /// The name on it, once read.
        name: Option<String>,
        /// The scopes the grant carries.
        scopes: Vec<String>,
    },
    /// The sign-in ended by itself: the service no longer honours the grant.
    Ended,
}

impl fmt::Debug for AccountStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedOut => formatter.write_str("SignedOut"),
            Self::Ended => formatter.write_str("Ended"),
            Self::SignedIn {
                email,
                name,
                scopes,
            } => formatter
                .debug_struct("SignedIn")
                .field("email", &email.as_ref().map(|_| "<present>"))
                .field("name", &name.as_ref().map(|_| "<present>"))
                .field("scopes", scopes)
                .finish(),
        }
    }
}

/// What reading the account's identity after a sign-in came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityRead {
    /// The address and name were read and kept.
    Read,
    /// The service could not be asked; the grant stands and the address is read later.
    Unread,
    /// The service named another account than the sign-in did, so the sign-in was undone.
    Disagreed,
}

/// What a sign-out did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignOut {
    /// Whether an account was signed in.
    pub was_signed_in: bool,
    /// Whether the service has acknowledged every revocation this device holds.
    pub service_told: bool,
}

/// The account signed in on this device: the grant in secure storage, one lock over every change
/// to it, and the token source every managed resource asks.
pub struct SignedInAccount {
    service: Arc<dyn AccountService>,
    store: Arc<dyn SecretStore>,
    client: Client,
    lock: tokio::sync::Mutex<()>,
    shared_lock: Option<PathBuf>,
    clock_ms: fn() -> u64,
    ended: AtomicBool,
    status: tokio::sync::watch::Sender<AccountStatus>,
}

impl fmt::Debug for SignedInAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedInAccount")
            .field("client", &self.client)
            .field("shared_lock", &self.shared_lock)
            .finish_non_exhaustive()
    }
}

/// The lock, held: the shared file first, so it is released before the in-process lock.
struct Held<'a> {
    file: Option<std::fs::File>,
    _mutex: tokio::sync::MutexGuard<'a, ()>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
}

/// The error a caller gets when no account is signed in.
fn signed_out() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::HostNotConfigured,
        "no account is signed in on this device".to_owned(),
    ))
}

/// The error a caller gets when the sign-in has ended.
fn ended() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::PermissionDenied,
        "the sign-in on this device has ended; sign in again".to_owned(),
    ))
}

impl SignedInAccount {
    /// The account kept in `store`, signed in through `service` as `client`.
    #[must_use]
    pub fn new(
        service: Arc<dyn AccountService>,
        store: Arc<dyn SecretStore>,
        client: Client,
    ) -> Self {
        let (status, _) = tokio::sync::watch::channel(AccountStatus::SignedOut);
        Self {
            service,
            store,
            client,
            lock: tokio::sync::Mutex::new(()),
            shared_lock: None,
            clock_ms: system_milliseconds,
            ended: AtomicBool::new(false),
            status,
        }
    }

    /// Also takes an advisory lock on `path` around every change, for another process on this
    /// machine that keeps the same account in the same store.
    #[must_use]
    pub fn with_shared_lock(mut self, path: PathBuf) -> Self {
        self.shared_lock = Some(path);
        self
    }

    /// Reads the time in milliseconds since the Unix epoch from `clock`, for a test.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock_ms = clock;
        self
    }

    /// The client this account signs in as.
    #[must_use]
    pub const fn client(&self) -> Client {
        self.client
    }

    /// Changes of status, as they happen.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<AccountStatus> {
        self.status.subscribe()
    }

    /// Where this device stands with an account now.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn status(&self) -> Result<AccountStatus> {
        Ok(match self.read_grant()? {
            Some(grant) => Self::summary(&grant),
            None if self.ended.load(Ordering::SeqCst) => AccountStatus::Ended,
            None => AccountStatus::SignedOut,
        })
    }

    fn summary(grant: &StoredGrant) -> AccountStatus {
        AccountStatus::SignedIn {
            email: grant.email.clone(),
            name: grant.name.clone(),
            scopes: grant.scopes.clone(),
        }
    }

    fn publish(&self) {
        if let Ok(status) = self.status() {
            self.status.send_replace(status);
        }
    }

    async fn hold(&self) -> Result<Held<'_>> {
        let mutex = self.lock.lock().await;
        let file = match &self.shared_lock {
            None => None,
            Some(path) => {
                let path = path.clone();
                let taken =
                    tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
                        let mut options = std::fs::OpenOptions::new();
                        options.create(true).truncate(false).write(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt as _;
                            options.mode(0o600);
                        }
                        let file = options.open(&path)?;
                        file.lock()?;
                        Ok(file)
                    })
                    .await
                    .map_err(|_| storage("the account lock could not be taken"))?
                    .map_err(|error| {
                        storage(&format!("the account lock could not be taken: {error}"))
                    })?;
                Some(taken)
            }
        };
        Ok(Held {
            file,
            _mutex: mutex,
        })
    }

    fn name(item: &str) -> Result<SecretName> {
        SecretName::new(item).map_err(|error| storage(&error.to_string()))
    }

    fn read_grant(&self) -> Result<Option<StoredGrant>> {
        let bytes = self
            .store
            .get(&Self::name(SESSION_ITEM)?)
            .map_err(|error| storage(&format!("the sign-in could not be read: {error}")))?;
        bytes
            .map(|bytes| StoredGrant::read(bytes.expose()))
            .transpose()
    }

    fn write_grant(&self, grant: &StoredGrant) -> Result<()> {
        self.store
            .set(&Self::name(SESSION_ITEM)?, &grant.write()?)
            .map_err(|error| storage(&format!("the sign-in could not be kept: {error}")))
    }

    fn delete_grant(&self) -> Result<()> {
        self.store
            .delete(&Self::name(SESSION_ITEM)?)
            .map_err(|error| storage(&format!("the sign-in could not be removed: {error}")))
    }

    fn read_pending(&self) -> Result<Vec<PendingRevocation>> {
        let Some(bytes) = self
            .store
            .get(&Self::name(PENDING_ITEM)?)
            .map_err(|error| {
                storage(&format!(
                    "the pending revocations could not be read: {error}"
                ))
            })?
        else {
            return Ok(Vec::new());
        };
        let document: PendingDocument =
            serde_json::from_slice(bytes.expose()).map_err(|error| {
                storage(&format!(
                    "the pending revocations could not be read: {}",
                    super::json_fault(&error)
                ))
            })?;
        document
            .entries
            .into_iter()
            .map(|entry| {
                Ok(PendingRevocation {
                    grant_id: entry.grant_id,
                    refresh_token: RefreshToken::new(entry.refresh_token)?,
                    queued_at_ms: entry.queued_at_ms,
                })
            })
            .collect()
    }

    fn write_pending(&self, entries: &[PendingRevocation]) -> Result<()> {
        let name = Self::name(PENDING_ITEM)?;
        if entries.is_empty() {
            return self.store.delete(&name).map_err(|error| {
                storage(&format!(
                    "the pending revocations could not be removed: {error}"
                ))
            });
        }
        let document = PendingDocument {
            entries: entries
                .iter()
                .map(|entry| PendingEntry {
                    grant_id: entry.grant_id.clone(),
                    refresh_token: entry.refresh_token.expose().to_owned(),
                    queued_at_ms: entry.queued_at_ms,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&document).map_err(|error| {
            storage(&format!(
                "the pending revocations could not be written: {}",
                super::json_fault(&error)
            ))
        })?;
        self.store.set(&name, &bytes).map_err(|error| {
            storage(&format!(
                "the pending revocations could not be kept: {error}"
            ))
        })
    }

    /// Adds a revocation to the list, dropping entries whose grants have ended by themselves and,
    /// past the limit, the oldest.
    fn queue(&self, grant_id: &str, refresh_token: RefreshToken) -> Result<()> {
        let now = (self.clock_ms)();
        let mut entries = self.read_pending()?;
        entries.retain(|entry| now.saturating_sub(entry.queued_at_ms) < PENDING_LIFETIME_MS);
        entries.push(PendingRevocation {
            grant_id: grant_id.to_owned(),
            refresh_token,
            queued_at_ms: now,
        });
        while entries.len() > PENDING_LIMIT {
            entries.remove(0);
        }
        self.write_pending(&entries)
    }

    /// Keeps a sign-in's tokens, replacing any grant this device held, whose revocation is queued.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot keep the grant; nothing is kept then.
    pub async fn commit(&self, issued: IssuedGrant, nonce: &str) -> Result<()> {
        let replaced = {
            let _held = self.hold().await?;
            let grant = StoredGrant::new(issued, self.client, nonce, (self.clock_ms)())?;
            let replaced = self.read_grant()?;
            if let Some(old) = &replaced {
                self.queue(&old.grant_id, old.refresh_token.clone())?;
            }
            self.write_grant(&grant)?;
            self.ended.store(false, Ordering::SeqCst);
            self.publish();
            replaced.is_some()
        };
        if replaced {
            let _ = self.send_pending().await;
        }
        Ok(())
    }

    /// Reads the signed-in account's address and name from the service and keeps them.
    ///
    /// A subject other than the sign-in's means the two answers disagree about who signed in, so
    /// the sign-in is undone and revoked. A service that cannot be asked leaves the grant as it is.
    ///
    /// # Errors
    ///
    /// Returns an error when no account is signed in or the store cannot be read.
    pub async fn complete_identity(&self) -> Result<IdentityRead> {
        let access = self.token("openid").await?;
        // The token and the grant it belongs to are taken together under the lock: a grant that
        // another sign-in, here or in another process, put in its place meanwhile is not the one
        // this read is about, and is left for its own read.
        let grant = {
            let _held = self.hold().await?;
            match self.read_grant()? {
                None => return Err(signed_out()),
                Some(grant) if grant.access_token.expose() == access.expose() => grant,
                Some(_) => return Ok(IdentityRead::Unread),
            }
        };
        match self.service.identity(&access).await {
            Ok(identity) if identity.subject != grant.subject => {
                // Only the grant the read was for is undone, and only while it is still here.
                if self
                    .remove_grant(Some(&grant.grant_id))
                    .await?
                    .was_signed_in
                {
                    Ok(IdentityRead::Disagreed)
                } else {
                    Ok(IdentityRead::Unread)
                }
            }
            Ok(identity) => {
                let _held = self.hold().await?;
                if let Some(mut current) = self.read_grant()?
                    && current.grant_id == grant.grant_id
                {
                    current.email = identity.email;
                    current.name = identity.name;
                    self.write_grant(&current)?;
                    self.publish();
                }
                Ok(IdentityRead::Read)
            }
            Err(_) => Ok(IdentityRead::Unread),
        }
    }

    /// Signs this device out: the grant is removed at once and its revocation queued, then every
    /// queued revocation is sent.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be changed; the device is then still signed in.
    pub async fn sign_out(&self) -> Result<SignOut> {
        self.remove_grant(None).await
    }

    /// Removes the grant, or only the grant `only` names while it is still the one here, queues
    /// its revocation, then sends every queued revocation.
    async fn remove_grant(&self, only: Option<&str>) -> Result<SignOut> {
        let was_signed_in = {
            let _held = self.hold().await?;
            match self.read_grant()? {
                Some(grant) if only.is_none_or(|id| id == grant.grant_id) => {
                    self.queue(&grant.grant_id, grant.refresh_token.clone())?;
                    self.delete_grant()?;
                    self.ended.store(false, Ordering::SeqCst);
                    self.publish();
                    true
                }
                Some(_) | None => false,
            }
        };
        let remaining = self.send_pending().await?;
        Ok(SignOut {
            was_signed_in,
            service_told: remaining == 0,
        })
    }

    /// Settles what an earlier run left: a grant whose own revocation is queued was being signed
    /// out when that run stopped, so it is removed; any other grant is kept. Then every queued
    /// revocation is sent. Returns how many the service has still not acknowledged.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or changed.
    pub async fn recover(&self) -> Result<usize> {
        {
            let _held = self.hold().await?;
            let now = (self.clock_ms)();
            let mut entries = self.read_pending()?;
            let before = entries.len();
            entries.retain(|entry| now.saturating_sub(entry.queued_at_ms) < PENDING_LIFETIME_MS);
            if entries.len() != before {
                self.write_pending(&entries)?;
            }
            if let Some(grant) = self.read_grant()?
                && entries.iter().any(|entry| entry.grant_id == grant.grant_id)
            {
                self.delete_grant()?;
            }
            self.publish();
        }
        self.send_pending().await
    }

    /// Sends every queued revocation and removes each one the service acknowledges. Returns how
    /// many are still waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or changed.
    pub async fn send_pending(&self) -> Result<usize> {
        let entries = {
            let _held = self.hold().await?;
            self.read_pending()?
        };
        for entry in entries {
            if self.service.revoke(&entry.refresh_token).await.is_ok() {
                let _held = self.hold().await?;
                let mut current = self.read_pending()?;
                current.retain(|held| {
                    !(held.grant_id == entry.grant_id && held.refresh_token == entry.refresh_token)
                });
                self.write_pending(&current)?;
            }
        }
        let _held = self.hold().await?;
        Ok(self.read_pending()?.len())
    }

    /// What the account has used, or none when this sign-in was not granted usage.
    ///
    /// # Errors
    ///
    /// Returns an error when no account is signed in, or the usage could not be read.
    pub async fn usage(&self) -> Result<Option<AccountUsage>> {
        match self.read_grant()? {
            None => Err(signed_out()),
            Some(grant) if !grant.carries(USAGE_SCOPE) => Ok(None),
            Some(_) => {
                let access = self.token(USAGE_SCOPE).await?;
                Ok(Some(self.service.usage(&access).await?))
            }
        }
    }
}

/// The refusal for a scope this sign-in does not carry.
fn not_granted(scope: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::PermissionDenied,
        format!("this sign-in was not granted the {scope} scope"),
    ))
}

impl AccountTokenSource for SignedInAccount {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            let queued = {
                let _held = self.hold().await?;
                let Some(stored) = self.read_grant()? else {
                    return Err(if self.ended.load(Ordering::SeqCst) {
                        ended()
                    } else {
                        signed_out()
                    });
                };
                if !stored.carries(scope) {
                    return Err(not_granted(scope));
                }
                let now = (self.clock_ms)();
                if stored.access_expires_at_ms > now.saturating_add(ACCESS_MARGIN_MS) {
                    return Ok(stored.access_token.clone());
                }
                match self.service.refresh(&stored).await? {
                    Refreshed::Rotated(issued) => {
                        let rotated = stored.rotated(issued, now);
                        self.write_grant(&rotated)?;
                        self.publish();
                        // A refresh may narrow the grant, which is kept as issued; its token goes
                        // out only for a scope it still carries.
                        if !rotated.carries(scope) {
                            return Err(not_granted(scope));
                        }
                        return Ok(rotated.access_token.clone());
                    }
                    Refreshed::Ended => {
                        self.delete_grant()?;
                        self.ended.store(true, Ordering::SeqCst);
                        self.publish();
                        false
                    }
                    Refreshed::Refused { leftover } => {
                        let queued = leftover.is_some();
                        if let Some(leftover) = leftover {
                            self.queue(&stored.grant_id, leftover)?;
                        }
                        self.delete_grant()?;
                        self.ended.store(true, Ordering::SeqCst);
                        self.publish();
                        queued
                    }
                }
            };
            if queued {
                let _ = self.send_pending().await;
            }
            Err(ended())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued(refresh: &str) -> IssuedGrant {
        IssuedGrant {
            access_token: AccountToken::new(format!(
                "{}-access",
                crate::services::rendering::NEVER_RENDERED
            ))
            .expect("a token"),
            expires_in_seconds: 600,
            refresh_token: RefreshToken::new(refresh).expect("a token"),
            scopes: vec!["openid".to_owned(), USAGE_SCOPE.to_owned()],
            subject: "an-account".to_owned(),
        }
    }

    #[test]
    fn a_rendering_of_a_request_a_grant_or_a_token_carries_none_of_them() {
        use crate::services::rendering::{NEVER_RENDERED, renders_only};

        renders_only(
            &AccountToken::new(NEVER_RENDERED).expect("a token"),
            "AccountToken(<notprinted>)",
        );
        renders_only(
            &RefreshToken::new(NEVER_RENDERED).expect("a token"),
            "RefreshToken(<notprinted>)",
        );

        let mut request =
            AuthorisationRequest::new(Client::Mobile, Redirect::AppLink).expect("a request");
        request.state = NEVER_RENDERED.to_owned();
        request.verifier = NEVER_RENDERED.to_owned();
        request.nonce = NEVER_RENDERED.to_owned();
        let attempt = request.attempt();
        renders_only(
            &request,
            &format!(
                "AuthorisationRequest{{client:Mobile,redirect:AppLink,attempt:AttemptId({attempt}),..}}"
            ),
        );

        let grant = AuthorisationGrant {
            client: Client::Desktop,
            redirect: Redirect::Loopback,
            attempt,
            code: NEVER_RENDERED.to_owned(),
            verifier: NEVER_RENDERED.to_owned(),
            nonce: NEVER_RENDERED.to_owned(),
        };
        renders_only(
            &grant,
            &format!(
                "AuthorisationGrant{{client:Desktop,redirect:Loopback,attempt:AttemptId({attempt}),..}}"
            ),
        );

        let tokens = issued(NEVER_RENDERED);
        renders_only(
            &tokens,
            "IssuedGrant{expires_in_seconds:600,scopes:[\"openid\",\"billing.read\"],..}",
        );

        let mut stored =
            StoredGrant::new(issued(NEVER_RENDERED), Client::Mobile, NEVER_RENDERED, 0)
                .expect("a grant");
        stored.grant_id = "a-grant".to_owned();
        stored.email = Some(NEVER_RENDERED.to_owned());
        stored.subject = NEVER_RENDERED.to_owned();
        renders_only(
            &stored,
            "StoredGrant{grant_id:\"a-grant\",revision:0,client:Mobile,scopes:[\"openid\",\"billing.read\"],..}",
        );

        renders_only(
            &AccountIdentity {
                subject: NEVER_RENDERED.to_owned(),
                email: Some(NEVER_RENDERED.to_owned()),
                name: None,
            },
            "AccountIdentity{email:Some(\"<present>\"),name:None,..}",
        );
    }

    #[test]
    fn a_stored_grant_reads_back_as_it_was_written() {
        let mut grant = StoredGrant::new(issued("a-refresh"), Client::Desktop, "a-nonce", 1_000)
            .expect("a grant");
        grant.email = Some("sam@example.com".to_owned());
        let read = StoredGrant::read(&grant.write().expect("bytes")).expect("read back");
        assert_eq!(read, grant);
        assert_eq!(read.access_expires_at_ms, 601_000);
    }

    #[test]
    fn a_stored_grant_for_another_issuer_is_not_read() {
        let grant =
            StoredGrant::new(issued("a-refresh"), Client::Desktop, "a-nonce", 0).expect("a grant");
        let mut document: serde_json::Value =
            serde_json::from_slice(&grant.write().expect("bytes")).expect("json");
        document["issuer"] = serde_json::json!("https://evil.example/auth");
        let error = StoredGrant::read(&serde_json::to_vec(&document).expect("bytes"))
            .expect_err("another issuer");
        assert_eq!(error.code(), ErrorCode::StorageUnavailable);
    }
}
