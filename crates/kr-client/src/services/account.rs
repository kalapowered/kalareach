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
//! * [`AuthorisationRequest`] builds the one address the browser is handed, asking for the scopes
//!   its caller names.
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
//! # An answer a gateway lost
//!
//! A gateway in front of the service answers 502 or 504 when the service's answer did not reach it,
//! which it can do after the service spent a code or rotated a refresh token. So such an answer to
//! an exchange or a refresh, naming no OAuth error of the service's, is `OUTCOME_UNKNOWN`, and
//! nothing sends the request again. A refresh whose answer was lost keeps the stored grant as it
//! was: its next refresh rotates the token when the first did not, and ends the sign-in when it did,
//! because the token it presents was spent and the new one was only in the lost answer. Nothing
//! short of signing in again recovers that. A revocation, an identity read and
//! a usage read are safe to send again, so the same answer to one of them stays transient.
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
use kr_protocol::error::ErrorCode;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use url::Url;

use super::json::Unreadable;
use super::{ServiceFuture, ServiceHttpAnswer};
use crate::error::{ClientError, Result};
use crate::shown::Shown;

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

/// The scope an account token needs to write what the account keeps as backup: its archives, and
/// the recovery bundle at its locator.
pub const BACKUP_WRITE_SCOPE: &str = "backup.write";

/// The scope an account token needs to read the recovery bundle and nothing else, which is what a
/// device restoring from a recovery kit asks for.
pub const BACKUP_RESTORE_SCOPE: &str = "backup.restore";

/// The scopes every authorisation asks for, whatever resources it asks for beside them.
///
/// The identity claims, which the ID token an exchange is checked by carries and the identity read
/// returns, and a refresh token that survives a restart, which the kept grant is renewed with.
pub const IDENTITY_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

/// The scopes this build knows by name beside the ones an application sign-in asks for: the ones
/// an authorisation for one purpose asks for.
const PURPOSE_SCOPES: [&str; 2] = [BACKUP_WRITE_SCOPE, BACKUP_RESTORE_SCOPE];

/// A scope this build knows, as this build's own name for it: one an application sign-in or an
/// authorisation for one purpose asks for.
///
/// A scope is text a service or a stored file supplied, so a diagnostic names one only through
/// this, and one this build does not know is not repeated: a summary counts it, and a refusal says
/// that it is one.
#[must_use]
pub(crate) fn known_scope(scope: &str) -> Option<&'static str> {
    REQUESTED_SCOPES
        .iter()
        .chain(&PURPOSE_SCOPES)
        .copied()
        .find(|known| *known == scope)
}

/// What a set of stored scopes says: the ones this build knows, by name and in the order they
/// were stored, and how many others there are.
///
/// Every rendering of stored scopes uses this, the command line's as well. The scopes themselves
/// are kept whole for what they are for: a request presents them and a check reads them.
#[must_use]
pub fn scope_summary(scopes: &[String]) -> Shown {
    let (known, unknown) = scope_names(scopes);
    scope_words(&known, unknown)
}

/// The stored scopes this build knows, by their names and in the order they were stored, and how
/// many others there are: [`scope_summary`] as values, for a document that lists them.
#[must_use]
pub fn scope_names(scopes: &[String]) -> (Vec<&'static str>, usize) {
    let mut known = Vec::new();
    let mut unknown = 0_usize;
    for scope in scopes {
        match known_scope(scope) {
            Some(name) if !known.contains(&name) => known.push(name),
            Some(_) => {}
            None => unknown += 1,
        }
    }
    (known, unknown)
}

/// What [`scope_names`] says, in the words [`scope_summary`] uses.
#[must_use]
pub fn scope_words(known: &[&'static str], unknown: usize) -> Shown {
    let named = Shown::joined(known.iter().copied().map(Shown::said), ", ");
    match (known.is_empty(), unknown) {
        (true, 0) => Shown::said("no scopes"),
        (false, 0) => named,
        (true, count) => crate::shown!("{} scope(s) this build does not know", count),
        (false, count) => {
            crate::shown!("{} and {} scope(s) this build does not know", named, count)
        }
    }
}

/// Every scope an application sign-in asks for, in the order the request states them.
///
/// The [`IDENTITY_SCOPES`], then the member's lease fetch, the call this device holds and the
/// answers it asks for, and usage. Not [`BACKUP_WRITE_SCOPE`]: nothing writes an account's backup
/// storage until the person turns recovery-enabled backup on, and that is a second authorisation
/// of its own, [`AuthorisationRequest::with_recovery_backup`], so no sign-in carries a capability
/// it has no use for.
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

/// Every scope the application's sign-in asks for once the person has turned recovery-enabled
/// backup on: the [`REQUESTED_SCOPES`], in their order, and [`BACKUP_WRITE_SCOPE`] after them.
///
/// It asks for the application's own scopes as well because the grant it leads to replaces the one
/// the device holds, and the application goes on using what that one carried.
pub const RECOVERY_BACKUP_SCOPES: [&str; 9] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    LEASE_SCOPE,
    super::voice::VOICE_SCOPE,
    "reasoning",
    USAGE_SCOPE,
    BACKUP_WRITE_SCOPE,
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
fn bearer_value(value: &str, what: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(local(crate::shown!("{} is not empty", what)));
    }
    if value.len() > 8192 {
        return Err(local(crate::shown!("{} is at most 8192 bytes", what)));
    }
    if !value
        .bytes()
        .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ')
    {
        return Err(local(crate::shown!(
            "{} is printable ASCII, as an authorisation header value is",
            what
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
        ClientError::refusal(
            ErrorCode::ResourceUnavailable,
            crate::shown!(
                "this device could not produce random bytes: {}",
                Shown::crypto(&error)
            ),
        )
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
            ClientError::refusal(
                ErrorCode::ResourceUnavailable,
                crate::shown!(
                    "this device could not produce random bytes: {}",
                    Shown::crypto(&error)
                ),
            )
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

impl crate::shown::Said for AttemptId {
    fn said(&self) -> crate::shown::Shown {
        crate::shown::Shown::hexadecimal(self.0)
    }
}

crate::display_as_said!(AttemptId);

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
///
/// It asks for the scopes its caller names and no others. The application's own sign-in asks for
/// [`REQUESTED_SCOPES`], and once the person has turned recovery-enabled backup on for
/// [`RECOVERY_BACKUP_SCOPES`]; an authorisation made for one purpose asks for the
/// [`IDENTITY_SCOPES`] and that purpose's resources, so the token that comes of it reaches what it
/// was asked for and nothing else.
pub struct AuthorisationRequest {
    client: Client,
    redirect: Redirect,
    attempt: AttemptId,
    scopes: Vec<String>,
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
    /// The application's sign-in for `client`, answered on `redirect`, asking for
    /// [`REQUESTED_SCOPES`].
    ///
    /// # Errors
    ///
    /// Returns an error when `redirect` is not registered for `client`, or when this device could
    /// not produce random bytes.
    pub fn new(client: Client, redirect: Redirect) -> Result<Self> {
        Self::asking(client, redirect, &REQUESTED_SCOPES[IDENTITY_SCOPES.len()..])
    }

    /// The application's sign-in once the person has turned recovery-enabled backup on, for
    /// `client`, answered on `redirect`, asking for [`RECOVERY_BACKUP_SCOPES`].
    ///
    /// It is the second authorisation that turning backup on takes, and the sign-in the
    /// application makes again while backup stays on. Until then no sign-in asks for
    /// `backup.write`, because nothing on the device writes an account's backup storage: the
    /// storage and manifest clients present that scope's token, and a source whose grant does not
    /// carry it refuses the token, so they send nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_recovery_backup(client: Client, redirect: Redirect) -> Result<Self> {
        Self::asking(
            client,
            redirect,
            &RECOVERY_BACKUP_SCOPES[IDENTITY_SCOPES.len()..],
        )
    }

    /// A request for `client`, answered on `redirect`, asking for the [`IDENTITY_SCOPES`] and the
    /// resources `resources` names, and for nothing else.
    ///
    /// A caller names what its one purpose reads: a device restoring from a recovery kit asks for
    /// [`BACKUP_RESTORE_SCOPE`] alone. The identity scopes are asked for whatever the resources are,
    /// because an exchange is checked by its ID token and a kept grant is renewed with its refresh
    /// token.
    ///
    /// # Errors
    ///
    /// Returns an error when `redirect` is not registered for `client`, when a resource is not a
    /// scope a request can carry or names a scope already asked for, or when this device could not
    /// produce random bytes.
    pub fn asking(client: Client, redirect: Redirect, resources: &[&str]) -> Result<Self> {
        if !client.owns(redirect) {
            return Err(local(crate::shown!(
                "{} is not a redirect registered for {}",
                redirect.uri(),
                client.id()
            )));
        }
        let mut scopes: Vec<String> = IDENTITY_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect();
        for resource in resources {
            // RFC 6749 section 3.3: a scope is printable ASCII other than a space, a quotation
            // mark and a backslash, because the request carries the list separated by spaces.
            let carried = !resource.is_empty()
                && resource
                    .bytes()
                    .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e));
            if !carried {
                return Err(local(
                    "a scope is printable ASCII with no space, quotation mark or backslash",
                ));
            }
            if scopes.iter().any(|asked| asked == resource) {
                return Err(local("an authorisation asks for each scope once"));
            }
            scopes.push((*resource).to_owned());
        }
        Ok(Self {
            client,
            redirect,
            attempt: AttemptId::fresh()?,
            scopes,
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
        let Ok(mut url) = Url::parse(ACCOUNT_ORIGIN).and_then(|origin| origin.join(AUTHORIZE_PATH))
        else {
            unreachable!("the pinned origin and path parse");
        };
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client.id())
            .append_pair("redirect_uri", self.redirect.uri())
            .append_pair("scope", &self.scopes.join(" "))
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

    /// The scopes this request asks for, in the order it states them.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
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
        let scopes: Shown = scope_summary(&self.scopes);
        formatter
            .debug_struct("IssuedGrant")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("scopes", &scopes)
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
#[derive(Clone, PartialEq, Eq)]
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

crate::debug_fields!(UsageLine {
    resource,
    used_bytes,
    allowance_bytes
});

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
            .field("origin", &Shown::address(&self.origin))
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

    /// Reads a JSON answer, refusing one that names a member twice ([`super::json::read`]).
    fn json(answer: &ServiceHttpAnswer) -> std::result::Result<serde_json::Value, Unreadable> {
        super::json::read(&answer.body)
    }

    /// Whether an answer is a gateway's that lost the service's own: a 502 or 504 naming no OAuth
    /// error, which a gateway in front of the service gives when the service's answer did not reach
    /// it, and can give after the service acted on the request.
    fn lost_by_a_gateway(answer: &ServiceHttpAnswer) -> bool {
        matches!(answer.status, 502 | 504) && !Self::names_error(answer)
    }

    /// Whether a refused answer names an OAuth error.
    fn names_error(answer: &ServiceHttpAnswer) -> bool {
        Self::json(answer)
            .ok()
            .and_then(|value| value.get("error").map(serde_json::Value::is_string))
            .unwrap_or(false)
    }
}

/// The payload of a compact JWT, as a JSON object.
///
/// Read like an answer, because it is one: claims that name a member twice could name two
/// subjects, and a check made against one of them would not cover the other.
fn id_token_claims(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    super::json::read(&bytes).ok()
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
fn upstream(what: &'static str, status: u16) -> ClientError {
    ClientError::refusal(
        ErrorCode::UpstreamUnavailable,
        crate::shown!(
            "the account service answered {} with status {}",
            what,
            status
        ),
    )
}

/// A request that may have run, whose answer a gateway lost.
///
/// The service may have spent the code, or rotated the refresh token, before the gateway gave up.
/// A code is spent once, and a rotated refresh token presented again revokes its family, so sending
/// the request again is not safe, and what became of it is unknown.
fn lost(what: &'static str, status: u16) -> ClientError {
    ClientError::refusal(
        ErrorCode::OutcomeUnknown,
        crate::shown!(
            "a gateway answered {} with status {}, so whether the account service carried it out \
             is unknown",
            what,
            status
        ),
    )
}

/// A success this client cannot read, with what was wrong with it and where, and nothing it held.
fn unreadable(what: &'static str, fault: Unreadable) -> ClientError {
    ClientError::refusal(
        ErrorCode::UpstreamUnavailable,
        crate::shown!(
            "the account service answered {} with status 200, and {}",
            what,
            fault
        ),
    )
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
                if Self::lost_by_a_gateway(&answer) {
                    return Err(lost("the exchange", answer.status));
                }
                return Err(upstream("the exchange", answer.status));
            }
            let Ok(value) = Self::json(&answer) else {
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
                if Self::lost_by_a_gateway(&answer) {
                    return Err(lost("the refresh", answer.status));
                }
                return Err(upstream("the refresh", answer.status));
            }
            let Ok(value) = Self::json(&answer) else {
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
            let value =
                Self::json(&answer).map_err(|fault| unreadable("the identity read", fault))?;
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
            let value = Self::json(&answer).map_err(|fault| unreadable("the usage read", fault))?;
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
        let scopes: Shown = scope_summary(&self.scopes);
        formatter
            .debug_struct("StoredGrant")
            // The grant's identifier is drawn like a secret and read back from the file, so it is
            // counted rather than repeated.
            .field("grant_id_bytes", &self.grant_id.len())
            .field("revision", &self.revision)
            .field("client", &self.client)
            .field("scopes", &scopes)
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

    /// Reads a stored grant.
    ///
    /// # Errors
    ///
    /// Returns a storage failure when the document is not one this build wrote.
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let document: GrantDocument = serde_json::from_slice(bytes).map_err(|error| {
            storage(crate::shown!(
                "the stored sign-in could not be read: {}",
                Shown::json(&error)
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
            storage(crate::shown!(
                "the sign-in could not be written: {}",
                Shown::json(&error)
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
fn storage(message: impl Into<Shown>) -> ClientError {
    ClientError::refusal(ErrorCode::StorageUnavailable, message.into())
}

/// A request this client would not make.
fn local(message: impl Into<Shown>) -> ClientError {
    ClientError::refusal(ErrorCode::InvalidArgument, message.into())
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
        /// Which grant this is: the same for the grant's whole life, across its refreshes, and
        /// another for any later sign-in, even of the same account. It names the grant without
        /// holding anything that could be presented.
        generation: String,
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
                ..
            } => {
                let scopes: Shown = scope_summary(scopes);
                formatter
                    .debug_struct("SignedIn")
                    .field("email", &email.as_ref().map(|_| "<present>"))
                    .field("name", &name.as_ref().map(|_| "<present>"))
                    .field("scopes", &scopes)
                    .finish_non_exhaustive()
            }
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
            .field("shared_lock", &self.shared_lock.as_deref().map(Shown::root))
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
    ClientError::refusal(
        ErrorCode::HostNotConfigured,
        crate::shown::Shown::said("no account is signed in on this device"),
    )
}

/// The error a caller gets when the sign-in has ended.
fn ended() -> ClientError {
    ClientError::refusal(
        ErrorCode::PermissionDenied,
        crate::shown::Shown::said("the sign-in on this device has ended; sign in again"),
    )
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
            generation: generation(grant),
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
                        storage(crate::shown!(
                            "the account lock could not be taken: {}",
                            Shown::io(&error)
                        ))
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
        SecretName::new(item).map_err(|error| storage(Shown::crypto(&error)))
    }

    fn read_grant(&self) -> Result<Option<StoredGrant>> {
        let bytes = self
            .store
            .get(&Self::name(SESSION_ITEM)?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the sign-in could not be read: {}",
                    Shown::crypto(&error)
                ))
            })?;
        bytes
            .map(|bytes| StoredGrant::read(bytes.expose()))
            .transpose()
    }

    fn write_grant(&self, grant: &StoredGrant) -> Result<()> {
        self.store
            .set(&Self::name(SESSION_ITEM)?, &grant.write()?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the sign-in could not be kept: {}",
                    Shown::crypto(&error)
                ))
            })
    }

    fn delete_grant(&self) -> Result<()> {
        self.store
            .delete(&Self::name(SESSION_ITEM)?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the sign-in could not be removed: {}",
                    Shown::crypto(&error)
                ))
            })
    }

    fn read_pending(&self) -> Result<Vec<PendingRevocation>> {
        let Some(bytes) = self
            .store
            .get(&Self::name(PENDING_ITEM)?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the pending revocations could not be read: {}",
                    Shown::crypto(&error)
                ))
            })?
        else {
            return Ok(Vec::new());
        };
        let document: PendingDocument =
            serde_json::from_slice(bytes.expose()).map_err(|error| {
                storage(crate::shown!(
                    "the pending revocations could not be read: {}",
                    Shown::json(&error)
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
                storage(crate::shown!(
                    "the pending revocations could not be removed: {}",
                    Shown::crypto(&error)
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
            storage(crate::shown!(
                "the pending revocations could not be written: {}",
                Shown::json(&error)
            ))
        })?;
        self.store.set(&name, &bytes).map_err(|error| {
            storage(crate::shown!(
                "the pending revocations could not be kept: {}",
                Shown::crypto(&error)
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
    pub async fn usage(&self) -> Result<Option<GrantUsage>> {
        match self.read_grant()? {
            None => Err(signed_out()),
            Some(grant) if !grant.carries(USAGE_SCOPE) => Ok(None),
            Some(_) => {
                let access = self.token(USAGE_SCOPE).await?;
                // The figures are the grant's whose token asks for them, taken together with the
                // token under the lock; a grant that replaced it meanwhile gets its own read.
                let generation = {
                    let _held = self.hold().await?;
                    match self.read_grant()? {
                        Some(current) if current.access_token.expose() == access.expose() => {
                            generation(&current)
                        }
                        Some(_) | None => {
                            return Err(ClientError::refusal(
                                ErrorCode::OutcomeUnknown,
                                crate::shown::Shown::said(
                                    "the sign-in changed while its usage was being read",
                                ),
                            ));
                        }
                    }
                };
                let usage = self.service.usage(&access).await?;
                Ok(Some(GrantUsage { generation, usage }))
            }
        }
    }
}

/// Usage, with the generation of the grant it was read with.
#[derive(Clone, PartialEq, Eq)]
pub struct GrantUsage {
    /// The grant the figures belong to, as [`AccountStatus::SignedIn`] names it.
    pub generation: String,
    /// The figures.
    pub usage: AccountUsage,
}

/// A grant's generation: a digest of its identifier, which names the grant and can be presented
/// nowhere.
fn generation(grant: &StoredGrant) -> String {
    let digest = sha2::Sha256::digest(grant.grant_id.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The refusal for a scope this sign-in does not carry, naming it when this build knows it.
fn not_granted(scope: &str) -> ClientError {
    ClientError::refusal(
        ErrorCode::PermissionDenied,
        match known_scope(scope) {
            Some(name) => crate::shown!("this sign-in was not granted the {} scope", name),
            None => Shown::said("this sign-in was not granted a scope this build does not know"),
        },
    )
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
            "IssuedGrant{expires_in_seconds:600,scopes:\"openid,billing.read\",..}",
        );

        let mut stored =
            StoredGrant::new(issued(NEVER_RENDERED), Client::Mobile, NEVER_RENDERED, 0)
                .expect("a grant");
        stored.grant_id = "a-grant".to_owned();
        stored.email = Some(NEVER_RENDERED.to_owned());
        stored.subject = NEVER_RENDERED.to_owned();
        renders_only(
            &stored,
            "StoredGrant{grant_id_bytes:7,revision:0,client:Mobile,scopes:\"openid,billing.read\",..}",
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

    /* ---------------------------------------------------------------------- */
    /* What an authorisation asks for                                          */
    /* ---------------------------------------------------------------------- */

    /// The one `scope` parameter an authorisation's address carries.
    fn asked(request: &AuthorisationRequest) -> Vec<String> {
        Url::parse(&request.url())
            .expect("an address")
            .query_pairs()
            .filter(|(name, _)| name == "scope")
            .map(|(_, value)| value.into_owned())
            .collect()
    }

    /// An authorisation asks for the identity scopes and exactly the resources its caller names,
    /// and the application's own sign-in asks for what it always has: the identity scopes first,
    /// then its resources, and not `backup.write`, which only turning recovery-enabled backup on
    /// asks for.
    #[test]
    fn an_authorisation_asks_for_the_identity_scopes_and_the_resources_its_caller_names() {
        let restore = AuthorisationRequest::asking(
            Client::Desktop,
            Redirect::Loopback,
            &[BACKUP_RESTORE_SCOPE],
        )
        .expect("a request");
        assert_eq!(
            asked(&restore),
            ["openid profile email offline_access backup.restore"]
        );
        assert_eq!(
            restore.scopes(),
            [
                "openid",
                "profile",
                "email",
                "offline_access",
                BACKUP_RESTORE_SCOPE
            ]
        );

        let identity = AuthorisationRequest::asking(Client::Mobile, Redirect::AppLink, &[])
            .expect("a request");
        assert_eq!(identity.scopes(), IDENTITY_SCOPES);

        let application =
            AuthorisationRequest::new(Client::Desktop, Redirect::Loopback).expect("a request");
        assert_eq!(asked(&application), [REQUESTED_SCOPES.join(" ")]);
        assert_eq!(application.scopes(), REQUESTED_SCOPES);
        assert_eq!(REQUESTED_SCOPES[..IDENTITY_SCOPES.len()], IDENTITY_SCOPES);
        assert!(!REQUESTED_SCOPES.contains(&BACKUP_WRITE_SCOPE));
        assert!(!REQUESTED_SCOPES.contains(&BACKUP_RESTORE_SCOPE));
    }

    /// A scope a request cannot carry, and a scope asked for twice, are refused before an
    /// address is built; so is a redirect the client did not register, as it always was.
    #[test]
    fn a_scope_an_authorisation_cannot_ask_for_is_refused() {
        for resources in [
            &[""][..],
            &["backup restore"],
            &["backup\"restore"],
            &["backup\\restore"],
            &["backup.réstore"],
            &["openid"],
            &[BACKUP_RESTORE_SCOPE, BACKUP_RESTORE_SCOPE],
        ] {
            let error =
                AuthorisationRequest::asking(Client::Desktop, Redirect::Loopback, resources)
                    .expect_err("a scope no request asks for");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{resources:?}");
        }
        assert!(
            AuthorisationRequest::asking(
                Client::Desktop,
                Redirect::AppLink,
                &[BACKUP_RESTORE_SCOPE]
            )
            .is_err()
        );
    }

    /// The token endpoint, answering every exchange with one answer.
    #[derive(Debug)]
    struct TokenEndpoint(serde_json::Value);

    impl AccountHttp for TokenEndpoint {
        fn post_form<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            let body = serde_json::to_vec(&self.0).expect("an answer");
            Box::pin(async move { Ok(ServiceHttpAnswer { status: 200, body }) })
        }

        fn get<'a>(
            &'a self,
            _url: &'a str,
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            Box::pin(async move { panic!("nothing here reads with a token") })
        }
    }

    /// An unsigned compact token with these claims; its signature is not what is checked.
    fn id_token(claims: &serde_json::Value) -> String {
        let encode = |value: &serde_json::Value| {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                serde_json::to_vec(value).expect("json"),
            )
        };
        format!(
            "{}.{}.signature",
            encode(&serde_json::json!({ "alg": "RS256", "typ": "JWT" })),
            encode(claims)
        )
    }

    /// A device restoring from a recovery kit authorises for the restore alone: the browser's
    /// answer, the exchange and the kept grant are the ones every sign-in goes through, and the
    /// token that comes of it is handed out for `backup.restore` and refused for every resource
    /// scope the application's own sign-in would have carried and for writing a bundle. The
    /// identity scopes are the grant's own, so they are not among them.
    #[tokio::test]
    async fn a_restore_authorisation_holds_a_token_for_its_scope_and_for_no_other() {
        let request = AuthorisationRequest::asking(
            Client::Desktop,
            Redirect::Loopback,
            &[BACKUP_RESTORE_SCOPE],
        )
        .expect("a request");
        let state = request.state.clone();
        let mut pending = PendingAuthorisation::new(request);
        let mut answer = Url::parse(Redirect::Loopback.uri()).expect("the redirect");
        answer
            .query_pairs_mut()
            .append_pair("code", "a-code")
            .append_pair("state", &state)
            .append_pair("iss", ISSUER);
        let Answer::Granted(grant) = pending.answer(answer.as_str(), Carrier::Terminal) else {
            panic!("the answer grants a code");
        };

        let now = system_seconds();
        let endpoint = Arc::new(TokenEndpoint(serde_json::json!({
            "access_token": "a-restore-token",
            "token_type": "Bearer",
            "expires_in": 600,
            "refresh_token": "a-refresh-token",
            "scope": "openid profile email offline_access backup.restore",
            "id_token": id_token(&serde_json::json!({
                "iss": ISSUER,
                "sub": "an-account",
                "aud": Client::Desktop.id(),
                "nonce": grant.nonce(),
                "iat": now - 5,
                "exp": now + 3600,
            })),
        })));
        let service = Arc::new(ManagedAccountService::new(
            endpoint as Arc<dyn AccountHttp>,
            Client::Desktop,
        ));
        let Exchanged::Issued(issued) = service.exchange(&grant).await.expect("an answer") else {
            panic!("the exchange is issued");
        };
        let account = SignedInAccount::new(
            service,
            Arc::new(kr_crypto::store::MemoryStore::new()),
            Client::Desktop,
        );
        account
            .commit(issued, grant.nonce())
            .await
            .expect("the grant is kept");

        assert_eq!(
            account
                .token(BACKUP_RESTORE_SCOPE)
                .await
                .expect("a token for the restore")
                .expose(),
            "a-restore-token"
        );
        let resources = &REQUESTED_SCOPES[IDENTITY_SCOPES.len()..];
        assert_eq!(
            resources.len(),
            4,
            "every resource the application asks for"
        );
        for other in resources.iter().chain([&BACKUP_WRITE_SCOPE]) {
            let refused = account.token(other).await.expect_err("not this grant's");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{other}");
        }
    }

    /* ---------------------------------------------------------------------- */
    /* What a diagnostic says of a scope                                       */
    /* ---------------------------------------------------------------------- */

    /// The scopes an authorisation for one purpose asks for are named as the application's own
    /// are: a restore grant's scopes, and the refusal for a scope a grant was not given, say
    /// `backup.restore` and `backup.write` by name. A scope this build does not know is counted in
    /// a summary, said to be one in a refusal, and never repeated; so is a resource an
    /// authorisation cannot ask for.
    #[test]
    fn the_backup_scopes_are_named_and_a_scope_this_build_does_not_know_is_never_repeated() {
        use crate::shown::marker::{
            MARKER, NEUTRAL, assert_unmarked, debug_renderings, failure_renderings,
        };

        // The neutral control: a restore grant's own scopes, every one of them named.
        let restore: Vec<String> = IDENTITY_SCOPES
            .iter()
            .chain([&BACKUP_RESTORE_SCOPE])
            .map(|scope| (*scope).to_owned())
            .collect();
        assert_eq!(
            scope_summary(&restore).as_str(),
            "openid, profile, email, offline_access, backup.restore"
        );

        // The negative control: the stored scopes hold the marker, which the summary counts.
        let stored: Vec<String> = [
            MARKER,
            "openid",
            BACKUP_RESTORE_SCOPE,
            BACKUP_WRITE_SCOPE,
            "openid",
        ]
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
        assert!(stored.iter().any(|scope| scope == MARKER));
        assert_eq!(
            scope_names(&stored),
            (vec!["openid", BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE], 1)
        );
        let summary = scope_summary(&stored).into_string();
        assert_eq!(
            summary,
            "openid, backup.restore, backup.write and 1 scope(s) this build does not know"
        );
        assert_unmarked("stored scopes", &[summary]);
        let mut grant =
            StoredGrant::new(issued("a-refresh"), Client::Desktop, "a-nonce", 0).expect("a grant");
        grant.scopes = stored;
        assert_unmarked("a stored grant", &debug_renderings(&grant));

        for (scope, said) in [
            (
                BACKUP_WRITE_SCOPE,
                "PERMISSION_DENIED: this sign-in was not granted the backup.write scope",
            ),
            (
                BACKUP_RESTORE_SCOPE,
                "PERMISSION_DENIED: this sign-in was not granted the backup.restore scope",
            ),
            (
                MARKER,
                "PERMISSION_DENIED: this sign-in was not granted a scope this build does not know",
            ),
            (
                NEUTRAL,
                "PERMISSION_DENIED: this sign-in was not granted a scope this build does not know",
            ),
        ] {
            let refused = not_granted(scope);
            assert_eq!(refused.to_string(), said);
            assert_unmarked(scope, &failure_renderings(refused));
        }

        for resource in [
            format!("{MARKER} {MARKER}"),
            format!("{MARKER}\"{MARKER}"),
            format!("{MARKER}\\{MARKER}"),
            format!("{MARKER}\u{e9}"),
        ] {
            let refused = AuthorisationRequest::asking(
                Client::Desktop,
                Redirect::Loopback,
                &[resource.as_str()],
            )
            .expect_err("not a scope a request carries");
            assert_eq!(
                refused.to_string(),
                "INVALID_ARGUMENT: a scope is printable ASCII with no space, quotation mark or \
                 backslash"
            );
            assert_unmarked(&resource, &failure_renderings(refused));
        }
        let twice =
            AuthorisationRequest::asking(Client::Desktop, Redirect::Loopback, &[MARKER, MARKER])
                .expect_err("one scope asked for twice");
        assert_unmarked("a scope asked for twice", &failure_renderings(twice));
        // A scope this build does not know is still one a request carries, and the request's
        // rendering holds none of what it asks for.
        let request = AuthorisationRequest::asking(Client::Desktop, Redirect::Loopback, &[MARKER])
            .expect("a scope a request carries");
        assert_eq!(request.scopes().last().map(String::as_str), Some(MARKER));
        assert_unmarked("an authorisation request", &debug_renderings(&request));
    }

    /// Commits the grant an exchange of `request`'s answer issues, with the scopes `granted` names.
    async fn signed_in_through(request: AuthorisationRequest, granted: &str) -> SignedInAccount {
        let state = request.state.clone();
        let client = request.client();
        let redirect = request.redirect();
        let mut pending = PendingAuthorisation::new(request);
        let mut answer = Url::parse(redirect.uri()).expect("the redirect");
        answer
            .query_pairs_mut()
            .append_pair("code", "a-code")
            .append_pair("state", &state)
            .append_pair("iss", ISSUER);
        let Answer::Granted(grant) = pending.answer(answer.as_str(), Carrier::Terminal) else {
            panic!("the answer grants a code");
        };
        let now = system_seconds();
        let endpoint = Arc::new(TokenEndpoint(serde_json::json!({
            "access_token": "an-access-token",
            "token_type": "Bearer",
            "expires_in": 600,
            "refresh_token": "a-refresh-token",
            "scope": granted,
            "id_token": id_token(&serde_json::json!({
                "iss": ISSUER,
                "sub": "an-account",
                "aud": client.id(),
                "nonce": grant.nonce(),
                "iat": now - 5,
                "exp": now + 3600,
            })),
        })));
        let service = Arc::new(ManagedAccountService::new(
            endpoint as Arc<dyn AccountHttp>,
            client,
        ));
        let Exchanged::Issued(issued) = service.exchange(&grant).await.expect("an answer") else {
            panic!("the exchange is issued");
        };
        let account = SignedInAccount::new(
            service,
            Arc::new(kr_crypto::store::MemoryStore::new()),
            client,
        );
        account
            .commit(issued, grant.nonce())
            .await
            .expect("the grant is kept");
        account
    }

    /// No sign-in carries `backup.write` until the person turns recovery-enabled backup on: the
    /// application's own sign-in asks for everything it uses and not that, so its token is refused
    /// for backup storage. Turning backup on is a second authorisation, which asks for what the
    /// application's sign-in asks for and `backup.write` after it, because the grant it leads to
    /// replaces the one the device holds; its token is handed out for backup storage and for every
    /// resource the application uses.
    #[tokio::test]
    async fn backup_write_is_asked_for_only_once_recovery_enabled_backup_is_turned_on() {
        let application =
            AuthorisationRequest::new(Client::Desktop, Redirect::Loopback).expect("a request");
        assert!(
            !application
                .scopes()
                .iter()
                .any(|scope| scope == BACKUP_WRITE_SCOPE)
        );

        let backup =
            AuthorisationRequest::with_recovery_backup(Client::Desktop, Redirect::Loopback)
                .expect("a request");
        assert_eq!(backup.scopes(), RECOVERY_BACKUP_SCOPES);
        assert_eq!(
            RECOVERY_BACKUP_SCOPES[..REQUESTED_SCOPES.len()],
            REQUESTED_SCOPES,
            "everything the application's sign-in asks for, first"
        );
        assert_eq!(RECOVERY_BACKUP_SCOPES.last(), Some(&BACKUP_WRITE_SCOPE));
        assert_eq!(asked(&backup), [RECOVERY_BACKUP_SCOPES.join(" ")]);
        assert!(
            AuthorisationRequest::with_recovery_backup(Client::Mobile, Redirect::Loopback).is_err(),
            "a redirect the client did not register"
        );

        let before = signed_in_through(application, &REQUESTED_SCOPES.join(" ")).await;
        let refused = before
            .token(BACKUP_WRITE_SCOPE)
            .await
            .expect_err("the application's own sign-in");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);

        let after = signed_in_through(backup, &RECOVERY_BACKUP_SCOPES.join(" ")).await;
        for scope in RECOVERY_BACKUP_SCOPES {
            after.token(scope).await.expect(scope);
        }
    }

    /// A gateway in front of the account service, answering every request with one status and a
    /// body of its own.
    #[derive(Debug)]
    struct Gateway {
        status: u16,
        body: &'static [u8],
    }

    impl Gateway {
        fn answer(&self) -> ServiceFuture<'_, ServiceHttpAnswer> {
            let answer = ServiceHttpAnswer {
                status: self.status,
                body: self.body.to_vec(),
            };
            Box::pin(async move { Ok(answer) })
        }
    }

    impl AccountHttp for Gateway {
        fn post_form<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.answer()
        }

        fn get<'a>(
            &'a self,
            _url: &'a str,
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.answer()
        }
    }

    /// The account service behind a gateway that answers with `status` and `body`.
    fn behind(status: u16, body: &'static [u8]) -> ManagedAccountService {
        ManagedAccountService::new(
            Arc::new(Gateway { status, body }) as Arc<dyn AccountHttp>,
            Client::Desktop,
        )
    }

    /// A code the browser handed back for a fresh request, ready to exchange.
    fn granted() -> AuthorisationGrant {
        let request =
            AuthorisationRequest::new(Client::Desktop, Redirect::Loopback).expect("a request");
        let state = request.state.clone();
        let mut pending = PendingAuthorisation::new(request);
        let mut answer = Url::parse(Redirect::Loopback.uri()).expect("the redirect");
        answer
            .query_pairs_mut()
            .append_pair("code", "a-code")
            .append_pair("state", &state)
            .append_pair("iss", ISSUER);
        let Answer::Granted(grant) = pending.answer(answer.as_str(), Carrier::Terminal) else {
            panic!("the answer grants a code");
        };
        grant
    }

    /// KR-REQ-23.57: a gateway's 502 or 504 with no OAuth error of the service's can follow the
    /// service spending the code or rotating the refresh token, so an exchange or a refresh it
    /// answers has an unknown outcome, which nothing sends again. The controls: the service's own
    /// error on a 502 keeps its reading, and a revocation, an identity read and a usage read, which
    /// are safe to send again, stay transient on a 503 and on a gateway's 502 or 504 alike.
    #[tokio::test]
    async fn kr_req_23_57_a_gateway_that_lost_an_exchange_or_a_refresh_leaves_its_outcome_unknown()
    {
        let grant = granted();
        let stored =
            StoredGrant::new(issued("a-refresh"), Client::Desktop, "a-nonce", 0).expect("a grant");
        let page: &'static [u8] = b"<html><body>Bad Gateway</body></html>";
        for status in [502, 504] {
            let service = behind(status, page);
            let exchanged = service
                .exchange(&grant)
                .await
                .expect_err("no exchange was read");
            let refreshed = service
                .refresh(&stored)
                .await
                .expect_err("no refresh was read");
            for error in [exchanged, refreshed] {
                assert_eq!(error.code(), ErrorCode::OutcomeUnknown, "{status}: {error}");
                let decision = error.decision(crate::retry::RequestClass::IdempotentRead);
                assert_eq!(
                    decision.recovery,
                    crate::retry::Recovery::QueryOutcome,
                    "{status}"
                );
            }
        }

        // The service's own error on a 502 is read as the service's.
        let service = behind(
            502,
            br#"{"error":"server_error","error_description":"Not now."}"#,
        );
        for error in [
            service.exchange(&grant).await.expect_err("refused"),
            service.refresh(&stored).await.expect_err("refused"),
        ] {
            assert_eq!(error.code(), ErrorCode::UpstreamUnavailable, "{error}");
        }

        // A call that is safe to send again stays transient, whoever gave up.
        let access = AccountToken::new("an-access-token").expect("a token");
        for status in [502, 503, 504] {
            let service = behind(status, page);
            for error in [
                service
                    .revoke(stored.refresh_token())
                    .await
                    .expect_err("not revoked"),
                service.identity(&access).await.expect_err("not read"),
                service.usage(&access).await.expect_err("not read"),
            ] {
                assert_eq!(
                    error.code(),
                    ErrorCode::UpstreamUnavailable,
                    "{status}: {error}"
                );
            }
        }
    }
}
