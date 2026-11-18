//! The login a proxy asks for, what this host knows about it, and the rule that keeps the login on
//! the host's own paths.
//!
//! A proxy named by its origin can hold a login ([`ProxyCredential`]): a user name and a password
//! that go to the proxy by HTTP Basic, in a `CONNECT` and in nothing else. The login carries a
//! verdict. It is clear when the host starts, and it is set once the proxy has refused the login
//! this host sent, or has asked for a sign-in method this host does not support. After the verdict
//! no request is admitted with the login ([`admit`]), so the proxy is asked for the same refused
//! login at most once for each request that was already connecting.
//!
//! Nothing here prints the login: the user and the password are held as secrets, and every
//! `Debug` of a type that holds one says it holds a login and nothing more.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kr_crypto::secret::SecretVec;
use reqwest::header::HeaderValue;
use tokio::sync::{Notify, watch};
use url::Url;

use crate::config::ProxyUrl;

/// The most targets a suspicion keeps; the oldest is dropped for a ninth.
const MAX_SUSPECTED: usize = 8;

/// The longest user name or password, in bytes.
pub const MAX_CREDENTIAL_PART_BYTES: usize = 255;

/// Why a proxy's login does not take a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyLoginKind {
    /// The proxy asks for a sign-in and this host holds no login for it.
    Needed,
    /// The proxy refused the login this host sent.
    Refused,
    /// The proxy asks for a sign-in method this host does not send.
    Unsupported,
    /// The address is plain `http`, and a login goes only to `https` addresses.
    ClearTextTarget,
}

impl ProxyLoginKind {
    /// The words for this kind as a clause: lower case and no full stop, so that it follows ": " in
    /// a composed error. None of them names an address or repeats anything the proxy wrote.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::Needed => "the proxy requires a sign-in, and this host holds no login for it",
            Self::Refused => {
                "the proxy refused the login this host holds, so this host starts no new request \
                 through the proxy until it restarts"
            }
            Self::Unsupported => {
                "the proxy asks for a sign-in method this host does not support; this host can \
                 send only a user name and password (Basic)"
            }
            Self::ClearTextTarget => {
                "this address is plain http, and while this host holds a login for the proxy, a \
                 request through it goes only to https addresses"
            }
        }
    }

    /// The words for this kind as a sentence that stands alone.
    #[must_use]
    pub fn sentence(self) -> String {
        let clause = self.clause();
        let mut first = clause.chars();
        let head = first.next().map(|letter| letter.to_ascii_uppercase());
        head.into_iter().chain(first).chain(['.']).collect()
    }

    /// Whether a request that meets this kind is not sent again until the host restarts.
    ///
    /// `Needed` is not: no login was refused, so the retry cadence of a request that the proxy
    /// turned away stays what it is for any other failure.
    #[must_use]
    pub const fn stops_until_restart(self) -> bool {
        !matches!(self, Self::Needed)
    }
}

/// A request that was not sent, or a connection that was not made, because of the proxy's login.
///
/// It prints the kind's sentence and nothing else, and its `Debug` holds no endpoint and no login.
pub struct ProxyLoginFailure {
    kind: ProxyLoginKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ProxyLoginFailure {
    /// A failure of `kind`.
    #[must_use]
    pub fn new(kind: ProxyLoginKind) -> Self {
        Self { kind, source: None }
    }

    /// A failure of `kind` that followed `source`, which stays on the error's chain.
    #[must_use]
    pub fn following(kind: ProxyLoginKind, source: Box<dyn Error + Send + Sync>) -> Self {
        Self {
            kind,
            source: Some(source),
        }
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> ProxyLoginKind {
        self.kind
    }
}

impl fmt::Debug for ProxyLoginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProxyLoginFailure({:?})", self.kind)
    }
}

impl fmt::Display for ProxyLoginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.kind.sentence())
    }
}

impl Error for ProxyLoginFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// The kind a [`ProxyLoginFailure`] on `error`'s chain carries, if one is there. It is found by the
/// type, never by the words.
#[must_use]
pub fn proxy_login_kind(error: &(dyn Error + 'static)) -> Option<ProxyLoginKind> {
    let mut current = Some(error);
    while let Some(link) = current {
        if let Some(failure) = link.downcast_ref::<ProxyLoginFailure>() {
            return Some(failure.kind);
        }
        current = link.source();
    }
    None
}

/// Why a login stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopKind {
    /// The proxy refused the login this host sent.
    Refused,
    /// The proxy asked for a sign-in method this host does not send.
    Unsupported,
}

impl StopKind {
    /// The kind a request meets once the verdict is set.
    #[must_use]
    pub const fn as_login_kind(self) -> ProxyLoginKind {
        match self {
            Self::Refused => ProxyLoginKind::Refused,
            Self::Unsupported => ProxyLoginKind::Unsupported,
        }
    }
}

/// The place a request went to: a host and a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The host, an IPv6 literal without its brackets.
    pub host: String,
    /// The port.
    pub port: u16,
}

impl Target {
    /// The host and port a URL names, with the scheme's default port when it names none.
    #[must_use]
    pub fn of(url: &Url) -> Option<Self> {
        let host = match url.host()? {
            url::Host::Domain(name) => name.to_owned(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
        Some(Self {
            host,
            port: url.port_or_known_default()?,
        })
    }
}

/// The targets whose failure may be a proxy's refusal that this host could not read as one, and
/// the wake-up a reader of them waits on.
///
/// The wake-up is a signal, not a count: a reader takes a queued target before it waits, so a
/// target that was queued while an earlier one was being checked is not left until another failure
/// comes.
#[derive(Debug, Default)]
pub struct Suspicion {
    targets: Mutex<VecDeque<Target>>,
    wake: Notify,
}

impl Suspicion {
    /// Queues `target` unless it is queued already, drops the oldest past eight, and wakes the
    /// reader.
    pub fn suspect(&self, target: Target) {
        {
            let mut targets = self.targets.lock().unwrap_or_else(PoisonError::into_inner);
            if !targets.contains(&target) {
                if targets.len() == MAX_SUSPECTED {
                    targets.pop_front();
                }
                targets.push_back(target);
            }
        }
        self.wake.notify_one();
    }

    /// Takes the oldest queued target, without waiting.
    #[must_use]
    pub fn take(&self) -> Option<Target> {
        self.targets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    /// Waits for a queued target and takes it. A target that is queued already is taken at once.
    pub async fn wait_take(&self) -> Target {
        loop {
            if let Some(target) = self.take() {
                return target;
            }
            self.wake.notified().await;
        }
    }
}

struct Inner {
    user: SecretVec,
    password: SecretVec,
    stop: watch::Sender<Option<StopKind>>,
    suspicion: Suspicion,
}

/// The login a proxy asks for, and the verdict on it.
///
/// Every clone shares one verdict: a start makes a new credential, and a refusal that any clone
/// meets stops every client that holds one. There is no `Display`, no `Serialize` and no accessor
/// that returns the password; the login leaves this type only as the `Proxy-Authorization` value
/// of [`ProxyCredential::authorization`].
#[derive(Clone)]
pub struct ProxyCredential(Arc<Inner>);

/// Why a credential line is not a login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The line is not UTF-8.
    #[error("the login is not UTF-8 text")]
    NotText,
    /// The line has no colon between the user name and the password.
    #[error("the login is not a user name and a password separated by a colon")]
    NoColon,
    /// The user name is empty.
    #[error("the login has no user name")]
    NoUser,
    /// The user name or the password holds a control character.
    #[error("the login holds a control character")]
    ControlCharacter,
    /// The user name or the password is longer than 255 bytes.
    #[error("the login's user name or password is longer than 255 bytes")]
    TooLong,
}

impl ProxyCredential {
    /// A login of `user` and `password`, with a clear verdict.
    ///
    /// # Errors
    ///
    /// Returns why the pair is not a login: an empty user name, a control character, or a part
    /// longer than 255 bytes.
    pub fn new(user: SecretVec, password: SecretVec) -> Result<Self, CredentialError> {
        let text = |part: &SecretVec| std::str::from_utf8(part.expose()).map(str::to_owned);
        let (Ok(user_text), Ok(password_text)) = (text(&user), text(&password)) else {
            return Err(CredentialError::NotText);
        };
        if user.is_empty() {
            return Err(CredentialError::NoUser);
        }
        if user.len() > MAX_CREDENTIAL_PART_BYTES || password.len() > MAX_CREDENTIAL_PART_BYTES {
            return Err(CredentialError::TooLong);
        }
        if user_text.chars().any(char::is_control) || password_text.chars().any(char::is_control) {
            return Err(CredentialError::ControlCharacter);
        }
        let (stop, _) = watch::channel(None);
        Ok(Self(Arc::new(Inner {
            user,
            password,
            stop,
            suspicion: Suspicion::default(),
        })))
    }

    /// Reads a login from a line of `user:password`.
    ///
    /// The line splits at the first colon, so the user name has none and the password may. Spaces
    /// are kept, one trailing line ending (`\n` or `\r\n`) is removed and nothing else is trimmed.
    /// An empty password is allowed.
    ///
    /// # Errors
    ///
    /// As [`ProxyCredential::new`], and when the line is not UTF-8 or has no colon.
    pub fn parse_line(line: &SecretVec) -> Result<Self, CredentialError> {
        let bytes = line.expose();
        let bytes = bytes
            .strip_suffix(b"\r\n")
            .or_else(|| bytes.strip_suffix(b"\n"))
            .unwrap_or(bytes);
        if std::str::from_utf8(bytes).is_err() {
            return Err(CredentialError::NotText);
        }
        let colon = bytes
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(CredentialError::NoColon)?;
        Self::new(
            SecretVec::new(bytes[..colon].to_vec()),
            SecretVec::new(bytes[colon + 1..].to_vec()),
        )
    }

    /// The `Proxy-Authorization` value: `Basic` and the base64 of `user:password`, marked
    /// sensitive.
    #[must_use]
    pub fn authorization(&self) -> HeaderValue {
        let mut pair = Vec::with_capacity(self.0.user.len() + 1 + self.0.password.len());
        pair.extend_from_slice(self.0.user.expose());
        pair.push(b':');
        pair.extend_from_slice(self.0.password.expose());
        let mut value = String::from("Basic ");
        STANDARD.encode_string(&pair, &mut value);
        let mut header = HeaderValue::from_str(&value).expect("base64 is a header value");
        header.set_sensitive(true);
        header
    }

    /// Records that the proxy refused the login this host sent, or asked for a sign-in method this
    /// host does not send.
    ///
    /// `Unsupported` is sticky: once it is the reason it stays, whatever arrives after it.
    pub fn refuse(&self, kind: StopKind) {
        self.0.stop.send_modify(|stop| {
            if *stop != Some(StopKind::Unsupported) {
                *stop = Some(kind);
            }
        });
    }

    /// Why the login stopped, when it has.
    #[must_use]
    pub fn stopped(&self) -> Option<StopKind> {
        *self.0.stop.borrow()
    }

    /// Whether the proxy asked for a sign-in method this host does not send.
    #[must_use]
    pub fn unsupported(&self) -> bool {
        self.stopped() == Some(StopKind::Unsupported)
    }

    /// Waits until the verdict is set, and returns at once when it is set already: a verdict that
    /// was set before the wait began is seen.
    pub async fn stopped_wait(&self) -> StopKind {
        let mut stop = self.0.stop.subscribe();
        let outcome = stop
            .wait_for(Option::is_some)
            .await
            .map(|stopped| stopped.unwrap_or(StopKind::Refused));
        match outcome {
            Ok(kind) => kind,
            // The sender is held by this very value, so it cannot be gone while this waits.
            Err(_) => std::future::pending().await,
        }
    }

    /// The targets whose failure may be a refusal this host could not read.
    #[must_use]
    pub fn suspicion(&self) -> &Suspicion {
        &self.0.suspicion
    }

    /// A handle on this login's verdict that holds no login: a part of the host that has to stop
    /// when the verdict is set, and has no use for the login, holds this.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        Verdict(Arc::clone(&self.0))
    }
}

/// The verdict on a login, shared with the credential that made it, and nothing else of it.
#[derive(Clone)]
pub struct Verdict(Arc<Inner>);

impl Verdict {
    /// Why the login stopped, when it has.
    #[must_use]
    pub fn stopped(&self) -> Option<StopKind> {
        *self.0.stop.borrow()
    }

    /// Waits until the verdict is set, and returns at once when it is set already.
    pub async fn stopped_wait(&self) -> StopKind {
        ProxyCredential(Arc::clone(&self.0)).stopped_wait().await
    }
}

impl fmt::Debug for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Verdict")
    }
}

impl PartialEq for ProxyCredential {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (kr_crypto::constant_time_eq(self.0.user.expose(), other.0.user.expose())
                & kr_crypto::constant_time_eq(self.0.password.expose(), other.0.password.expose()))
    }
}

impl Eq for ProxyCredential {}

impl fmt::Debug for ProxyCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyCredential(held)")
    }
}

/// Whether a request to `url` may be sent through `proxy`.
///
/// A proxy that holds a login carries `CONNECT` tunnels and nothing else, so the login travels
/// only in a `CONNECT`, and a tunnel that is reused sends it no more. A request is refused once the
/// verdict is set, and a request to a plain `http` address is refused whatever the verdict is.
///
/// # Errors
///
/// Returns the kind that says why the request is not admitted.
pub fn admit(proxy: Option<&ProxyUrl>, url: &Url) -> Result<(), ProxyLoginKind> {
    let Some(login) = proxy.and_then(ProxyUrl::login) else {
        return Ok(());
    };
    if let Some(stop) = login.stopped() {
        return Err(stop.as_login_kind());
    }
    if url.scheme() == "http" {
        return Err(ProxyLoginKind::ClearTextTarget);
    }
    Ok(())
}

/// hyper-util's words for a `CONNECT` the proxy answered `407`, which it says of that status only.
///
/// The layer matches it by equality on each link of the error chain, so a change of the library's
/// words fails the case that reads a real chain instead of silently missing a refusal.
pub const TUNNEL_PROXY_AUTH_REQUIRED: &str = "tunnel error: proxy authorization required";
/// hyper-util's words for every other refusal of a `CONNECT`, an `HTTP/1.0 407` among them.
pub const TUNNEL_UNSUCCESSFUL: &str = "tunnel error: unsuccessful";

type BoxError = Box<dyn Error + Send + Sync>;

/// Whether a link of `error`'s chain says exactly `text`.
fn chain_holds(error: &(dyn Error + 'static), text: &str) -> bool {
    let mut current = Some(error);
    while let Some(link) = current {
        if link.to_string() == text {
            return true;
        }
        current = link.source();
    }
    false
}

/// A client's connector layer for a proxy: it stops a connect once the verdict is set, and reads a
/// `407` to the `CONNECT` that carried the login.
///
/// It is generic over the request type because the library's own cannot be named outside it. It is
/// installed whether or not a login is held, so a proxy that asks for a login that nothing holds
/// is `Needed`.
#[derive(Clone)]
pub struct ProxyLoginLayer {
    login: Option<ProxyCredential>,
}

impl ProxyLoginLayer {
    /// The layer for a proxy whose login is `login`, if it holds one.
    #[must_use]
    pub const fn new(login: Option<ProxyCredential>) -> Self {
        Self { login }
    }
}

impl<S> tower_layer::Layer<S> for ProxyLoginLayer {
    type Service = ProxyLoginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyLoginService {
            inner,
            login: self.login.clone(),
        }
    }
}

/// The service [`ProxyLoginLayer`] makes.
#[derive(Clone)]
pub struct ProxyLoginService<S> {
    inner: S,
    login: Option<ProxyCredential>,
}

impl<S, R> tower_service::Service<R> for ProxyLoginService<S>
where
    S: tower_service::Service<R, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    R: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        // The clone is the one that was not made ready, so the one that was is used for the call.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let login = self.login.clone();
        Box::pin(async move {
            let stopped = |kind: StopKind| -> BoxError {
                Box::new(ProxyLoginFailure::new(kind.as_login_kind()))
            };
            if let Some(kind) = login.as_ref().and_then(ProxyCredential::stopped) {
                return Err(stopped(kind));
            }
            let connecting = inner.call(request);
            let outcome = match &login {
                // The verdict is polled first, so one set before a poll cannot lose to a connect
                // that finishes in that poll, and the inner future is dropped when it wins.
                Some(login) => tokio::select! {
                    biased;
                    kind = login.stopped_wait() => return Err(stopped(kind)),
                    outcome = connecting => outcome,
                },
                None => connecting.await,
            };
            outcome.map_err(|error| {
                if !chain_holds(error.as_ref(), TUNNEL_PROXY_AUTH_REQUIRED) {
                    return error;
                }
                let kind = if let Some(login) = &login {
                    login.refuse(StopKind::Refused);
                    ProxyLoginKind::Refused
                } else {
                    ProxyLoginKind::Needed
                };
                Box::new(ProxyLoginFailure::following(kind, error))
            })
        })
    }
}

/// Points a client at `proxy`: every request goes through it, a login it holds travels in the
/// `CONNECT` as one sensitive `Proxy-Authorization` value built from the raw bytes, and the
/// connector layer reads the proxy's answer. No login is in any URL, so the library's `Debug` of
/// the proxy prints none.
///
/// # Errors
///
/// Returns the library's error when the proxy's address is not one it takes.
pub fn proxied(
    builder: reqwest::ClientBuilder,
    proxy: &ProxyUrl,
) -> Result<reqwest::ClientBuilder, reqwest::Error> {
    let mut selected = reqwest::Proxy::all(proxy.as_url().clone())?;
    if let Some(login) = proxy.login() {
        selected = selected.custom_http_auth(login.authorization());
    }
    Ok(builder
        .proxy(selected)
        .connector_layer(ProxyLoginLayer::new(proxy.login().cloned())))
}

/// Notes a failed send through `proxy` to `url`: a `CONNECT` that failed with the library's words
/// for any refusal but `407` may have been an `HTTP/1.0 407`, which the library does not name, so
/// the target is queued for the one bounded re-check through the host's writer. A proxy with no
/// login has nothing to check.
pub fn note_failure(proxy: &ProxyUrl, url: &Url, error: &(dyn Error + 'static)) {
    let Some(login) = proxy.login() else {
        return;
    };
    if chain_holds(error, TUNNEL_UNSUCCESSFUL)
        && let Some(target) = Target::of(url)
    {
        login.suspicion().suspect(target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> SecretVec {
        SecretVec::new(text.as_bytes().to_vec())
    }

    /// A login is read from `user:password`: the first colon splits it, spaces stay, one line
    /// ending goes, and a user name with a non-ASCII letter or an empty password is a login.
    ///
    /// Covers KR-REQ-10.02.
    #[test]
    fn a_credential_line_is_read_at_its_first_colon() {
        let login = ProxyCredential::parse_line(&line("us\u{e9}r:p:a ss\r\n")).expect("a login");
        assert_eq!(
            login.authorization().as_bytes(),
            format!("Basic {}", STANDARD.encode("us\u{e9}r:p:a ss")).as_bytes()
        );
        assert!(ProxyCredential::parse_line(&line("user:")).is_ok());
        for (bad, why) in [
            ("nocolon", CredentialError::NoColon),
            (":password", CredentialError::NoUser),
            ("us\ter:p", CredentialError::ControlCharacter),
            ("user:pa\u{7}ss", CredentialError::ControlCharacter),
            (
                &format!("user:{}", "x".repeat(256)),
                CredentialError::TooLong,
            ),
        ] {
            assert_eq!(ProxyCredential::parse_line(&line(bad)).err(), Some(why));
        }
        assert_eq!(
            ProxyCredential::parse_line(&SecretVec::new(vec![b'u', b':', 0xff])).err(),
            Some(CredentialError::NotText)
        );
    }

    /// `Unsupported` outranks `Refused` whatever order they arrive in, every clone shares the
    /// verdict, and a verdict set before a wait begins is seen by the wait.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_verdict_is_shared_and_unsupported_is_sticky() {
        let login = ProxyCredential::parse_line(&line("u:p")).expect("a login");
        let clone = login.clone();
        assert_eq!(clone.stopped(), None);
        clone.refuse(StopKind::Unsupported);
        login.refuse(StopKind::Refused);
        assert_eq!(login.stopped(), Some(StopKind::Unsupported));
        assert!(clone.unsupported());
        assert_eq!(login.stopped_wait().await, StopKind::Unsupported);
        let other = ProxyCredential::parse_line(&line("u:p")).expect("a login");
        assert_eq!(
            other.stopped(),
            None,
            "a new credential has a verdict of its own"
        );
        assert_eq!(
            login, other,
            "equal logins compare equal whatever their verdicts"
        );
    }

    /// The suspicion keeps a queued target until it is taken, once, whatever the wake-ups, and
    /// drops the oldest past eight.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_suspicion_hands_out_every_queued_target() {
        let suspicion = Suspicion::default();
        let target = |port| Target {
            host: "a.example".to_owned(),
            port,
        };
        suspicion.suspect(target(1));
        suspicion.suspect(target(1));
        suspicion.suspect(target(2));
        assert_eq!(suspicion.wait_take().await, target(1));
        // The second target was queued with only one wake-up stored: it is taken with no new one.
        assert_eq!(suspicion.wait_take().await, target(2));
        assert_eq!(suspicion.take(), None);
        for port in 10..20 {
            suspicion.suspect(target(port));
        }
        assert_eq!(suspicion.take(), Some(target(12)));
    }

    /// A kind is found on an error chain by its type, and its words are the ones the guides show.
    ///
    /// Covers KR-REQ-10.02.
    #[test]
    fn a_kind_is_found_by_its_type_and_said_in_its_words() {
        let inner: Box<dyn Error + Send + Sync> = "tunnel error".into();
        let failure = ProxyLoginFailure::following(ProxyLoginKind::Refused, inner);
        let chain: &(dyn Error + 'static) = &failure;
        assert_eq!(proxy_login_kind(chain), Some(ProxyLoginKind::Refused));
        assert_eq!(
            failure.to_string(),
            "The proxy refused the login this host holds, so this host starts no new request \
             through the proxy until it restarts."
        );
        let plain: Box<dyn Error + 'static> = "tunnel error".into();
        assert_eq!(proxy_login_kind(&*plain), None);
        assert!(ProxyLoginKind::Refused.stops_until_restart());
        assert!(!ProxyLoginKind::Needed.stops_until_restart());
    }

    /// The gate: no login admits everything, a login refuses a plain `http` address, and a set
    /// verdict refuses everything with its own kind.
    ///
    /// Covers KR-REQ-10.02.
    #[test]
    fn a_proxy_that_holds_a_login_admits_https_until_the_verdict() {
        let proxy: ProxyUrl = "https://proxy.example:3128".parse().expect("a proxy");
        let https = Url::parse("https://origin.example/").expect("a URL");
        let http = Url::parse("http://origin.example/").expect("a URL");
        assert_eq!(admit(Some(&proxy), &http), Ok(()));
        assert_eq!(admit(None, &http), Ok(()));
        let login = ProxyCredential::parse_line(&line("u:p")).expect("a login");
        let proxy = proxy.with_login(login.clone());
        assert_eq!(admit(Some(&proxy), &https), Ok(()));
        assert_eq!(
            admit(Some(&proxy), &http),
            Err(ProxyLoginKind::ClearTextTarget)
        );
        login.refuse(StopKind::Refused);
        assert_eq!(admit(Some(&proxy), &https), Err(ProxyLoginKind::Refused));
        login.refuse(StopKind::Unsupported);
        assert_eq!(
            admit(Some(&proxy), &https),
            Err(ProxyLoginKind::Unsupported)
        );
    }
}
