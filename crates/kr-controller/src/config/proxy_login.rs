//! What this host knows of the login its proxy asks for, and what the doctor says of it.
//!
//! The start reads the stored login once and checks the proxy once ([`ProxyStart`], [`ProxyItem`]).
//! After that the running host adds what it learned: the verdict on the login, whether the network
//! endpoint has finished closing and whether the stored login changed since the start. The doctor's
//! words are written here and nowhere else, as literals, so a row cannot carry a login.

use kr_protocol::hostinfo::export::Sentence;

use super::Started;

/// What the start check found at the proxy. Set once, after the check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyStart {
    /// The host reaches the network directly, or the check never ran.
    #[default]
    NoProxy,
    /// The proxy opened a tunnel.
    Open,
    /// The check did not finish: the deadline, a failed connection or TLS, a failed anchor read,
    /// or an answer it could not read.
    Unchecked,
    /// No address to test the proxy with.
    NoTarget,
    /// The proxy asked for a login this host does not hold.
    NeedsLogin,
    /// The proxy refused the login this host holds.
    LoginRefused,
    /// The proxy asks for a sign-in method this host does not send.
    SchemeUnsupported,
}

/// What reading the stored login at the start found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyItem {
    /// No login is stored.
    #[default]
    Absent,
    /// A login is stored for the proxy the document names, and the route holds it.
    Held,
    /// The item could not be read or did not decode; the route holds no login.
    Unreadable,
    /// The item was made for another proxy; the route holds no login.
    ForAnotherProxy,
}

/// What changed in the stored login since the start. A change applies at the next start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyChange {
    /// Nothing changed.
    #[default]
    None,
    /// A login was stored after the start.
    Stored,
    /// The stored login was cleared after the start.
    Cleared,
}

/// Where the network endpoint stands when the proxy's login is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyPhase {
    /// The start skipped the network start.
    Skipped,
    /// No network was registered.
    NoNetwork,
    /// The endpoint is closing.
    Closing,
    /// The endpoint finished closing.
    Closed,
}

/// The state the doctor reads a running host's proxy login at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyState {
    /// See [`ProxyStart::NoProxy`].
    NoProxy,
    /// See [`ProxyStart::Open`].
    Open,
    /// See [`ProxyStart::Unchecked`].
    Unchecked,
    /// See [`ProxyStart::NoTarget`].
    NoTarget,
    /// See [`ProxyStart::NeedsLogin`].
    NeedsLogin,
    /// The proxy refused the login, at the start or later.
    LoginRefused,
    /// See [`ProxyStart::SchemeUnsupported`].
    SchemeUnsupported,
}

/// What a running host reads of its proxy login. All of it is read from live state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyReading {
    /// What the start check found.
    pub start: ProxyStart,
    /// What reading the stored login at the start found.
    pub item: ProxyItem,
    /// Whether the verdict on the login is stopped.
    pub stopped: bool,
    /// Whether the proxy asked for a sign-in method this host does not send, as a client met it.
    pub unsupported: bool,
    /// Whether the network endpoint finished closing.
    pub closed: bool,
    /// Whether the start skipped the network start.
    pub skipped: bool,
    /// Whether a network is registered.
    pub registered: bool,
    /// What changed in the stored login since the start.
    pub changed: ProxyChange,
}

impl ProxyReading {
    /// The state the doctor reads: an unsupported sign-in method outranks a refusal.
    #[must_use]
    pub fn state(&self) -> ProxyState {
        if self.start == ProxyStart::SchemeUnsupported || self.unsupported {
            return ProxyState::SchemeUnsupported;
        }
        if self.stopped {
            return ProxyState::LoginRefused;
        }
        match self.start {
            ProxyStart::NoProxy => ProxyState::NoProxy,
            ProxyStart::Open => ProxyState::Open,
            ProxyStart::Unchecked => ProxyState::Unchecked,
            ProxyStart::NoTarget => ProxyState::NoTarget,
            ProxyStart::NeedsLogin => ProxyState::NeedsLogin,
            ProxyStart::LoginRefused => ProxyState::LoginRefused,
            ProxyStart::SchemeUnsupported => ProxyState::SchemeUnsupported,
        }
    }

    /// Where the network endpoint stands.
    #[must_use]
    pub fn phase(&self) -> ProxyPhase {
        if self.skipped {
            ProxyPhase::Skipped
        } else if !self.registered {
            ProxyPhase::NoNetwork
        } else if self.closed {
            ProxyPhase::Closed
        } else {
            ProxyPhase::Closing
        }
    }
}

/// The first remedy of R1: store a login.
const R1: &str = "Store a login the proxy accepts with `kr host network --proxy-login \
                  --proxy-credential-file <file>`, then run `kr host stop`; the daemon uses the \
                  login from its next start.";
/// A proxy that signs in by a method this host does not send.
const R2: &str = "Use a proxy that signs in by Basic, or run a local proxy that signs in for this \
                  host and name it in `network.proxy_url`, then run `kr host stop`; the daemon \
                  uses that proxy from its next start.";
/// A login stored after the start.
const R3: &str = "Run `kr host stop`; the daemon uses the stored login from its next start.";
/// A login cleared after the start.
const R4: &str = "Run `kr host stop`; the daemon uses no login from its next start.";
/// What a person does when a service's request was stopped by the proxy's login: the kind decides
/// whether a login is missing or the proxy asks for a method this host does not send.
#[must_use]
pub(crate) const fn remedy_for_kind(kind: kr_transport::proxy::ProxyLoginKind) -> &'static str {
    match kind {
        kr_transport::proxy::ProxyLoginKind::Unsupported => R2,
        _ => R1,
    }
}
/// An `http` relay while a login is held.
const R_HTTP_RELAY: &str = "Use an https relay.";

/// What the doctor says of the proxy login: sentences for the network row, whether the row warns,
/// and the remedy that ranks first.
#[derive(Debug)]
pub(super) struct ProxyWords {
    /// The network row's detail, with the proxy's sentences appended.
    pub(super) detail: Sentence,
    /// Whether any sentence of the proxy warns.
    pub(super) warns: bool,
    /// The proxy remedy that ranks first, when one applies.
    pub(super) remedy: Option<&'static str>,
}

/// Appends the proxy's sentences to `detail` and chooses its remedy.
///
/// The remedies rank: R2, then R3 or R4 for a stored change, then R1, then the `http` relay's.
pub(super) fn words(mut detail: Sentence, started: &Started, reading: ProxyReading) -> ProxyWords {
    let mut warns = false;
    let mut remedy: Option<&'static str> = None;
    let mut rank = u8::MAX;
    let mut take = |at: u8, text: &'static str| {
        if at < rank {
            rank = at;
            remedy = Some(text);
        }
    };
    let state = reading.state();
    let phase = reading.phase();
    let held = started.proxy_login.is_some();
    let sentence = match (state, phase) {
        (ProxyState::NoProxy | ProxyState::Open, _) => None,
        (ProxyState::Unchecked, _) => {
            Some("the start check could not tell whether the proxy asks for a login")
        }
        (ProxyState::NoTarget, _) => {
            Some("the start found no address to test the proxy with, so the proxy was not checked")
        }
        (ProxyState::NeedsLogin, ProxyPhase::Skipped) => Some(
            "the proxy requires a sign-in, and this host holds no login for it, so this host did \
             not start its network",
        ),
        (ProxyState::NeedsLogin, _) => {
            Some("the proxy requires a sign-in, and this host holds no login for it")
        }
        (ProxyState::LoginRefused, ProxyPhase::Skipped) => Some(
            "the proxy refused the login this host holds, so this host starts no new request \
             through the proxy; it did not start its network",
        ),
        (ProxyState::LoginRefused, ProxyPhase::NoNetwork) => Some(
            "the proxy refused the login this host holds, so this host starts no new request \
             through the proxy",
        ),
        (ProxyState::LoginRefused, ProxyPhase::Closing) => Some(
            "the proxy refused the login this host holds, so this host starts no new request \
             through the proxy; it is closing its network endpoint",
        ),
        (ProxyState::LoginRefused, ProxyPhase::Closed) => Some(
            "the proxy refused the login this host holds, so this host starts no new request \
             through the proxy; it closed its network endpoint: its relay and direct \
             connections ended, and the local socket still serves",
        ),
        (ProxyState::SchemeUnsupported, ProxyPhase::Skipped) => Some(
            "the proxy asks for a sign-in method this host does not support; this host can send \
             only a user name and password (Basic), and it did not start its network",
        ),
        (ProxyState::SchemeUnsupported, ProxyPhase::NoNetwork) => Some(
            "the proxy asks for a sign-in method this host does not support; this host can send \
             only a user name and password (Basic)",
        ),
        (ProxyState::SchemeUnsupported, ProxyPhase::Closing) => Some(
            "the proxy asks for a sign-in method this host does not support; this host can send \
             only a user name and password (Basic), and it is closing its network endpoint",
        ),
        (ProxyState::SchemeUnsupported, ProxyPhase::Closed) => Some(
            "the proxy asks for a sign-in method this host does not support; this host can send \
             only a user name and password (Basic), and it closed its network endpoint: its \
             relay and direct connections ended, and the local socket still serves",
        ),
    };
    if let Some(text) = sentence {
        detail = detail.stated("; ").stated(text);
        if matches!(
            state,
            ProxyState::NeedsLogin | ProxyState::LoginRefused | ProxyState::SchemeUnsupported
        ) {
            warns = true;
            take(
                if state == ProxyState::SchemeUnsupported {
                    0
                } else {
                    2
                },
                if state == ProxyState::SchemeUnsupported {
                    R2
                } else {
                    R1
                },
            );
        }
    }
    match reading.item {
        ProxyItem::Unreadable => {
            detail = detail.stated(
                "; the proxy login stored on this host could not be read when the host started, \
                 so none was sent",
            );
            warns = true;
            take(2, R1);
        }
        ProxyItem::ForAnotherProxy => {
            detail = detail.stated(
                "; the stored proxy login was made for another proxy, so this host did not send \
                 it when it started",
            );
            warns = true;
            take(2, R1);
        }
        ProxyItem::Absent | ProxyItem::Held => {}
    }
    let clear_text = started
        .network
        .proxy_url()
        .is_some_and(|proxy| proxy.starts_with("http://"));
    if held
        && clear_text
        && matches!(
            state,
            ProxyState::Open | ProxyState::Unchecked | ProxyState::NoTarget
        )
    {
        detail = detail.stated(
            "; the login is sent in clear to the proxy, because the proxy's address is an http \
             one",
        );
    }
    let http_relay = started
        .network
        .relay_urls()
        .iter()
        .any(|relay| relay.starts_with("http://"));
    if held && http_relay {
        detail = detail.stated(
            "; while this host holds a login for the proxy, an http relay gets no latency probe; \
             where no QUIC address probe answers, which is always so for a relay-only host, this \
             host does not choose it as home relay and does not connect to it",
        );
        warns = true;
        take(3, R_HTTP_RELAY);
    }
    match reading.changed {
        ProxyChange::None => {}
        ProxyChange::Stored => {
            detail = detail.stated(
                "; the proxy login stored on this host changed since this host started, and the \
                 change applies when the host restarts",
            );
            warns = true;
            take(1, R3);
        }
        ProxyChange::Cleared => {
            detail = detail.stated(
                "; the proxy login stored on this host changed since this host started, and the \
                 change applies when the host restarts",
            );
            warns = true;
            take(1, R4);
        }
    }
    ProxyWords {
        detail,
        warns,
        remedy,
    }
}
