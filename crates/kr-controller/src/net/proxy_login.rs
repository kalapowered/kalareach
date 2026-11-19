//! The login this host holds for its proxy: the stored item, the check the start makes once, and
//! the watch that checks again when a request fails in a way that may be a refusal.
//!
//! Every send that carries the login goes through `kr_client::tunnel::through` or through the
//! product's clients, which the verdict stops. The check and the watch use `through` too, so the
//! login is written by the one writer and a refusal sets the one verdict.

use std::sync::Arc;
use std::time::Duration;

use kr_client::tunnel::{TunnelFailure, through};
use kr_crypto::secret::SecretVec;
use kr_crypto::store::{SecretName, SecretStore};
use kr_protocol::hostinfo::configuration::NetworkSelection;
use kr_protocol::ids::EnvironmentId;
use kr_transport::config::ProxyUrl;
use kr_transport::proxy::{ProxyCredential, ProxyLoginKind, Target};
use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;
use url::Url;

use crate::config::{ProxyItem, ProxyStart, Started};

/// How long the start check waits for the proxy's answer in all: name lookup, connection, TLS and
/// the head of the answer.
pub const CHECK_DEADLINE: Duration = Duration::from_secs(10);

/// How long the watch waits after a check before it takes another suspicion, so the proxy sees at
/// most one re-check `CONNECT` in an interval whatever the clients do.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(60);

/// The name of the one item that holds the login: the environment's own, in the host's store.
///
/// # Errors
///
/// Returns an error only when the environment's identifier is not a valid name, which it is not.
pub fn item_name(environment_id: EnvironmentId) -> Result<SecretName, kr_crypto::CryptoError> {
    SecretName::new(format!("{environment_id}/network-proxy-login"))
}

/// The bytes of the item: the proxy's origin, a line feed, then `user:password`.
#[must_use]
pub fn item_bytes(origin: &str, line: &[u8]) -> SecretVec {
    let mut bytes = Vec::with_capacity(origin.len() + 1 + line.len());
    bytes.extend_from_slice(origin.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(line);
    SecretVec::new(bytes)
}

/// Reads the stored login for `proxy`, the proxy this document names.
///
/// The item is used only when the origin it was made for, parsed as a [`ProxyUrl`], equals the
/// document's. An item that does not decode, and a store that fails, read as [`ProxyItem::Unreadable`]
/// and the route holds no login; neither stops the daemon.
#[must_use]
pub fn read_item(
    store: &dyn SecretStore,
    environment_id: EnvironmentId,
    proxy: Option<&ProxyUrl>,
) -> (Option<ProxyCredential>, ProxyItem) {
    let Some(proxy) = proxy else {
        return (None, ProxyItem::Absent);
    };
    let Ok(name) = item_name(environment_id) else {
        return (None, ProxyItem::Unreadable);
    };
    let bytes = match store.get(&name) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return (None, ProxyItem::Absent),
        Err(_) => return (None, ProxyItem::Unreadable),
    };
    let Some(at) = bytes.expose().iter().position(|byte| *byte == b'\n') else {
        return (None, ProxyItem::Unreadable);
    };
    let (origin, line) = bytes.expose().split_at(at);
    let Some(origin) = std::str::from_utf8(origin)
        .ok()
        .and_then(|origin| origin.parse::<ProxyUrl>().ok())
    else {
        return (None, ProxyItem::Unreadable);
    };
    let Ok(login) = ProxyCredential::parse_line(&SecretVec::new(line[1..].to_vec())) else {
        return (None, ProxyItem::Unreadable);
    };
    if origin.as_url() == proxy.as_url() {
        (Some(login), ProxyItem::Held)
    } else {
        (None, ProxyItem::ForAnotherProxy)
    }
}

/// The TLS the checks and the front's tunnels verify an `https` proxy with: the platform's trust
/// and the anchors the network section names.
///
/// # Errors
///
/// Returns an error when the platform's verification cannot be set up.
pub fn proxy_tls(anchors: &[Vec<u8>]) -> Result<Arc<ClientConfig>, rustls::Error> {
    let roots: Vec<CertificateDer<'static>> = anchors
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    kr_client::services::http::platform_tls(&roots).map(Arc::new)
}

/// Whether `origin` is one this build's route serves: the managed origin counts only where this
/// build serves it, so a test build that leaves an origin at the managed service reaches nothing.
fn served(origin: &str) -> bool {
    let managed = kr_client::services::account::ACCOUNT_ORIGIN;
    origin != managed || crate::release_matrix::managed_origin().as_deref() == Some(managed)
}

/// The address the start check tests the proxy with: the first selected relay, else the first
/// Pkarr server (the publisher, then the resolver), else the first origin the route serves among
/// the authority feed, the mailbox, the relay lease service, the storage service and the voice
/// broker. None when the document names none of them.
#[must_use]
pub fn start_target(started: &Started) -> Option<Target> {
    let network = &started.network;
    let first = network
        .relay_urls()
        .first()
        .map(String::as_str)
        .or_else(|| network.pkarr_publisher_url())
        .or_else(|| network.pkarr_resolver_url())
        .or_else(|| {
            [
                started.authority.origin(),
                started.mailbox.origin(),
                started.relay.origin(),
                started.storage.origin(),
                started.voice.broker_origin(),
            ]
            .into_iter()
            .flatten()
            .find(|origin| served(origin))
        })?;
    Target::of(&first.parse::<Url>().ok()?)
}

/// The anchors the network section names, read only when the section joins.
///
/// # Errors
///
/// Returns an error when a named file cannot be read or is empty.
pub fn read_anchors(selection: &NetworkSelection) -> crate::error::Result<Vec<Vec<u8>>> {
    if !selection.joins() {
        return Ok(Vec::new());
    }
    super::config::read_trust_anchors(selection.relay_trust_anchors())
}

/// Opens one tunnel to `target` through `proxy` and says what the proxy answered.
///
/// A `407` to a login that was sent sets the verdict inside [`through`]. The check ends at
/// `deadline`, whatever it was waiting for.
pub async fn check(
    proxy: &ProxyUrl,
    target: &Target,
    tls: &Arc<ClientConfig>,
    deadline: Duration,
) -> ProxyStart {
    let opened =
        tokio::time::timeout(deadline, through(proxy, &target.host, target.port, tls)).await;
    match opened {
        Ok(Ok(_carrier)) => ProxyStart::Open,
        Ok(Err(TunnelFailure::Login(ProxyLoginKind::Unsupported))) => ProxyStart::SchemeUnsupported,
        Ok(Err(TunnelFailure::Login(ProxyLoginKind::Refused))) => ProxyStart::LoginRefused,
        Ok(Err(TunnelFailure::Login(ProxyLoginKind::Needed))) => ProxyStart::NeedsLogin,
        Ok(Err(_)) | Err(_) => ProxyStart::Unchecked,
    }
}

/// What a start check is given to run with.
#[derive(Clone, Debug)]
pub struct Timing {
    /// The check's total deadline.
    pub deadline: Duration,
    /// The wait between two checks of the watch.
    pub interval: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            deadline: CHECK_DEADLINE,
            interval: RECHECK_INTERVAL,
        }
    }
}

/// The task that checks the proxy again when a request failed in a way that may be a refusal, and
/// ends with the controller.
///
/// It sets nothing itself: `through` sets the verdict when it sent the login and met a `407`. A
/// target that was queued while an earlier check ran is taken before the task waits. After a
/// check it waits `interval` before the next, and it ends when the verdict is stopped, since
/// nothing is sent then.
pub struct Watch {
    task: tokio::task::AbortHandle,
    /// How many checks this watch has finished, for a suite that waits for one.
    #[cfg(any(test, feature = "testing"))]
    done: Arc<std::sync::atomic::AtomicU64>,
}

impl Watch {
    /// Starts the watch over `proxy`, which holds the login.
    ///
    /// Returns `None` when `proxy` holds none.
    #[must_use]
    pub fn start(proxy: ProxyUrl, tls: Arc<ClientConfig>, timing: Timing) -> Option<Self> {
        let login = proxy.login()?.clone();
        #[cfg(any(test, feature = "testing"))]
        let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
        #[cfg(any(test, feature = "testing"))]
        let counted = Arc::clone(&done);
        let task = tokio::spawn(async move {
            loop {
                let target = tokio::select! {
                    () = async { login.stopped_wait().await; } => return,
                    target = login.suspicion().wait_take() => target,
                };
                let _ = check(&proxy, &target, &tls, timing.deadline).await;
                #[cfg(any(test, feature = "testing"))]
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(timing.interval).await;
            }
        });
        Some(Self {
            task: task.abort_handle(),
            #[cfg(any(test, feature = "testing"))]
            done,
        })
    }

    /// Whether the task has ended: it ends when the verdict is stopped.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn ended(&self) -> bool {
        self.task.is_finished()
    }

    /// How many checks the watch has finished.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn checks_done(&self) -> u64 {
        self.done.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The timing this start runs the check and the watch with: the product's, or the one a suite gave
/// the start in progress.
#[must_use]
pub(crate) fn timing_of_the_start() -> Timing {
    #[cfg(any(test, feature = "testing"))]
    if let Some(timing) = crate::testing::proxy_login_timing() {
        return timing;
    }
    Timing::default()
}
