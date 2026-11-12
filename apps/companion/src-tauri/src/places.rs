//! The places this application holds on a paired host's bound of connections.
//!
//! A host lets a device hold [`HOST_CONNECTIONS`] connections for use and twice as many live ones,
//! so that every connection in use can linger once beside its replacement, and it ends none that
//! it has heard from lately for a new one: a device that dials past its bound is refused. Every
//! dial this application makes to a paired host therefore takes a place from one budget before it
//! connects, and gives it back when the connection it carries ends, by any road: a connection
//! closed, dropped, cancelled while it was dialled, refused or ended by the host.
//!
//! One place of the budget is the main link's alone: no other kind of connection can take it, so
//! that the link without which the application cannot reach the host is never made to wait behind
//! the others. A dial that finds no place waits for one, for no longer than [`PLACE_WAIT`], and is
//! then refused for now with the code a host refuses with when it cannot take another connection;
//! every caller treats that as it treats the host's own refusal.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use kr_client::error::Result;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::link::{EndpointHold, HostInUse, HostLink, LinkError, Presentation};
use kr_client::pairing::paired::PairedHost;
use kr_client::session::Session;
use kr_client::transport::{ControlTransport, Reach, TransportFuture};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{ConnectionId, DeviceId};
use kr_protocol::pairing::NetworkConfig;
use kr_protocol::scalars::EndpointKey;
use kr_transport::handshake::LocalIdentity;
use tokio::sync::Notify;

use crate::standing::{AMBIENT_LIMIT, OPENED_LIMIT};

/// How many connections this application holds to one host at once, of every kind, the main link's
/// own place included: what the host lets a device use at once. The host holds twice as many live
/// connections, so that each of these may linger once beside its replacement.
///
/// The kinds that have a limit of their own come to `IN_USE` of them; the places left over are for
/// the connections that finish beside a replacement: a link the person left that still finishes its
/// requests, and an open that a later one superseded. A kind that has no limit of its own is held
/// by this number and no other, and a connection that is never closed keeps its place: every dial
/// to that host then waits for one.
pub const HOST_CONNECTIONS: usize = IN_USE + 2;

/// What the kinds of connection that have a limit of their own come to, all of them held at once:
///
/// * the main connection: one;
/// * the opened links: one for each opened session, at most [`OPENED_LIMIT`];
/// * a raw terminal view for each opened session, at most [`OPENED_LIMIT`]: native code holds the
///   raw views of an opening to no number, and this counts one for each opened session;
/// * the ambient links, at most [`AMBIENT_LIMIT`];
/// * the owner's confirmations: two, a review beside the cycle of visits;
/// * a revocation reading: two, a view beside a revoke or in a second window;
/// * the push registration: one;
/// * the inbox's kept connection: one;
/// * a voice call's own connection, when it avoids the main session: one;
/// * the sharing desk's repeat connection and its reading connection: two.
///
/// A visit to a host that is not the one in use takes places on that host, and it holds the host
/// in use to none of them.
const IN_USE: usize = 1 + OPENED_LIMIT + OPENED_LIMIT + AMBIENT_LIMIT + 2 + 2 + 1 + 1 + 1 + 2;

/// The longest a dial waits for a place before it is refused for now.
pub const PLACE_WAIT: Duration = Duration::from_secs(5);

/// What a connection is for, as far as its place is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The connection the application keeps to the host in use.
    Main,
    /// Every other connection.
    Other,
}

tokio::task_local! {
    /// What the dial made in this task is for. A dial that is not marked is [`Kind::Other`].
    static DIAL_FOR: Kind;
}

/// Runs `dial`, and has the dial it makes take the main link's place.
pub async fn as_the_main_link<F: std::future::Future>(dial: F) -> F::Output {
    DIAL_FOR.scope(Kind::Main, dial).await
}

fn kind_of_this_dial() -> Kind {
    DIAL_FOR.try_with(|kind| *kind).unwrap_or(Kind::Other)
}

#[derive(Default)]
struct Held {
    main: usize,
    others: usize,
}

/// The places held on each host, for every kind.
pub struct Places {
    total: usize,
    held: Mutex<BTreeMap<DeviceId, Held>>,
    freed: Notify,
}

/// One place on one host's bound, given back when it is dropped.
pub struct Place {
    places: Arc<Places>,
    host: DeviceId,
    kind: Kind,
}

impl Drop for Place {
    fn drop(&mut self) {
        {
            let mut held = self
                .places
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = held.get_mut(&self.host) {
                match self.kind {
                    Kind::Main => count.main = count.main.saturating_sub(1),
                    Kind::Other => count.others = count.others.saturating_sub(1),
                }
                if count.main + count.others == 0 {
                    held.remove(&self.host);
                }
            }
        }
        self.places.freed.notify_waiters();
    }
}

/// The places of this application, which every dial takes from.
static PLACES: LazyLock<Arc<Places>> = LazyLock::new(|| Places::new(HOST_CONNECTIONS));

/// The budget every dial of this application takes a place from.
#[must_use]
pub fn budget() -> Arc<Places> {
    Arc::clone(&PLACES)
}

impl Places {
    /// A budget of `total` places on each host, one of them the main link's alone.
    #[must_use]
    pub fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            total,
            held: Mutex::new(BTreeMap::new()),
            freed: Notify::new(),
        })
    }

    fn free_for(&self, held: &BTreeMap<DeviceId, Held>, host: DeviceId, kind: Kind) -> bool {
        let count = held.get(&host);
        let (main, others) = count.map_or((0, 0), |count| (count.main, count.others));
        match kind {
            Kind::Main => main + others < self.total,
            // The last place is the main link's.
            Kind::Other => main + others < self.total && others + 1 < self.total,
        }
    }

    /// Takes a place on `host` if one is free for `kind` now.
    #[must_use]
    pub fn try_take(self: &Arc<Self>, host: DeviceId, kind: Kind) -> Option<Place> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.free_for(&held, host, kind) {
            return None;
        }
        let count = held.entry(host).or_default();
        match kind {
            Kind::Main => count.main += 1,
            Kind::Other => count.others += 1,
        }
        Some(Place {
            places: Arc::clone(self),
            host,
            kind,
        })
    }

    /// How many places are held on `host` now, of every kind.
    #[must_use]
    pub fn held_on(&self, host: DeviceId) -> usize {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.get(&host).map_or(0, |count| count.main + count.others)
    }

    /// Whether a place on `host` is free for `kind` now.
    fn is_free(&self, host: DeviceId, kind: Kind) -> bool {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        self.free_for(&held, host, kind)
    }

    /// Takes a place, waiting for one for no longer than `within`.
    pub async fn take(
        self: &Arc<Self>,
        host: DeviceId,
        kind: Kind,
        within: Duration,
    ) -> Option<Place> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if let Some(place) = self.try_take(host, kind) {
                return Some(place);
            }
            if tokio::time::timeout_at(deadline, freed).await.is_err() {
                return self.try_take(host, kind);
            }
        }
    }

    /// Waits until a place on `host` is free for `kind`, however long that is: for a task that
    /// keeps trying in the background and has no caller to give up for it.
    pub async fn until_free(&self, host: DeviceId, kind: Kind) {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if self.is_free(host, kind) {
                return;
            }
            freed.await;
        }
    }
}

/// Whether a refusal says that a host cannot take another connection from this computer for now.
/// It is read from the code alone: the host refuses with it when this computer holds as many
/// connections as the host allows, and a dial that finds no place here is refused with it.
pub(crate) fn is_no_room(code: ErrorCode) -> bool {
    code == ErrorCode::ResourceUnavailable
}

/// What a person is told when a host cannot take another connection from this computer for now:
/// the cause, and that the next try asks again, with no time promised.
pub(crate) const NO_ROOM_FOR_NOW: &str = "the host cannot take another connection from this \
                                          computer just now; this computer asks again by itself";

/// What a dial that finds no place is refused with: the code a host refuses a connection with when
/// it cannot take another for now, which every caller asks again after.
fn full() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "this device already holds as many connections to this host as it keeps at once, and one \
         of them is still finishing; it asks again by itself",
    )
}

/// A link that takes a place from `places` before each dial to a paired host.
pub struct Budgeted {
    inner: Arc<dyn HostLink>,
    places: Arc<Places>,
}

impl Budgeted {
    /// `inner`, with every paired dial held to `places`.
    #[must_use]
    pub fn over(inner: Arc<dyn HostLink>, places: Arc<Places>) -> Arc<dyn HostLink> {
        Arc::new(Self { inner, places })
    }

    async fn place_for(&self, host: &PairedHost) -> std::result::Result<Place, LinkError> {
        self.places
            .take(host.host_device_id, kind_of_this_dial(), PLACE_WAIT)
            .await
            .ok_or_else(|| LinkError::Refused(full()))
    }
}

impl HostLink for Budgeted {
    fn dial<'a>(
        &'a self,
        network: &'a NetworkConfig,
        endpoint: &'a EndpointKey,
    ) -> BoxFuture<'a, std::result::Result<iroh::endpoint::Connection, LinkError>> {
        self.inner.dial(network, endpoint)
    }

    fn open_unpaired<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, std::result::Result<Box<dyn kr_client::pairing::link::Preauth>, LinkError>>
    {
        self.inner.open_unpaired(connection, identity)
    }

    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, std::result::Result<Arc<dyn ControlTransport>, LinkError>> {
        Box::pin(async move {
            let place = self.place_for(host).await?;
            let transport = self.inner.connect_paired_transport(host, identity).await?;
            Ok(Placed::over(transport, place))
        })
    }

    fn visit_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, std::result::Result<Arc<dyn ControlTransport>, LinkError>> {
        Box::pin(async move {
            let place = self.place_for(host).await?;
            let transport = self
                .inner
                .visit_paired_transport(host, identity, in_use)
                .await?;
            Ok(Placed::over(transport, place))
        })
    }

    fn present_membership<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        presentation: Presentation,
    ) -> BoxFuture<'a, std::result::Result<(), LinkError>> {
        self.inner
            .present_membership(session, host, identity, presentation)
    }

    fn hold<'a>(
        &'a self,
        network: &'a NetworkConfig,
    ) -> BoxFuture<'a, std::result::Result<EndpointHold, LinkError>> {
        self.inner.hold(network)
    }

    fn visit_hold<'a>(
        &'a self,
        network: &'a NetworkConfig,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, std::result::Result<EndpointHold, LinkError>> {
        self.inner.visit_hold(network, in_use)
    }

    fn would_refuse_visit<'a>(
        &'a self,
        network: &'a NetworkConfig,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, bool> {
        self.inner.would_refuse_visit(network, in_use)
    }

    fn relay_capacity_refused(&self, network: &NetworkConfig, endpoint: &EndpointKey) -> bool {
        self.inner.relay_capacity_refused(network, endpoint)
    }
}

/// A transport that holds a place until it is closed or dropped.
struct Placed {
    inner: Arc<dyn ControlTransport>,
    place: Mutex<Option<Place>>,
}

impl std::fmt::Debug for Placed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Placed")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl Placed {
    fn over(inner: Arc<dyn ControlTransport>, place: Place) -> Arc<dyn ControlTransport> {
        Arc::new(Self {
            inner,
            place: Mutex::new(Some(place)),
        })
    }
}

impl ControlTransport for Placed {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }

    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }

    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }

    fn reach(&self) -> Option<Reach> {
        self.inner.reach()
    }

    fn ended_by_this_device(&self) -> Option<ProtocolError> {
        self.inner.ended_by_this_device()
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        self.inner.send(frame)
    }

    fn send_before<'a>(
        &'a self,
        frame: &'a ControlFrame,
        not_after: tokio::time::Instant,
        wanted: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> TransportFuture<'a, bool> {
        self.inner.send_before(frame, not_after, wanted)
    }

    fn claim_receiver(&self) -> Result<()> {
        self.inner.claim_receiver()
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        self.inner.recv()
    }

    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }

    fn close(&self) {
        self.inner.close();
        self.place
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(byte: u8) -> DeviceId {
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    /// A transport that is only closed, as a connection that carries a place is.
    #[derive(Debug)]
    struct Closed;

    impl ControlTransport for Closed {
        fn connection_id(&self) -> ConnectionId {
            unreachable!("a case that only closes")
        }
        fn limits(&self) -> ReceiveLimits {
            unreachable!("a case that only closes")
        }
        fn initial_action_window(&self) -> ActionWindow {
            unreachable!("a case that only closes")
        }
        fn ended_by_this_device(&self) -> Option<ProtocolError> {
            None
        }
        fn send<'a>(&'a self, _frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
            unreachable!("a case that only closes")
        }
        fn send_before<'a>(
            &'a self,
            _frame: &'a ControlFrame,
            _not_after: tokio::time::Instant,
            _wanted: &'a (dyn Fn() -> bool + Send + Sync),
        ) -> TransportFuture<'a, bool> {
            unreachable!("a case that only closes")
        }
        fn claim_receiver(&self) -> Result<()> {
            Ok(())
        }
        fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
            unreachable!("a case that only closes")
        }
        fn revoke_streams(&self) {}
        fn close(&self) {}
    }

    /// KR-REQ-19.08: with every place but the main link's held by other kinds, and more dials
    /// waiting for one, the main link's dial does not wait, and no other kind can take the place
    /// that is the main link's.
    #[tokio::test]
    async fn the_main_links_place_is_its_alone() {
        let places = Places::new(4);
        let held: Vec<_> = (0..3)
            .map(|_| places.try_take(host(1), Kind::Other).expect("a place"))
            .collect();
        assert!(places.try_take(host(1), Kind::Other).is_none());
        let waiting = tokio::spawn({
            let places = Arc::clone(&places);
            async move {
                places
                    .take(host(1), Kind::Other, Duration::from_millis(200))
                    .await
                    .is_none()
            }
        });
        let main = tokio::time::timeout(
            Duration::from_millis(50),
            places.take(host(1), Kind::Main, Duration::from_secs(60)),
        )
        .await
        .expect("the main link does not wait behind the other kinds")
        .expect("its place");
        assert!(
            waiting.await.expect("the waiting dial ends"),
            "the other kinds got no place"
        );
        // Another host's places are its own.
        assert!(places.try_take(host(2), Kind::Other).is_some());
        drop((held, main));
    }

    /// KR-REQ-19.08: callers that each hold a place and ask for one more, with every free place
    /// held, are each refused for now when their own time limit ends, every place goes back, and
    /// the next dial is given one. No holder lets go of its place before every holder has been
    /// answered, so none is refused for another's sake.
    #[tokio::test]
    async fn holders_that_each_ask_for_one_more_are_refused_and_every_place_returns() {
        let places = Places::new(4);
        let holders: Vec<_> = (0..3)
            .map(|_| places.try_take(host(1), Kind::Other).expect("a place"))
            .collect();
        let asks: Vec<_> = (0..holders.len())
            .map(|_| {
                let places = Arc::clone(&places);
                tokio::spawn(async move {
                    places
                        .take(host(1), Kind::Other, Duration::from_millis(100))
                        .await
                        .is_none()
                })
            })
            .collect();
        for ask in asks {
            assert!(
                ask.await.expect("the holder ends"),
                "refused inside its own time limit"
            );
        }
        drop(holders);
        assert_eq!(places.held_on(host(1)), 0, "every place went back");
        assert!(
            places.try_take(host(1), Kind::Other).is_some(),
            "the next dial is given one"
        );
    }

    /// KR-REQ-19.08: a connection gives its place back when it is closed, and a dial that was
    /// waiting for one is given it then, not when its own delay ends.
    #[tokio::test]
    async fn a_place_returns_when_its_connection_is_closed() {
        let places = Places::new(3);
        // Two places for the other kinds, and the third is the main link's.
        let first = places.try_take(host(1), Kind::Other).expect("a place");
        let second = places.try_take(host(1), Kind::Other).expect("a place");
        let connection = Placed::over(Arc::new(Closed), first);
        let waiting = tokio::spawn({
            let places = Arc::clone(&places);
            async move {
                places
                    .take(host(1), Kind::Other, Duration::from_secs(60))
                    .await
                    .is_some()
            }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "no place is free for it yet");
        connection.close();
        assert!(
            waiting.await.expect("the waiting dial ends"),
            "given the place at the close"
        );
        drop(second);
    }
}
