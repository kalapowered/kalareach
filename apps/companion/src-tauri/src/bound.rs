//! A connection to a member's host, bound to the sign-in it was opened under.
//!
//! Every connection this device makes to a host whose grant answers to an organisation comes from
//! one place, the link, and the link returns it as a [`BoundTransport`]: the main connection, a
//! visit, a session link, a terminal view, the owner watcher's session and a push run's line all
//! live on one. It carries what the sign-in that was in force when the connection was opened, and
//! it ends the moment that sign-in is not the one in force: the account signed out, or another
//! signed in, or the same one signed in again.
//!
//! Which sign-in is in force is read from the status the account publishes, never from its store
//! after the connection is opened, so the question costs nothing and is asked of every call. A call
//! made after a sign-out has returned, whether it sends or waits for a frame, finds the connection
//! ended: it is not left to a task to have run first. The words of why are kept before the
//! connection is closed, so whoever finds it closed can ask for them.
//!
//! A change the account object does not publish is not heard: another process of the application
//! that shares its store on a desktop, or a publish whose status could not be read. The keeper of
//! the lease finds it at its next request, and the host ends the lease within fifteen minutes.
//!
//! A connection that presents no lease of its own (a session link, a terminal view) serves the
//! person only while the keeper of this sign-in holds a lease the host took: until then its
//! requests end it, so a link opened after a switch to an account whose lease the host refuses is
//! not served on the lease of the account before. A connection that presents its own is judged by
//! the host on that lease.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use kr_client::error::{ClientError, Result};
use kr_client::organisation::LeaseStop;
use kr_client::services::account::AccountStatus;
use kr_client::transport::{ControlTransport, Reach, TransportFuture};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ProtocolError;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::ConnectionId;
use kr_protocol::method::Method;
use tokio::sync::{Notify, watch};

/// Whether the keeper of the bound sign-in holds a lease the host took, and otherwise the stop that
/// says why not.
pub type LeaseGate = Arc<dyn Fn() -> std::result::Result<(), LeaseStop> + Send + Sync>;

/// What a bound connection is bound to, and what became of it.
pub struct Binding {
    /// The sign-in the connection was opened under.
    generation: String,
    /// What the account has published since the connection last looked.
    changes: Mutex<watch::Receiver<AccountStatus>>,
    lease: LeaseGate,
    /// Whether the connection has presented a lease of its own, which the host then judges.
    presented: AtomicBool,
    inner: Arc<dyn ControlTransport>,
    /// Why the connection ended, once it did: the first reason is the one kept.
    stop: OnceLock<ProtocolError>,
}

impl Binding {
    /// The reason the connection has ended, finding out first whether it should have: nothing is
    /// read of the account's store, only what it published.
    fn check(&self) -> Option<ProtocolError> {
        if let Some(stop) = self.stop.get() {
            return Some(stop.clone());
        }
        self.account_left().map(|stop| self.end(&stop))
    }

    fn account_left(&self) -> Option<LeaseStop> {
        let mut changes = self.changes.lock().unwrap_or_else(PoisonError::into_inner);
        if !changes.has_changed().unwrap_or(false) {
            return None;
        }
        // Marked seen before it is read, so a publish that follows the read is seen by the next
        // question and not lost.
        match &*changes.borrow_and_update() {
            AccountStatus::SignedIn { generation, .. } if *generation == self.generation => None,
            AccountStatus::SignedIn { .. } => Some(LeaseStop::AccountChanged),
            AccountStatus::SignedOut | AccountStatus::Ended => Some(LeaseStop::SignIn),
        }
    }

    /// Keeps `stop` as the reason (unless one is kept), then ends the connection, so that whoever
    /// is woken by the end finds the reason.
    fn end(&self, stop: &LeaseStop) -> ProtocolError {
        let error = self
            .stop
            .get_or_init(|| ProtocolError::new(stop.code(), stop.to_string()))
            .clone();
        self.inner.close();
        error
    }

    /// Ends a connection that presents no lease of its own when it is asked for something that only
    /// a lease the host took allows and the keeper of this sign-in holds none. The presentation of
    /// a lease is what gets one, so it is always allowed, and a connection that has made one is
    /// judged by the host on it.
    fn gate(&self, frame: &ControlFrame) -> Option<ProtocolError> {
        let method = match frame {
            ControlFrame::Request(request) => request.method.as_str(),
            ControlFrame::Mutation(request) => request.method.as_str(),
            _ => return None,
        };
        if method == Method::MembershipPresent.as_str() {
            self.presented.store(true, Ordering::Release);
            return None;
        }
        if self.presented.load(Ordering::Acquire) {
            return None;
        }
        (self.lease)().err().map(|stop| self.end(&stop))
    }
}

/// A transport that ends when the sign-in it was opened under is not in force.
pub struct BoundTransport {
    binding: Arc<Binding>,
    /// Told when the transport is closed or dropped, so its task ends with it.
    over: Arc<Notify>,
}

impl std::fmt::Debug for BoundTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundTransport")
            .field("inner", &self.binding.inner)
            .finish_non_exhaustive()
    }
}

impl BoundTransport {
    /// `inner`, bound to the sign-in `generation`, whose changes `gate_changes` and `task_changes`
    /// report (each subscribed before the sign-in was read). `lease` says whether the keeper holds a
    /// lease the host took.
    pub fn over(
        inner: Arc<dyn ControlTransport>,
        generation: String,
        gate_changes: watch::Receiver<AccountStatus>,
        mut task_changes: watch::Receiver<AccountStatus>,
        lease: LeaseGate,
    ) -> Arc<dyn ControlTransport> {
        let binding = Arc::new(Binding {
            generation,
            changes: Mutex::new(gate_changes),
            lease,
            presented: AtomicBool::new(false),
            inner,
            stop: OnceLock::new(),
        });
        let over = Arc::new(Notify::new());
        let watching = Arc::clone(&binding);
        let ended = Arc::clone(&over);
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::select! {
                    () = ended.notified() => return,
                    changed = task_changes.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                if watching.check().is_some() {
                    return;
                }
            }
        });
        Arc::new(Self { binding, over })
    }

    /// Why the connection ended, when it has, and the moment it should have if it has not.
    #[must_use]
    pub fn stopped(&self) -> Option<ProtocolError> {
        self.binding.check()
    }
}

impl Drop for BoundTransport {
    fn drop(&mut self) {
        self.over.notify_one();
    }
}

impl ControlTransport for BoundTransport {
    fn connection_id(&self) -> ConnectionId {
        self.binding.inner.connection_id()
    }

    fn limits(&self) -> ReceiveLimits {
        self.binding.inner.limits()
    }

    fn initial_action_window(&self) -> ActionWindow {
        self.binding.inner.initial_action_window()
    }

    fn reach(&self) -> Option<Reach> {
        self.binding.inner.reach()
    }

    fn ended_by_this_device(&self) -> Option<ProtocolError> {
        self.stopped()
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            if self.binding.check().is_some() || self.binding.gate(frame).is_some() {
                return Err(ClientError::ConnectionEnded);
            }
            self.binding.inner.send(frame).await
        })
    }

    fn claim_receiver(&self) -> Result<()> {
        self.binding.inner.claim_receiver()
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            let frame = self.binding.inner.recv().await;
            // What was read from the host after the account left is not handed on.
            if self.binding.check().is_some() {
                return Err(ClientError::ConnectionEnded);
            }
            frame
        })
    }

    fn revoke_streams(&self) {
        self.binding.inner.revoke_streams();
    }

    fn close(&self) {
        self.over.notify_one();
        self.binding.inner.close();
    }
}
