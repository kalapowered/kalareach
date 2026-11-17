//! The dispatch boundary and its guard.
//!
//! The guard is made here and nowhere else: its constructor and its fields are private to this
//! module, and so are the two takes of a boundary, [`DispatchBoundary::lock`] and
//! [`DispatchBoundary::try_lock`]. The service takes its one boundary through
//! [`WorkerService::take_boundary`] and [`WorkerService::try_take_boundary`], which are written
//! here and read the service's own field, so no other code of the service can take a boundary, a
//! second one made beside the service's included. The functions that run under the boundary take
//! a borrow of the guard as a parameter, so a caller that holds no guard of a boundary does not
//! compile. That the guard is the service's own is not held by the compiler: the two entries
//! (`receipted` and `continue_prepared`) check it with [`DispatchGuard::is_of`] before any work.

use std::sync::Mutex;

use super::WorkerService;

/// The dispatch boundary: a lock that says so when it is let go.
///
/// Every holder takes it as an ordinary lock and drops its guard as one. Letting go wakes the
/// presentations that wait for it, so that each tries at once and none waits out its pause while
/// the boundary stands free between two mutations.
#[derive(Debug)]
pub(super) struct DispatchBoundary {
    lock: Mutex<()>,
    released: tokio::sync::Notify,
}

impl DispatchBoundary {
    pub(super) fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            released: tokio::sync::Notify::new(),
        }
    }

    /// Takes the boundary, waiting for whoever holds it.
    fn lock(&self) -> std::sync::LockResult<DispatchGuard<'_>> {
        self.lock
            .lock()
            .map(|guard| DispatchGuard::new(guard, &self.released))
            .map_err(|poisoned| {
                std::sync::PoisonError::new(DispatchGuard::new(
                    poisoned.into_inner(),
                    &self.released,
                ))
            })
    }

    /// Takes the boundary if nobody holds it, and never waits.
    fn try_lock(&self) -> std::sync::TryLockResult<DispatchGuard<'_>> {
        self.lock
            .try_lock()
            .map(|guard| DispatchGuard::new(guard, &self.released))
            .map_err(|refused| match refused {
                std::sync::TryLockError::Poisoned(poisoned) => {
                    std::sync::TryLockError::Poisoned(std::sync::PoisonError::new(
                        DispatchGuard::new(poisoned.into_inner(), &self.released),
                    ))
                }
                std::sync::TryLockError::WouldBlock => std::sync::TryLockError::WouldBlock,
            })
    }

    /// Completes when the boundary is next let go. It is created before a try, so a release that
    /// comes between the try and the wait is not missed.
    pub(super) fn released(&self) -> tokio::sync::futures::Notified<'_> {
        self.released.notified()
    }
}

impl WorkerService {
    /// Takes the service's dispatch boundary, waiting for whoever holds it.
    pub(super) fn take_boundary(&self) -> std::sync::LockResult<DispatchGuard<'_>> {
        self.dispatch.lock()
    }

    /// Takes the service's dispatch boundary if nobody holds it, and never waits.
    pub(super) fn try_take_boundary(&self) -> std::sync::TryLockResult<DispatchGuard<'_>> {
        self.dispatch.try_lock()
    }
}

/// The dispatch boundary, held. Letting go of it wakes the presentations waiting for it.
#[derive(Debug)]
pub struct DispatchGuard<'a> {
    guard: Option<std::sync::MutexGuard<'a, ()>>,
    released: &'a tokio::sync::Notify,
}

impl<'a> DispatchGuard<'a> {
    const fn new(guard: std::sync::MutexGuard<'a, ()>, released: &'a tokio::sync::Notify) -> Self {
        Self {
            guard: Some(guard),
            released,
        }
    }
}

impl DispatchGuard<'_> {
    /// Whether this guard holds `boundary`: the guard points at the release signal of the boundary
    /// that it took, so one pointer comparison tells, and no lock is read or taken.
    pub(super) fn is_of(&self, boundary: &DispatchBoundary) -> bool {
        std::ptr::eq(self.released, &boundary.released)
    }
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        // The lock goes first, so that a woken presentation finds it free.
        drop(self.guard.take());
        self.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use kr_ipc::peer::PeerIdentity;
    use kr_ipc::verify::WorkerIdentity;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::identity::{DesktopBinding, WorkerProfile};
    use kr_protocol::ids::{
        ActionId, ActionWindowId, ActorId, BuildId, ConnectionId, ControllerGeneration,
        EnvironmentId, RequestId, SessionEpoch, SessionId,
    };
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{DurationMs, Nullable, Uuid};
    use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
    use kr_transport::clock::{ContinuousClock, SystemContinuousClock};

    use super::WorkerService;
    use crate::runtime::SessionRuntime;
    use crate::service::{Caller, ConnectionState, Freshness, ServiceBinding};
    use crate::session::{Session, SessionConfig};

    /// A service of its own, with the session and the host tree that it stands on.
    struct Standing {
        service: WorkerService,
        _host: kr_ipc::testing::TempHost,
    }

    fn a_service() -> Standing {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let environment_id: EnvironmentId = host.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process,
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: crate::testing::posix_script("sleep 30"),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(environment.journal_database(session_id)),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: crate::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        let service = WorkerService::new(
            runtime,
            identity,
            endpoint,
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *kr_crypto::keys::AuthorisationKeyPair::generate()
                    .expect("a controller key")
                    .public(),
                controller_generation: ControllerGeneration::new(1),
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                journal_path: None,
            },
        )
        .expect("a worker service");
        Standing {
            service,
            _host: host,
        }
    }

    fn a_mutation(method: Method) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("window").expect("an id"),
            requested_ttl_ms: DurationMs::new(1),
            params: ParamsValue::empty(),
        }
    }

    /// The text that a panic carries.
    fn said(panic: &(dyn std::any::Any + Send)) -> String {
        panic
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_default()
    }

    /// A guard says whose boundary it holds, and the first admission refuses the guard of another
    /// service before it does any work: with the check removed the same call goes on to its first
    /// look at the authority and returns an error, so a refusal that is a panic with the check's own
    /// text shows that nothing ran before it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guard_of_another_service_is_refused_by_the_first_admission() {
        let first = a_service();
        let second = a_service();
        {
            let own = first
                .service
                .take_boundary()
                .expect("the first boundary is free");
            assert!(
                own.is_of(&first.service.dispatch),
                "a guard is of its own boundary"
            );
            assert!(
                !own.is_of(&second.service.dispatch),
                "and of no other service's boundary"
            );
        }
        let foreign = second
            .service
            .take_boundary()
            .expect("the second boundary is free");
        let mut state = ConnectionState::new(
            ConnectionId::new(kr_ipc::new_uuid()),
            &PeerIdentity {
                uid: 0,
                gid: 0,
                pid: None,
            },
            Arc::new(Mutex::new(Vec::new())),
        );
        let method = Method::SessionDetach;
        let mutation = a_mutation(method);
        let entry = WorkerService::entry(method, MethodVersion::V1, ActorIngress::LocalIpc)
            .expect("the worker lists the method");
        let caller = Caller::local(ActorId::new("local:0").expect("an actor"));
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            first.service.receipted(
                &mut state,
                &mutation,
                method,
                entry,
                &caller,
                Freshness::Window(SystemContinuousClock::new().now()),
                &foreign,
            )
        }));
        let panic = refused
            .err()
            .expect("the guard of another service is refused");
        assert_eq!(
            said(&*panic),
            "the dispatch barrier is the one of this service"
        );
        // The refused guard still holds the second service's boundary, which stays held.
        assert!(second.service.try_take_boundary().is_err());
        drop(foreign);
        assert!(second.service.try_take_boundary().is_ok());
    }
}
