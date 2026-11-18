//! The dispatch boundary and its guard.
//!
//! The guard is made here and nowhere else: its constructor and its fields are private to this
//! module, and so are the two takes of a boundary, [`DispatchBoundary::lock`] and
//! [`DispatchBoundary::try_lock`]. The service takes its one boundary through
//! [`WorkerService::take_boundary`] and [`WorkerService::try_take_boundary`], which are written
//! here and read the service's own field, so no other code of the service can take a boundary, a
//! second one made beside the service's included.
//!
//! Nine functions take a borrow of the guard as a parameter, so a caller that holds no guard of a
//! boundary does not compile: `receipted`, `continue_prepared`, `admit_and_dispatch`,
//! `dispatch_accepted`, `standing_pass`, `revalidate_time`, `accept_generation`, `fence` and
//! `fence_what_is_owed`. Scope alone holds the rest of the work that runs under the boundary (the
//! expiry task's release of grants, the maintenance pass's session work after its two calls, the
//! storage recovery and the answers of the announcement), and the compiler does not stop a change
//! there that lets a guard go early. That the guard is the service's own is not held by the
//! compiler either: the two entries (`receipted` and `continue_prepared`) check it with
//! [`DispatchGuard::is_of`] before any work.
//!
//! A thread that holds the boundary and waits for it again waits on itself for ever. The waiting
//! take, [`DispatchBoundary::lock`], compares the calling thread with the thread that holds the
//! boundary before it waits, and panics where they are the same, in every build. The boundary
//! records its holder for this: one number, zero when nobody holds it, that the guard sets when the
//! mutex gives it, also inside a poison error, and clears before the mutex is let go. The record is
//! no lock, and nothing waits on it. Where the first guard is on the stack that the panic unwinds,
//! the mutex is poisoned and every later take of it panics. The trying take, which cannot wait,
//! does not compare: the holder gets "busy" as any other thread does. A take by another thread
//! that the holder waits for is not refused. The tests of the roster in
//! `tests/standing_takes.txt` show each new mention of a function that takes the boundary, by
//! function, to a person; they prove nothing about the property.

use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::WorkerService;

/// The number that the next thread to ask for one is given. A number is never given twice and is
/// never zero, which stands for no holder.
static NEXT_THREAD_NUMBER: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// This thread's number, zero until the thread first asks for it.
    static THREAD_NUMBER: Cell<u64> = const { Cell::new(0) };
}

/// A number for the calling thread: the same for the thread's whole life, and different from the
/// number of every other thread of the process. (The standard library's own thread number is not
/// available at the pinned compiler.)
fn this_thread() -> u64 {
    THREAD_NUMBER.with(|cell| {
        if cell.get() == 0 {
            // A counter that would wrap ends the asking thread with a panic and is never handed
            // out twice.
            let number = NEXT_THREAD_NUMBER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .expect("the process has used every thread number");
            cell.set(number);
        }
        cell.get()
    })
}

/// The dispatch boundary: a lock that says so when it is let go.
///
/// Every holder takes it as an ordinary lock and drops its guard as one. Letting go wakes the
/// presentations that wait for it, so that each tries at once and none waits out its pause while
/// the boundary stands free between two mutations.
#[derive(Debug)]
pub(super) struct DispatchBoundary {
    lock: Mutex<()>,
    released: tokio::sync::Notify,
    /// The number of the thread that holds the boundary, or zero. Only the holder writes it, and
    /// the mutex orders the holders, so relaxed loads and stores are enough.
    holder: AtomicU64,
}

impl DispatchBoundary {
    pub(super) fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            released: tokio::sync::Notify::new(),
            holder: AtomicU64::new(0),
        }
    }

    /// Takes the boundary, waiting for whoever holds it. A thread that holds it already would wait
    /// on itself for ever, so that thread is refused with a panic before it waits.
    fn lock(&self) -> std::sync::LockResult<DispatchGuard<'_>> {
        assert!(
            self.holder.load(Ordering::Relaxed) != this_thread(),
            "the thread that holds the dispatch boundary took it again"
        );
        self.lock
            .lock()
            .map(|guard| DispatchGuard::new(guard, self))
            .map_err(|poisoned| {
                std::sync::PoisonError::new(DispatchGuard::new(poisoned.into_inner(), self))
            })
    }

    /// Takes the boundary if nobody holds it, and never waits. It cannot wait on itself, so it
    /// does not compare: the thread that holds the boundary gets "busy", as any other does.
    fn try_lock(&self) -> std::sync::TryLockResult<DispatchGuard<'_>> {
        self.lock
            .try_lock()
            .map(|guard| DispatchGuard::new(guard, self))
            .map_err(|refused| match refused {
                std::sync::TryLockError::Poisoned(poisoned) => std::sync::TryLockError::Poisoned(
                    std::sync::PoisonError::new(DispatchGuard::new(poisoned.into_inner(), self)),
                ),
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
    boundary: &'a DispatchBoundary,
}

impl<'a> DispatchGuard<'a> {
    /// The guard of a boundary whose mutex has just given `guard`: the calling thread is now the
    /// holder.
    fn new(guard: std::sync::MutexGuard<'a, ()>, boundary: &'a DispatchBoundary) -> Self {
        boundary.holder.store(this_thread(), Ordering::Relaxed);
        Self {
            guard: Some(guard),
            boundary,
        }
    }
}

impl DispatchGuard<'_> {
    /// Whether this guard holds `boundary`: one pointer comparison tells, and no lock is read or
    /// taken.
    pub(super) fn is_of(&self, boundary: &DispatchBoundary) -> bool {
        std::ptr::eq(self.boundary, boundary)
    }
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        // The record is cleared before the lock is let go: after it, the clear could erase the
        // number of the thread that took the boundary next.
        self.boundary.holder.store(0, Ordering::Relaxed);
        // The lock goes next, so that a woken presentation finds it free.
        drop(self.guard.take());
        self.boundary.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, TryLockError, mpsc};
    use std::time::Duration;

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

    use super::{DispatchBoundary, WorkerService, this_thread};
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
    /// service with a panic of the check's own text. That the check is the entry's first statement
    /// is read by the roster case `the_two_entries_begin_with_the_check_that_their_guard_is_the_services_own`;
    /// this case shows that the guard of another boundary is refused, and that the comparison gives
    /// false for it and true for the service's own.
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
        assert!(
            refused.is_err(),
            "the guard of another service is refused by a panic"
        );
        let panic = refused.err().expect("a panic, as asserted above");
        assert_eq!(
            said(&*panic),
            "the dispatch barrier is the one of this service"
        );
        // The refused guard still holds the second service's boundary, which stays held.
        assert!(second.service.try_take_boundary().is_err());
        drop(foreign);
        assert!(second.service.try_take_boundary().is_ok());
    }

    /// How long a case waits for the answer of a scene that runs on a thread of its own. A scene
    /// in which a thread waits on itself never answers, so this bound ends the case.
    const BOUND: Duration = Duration::from_secs(10);

    /// The words that the boundary's waiting take panics with when its caller holds the boundary.
    const REFUSAL: &str = "the thread that holds the dispatch boundary took it again";

    /// What a take of a boundary came to.
    #[derive(Debug, PartialEq, Eq)]
    enum Taken {
        /// The take gave a guard of a boundary that no panic had poisoned, and it was let go.
        Free,
        /// The take gave a guard inside a poison error, and it was let go.
        Poisoned,
        /// The trying take found the boundary held.
        Busy,
        /// The take panicked, with this text.
        Refused(String),
    }

    /// The waiting take, with a panic of the take caught and its text kept.
    fn waits(boundary: &DispatchBoundary) -> Taken {
        catch_unwind(AssertUnwindSafe(|| match boundary.lock() {
            Ok(_guard) => Taken::Free,
            Err(_poisoned) => Taken::Poisoned,
        }))
        .unwrap_or_else(|panic| Taken::Refused(said(&*panic)))
    }

    /// The trying take, with a panic of the take caught and its text kept.
    fn tries(boundary: &DispatchBoundary) -> Taken {
        catch_unwind(AssertUnwindSafe(|| match boundary.try_lock() {
            Ok(_guard) => Taken::Free,
            Err(TryLockError::Poisoned(_poisoned)) => Taken::Poisoned,
            Err(TryLockError::WouldBlock) => Taken::Busy,
        }))
        .unwrap_or_else(|panic| Taken::Refused(said(&*panic)))
    }

    /// Runs `scene` on a thread of its own and gives the receiver of its answer. The case receives
    /// with `BOUND`, so a scene that never answers fails the case and does not stand.
    fn on_a_thread_of_its_own<T: Send + 'static>(
        scene: impl FnOnce() -> T + Send + 'static,
    ) -> mpsc::Receiver<T> {
        let (answer, answered) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(scene());
        });
        answered
    }

    /// A boundary that a panic poisoned: a thread took it and panicked while it held the guard.
    fn a_poisoned_boundary() -> Arc<DispatchBoundary> {
        let boundary = Arc::new(DispatchBoundary::new());
        let poisoner = Arc::clone(&boundary);
        let ended = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("the boundary is free");
            panic!("a panic under the boundary");
        })
        .join();
        assert!(ended.is_err(), "the thread ended by its panic");
        boundary
    }

    /// The thread that holds the boundary and waits for it again waits on itself for ever. The
    /// waiting take refuses it with a panic. The whole scene runs on a thread of its own, with the
    /// first guard held outside the catch, so that a take without the refusal fails the case at
    /// its bound.
    #[test]
    fn the_thread_that_holds_the_boundary_is_refused_when_it_waits_for_it_again() {
        let boundary = Arc::new(DispatchBoundary::new());
        let answered = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            move || {
                let first = boundary.lock().expect("the boundary is free");
                let second = waits(&boundary);
                drop(first);
                second
            }
        });
        let Ok(second) = answered.recv_timeout(BOUND) else {
            panic!(
                "the thread that holds the boundary waited for it again and gave no answer \
                 within {BOUND:?}: it waits on itself"
            );
        };
        assert_eq!(second, Taken::Refused(REFUSAL.to_owned()));
        assert_eq!(
            tries(&boundary),
            Taken::Free,
            "the boundary is free once the holder has dropped its guard"
        );
    }

    /// The trying take cannot wait on itself, so it does not refuse: the holder gets "busy", as
    /// any other thread does.
    #[test]
    fn the_thread_that_holds_the_boundary_gets_busy_when_it_tries_for_it_again() {
        let boundary = DispatchBoundary::new();
        let first = boundary.lock().expect("the boundary is free");
        assert_eq!(tries(&boundary), Taken::Busy);
        drop(first);
        assert_eq!(tries(&boundary), Taken::Free);
    }

    /// Another thread's try finds the boundary busy, and another thread that waits for it is not
    /// refused: it gets the boundary once the holder has dropped its guard.
    #[test]
    fn another_thread_gets_busy_when_it_tries_and_the_boundary_after_the_drop_when_it_waits() {
        let boundary = Arc::new(DispatchBoundary::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let held = boundary.lock().expect("the boundary is free");
        let tried = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            move || tries(&boundary)
        });
        let Ok(tried) = tried.recv_timeout(BOUND) else {
            panic!("another thread's try gave no answer within {BOUND:?}");
        };
        assert_eq!(tried, Taken::Busy);
        let waiting = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            let dropped = Arc::clone(&dropped);
            move || {
                catch_unwind(AssertUnwindSafe(|| {
                    let _guard = boundary.lock().expect("the boundary is not poisoned");
                    dropped.load(Ordering::SeqCst)
                }))
                .map_err(|panic| said(&*panic))
            }
        });
        dropped.store(true, Ordering::SeqCst);
        drop(held);
        let Ok(came_after_the_drop) = waiting.recv_timeout(BOUND) else {
            panic!("another thread that waited for the boundary got it within {BOUND:?}: never");
        };
        assert_eq!(
            came_after_the_drop,
            Ok(true),
            "the waiting thread is not refused, and gets the boundary only after the drop"
        );
    }

    /// After the drop, the same thread takes the boundary again, waiting or trying, with no
    /// refusal.
    #[test]
    fn the_same_thread_takes_the_boundary_again_after_the_drop() {
        let boundary = Arc::new(DispatchBoundary::new());
        let answered = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            move || {
                let first = boundary.lock().expect("the boundary is free");
                drop(first);
                let waited = waits(&boundary);
                let tried = tries(&boundary);
                (waited, tried)
            }
        });
        let Ok(again) = answered.recv_timeout(BOUND) else {
            panic!("the thread that dropped its guard gave no answer within {BOUND:?}");
        };
        assert_eq!(again, (Taken::Free, Taken::Free));
    }

    /// A panic that unwinds the guard lets the boundary go, and poisons it, as a std mutex does:
    /// the next take by that thread is no refusal. It is a poison error, for the waiting form and
    /// for the trying form.
    #[test]
    fn a_panic_that_unwinds_the_guard_clears_the_holder_and_poisons_the_boundary() {
        let boundary = Arc::new(DispatchBoundary::new());
        let answered = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            move || {
                let unwound = catch_unwind(AssertUnwindSafe(|| {
                    let _guard = boundary.lock().expect("the boundary is free");
                    panic!("a panic under the boundary");
                }));
                let waited = waits(&boundary);
                let tried = tries(&boundary);
                (unwound.is_err(), waited, tried)
            }
        });
        let Ok(after) = answered.recv_timeout(BOUND) else {
            panic!("the thread whose guard a panic unwound gave no answer within {BOUND:?}");
        };
        assert_eq!(after, (true, Taken::Poisoned, Taken::Poisoned));
    }

    /// A guard that comes inside the poison error of a waiting take holds the boundary like any
    /// other: the holder's second waiting take is refused.
    #[test]
    fn a_guard_that_comes_inside_a_poison_error_of_a_wait_holds_the_boundary() {
        let boundary = a_poisoned_boundary();
        let answered = on_a_thread_of_its_own(move || {
            let Err(poisoned) = boundary.lock() else {
                return Taken::Free;
            };
            let first = poisoned.into_inner();
            let second = waits(&boundary);
            drop(first);
            second
        });
        let Ok(second) = answered.recv_timeout(BOUND) else {
            panic!(
                "the thread that holds the boundary through a poison error waited for it again \
                 and gave no answer within {BOUND:?}: it waits on itself"
            );
        };
        assert_eq!(second, Taken::Refused(REFUSAL.to_owned()));
    }

    /// The record names the thread that holds the boundary while its guard stands, for the waiting
    /// take and for the trying one, and is zero once the guard is dropped.
    #[test]
    fn the_record_names_the_holder_while_the_guard_stands_and_is_zero_after_the_drop() {
        let boundary = Arc::new(DispatchBoundary::new());
        let answered = on_a_thread_of_its_own({
            let boundary = Arc::clone(&boundary);
            move || {
                let number = this_thread();
                let held = boundary.lock().expect("the boundary is free");
                let during_the_wait = boundary.holder.load(Ordering::Relaxed);
                drop(held);
                let after_the_wait = boundary.holder.load(Ordering::Relaxed);
                let held = boundary.try_lock().expect("the boundary is free");
                let during_the_try = boundary.holder.load(Ordering::Relaxed);
                drop(held);
                let after_the_try = boundary.holder.load(Ordering::Relaxed);
                (
                    number,
                    [
                        during_the_wait,
                        after_the_wait,
                        during_the_try,
                        after_the_try,
                    ],
                )
            }
        });
        let Ok((number, record)) = answered.recv_timeout(BOUND) else {
            panic!("the thread that took the boundary gave no answer within {BOUND:?}");
        };
        assert_ne!(
            number, 0,
            "no thread has the number that stands for no holder"
        );
        assert_eq!(record, [number, 0, number, 0]);
    }

    /// A thread's number is the same for its whole life, never zero, and its own: no other thread
    /// of the process has it.
    #[test]
    fn every_thread_has_a_number_of_its_own_that_is_never_zero() {
        let mine = this_thread();
        assert_ne!(mine, 0);
        assert_eq!(this_thread(), mine, "the number does not change");
        let answered = on_a_thread_of_its_own(|| (this_thread(), this_thread()));
        let Ok((other, again)) = answered.recv_timeout(BOUND) else {
            panic!("another thread gave no number within {BOUND:?}");
        };
        assert_ne!(other, 0);
        assert_eq!(other, again, "the number does not change");
        assert_ne!(other, mine, "two threads do not share a number");
    }

    /// The record belongs to one boundary: a thread that holds one boundary is not refused when it
    /// waits for another.
    #[test]
    fn the_thread_that_holds_one_boundary_is_not_refused_when_it_waits_for_another() {
        let first = Arc::new(DispatchBoundary::new());
        let second = Arc::new(DispatchBoundary::new());
        let answered = on_a_thread_of_its_own(move || {
            let held = first.lock().expect("the first boundary is free");
            let taken = waits(&second);
            drop(held);
            taken
        });
        let Ok(taken) = answered.recv_timeout(BOUND) else {
            panic!("the thread that holds one boundary gave no answer within {BOUND:?}");
        };
        assert_eq!(taken, Taken::Free);
    }

    /// A guard that comes inside the poison error of a trying take holds the boundary like any
    /// other: the holder's waiting take is refused.
    #[test]
    fn a_guard_that_comes_inside_a_poison_error_of_a_try_holds_the_boundary() {
        let boundary = a_poisoned_boundary();
        let answered = on_a_thread_of_its_own(move || {
            let Err(TryLockError::Poisoned(poisoned)) = boundary.try_lock() else {
                return Taken::Free;
            };
            let first = poisoned.into_inner();
            let second = waits(&boundary);
            drop(first);
            second
        });
        let Ok(second) = answered.recv_timeout(BOUND) else {
            panic!(
                "the thread that holds the boundary through the poison error of a try waited for \
                 it again and gave no answer within {BOUND:?}: it waits on itself"
            );
        };
        assert_eq!(second, Taken::Refused(REFUSAL.to_owned()));
    }
}
