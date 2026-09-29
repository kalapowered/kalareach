use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::ids::{ActorId, ConnectionId, DeviceId};
use kr_protocol::scalars::{DurationMs, Nullable};

use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;

use super::output::{Authorisation, FrameSink, RelayGrant, Relaying, RemoteOutput, Written};
use crate::grants::organisation::testing::TestOrganisation;
use crate::grants::policy::{HeldBound, Stands};
use crate::service::Controller;

/// How long a test waits for a write to start waiting before it fails. A write that returns
/// without waiting would otherwise hold the test, and the job running it, for ever.
const WAIT_BOUND: Duration = Duration::from_secs(30);

/// How far one frame got at the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reached {
    /// The first part of the frame, and then the peer stopped making room.
    Part,
    /// All of it.
    Whole,
}

/// A control stream whose writer, and whose peer, a test holds.
///
/// It keeps the contract a real one keeps: the writer is taken first, and `admits` is read
/// after it has been taken and before every attempt to hand bytes over.
#[derive(Debug)]
struct HeldStream {
    /// The writer. A write takes a permit, and there are none until the test gives one.
    writer: tokio::sync::Semaphore,
    /// Room at the peer for the rest of a frame, when the peer stops reading part way.
    room: Option<tokio::sync::Semaphore>,
    /// One permit each time a write starts to wait: for the writer, or for the peer.
    waits: tokio::sync::Semaphore,
    reached: std::sync::Mutex<Vec<Reached>>,
    closed: AtomicBool,
}

impl HeldStream {
    fn new(peer_stops_reading: bool) -> Arc<Self> {
        Arc::new(Self {
            writer: tokio::sync::Semaphore::new(0),
            room: peer_stops_reading.then(|| tokio::sync::Semaphore::new(0)),
            waits: tokio::sync::Semaphore::new(0),
            reached: std::sync::Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        })
    }

    /// Returns once writes have started to wait `times` times, and fails the test when they
    /// have not within [`WAIT_BOUND`].
    async fn waited(&self, times: u32) {
        tokio::time::timeout(WAIT_BOUND, self.waits.acquire_many(times))
            .await
            .unwrap_or_else(|_| {
                panic!("the write did not start to wait {times} times within {WAIT_BOUND:?}")
            })
            .expect("the count stays open")
            .forget();
    }

    fn reached(&self) -> Vec<Reached> {
        self.reached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl FrameSink for Arc<HeldStream> {
    fn send_while<'a>(
        &'a self,
        _frame: &'a ControlFrame,
        admits: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            self.waits.add_permits(1);
            let _writer = self.writer.acquire().await.expect("the writer stays open");
            if !admits() {
                return Ok(false);
            }
            if let Some(room) = &self.room {
                self.reached
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Reached::Part);
                self.waits.add_permits(1);
                let _room = room.acquire().await.expect("the peer stays open");
            }
            if !admits() {
                return Ok(false);
            }
            self.reached
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Reached::Whole);
            Ok(true)
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// A registered connection's write boundary, writing to `stream`.
fn output(controller: &Arc<Controller>, stream: &Arc<HeldStream>) -> RemoteOutput {
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    controller.admitted_table().insert(
        connection_id,
        crate::service::AdmittedConnection {
            actor_id: ActorId::new("device:test").expect("a principal"),
            admitted_revision: controller.policy().authority_revision(),
        },
    );
    RemoteOutput::writing_to(
        Box::new(Arc::clone(stream)),
        Arc::new(Authorisation {
            controller: Arc::clone(controller),
            devices: Arc::clone(controller.devices()),
            pending: Arc::new(crate::service::net::devices::PendingExpiry::default()),
            clock: Arc::new(crate::service::net::devices::ClockTrust::default()),
            device_id: DeviceId::new(kr_ipc::new_uuid()),
            connection_id,
            grant_deadline: None,
            grant_expires_at_ms: None,
            expired: AtomicBool::new(false),
            recorded: AtomicBool::new(false),
        }),
    )
}

/// The decision a batch was written under, taken now and bounded by nothing but events.
fn decided_now(controller: &Controller) -> RelayGrant {
    RelayGrant {
        epoch: controller.authority_epoch(),
        until: None,
        lapses_at_ms: None,
        under: Vec::new(),
    }
}

fn batch() -> ControlFrame {
    ControlFrame::Event(ControlEvent::Keepalive)
}

/// The owner chooses a bounded offline policy with no synchronisation to measure from, so a
/// paired device's remote access is outside its bound at once.
fn lapse_the_offline_bound(controller: &Controller) {
    controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: DurationMs::new(60_000),
                last_synchronised_at_ms: Nullable::null(),
            }));
        })
        .expect("the owner's choice is recorded");
}

/// Asserts that the grant the connection writes under was left as it was.
fn grant_left_alone(output: &RemoteOutput) {
    assert!(
        output.authority.has_time_left(),
        "a lapsed bound is not an expiry of the grant"
    );
    assert_eq!(
        output.authority.pending.owed(),
        0,
        "and no expiry is written"
    );
}

/// A batch decided while the bound held, and then held at the writer while it lapsed, does not
/// reach the peer when the writer comes free. Nothing of it went, so the stream is whole and
/// the batch is decided again rather than the connection ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_held_at_the_writer_is_not_written_once_the_policy_moves() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::super::tests::daemon(&temp).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();

    stream.writer.add_permits(1);
    let redecide = || true;
    let relaying = Relaying {
        grant: decided_now(&controller),
        redecide: &redecide,
    };
    assert_eq!(
        output.write(&batch(), &[], Some(relaying)).await,
        Written::Sent,
        "with nothing moving, the batch goes"
    );
    // The writer is held again from here, and the wait that write made is counted.
    stream
        .writer
        .try_acquire()
        .expect("the writer came back")
        .forget();
    stream.waited(1).await;

    let relaying = Relaying {
        grant: decided_now(&controller),
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        lapse_the_offline_bound(&controller);
        stream.writer.add_permits(1);
    });
    assert_eq!(written, Written::Undecided);
    assert_eq!(
        stream.reached(),
        vec![Reached::Whole],
        "only the first batch went"
    );
    assert!(
        !stream.closed(),
        "the stream is whole, so the connection stands"
    );
    grant_left_alone(&output);
    drop(controller);
}

/// The same, with the writer never coming free: the watch finds the decision gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_that_waits_for_the_writer_is_decided_again_by_the_watch() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::super::tests::daemon(&temp).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();

    let redecide = || true;
    let relaying = Relaying {
        grant: decided_now(&controller),
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        lapse_the_offline_bound(&controller);
    });
    assert_eq!(written, Written::Undecided);
    assert!(stream.reached().is_empty(), "nothing reached the peer");
    assert!(!stream.closed());
    grant_left_alone(&output);
    drop(controller);
}

/// A batch part way to a peer that stopped reading is abandoned when the policy moves, and the
/// connection is closed, which is what stops the rest of it: a frame left in pieces ends the
/// stream. Whether the peer makes room again or never does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_waiting_for_the_peer_is_abandoned_once_the_policy_moves() {
    for peer_makes_room in [true, false] {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(true);
        let output = output(&controller, &stream);
        let frame = batch();
        stream.writer.add_permits(1);

        let redecide = || true;
        let relaying = Relaying {
            grant: decided_now(&controller),
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
            // Once for the writer, and once for the peer.
            stream.waited(2).await;
            lapse_the_offline_bound(&controller);
            if peer_makes_room {
                stream.room.as_ref().expect("a slow peer").add_permits(1);
            }
        });
        assert_eq!(
            written,
            Written::Withdrawn,
            "peer makes room: {peer_makes_room}"
        );
        assert_eq!(stream.reached(), vec![Reached::Part], "the rest never went");
        assert!(stream.closed(), "the connection is closed");
        grant_left_alone(&output);
        drop(controller);
    }
}

/// A decision bounded in time stops holding when its bound passes while the batch waits. On
/// clocks the test moves by hand, so the bound passes only once the batch is waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_held_past_its_decisions_bound_is_not_written() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, _wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();

    let redecide = || true;
    let relaying = Relaying {
        grant: RelayGrant {
            epoch: controller.authority_epoch(),
            until: controller
                .clock
                .now()
                .checked_add(Duration::from_millis(30)),
            lapses_at_ms: None,
            under: Vec::new(),
        },
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        continuous.advance(Duration::from_millis(60));
        stream.writer.add_permits(1);
    });
    assert_eq!(written, Written::Undecided);
    assert!(stream.reached().is_empty());
    assert!(!stream.closed());
    drop(controller);
}

/// A decision the watch takes again and finds refused stops a waiting batch, although nothing
/// the poll reads has moved: a clock stepped forward ends a decision that way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_the_decision_no_longer_allows_is_not_written() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::super::tests::daemon(&temp).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();

    let allowed = AtomicBool::new(true);
    let redecide = || allowed.load(Ordering::Acquire);
    let relaying = Relaying {
        grant: decided_now(&controller),
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        allowed.store(false, Ordering::Release);
    });
    assert_eq!(written, Written::Undecided);
    assert!(stream.reached().is_empty());
    drop(controller);
}

/// A batch whose decision runs out at a moment in UTC is not written once another decision
/// has read a clock past that moment, although the epoch has not moved and the wall clock
/// the boundary reads may be behind: the floor that decision raised is read at every attempt.
/// Whether the batch waited for the writer, or had started and waited for the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_is_not_written_once_the_floor_passes_its_decision() {
    for peer_stops_reading in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(peer_stops_reading);
        let output = output(&controller, &stream);
        let frame = batch();
        if peer_stops_reading {
            stream.writer.add_permits(1);
        }
        let (lasting, lasting_record) = super::super::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            controller.policy().authority_revision(),
        );
        let lapses_at_ms = kr_ipc::now_ms().get() + 60 * 60 * 1000;

        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: None,
                lapses_at_ms: Some(lapses_at_ms),
                under: Vec::new(),
            },
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
            stream.waited(if peer_stops_reading { 2 } else { 1 }).await;
            // Another request is decided at a reading past the moment, which raises the floor.
            controller
                .decide_for_device(
                    &lasting,
                    &lasting_record,
                    super::super::tests::listing(&temp, lapses_at_ms + 1),
                )
                .expect("a grant that does not expire");
            if peer_stops_reading {
                stream.room.as_ref().expect("a slow peer").add_permits(1);
            } else {
                stream.writer.add_permits(1);
            }
        });
        if peer_stops_reading {
            assert_eq!(written, Written::Withdrawn);
            assert_eq!(stream.reached(), vec![Reached::Part]);
            assert!(stream.closed());
        } else {
            assert_eq!(written, Written::Undecided);
            assert!(stream.reached().is_empty());
            assert!(!stream.closed());
        }
        drop(controller);
    }
}

/// Records a paired device whose grant runs out at `expiry`, and returns the grant's identifier.
fn a_paired_device(
    controller: &Controller,
    expiry: kr_protocol::grant::GrantExpiry,
) -> kr_protocol::ids::GrantId {
    let (grant, _) = super::super::tests::granted(expiry, controller.policy().authority_revision());
    let record = crate::service::net::devices::DeviceRecord {
        device_id: grant.recipient_device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([7; 32]),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([8; 32]),
        stored_envelope: None,
        notification_preview: None,
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: grant.clone(),
        paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    };
    controller
        .devices()
        .commit(&record)
        .expect("the device is recorded");
    grant.grant_id
}

/// A floor raised while the policy's lock is held stops a batch as surely as one a device's
/// decision raised. A workflow's grant that runs out at the moment the batch's decision does is
/// refused at a reading past it, and the lock is then held while that refusal's write waits for
/// storage. The batch is not written, whether it waited for the writer or had started and
/// waited for the peer.
///
/// The store is held until the batch's write has returned, and the decision's write waits for
/// it that long, so the lock is held throughout: a write that took the lock could not return
/// within its bound, and the lock is still held when it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_is_not_written_once_a_floor_raised_under_the_lock_passes_its_decision() {
    use kr_automation::authority::AuthoritySource as _;

    for peer_stops_reading in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        // On clocks the test moves by hand: the grant runs out only at the reading the
        // decision below is given, however long the runner takes between two steps.
        let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        controller
            .sharing()
            .grants()
            .wait_for_storage_up_to(WAIT_BOUND * 4)
            .expect("the store waits as long as the test holds it");
        let stream = HeldStream::new(peer_stops_reading);
        let output = output(&controller, &stream);
        let frame = batch();
        if peer_stops_reading {
            stream.writer.add_permits(1);
        }
        let now = wall.load(Ordering::SeqCst);
        let lapses_at_ms = now + 60 * 60 * 1000;
        let grant_id = a_paired_device(
            &controller,
            kr_protocol::grant::GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(lapses_at_ms),
            },
        );
        let grants = crate::automation::HostGrants::for_daemon(&controller);
        // The grant's anchor in this boot is taken the first time anything asks, which writes;
        // it is asked here, before storage is held, so the decision below waits only on the
        // floor's write.
        grants
            .grant(grant_id, now)
            .expect("the grant stands before it runs out");

        // Another writer holds storage, so the write that decision owes waits with the lock
        // held.
        let storage = rusqlite::Connection::open(temp.environment().registry_database())
            .expect("opens the registry");
        storage
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("storage is held");

        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: None,
                lapses_at_ms: Some(lapses_at_ms),
                under: Vec::new(),
            },
            redecide: &redecide,
        };
        let mut deciding = None;
        // Longer than the helper below may take to let the batch go, and far shorter than the
        // decision's write waits for the store.
        let written = async {
            tokio::time::timeout(WAIT_BOUND * 2, output.write(&frame, &[], Some(relaying)))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "the batch's write did not return while the decision held the \
                         policy's lock"
                    )
                })
        };
        let (written, ()) = tokio::join!(written, async {
            stream.waited(if peer_stops_reading { 2 } else { 1 }).await;
            deciding = Some(std::thread::spawn(move || {
                grants.grant(grant_id, lapses_at_ms + 1)
            }));
            // What the write decides from is the floor that decision raises, and the decision
            // holds the policy's lock while its write waits for storage. The batch is released
            // once both hold; the lock alone can be taken before the floor moves.
            tokio::time::timeout(WAIT_BOUND, async {
                while controller.utc_floor().get() <= lapses_at_ms
                    || controller.policy.try_lock().is_ok()
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the decision did not raise the floor and hold the lock within \
                     {WAIT_BOUND:?}"
                )
            });
            if peer_stops_reading {
                stream.room.as_ref().expect("a slow peer").add_permits(1);
            } else {
                stream.writer.add_permits(1);
            }
        });
        // The write has returned, and the decision still holds the lock it held before the
        // batch was let go: the write never took it.
        assert!(
            controller.policy.try_lock().is_err(),
            "the decision still holds the policy's lock"
        );
        let deciding = deciding.expect("the workflow's grant was decided");
        assert!(
            !deciding.is_finished(),
            "the decision is still waiting for the store"
        );
        storage.execute_batch("ROLLBACK;").expect("storage is free");
        let _ = deciding.join();
        if peer_stops_reading {
            assert_eq!(written, Written::Withdrawn);
            assert_eq!(stream.reached(), vec![Reached::Part]);
            assert!(stream.closed());
        } else {
            assert_eq!(written, Written::Undecided);
            assert!(stream.reached().is_empty());
            assert!(!stream.closed());
        }
        drop(controller);
    }
}

/// A moment in UTC the boundary reads for itself stays read. A grant runs out while its batch
/// waits and nothing but the boundary reads the clock; the floor that reading raised is written
/// down by the next step that may write, and a decision after the wall clock was wound back,
/// on this connection or on another after a restart, finds the grant run out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_moment_the_boundary_reads_holds_for_every_later_decision() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();
    let lapses_at_ms = wall.load(Ordering::SeqCst) + 200;
    let (expiring, expiring_record) = super::super::tests::granted(
        kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(lapses_at_ms),
        },
        controller.policy().authority_revision(),
    );

    let redecide = || true;
    let relaying = Relaying {
        grant: RelayGrant {
            epoch: controller.authority_epoch(),
            until: None,
            lapses_at_ms: Some(lapses_at_ms),
            under: Vec::new(),
        },
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        // Nothing but the boundary reads the wall clock from here.
        wall.store(lapses_at_ms + 200, Ordering::SeqCst);
        stream.writer.add_permits(1);
    });
    assert_eq!(written, Written::Undecided);
    assert!(stream.reached().is_empty());

    // What the relay and the record task do outside the poll.
    controller.settle_floor();
    assert!(
        super::super::tests::written_floor(&controller) >= lapses_at_ms,
        "the moment the boundary read is written down"
    );
    let wound_back = super::super::tests::listing(&temp, lapses_at_ms - 60_000);
    let refused = controller
        .decide_for_device(&expiring, &expiring_record, wound_back.clone())
        .expect_err("the moment the boundary read holds for the retry");
    assert!(
        matches!(
            refused,
            crate::config::ceilings::CeilingRefusal::Refused(
                crate::grants::Refusal::Expired { .. }
            )
        ),
        "{refused:?}"
    );

    drop(output);
    drop(controller);
    let controller = super::super::tests::daemon(&temp).await;
    controller
        .decide_for_device(&expiring, &expiring_record, wound_back)
        .expect_err("and for another connection after a restart");
    drop(controller);
}

/// An offline bound the boundary finds run out on the continuous clock stops the batch, and
/// the boundary writes nothing itself: it owes the record of the time the bound has spent, and
/// the step outside the poll that settles the floor writes it down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_the_boundary_finds_run_out_is_written_down_outside_the_poll() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let stream = HeldStream::new(false);
    let output = output(&controller, &stream);
    let frame = batch();
    let synchronised = wall.load(Ordering::SeqCst);
    controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: DurationMs::new(200),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(
                    synchronised,
                )),
            }));
        })
        .expect("the owner's choice is recorded");
    let (lasting, lasting_record) = super::super::tests::granted(
        kr_protocol::grant::GrantExpiry::Never,
        controller.policy().authority_revision(),
    );
    let decision = controller
        .decide_for_device(
            &lasting,
            &lasting_record,
            super::super::tests::listing(&temp, synchronised),
        )
        .expect("inside the bound");
    let recorded = |controller: &Controller| {
        controller
            .devices()
            .offline_anchor_for(synchronised, &controller.boot_identity)
            .expect("reads the record")
            .expect("the bound's time is recorded")
            .0
            .elapsed_ms
    };

    let redecide = || true;
    let relaying = Relaying {
        grant: RelayGrant {
            epoch: controller.authority_epoch(),
            until: decision
                .decided
                .permitted
                .offline
                .as_ref()
                .and_then(crate::grants::policy::HeldBound::continuous_deadline),
            lapses_at_ms: None,
            under: Vec::new(),
        },
        redecide: &redecide,
    };
    let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
        stream.waited(1).await;
        continuous.advance(Duration::from_millis(400));
        stream.writer.add_permits(1);
    });
    assert_eq!(written, Written::Undecided);
    assert!(stream.reached().is_empty());
    assert!(
        recorded(&controller) < 200,
        "the boundary wrote nothing itself"
    );

    // What the relay and the record task do outside the poll.
    controller.settle_floor();
    assert!(
        recorded(&controller) > 200,
        "the time the bound has spent is written down"
    );
    drop(output);
    drop(controller);
}

/// A recording of every frame a connection hands its stream, each after the stream's own check.
#[derive(Debug, Default)]
struct Recording(std::sync::Mutex<Vec<ControlFrame>>);

impl Recording {
    fn frames(&self) -> Vec<ControlFrame> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl FrameSink for Arc<Recording> {
    fn send_while<'a>(
        &'a self,
        frame: &'a ControlFrame,
        admits: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            if !admits() {
                return Ok(false);
            }
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(frame.clone());
            Ok(true)
        })
    }

    fn close(&self) {}
}

/// The record of the paired device a grant was issued to.
fn record_for(grant: &kr_protocol::grant::Grant) -> crate::service::net::devices::DeviceRecord {
    crate::service::net::devices::DeviceRecord {
        device_id: grant.recipient_device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([7; 32]),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([8; 32]),
        stored_envelope: None,
        notification_preview: None,
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: grant.clone(),
        paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    }
}

/// A member device of a new organisation named by `byte`, bound to a lease installed at `now`,
/// and its grant and a connection of its own, with that connection's decision of a session
/// listing.
fn member(
    controller: &Arc<Controller>,
    byte: u8,
    now: u64,
) -> (
    TestOrganisation,
    kr_protocol::grant::Grant,
    super::RemoteConnection,
    super::decision::Asked,
) {
    let organisation = TestOrganisation::new(byte, now - 60 * 60 * 1000);
    let (grant, _) = super::super::tests::leased_member(controller, &organisation, now);
    let connection = super::RemoteConnection::for_test(controller, record_for(&grant));
    let asked = connection
        .ask(None, Method::SessionList.entry(), false)
        .expect("the lease answers for the member's grant");
    (organisation, grant, connection, asked)
}

/// Runs the frame gate's check of `under` by `judge` on a thread of its own, and fails the test
/// when it has not answered within [`WAIT_BOUND`].
fn gate(
    controller: &Arc<Controller>,
    under: &[HeldBound],
    judge: fn(&HeldBound, kr_transport::clock::ContinuousInstant, u64) -> Stands,
) -> bool {
    let (answer, answered) = std::sync::mpsc::channel();
    let controller = Arc::clone(controller);
    let under = under.to_vec();
    std::thread::spawn(move || {
        let _ = answer.send(super::output::bounds_hold(&controller, &under, judge));
    });
    answered
        .recv_timeout(WAIT_BOUND)
        .expect("the gate answers without waiting")
}

/// A frame gate reads one snapshot of each bound, and never waits for the writer publishing the
/// next. With a lease's renewal stopped after its snapshot is built and before the swap, and the
/// first lease's end passed meanwhile, the gate reads the snapshot in force, which has ended;
/// stopped after the swap, it reads the renewal, which continues the lease's run. The writer
/// holds the policy's lock throughout, and the store is held with every write made to wait an
/// hour for it, so a gate that took the lock or called the store could not answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_gate_reads_one_snapshot_and_never_waits_for_its_writer() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let (organisation, grant, _connection, asked) = member(&controller, 0x41, now);
    let under = asked.decision.bounds();
    assert!(
        gate(&controller, &under, HeldBound::stands_at),
        "the lease holds"
    );

    // A minute on, while the lease holds, a renewal is presented: it ends a minute later.
    continuous.advance(Duration::from_secs(60));
    let (built, stopped) = std::sync::mpsc::channel();
    let (swap, swapping) = std::sync::mpsc::channel::<()>();
    let (swapped, swap_seen) = std::sync::mpsc::channel();
    let (finish, finishing) = std::sync::mpsc::channel::<()>();
    let writer = {
        let controller = Arc::clone(&controller);
        let grant = grant.clone();
        std::thread::spawn(move || {
            crate::grants::policy::publishing::stop_before_the_swap(move || {
                let _ = built.send(());
                let _ = swapping.recv();
            });
            crate::grants::policy::publishing::stop_after_the_swap(move || {
                let _ = swapped.send(());
                let _ = finishing.recv();
            });
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 1_000,
                &[ActionRight::SessionView],
            )
        })
    };
    stopped
        .recv_timeout(WAIT_BOUND)
        .expect("the renewal built its snapshot");
    // Past the first lease's end and inside the renewal's, with the renewal not yet swapped in.
    continuous.advance(Duration::from_secs(14 * 60 + 30));
    controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(Duration::from_secs(3_600))
        .expect("every write waits an hour for the store");
    let storage = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    storage
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("storage is held");

    assert!(
        !gate(&controller, &under, HeldBound::stands_at),
        "before the swap the gate reads the snapshot in force, which has ended"
    );
    swap.send(()).expect("the writer waits");
    swap_seen
        .recv_timeout(WAIT_BOUND)
        .expect("the renewal swapped its snapshot in");
    assert!(
        gate(&controller, &under, HeldBound::stands_at),
        "after the swap it reads the renewal"
    );
    assert!(
        !gate(&controller, &under, HeldBound::holds_as_decided),
        "and a batch decided under the old snapshot is decided again"
    );
    finish.send(()).expect("the writer waits");
    storage.execute_batch("ROLLBACK;").expect("storage is free");
    writer
        .join()
        .expect("the writer ends")
        .expect("the renewal is written down")
        .expect("the renewal installs");
    drop(controller);
}

/// A response is written under the lease its request was decided under, as the lease stands
/// when it is written. Held at the writer past the lease's end on the continuous clock, it is not
/// written, and the connection stands, because the grant has not lapsed. A renewal published
/// before that end lets it go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_is_written_under_its_lease_as_it_stands() {
    for renewed in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let (organisation, grant, _connection, asked) = member(&controller, 0x42, now);
        let under = asked.decision.bounds();
        if renewed {
            continuous.advance(Duration::from_secs(60));
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 60_000,
                &[ActionRight::SessionView],
            )
            .expect("written down")
            .expect("the renewal installs");
        }
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();
        let (written, ()) = tokio::join!(output.write(&frame, &under, None), async {
            stream.waited(1).await;
            // Fifteen and a half minutes after the first lease: past its end, and inside the
            // renewal's.
            continuous.advance(Duration::from_secs(if renewed {
                14 * 60 + 30
            } else {
                15 * 60 + 30
            }));
            stream.writer.add_permits(1);
        });
        if renewed {
            assert_eq!(written, Written::Sent, "the renewal lets it go");
            assert_eq!(stream.reached(), vec![Reached::Whole]);
        } else {
            assert_eq!(written, Written::Undecided, "past the lease's end");
            assert!(stream.reached().is_empty());
            assert!(!stream.closed(), "the connection stands");
            assert!(output.authority.has_time_left(), "the grant has not lapsed");
        }
        drop(controller);
    }
}

/// A response is not written once this host's reading of UTC reaches its lease's signed expiry,
/// although the lease's continuous deadline is ahead, and the floor that reading raised is
/// owed its record. With the floor short of the expiry, it goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_is_not_written_once_the_floor_reaches_its_leases_expiry() {
    for reached in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let (_organisation, _grant, _connection, asked) = member(&controller, 0x43, now);
        let under = asked.decision.bounds();
        let expires_at_ms = under[0].utc_deadline_ms().expect("a signed expiry");
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();
        let (written, ()) = tokio::join!(output.write(&frame, &under, None), async {
            stream.waited(1).await;
            controller.utc_floor().observe(if reached {
                expires_at_ms
            } else {
                expires_at_ms - 1
            });
            stream.writer.add_permits(1);
        });
        if reached {
            assert_eq!(written, Written::Undecided);
            assert!(stream.reached().is_empty());
            assert!(
                controller.utc_floor().is_owed(),
                "the lapse is owed its record"
            );
        } else {
            assert_eq!(written, Written::Sent);
            assert!(!controller.utc_floor().is_owed());
        }
        drop(controller);
    }
}

/// A relayed batch is held to the snapshot its decision loaded: a publication in the lease's
/// cell has the batch decided again, although nothing ended and the epoch did not move. With
/// nothing published, it goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_batch_is_decided_again_once_its_lease_publishes_anew() {
    for published in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let (organisation, grant, _connection, asked) = member(&controller, 0x44, now);
        let cell = super::super::tests::member_cell(&controller, &organisation, &grant);
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();
        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: None,
                lapses_at_ms: None,
                under: asked.decision.bounds(),
            },
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, &[], Some(relaying)), async {
            stream.waited(1).await;
            if published {
                let held = cell.load();
                cell.publish(
                    held.identity,
                    held.continuous_deadline,
                    held.utc_deadline_ms.map(|end| end + 60_000),
                    false,
                    true,
                );
            }
            stream.writer.add_permits(1);
        });
        assert_eq!(
            written,
            if published {
                Written::Undecided
            } else {
                Written::Sent
            }
        );
        drop(controller);
    }
}

/// What is cut from a decision ends by the earliest of every bound it was decided under, on
/// both clocks: the lease's continuous deadline, and its signed expiry converted at this host's
/// reading of UTC, so a request decided a second before the lease's expiry is bounded a second
/// out. Once one has passed, the request is decided again and refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_ends_by_the_earliest_bound_it_was_decided_under() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let (_organisation, _grant, connection, asked) = member(&controller, 0x45, now);
    let lease = asked.decision.bounds()[0].clone();
    assert_eq!(
        connection.authority_until(&asked).expect("in force"),
        lease.continuous_deadline(),
        "with UTC far from the expiry, the lease's continuous deadline bounds it"
    );

    let expires_at_ms = lease.utc_deadline_ms().expect("a signed expiry");
    wall.store(expires_at_ms - 1_000, Ordering::SeqCst);
    let bound = controller
        .clock
        .now()
        .checked_add(Duration::from_millis(1_000))
        .expect("a second out");
    assert!(
        connection
            .authority_until(&asked)
            .expect("in force")
            .is_some_and(|until| until <= bound),
        "a second before the expiry, a second out at most"
    );

    wall.store(expires_at_ms, Ordering::SeqCst);
    let refused = connection
        .authority_until(&asked)
        .expect_err("the lease has run out in UTC");
    assert!(
        refused.message.contains("lease"),
        "decided again, and refused as the lease: {refused:?}"
    );
    drop(controller);
}

/// An answer whose lease ran out before it was written is answered with the refusal its
/// request is decided to now, and the connection stands. With the lease live, the answer itself
/// goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_whose_lease_ran_out_is_answered_with_its_refusal() {
    for lapsed in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let (_organisation, grant, _connection, _asked) = member(&controller, 0x46, now);
        let recording = Arc::new(Recording::default());
        let connection = super::RemoteConnection::for_test_writing_to(
            &controller,
            record_for(&grant),
            Box::new(Arc::clone(&recording)),
        );
        let answered = connection
            .answer(ControlFrame::Request(kr_protocol::envelope::Request {
                request_id: kr_protocol::ids::RequestId::new(1),
                method: Method::SessionList.into(),
                method_version: kr_protocol::method::MethodVersion::V1,
                params: kr_protocol::envelope::ParamsValue::from_typed(
                    &kr_protocol::session::SessionListParams {
                        environment_id: Nullable::null(),
                        include_closed: false,
                    },
                )
                .expect("encodes"),
            }))
            .await
            .expect("an answer");
        assert!(
            matches!(
                answered.frame(),
                ControlFrame::Response(kr_protocol::envelope::Response {
                    outcome: kr_protocol::envelope::Outcome::Ok(_),
                    ..
                })
            ),
            "the listing was answered: {:?}",
            answered.frame()
        );
        if lapsed {
            continuous.advance(Duration::from_secs(15 * 60 + 30));
        }
        assert!(
            connection.write_answer(answered).await,
            "the connection stands"
        );
        let written = recording.frames();
        assert_eq!(written.len(), 1, "one answer");
        match &written[0] {
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Error(refusal),
                ..
            }) => assert!(lapsed, "refused while the lease holds: {refusal:?}"),
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            }) => assert!(!lapsed, "the listing went past the lease's end"),
            other => panic!("not an answer: {other:?}"),
        }
        drop(controller);
    }
}

/// A response decided under a lease that has ended is never written under a lease installed
/// after that end, which is a new run of the device's lease and can grant less: installed after
/// the end, a replacement that drops the right the response needed is not a narrowing the host
/// fences, so the response is decided again, and refused, instead. The control: a renewal
/// installed while the lease held continues its run and lets the response go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_is_not_written_under_a_lease_installed_after_its_own_ended() {
    for renewed_in_time in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let (organisation, grant, _connection, _asked) = member(&controller, 0x47, now);
        let recording = Arc::new(Recording::default());
        let connection = super::RemoteConnection::for_test_writing_to(
            &controller,
            record_for(&grant),
            Box::new(Arc::clone(&recording)),
        );
        let answered = connection
            .answer(ControlFrame::Request(listing(1)))
            .await
            .expect("an answer");
        if renewed_in_time {
            continuous.advance(Duration::from_secs(60));
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 60_000,
                &[ActionRight::SessionView],
            )
            .expect("written down")
            .expect("the renewal installs");
            continuous.advance(Duration::from_secs(14 * 60 + 30));
        } else {
            continuous.advance(Duration::from_secs(15 * 60 + 30));
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 60_000,
                &[],
            )
            .expect("written down")
            .expect("the replacement installs");
        }
        assert!(
            connection.write_answer(answered).await,
            "the connection stands"
        );
        let written = recording.frames();
        assert_eq!(written.len(), 1, "one answer");
        match &written[0] {
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Error(refusal),
                ..
            }) => assert!(
                !renewed_in_time && refusal.message.contains("session.view"),
                "refused as the replacement decides: {refusal:?}"
            ),
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            }) => assert!(
                renewed_in_time,
                "the listing went under a lease installed after its own ended"
            ),
            other => panic!("not an answer: {other:?}"),
        }
        drop(controller);
    }
}

/// A session listing asked by a paired device.
fn listing(request_id: u64) -> kr_protocol::envelope::Request {
    kr_protocol::envelope::Request {
        request_id: kr_protocol::ids::RequestId::new(request_id),
        method: Method::SessionList.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        params: kr_protocol::envelope::ParamsValue::from_typed(
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .expect("encodes"),
    }
}

/// A worker's acceptance of a close of `session_id`, with its description of the session.
fn acceptance(session_id: kr_protocol::ids::SessionId) -> kr_protocol::session::SessionCloseResult {
    let mut described =
        crate::service::a_close_a_worker_never_answers::read_result(session_id).session;
    described.state = kr_protocol::session::SessionState::Closing;
    kr_protocol::session::SessionCloseResult {
        session_id,
        state: kr_protocol::session::SessionState::Closing,
        durability: kr_protocol::session::Durability::Durable,
        closure: Nullable::null(),
        session: Some(described),
    }
}

/// The answer that carries `answer` to request 1.
fn close_answer(answer: &kr_protocol::session::SessionCloseResult) -> ControlFrame {
    ControlFrame::Response(kr_protocol::envelope::Response {
        request_id: kr_protocol::ids::RequestId::new(1),
        outcome: kr_protocol::envelope::Outcome::Ok(
            kr_protocol::envelope::ParamsValue::from_typed(answer).expect("encodes"),
        ),
    })
}

/// The one close answer `recording` was written, and whether it carried a description at all,
/// as a member of its own.
fn written_close(recording: &Recording) -> (kr_protocol::session::SessionCloseResult, bool) {
    let frames = recording.frames();
    assert_eq!(frames.len(), 1, "one answer: {frames:?}");
    let ControlFrame::Response(kr_protocol::envelope::Response {
        outcome: kr_protocol::envelope::Outcome::Ok(value),
        ..
    }) = &frames[0]
    else {
        panic!("not the close's answer: {:?}", frames[0]);
    };
    let carried = match value.as_value() {
        kr_cbor::CanonicalValue::Map(map) => map.get("session").is_some(),
        _ => false,
    };
    (value.to_typed().expect("a close answer"), carried)
}

/// KR-REQ-23.34: a `session.close` answer carries the worker's description of the session only
/// where the decision it is written under lets the device read the session. With `session.view`
/// it goes whole; without it the acceptance goes and the description does not, not even as a
/// member that says nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_answer_carries_the_description_only_to_a_device_that_may_read_the_session() {
    for may_read in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let (mut grant, _) = super::super::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            controller.policy().authority_revision(),
        );
        grant.actions = if may_read {
            [ActionRight::SessionView, ActionRight::SessionClose]
                .into_iter()
                .collect()
        } else {
            [ActionRight::SessionClose].into_iter().collect()
        };
        let device = record_for(&grant);
        controller.devices().commit(&device).expect("paired");
        let recording = Arc::new(Recording::default());
        let connection = super::RemoteConnection::for_test_writing_to(
            &controller,
            device,
            Box::new(Arc::clone(&recording)),
        );
        let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
        let asked = connection
            .ask(Some(session_id), Method::SessionClose.entry(), false)
            .expect("the grant admits the close");
        let accepted = acceptance(session_id);

        assert!(
            connection
                .write_answer(super::decision::Answered {
                    frame: close_answer(&accepted),
                    asked: Some(asked),
                })
                .await,
            "the connection stands"
        );
        let (written, carried) = written_close(&recording);
        if may_read {
            assert_eq!(written, accepted, "the answer goes whole");
        } else {
            assert_eq!(
                written,
                kr_protocol::session::SessionCloseResult {
                    session: None,
                    ..accepted
                },
                "the acceptance goes without the description"
            );
            assert!(!carried, "and no member of it goes either");
        }
        drop(controller);
    }
}

/// KR-REQ-23.34: the description is taken out of a `session.close` answer whatever else the answer
/// holds. An answer this build cannot decode, as one from a worker built after this daemon may
/// be, goes to a device that may not read the session without its `session` member, and every
/// other member of it goes as the worker wrote it. With `session.view` it goes whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_answer_this_build_cannot_decode_goes_without_the_description_to_a_device_that_may_not_read_the_session()
 {
    for may_read in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let (mut grant, _) = super::super::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            controller.policy().authority_revision(),
        );
        grant.actions = if may_read {
            [ActionRight::SessionView, ActionRight::SessionClose]
                .into_iter()
                .collect()
        } else {
            [ActionRight::SessionClose].into_iter().collect()
        };
        let device = record_for(&grant);
        controller.devices().commit(&device).expect("paired");
        let recording = Arc::new(Recording::default());
        let connection = super::RemoteConnection::for_test_writing_to(
            &controller,
            device,
            Box::new(Arc::clone(&recording)),
        );
        let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
        let asked = connection
            .ask(Some(session_id), Method::SessionClose.entry(), false)
            .expect("the grant admits the close");
        // The acceptance as a worker that added a member to it later would write it.
        let kr_cbor::CanonicalValue::Map(mut members) =
            kr_protocol::envelope::ParamsValue::from_typed(&acceptance(session_id))
                .expect("encodes")
                .into_value()
        else {
            panic!("an acceptance is a map");
        };
        members
            .insert(
                "added_later".to_owned(),
                kr_cbor::CanonicalValue::text("as written"),
            )
            .expect("a member the acceptance does not have");
        let newer = kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Map(members));
        assert!(
            newer
                .to_typed::<kr_protocol::session::SessionCloseResult>()
                .is_err(),
            "this build cannot decode it"
        );
        let answer = ControlFrame::Response(kr_protocol::envelope::Response {
            request_id: kr_protocol::ids::RequestId::new(1),
            outcome: kr_protocol::envelope::Outcome::Ok(newer),
        });

        assert!(
            connection
                .write_answer(super::decision::Answered {
                    frame: answer,
                    asked: Some(asked),
                })
                .await,
            "the connection stands"
        );
        let frames = recording.frames();
        assert_eq!(frames.len(), 1, "one answer: {frames:?}");
        let ControlFrame::Response(kr_protocol::envelope::Response {
            outcome: kr_protocol::envelope::Outcome::Ok(written),
            ..
        }) = &frames[0]
        else {
            panic!("not the close's answer: {:?}", frames[0]);
        };
        let kr_cbor::CanonicalValue::Map(written) = written.as_value() else {
            panic!("an answer is a map");
        };
        assert_eq!(
            written.get("session").is_some(),
            may_read,
            "the description goes only to a device that may read the session"
        );
        assert_eq!(
            written.get("added_later"),
            Some(&kr_cbor::CanonicalValue::text("as written")),
            "the member this build does not know goes as it came"
        );
        assert!(
            written.get("state").is_some() && written.get("durability").is_some(),
            "and so does the rest of the acceptance: {written:?}"
        );
        drop(controller);
    }
}

/// KR-REQ-23.34: a close answer decided under a lease that has ended is written under the
/// decision taken again as things stand, and that decision decides what it shows. A replacement
/// lease installed after the end that keeps `session.close` and drops `session.view` lets the
/// acceptance go without the session's description. The control: a renewal installed while the
/// lease held continues its run, and the answer goes whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_answer_written_under_a_replacement_lease_without_view_goes_without_the_description()
 {
    for renewed_in_time in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let organisation = TestOrganisation::new(0x49, now - 60 * 60 * 1000);
        let (grant, _) = super::super::tests::leased_member(&controller, &organisation, now);
        let grant = kr_protocol::grant::Grant {
            actions: [ActionRight::SessionView, ActionRight::SessionClose]
                .into_iter()
                .collect(),
            ..grant
        };
        // The member's lease comes to admit closing as well as viewing, while it holds.
        continuous.advance(Duration::from_secs(1));
        super::super::tests::renew_member(
            &controller,
            &organisation,
            &grant,
            now + 1_000,
            &[ActionRight::SessionView, ActionRight::SessionClose],
        )
        .expect("written down")
        .expect("the renewal installs");
        let recording = Arc::new(Recording::default());
        let connection = super::RemoteConnection::for_test_writing_to(
            &controller,
            record_for(&grant),
            Box::new(Arc::clone(&recording)),
        );
        let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
        let asked = connection
            .ask(Some(session_id), Method::SessionClose.entry(), false)
            .expect("the lease answers for the close");
        let accepted = acceptance(session_id);

        if renewed_in_time {
            continuous.advance(Duration::from_secs(60));
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 61_000,
                &[ActionRight::SessionView, ActionRight::SessionClose],
            )
            .expect("written down")
            .expect("the renewal installs");
            continuous.advance(Duration::from_secs(14 * 60 + 30));
        } else {
            continuous.advance(Duration::from_secs(15 * 60 + 30));
            super::super::tests::renew_member(
                &controller,
                &organisation,
                &grant,
                now + 61_000,
                &[ActionRight::SessionClose],
            )
            .expect("written down")
            .expect("the replacement installs");
        }
        assert!(
            connection
                .write_answer(super::decision::Answered {
                    frame: close_answer(&accepted),
                    asked: Some(asked),
                })
                .await,
            "the connection stands"
        );
        let (written, carried) = written_close(&recording);
        if renewed_in_time {
            assert_eq!(written, accepted, "the renewal lets the whole answer go");
        } else {
            assert_eq!(
                written,
                kr_protocol::session::SessionCloseResult {
                    session: None,
                    ..accepted
                },
                "the replacement lets the acceptance go without the description"
            );
            assert!(!carried);
        }
        drop(controller);
    }
}
