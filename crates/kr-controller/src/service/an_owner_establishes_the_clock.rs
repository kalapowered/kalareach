//! The owner's route to establish the host's clock, through the local door of a real daemon.
//!
//! A host that finds its wall clock going backwards stops forgetting by it and stops deciding
//! expiring grants against it, and only its owner's confirmation ends that. The daemon here has no
//! network, which is how a host is configured by default: the owner is the person at the host's own
//! terminal, who has no paired device to confirm with. Each test drives the local door's own entry
//! point, asks for the confirmation the way `kr host clock --establish` does, answers it on the
//! terminal channel with a key made for that one answer, and spends it with
//! `host.clock.establish`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_ipc::peer::PeerIdentity;
use kr_pairing::confirm::sign_confirmation;
use kr_protocol::confirmation::{
    ConfirmationSubject, HostClockEstablishParams, HostClockEstablishResult,
    OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ConnectionId, DeviceId, EnvironmentId, RequestId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::pairing::{ConfirmationChannel, OwnerConfirmationRequest};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use crate::service::Controller;
use crate::service::net::tests::{daemon_on, manual_clocks, stopped};

/// How long a mutation's freshness lasts, on the continuous clock the test moves.
const STANDING: Duration = Duration::from_secs(60);

/// What a mutation of this module asks for by default, in milliseconds.
const TTL_MS: u64 = 30_000;

/// One caller at the local door: the connection it registered and the principal it acts as.
#[derive(Clone)]
pub(super) struct Door {
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    connection_id: ConnectionId,
    actor_id: ActorId,
    window: ActionWindowId,
}

impl Door {
    /// Registers one connection, the way a caller's handshake does.
    pub(super) async fn open(
        temp: &kr_ipc::testing::TempHost,
        controller: &Arc<Controller>,
    ) -> Self {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let actor_id = ActorId::new("local:test").expect("a principal");
        controller
            .admit_connection(
                connection_id,
                &actor_id,
                &PeerIdentity {
                    uid: kr_ipc::paths::current_uid(),
                    gid: 0,
                    pid: None,
                },
                kr_protocol::local::LocalClientKind::Cli,
            )
            .await
            .expect("the connection is registered");
        let window = controller
            .issue_window(connection_id)
            .expect("the connection is given its action window");
        Self {
            controller: Arc::clone(controller),
            environment_id: temp.environment_id(),
            connection_id,
            actor_id,
            window: window.action_window_id,
        }
    }

    /// The connection this caller registered.
    pub(super) const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// The principal this caller acts as.
    pub(super) const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// The deadline a first admission carries here.
    pub(super) fn accepted(&self) -> AcceptedDeadline {
        AcceptedDeadline {
            deadline: self
                .controller
                .clock
                .now()
                .checked_add(STANDING)
                .expect("a deadline"),
            bound: DeadlineBound::RequestedTtl,
        }
    }

    /// A mutation of `method` under `action_id`, asking for a lifetime of `ttl_ms`.
    pub(super) fn mutation<P: serde::Serialize>(
        &self,
        method: Method,
        action_id: ActionId,
        ttl_ms: u64,
        params: &P,
    ) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id,
            grant_id: Nullable::null(),
            target: ActionTarget::environment(self.environment_id),
            expected: ParamsValue::empty(),
            action_window_id: self.window.clone(),
            requested_ttl_ms: DurationMs::new(ttl_ms),
            params: ParamsValue::from_typed(params).expect("encodes"),
        }
    }

    /// Performs one mutation through the local door's own entry point and returns what it said.
    pub(super) async fn perform<R: kr_protocol::wire::WireMessage>(
        &self,
        mutation: MutationRequest,
    ) -> Result<R, ProtocolError> {
        let frame = self
            .controller
            .perform(&self.actor_id, self.connection_id, None, mutation)
            .await;
        match frame {
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Ok(value),
                ..
            }) => Ok(value
                .to_typed::<R>()
                .expect("an answer of the method's type")),
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Error(error),
                ..
            }) => Err(error),
            other => panic!("a mutation is answered with a response: {other:?}"),
        }
    }

    /// Asks for the confirmation of the clock, as the command does.
    pub(super) async fn challenge(&self) -> OwnerConfirmationRequestResult {
        self.perform(self.mutation(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            TTL_MS,
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::EstablishClock,
            },
        ))
        .await
        .expect("a challenge for the clock")
    }

    /// Answers a challenge on the terminal channel, with a key made for that one answer.
    pub(super) async fn answer(
        &self,
        request: &OwnerConfirmationRequest,
    ) -> Result<OwnerConfirmationCompleteResult, ProtocolError> {
        let key = AuthorisationKeyPair::generate().expect("a key");
        let proof = sign_confirmation(&key, request, ConfirmationChannel::LocalBootstrapTerminal)
            .expect("a proof");
        self.perform(self.mutation(
            Method::OwnerConfirmationComplete,
            ActionId::new(kr_ipc::new_uuid()),
            TTL_MS,
            &OwnerConfirmationCompleteParams {
                proof,
                bootstrap_signer: Nullable::some(*key.public()),
            },
        ))
        .await
    }

    /// Answers a challenge in an owner device's own ceremony, with the device's own key.
    pub(super) async fn answer_as_device(
        &self,
        request: &OwnerConfirmationRequest,
        keys: &kr_crypto::keys::DeviceKeys,
    ) -> Result<OwnerConfirmationCompleteResult, ProtocolError> {
        let proof = sign_confirmation(
            &keys.authorisation,
            request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        self.perform(self.mutation(
            Method::OwnerConfirmationComplete,
            ActionId::new(kr_ipc::new_uuid()),
            TTL_MS,
            &OwnerConfirmationCompleteParams {
                proof,
                bootstrap_signer: Nullable::null(),
            },
        ))
        .await
    }

    /// Spends a confirmation of the clock, under a fresh action identifier.
    pub(super) async fn establish(&self) -> Result<HostClockEstablishResult, ProtocolError> {
        self.perform(self.mutation(
            Method::HostClockEstablish,
            ActionId::new(kr_ipc::new_uuid()),
            TTL_MS,
            &HostClockEstablishParams {},
        ))
        .await
    }

    /// The owner at the terminal establishes the clock: the challenge, its answer and its spending.
    pub(super) async fn the_owner_establishes(&self) -> HostClockEstablishResult {
        let challenge = self.challenge().await;
        assert!(
            challenge.initial_bootstrap,
            "a host with no owner is confirmed at its terminal"
        );
        self.answer(&challenge.request)
            .await
            .expect("the terminal answers the challenge");
        self.establish().await.expect("the clock is established")
    }
}

/// The owner at `controller`'s own terminal establishes its clock through the local door.
pub(super) async fn the_owner_establishes(
    temp: &kr_ipc::testing::TempHost,
    controller: &Arc<Controller>,
) {
    Door::open(temp, controller)
        .await
        .the_owner_establishes()
        .await;
}

/// Whether the host proves its clock now.
pub(super) fn proven(controller: &Controller) -> bool {
    controller
        .lifetimes()
        .clock_trust()
        .sample(controller.devices())
        .expect("the host samples its clock")
        .is_some()
}

/// A daemon on clocks the test moves, whose wall clock has gone back by more than the tolerance
/// and so is not proven.
pub(super) async fn distrusting() -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    kr_transport::clock::ManualClock,
    Arc<std::sync::atomic::AtomicU64>,
    crate::service::Clocks,
) {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks.clone()).await;
    let start = wall.load(Ordering::SeqCst);
    assert!(proven(&controller), "the clock is proven where it starts");
    wall.store(start - 60_000, Ordering::SeqCst);
    assert!(!proven(&controller), "the step back is found");
    (temp, controller, continuous, wall, clocks)
}

/// The code a refused answer carries.
pub(super) fn code<T: std::fmt::Debug>(answer: Result<T, ProtocolError>) -> ErrorCode {
    answer.expect_err("the answer is a refusal").code
}

/// When the host's record says its owner last established the clock.
pub(super) fn confirmed_at(temp: &kr_ipc::testing::TempHost) -> Option<i64> {
    rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry")
        .query_row(
            "SELECT confirmed_at_ms FROM network_clock WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .expect("the clock record is readable")
}

/// A paired device with `grant`'s rights, which never expire unless `expiry` says so.
///
/// Its keys are the ones it answers confirmations with; its record is committed to the host's
/// device directory as a pairing would have committed it.
pub(super) fn paired(
    controller: &Controller,
    keys: &kr_crypto::keys::DeviceKeys,
    byte: u8,
    rights: &[kr_protocol::rights::ActionRight],
    expiry: kr_protocol::grant::GrantExpiry,
) -> crate::service::net::devices::DeviceRecord {
    use kr_protocol::grant::{EnvironmentSelector, Grant, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceKeyRevision, GrantId};
    use kr_protocol::pairing::{DeviceName, DevicePlatform};
    use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

    let device_id = DeviceId::new(Uuid::from_bytes([byte; 16]));
    let record = crate::service::net::devices::DeviceRecord {
        device_id,
        endpoint_id: *keys.transport.public(),
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: *keys.authorisation.public(),
        stored_envelope: Some(*keys.stored_envelope.public()),
        notification_preview: Some(*keys.notification_preview.public()),
        device_name: DeviceName::new("A phone").expect("a name"),
        platform: DevicePlatform::Android,
        grant: Grant {
            grant_id: GrantId::new(Uuid::from_bytes([byte; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0; 16])),
            recipient_device_id: device_id,
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: rights.iter().copied().collect::<CanonicalSet<_>>(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry,
            organisation: Nullable::null(),
        },
        paired_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
        revoked_at_ms: None,
        expired_at_ms: None,
        committed_invitation_id: Some(kr_protocol::ids::InvitationId::new(Uuid::from_bytes(
            [byte; 16],
        ))),
    };
    controller
        .devices()
        .commit(&record)
        .expect("the pairing is committed");
    record
}

/// A paired device whose grant ends at `expires_at_ms`, which this boot has not anchored yet.
pub(super) fn expiring_device(
    controller: &Controller,
    expires_at_ms: u64,
) -> crate::service::net::devices::DeviceRecord {
    paired(
        controller,
        &kr_crypto::keys::DeviceKeys::generate().expect("keys"),
        0x31,
        &[kr_protocol::rights::ActionRight::SessionView],
        kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
        },
    )
}

/// Whether this host decides an expiring device's grant now: its end is measured on a clock the
/// host proves.
pub(super) fn decides(
    controller: &Controller,
    device: &crate::service::net::devices::DeviceRecord,
) -> bool {
    controller.lifetimes().paired(device).is_ok()
}

/// KR-REQ-09.19, KR-REQ-10.53: a confirmation of the clock is spent by the effect that names it and
/// by nothing else, once. A challenge nobody answered spends nothing, an answered one is spent by
/// the first effect, and the next effect finds none left: even a host that already trusts its
/// clock is not established again on a confirmation spent before. The control is a fresh
/// confirmation, which spends again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmation_of_the_clock_is_spent_once_by_the_effect_that_names_it() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;

    assert_eq!(
        code(door.establish().await),
        ErrorCode::OwnerConfirmationRequired,
        "with no confirmation at all the clock is not established"
    );
    let challenge = door.challenge().await;
    assert_eq!(
        code(door.establish().await),
        ErrorCode::OwnerConfirmationRequired,
        "a challenge nobody answered spends nothing"
    );
    assert!(
        !proven(&controller),
        "and the host still distrusts its clock"
    );

    door.answer(&challenge.request)
        .await
        .expect("the terminal answers the challenge");
    assert!(
        !proven(&controller),
        "an answer is recorded and is not a spend: the clock is not established by it"
    );
    door.establish()
        .await
        .expect("the answered confirmation is spent");
    assert!(
        proven(&controller),
        "the owner's confirmation ends the distrust"
    );

    assert_eq!(
        code(door.establish().await),
        ErrorCode::OwnerConfirmationRequired,
        "the confirmation was spent once"
    );
    door.the_owner_establishes().await;
}

/// KR-REQ-09.19: an establishment is one action. Asked again under the same identifier and the same
/// request it is answered from what the first one recorded, even when no confirmation is left and
/// across a restart, and it is not performed a second time; under another request it is refused as
/// the reuse of an identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_establishment_asked_again_is_answered_from_its_record() {
    let (temp, controller, _continuous, wall, clocks) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    // The request as it was first sent, window and lifetime included: a repeat is the same bytes.
    let original = door.mutation(
        Method::HostClockEstablish,
        ActionId::new(kr_ipc::new_uuid()),
        TTL_MS,
        &HostClockEstablishParams {},
    );
    let first: HostClockEstablishResult = door
        .perform(original.clone())
        .await
        .expect("the clock is established");
    assert_eq!(first.confirmation_id, challenge.request.confirmation_id);
    let established_at = confirmed_at(&temp);
    assert!(established_at.is_some(), "the record says it");

    wall.store(wall.load(Ordering::SeqCst) + 10_000, Ordering::SeqCst);
    assert_eq!(
        door.perform::<HostClockEstablishResult>(original.clone())
            .await
            .expect("answered from the record"),
        first,
        "a repeat is given the first answer"
    );
    assert_eq!(
        confirmed_at(&temp),
        established_at,
        "and the clock is not established a second time"
    );
    let mut another = original.clone();
    another.requested_ttl_ms = DurationMs::new(TTL_MS + 1);
    assert_eq!(
        code(door.perform::<HostClockEstablishResult>(another).await),
        ErrorCode::IdConflict,
        "the same identifier with another request is a reused identifier"
    );

    drop(door);
    stopped(controller).await;
    let controller = daemon_on(&temp, clocks).await;
    let door = Door::open(&temp, &controller).await;
    assert_eq!(
        door.perform::<HostClockEstablishResult>(original)
            .await
            .expect("answered from the record after a restart"),
        first
    );
    assert_eq!(confirmed_at(&temp), established_at);
}

/// A connection to the registry database the daemon writes, which waits for the daemon's own use.
pub(super) fn registry(temp: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own use");
    registry
}

/// KR-REQ-09.18, KR-REQ-09.19: an establishment is all or nothing, and a refusal leaves the owner's
/// confirmation to try again. The record of the clock refuses the write that establishes it: the
/// host still distrusts its clock and the confirmation stays answered, and once the record takes
/// the write the same confirmation establishes the clock. A restart after the refusal still finds
/// the distrust on the record, and needs a new confirmation, since a challenge ends with its
/// daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_write_of_the_clock_changes_nothing_and_the_same_confirmation_tries_again() {
    let (temp, controller, _continuous, _wall, clocks) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    let registry = registry(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_the_establishment BEFORE UPDATE ON network_clock
             WHEN NEW.confirmed_at_ms IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'refused'); END",
        )
        .expect("the record refuses the write");

    assert_eq!(
        code(door.establish().await),
        ErrorCode::StorageUnavailable,
        "the refusal is the record's"
    );
    assert!(!proven(&controller), "the host still distrusts its clock");
    assert_eq!(confirmed_at(&temp), None, "nothing was written");

    // A restart after the refusal: the distrust is on the record, and the challenge is gone.
    drop(door);
    stopped(controller).await;
    let controller = daemon_on(&temp, clocks).await;
    assert!(
        !proven(&controller),
        "the restart still finds the distrust on the record"
    );
    let door = Door::open(&temp, &controller).await;
    assert_eq!(
        code(door.establish().await),
        ErrorCode::OwnerConfirmationRequired,
        "no confirmation survives the daemon that issued it"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_the_establishment")
        .expect("the record takes the write");
    door.the_owner_establishes().await;
    assert!(proven(&controller));
}

/// KR-REQ-09.17, KR-REQ-09.19: a host whose clock continuity is lost, and which distrusts nothing
/// else, is not freed by an establishment that failed. The record refuses the write that ends the
/// continuity: the error is the answer and the host is as unproven as before, and the same
/// confirmation ends it once the record takes the write. A start that found the floor gone leaves
/// the boot's continuity lost, which is set here as it leaves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_write_of_the_continuity_leaves_the_host_unproven() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks.clone()).await;
    assert!(proven(&controller), "the clock is proven where it starts");
    let registry = registry(&temp);
    registry
        .execute(
            "INSERT INTO clock_continuity (boot_epoch, lost_at_ms, established_at_ms)
             VALUES (?1, 1, NULL)
             ON CONFLICT (boot_epoch) DO UPDATE SET lost_at_ms = 1, established_at_ms = NULL",
            [controller.boot_epoch.get().to_be_bytes().as_slice()],
        )
        .expect("the boot's continuity is lost");
    controller.utc_floor().lose_continuity();
    assert!(!proven(&controller), "a lost continuity proves nothing");

    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_the_continuity BEFORE UPDATE ON clock_continuity
             BEGIN SELECT RAISE(ABORT, 'refused'); END",
        )
        .expect("the record refuses the write");
    assert_eq!(
        code(door.establish().await),
        ErrorCode::StorageUnavailable,
        "the refusal is the record's"
    );
    assert!(controller.utc_floor().continuity_lost(), "still lost");
    assert!(
        !proven(&controller),
        "and the host is as unproven as before"
    );
    assert_eq!(confirmed_at(&temp), None, "the owner confirmed nothing");

    // A restart after the refusal finds the continuity still lost on the record.
    drop(door);
    stopped(controller).await;
    let controller = daemon_on(&temp, clocks.clone()).await;
    assert!(
        controller.utc_floor().continuity_lost(),
        "the restart still finds it lost"
    );
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");

    registry
        .execute_batch("DROP TRIGGER refuse_the_continuity")
        .expect("the record takes the write");
    door.establish()
        .await
        .expect("the same confirmation ends the lost continuity");
    assert!(!controller.utc_floor().continuity_lost());
    assert!(proven(&controller));

    // A restart after the establishment keeps it ended, and one before it would have found the
    // continuity lost: the record, not the daemon's memory, is what says so.
    drop(door);
    stopped(controller).await;
    let controller = daemon_on(&temp, clocks).await;
    assert!(!controller.utc_floor().continuity_lost());
    assert!(proven(&controller));
}

/// KR-REQ-09.19: a commit that fails after every check passed spends nothing. The directory's
/// connection is made to refuse the commit itself (a deferred constraint that the establishing
/// write breaks), the establishment fails, the host still distrusts its clock, and the same
/// confirmation establishes it once the connection takes the commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_that_fails_leaves_the_confirmation_answered() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    controller
        .devices()
        .with(|connection| {
            connection.execute_batch(
                "CREATE TABLE clock_probe_parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE clock_probe_child
                     (parent INTEGER REFERENCES clock_probe_parent (id)
                      DEFERRABLE INITIALLY DEFERRED);
                 CREATE TRIGGER clock_probe AFTER UPDATE ON network_clock
                 WHEN NEW.confirmed_at_ms IS NOT NULL
                 BEGIN INSERT INTO clock_probe_child VALUES (1); END;",
            )
        })
        .expect("the connection refuses the commit");

    assert_eq!(
        code(door.establish().await),
        ErrorCode::StorageUnavailable,
        "the commit is refused"
    );
    assert!(!proven(&controller), "the host still distrusts its clock");

    controller
        .devices()
        .with(|connection| {
            connection.execute_batch(
                "DROP TRIGGER clock_probe;
                 DROP TABLE clock_probe_child;
                 DROP TABLE clock_probe_parent;",
            )
        })
        .expect("the connection takes the commit");
    door.establish()
        .await
        .expect("the same confirmation establishes the clock");
    assert!(proven(&controller));
}

/// KR-REQ-10.52, KR-REQ-09.19: a host that has an owner and is not on the network cannot be asked
/// for a confirmation of its clock: an owner device is the only one that could answer, and none
/// reaches it. The request is refused at once as not configured, naming the network, and leaves no
/// challenge behind. The control is the same host before it has an owner, which is asked and
/// answered at its terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_with_an_owner_and_no_network_is_not_asked_for_a_confirmation_nobody_can_give() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let before = door.challenge().await;
    assert!(
        before.initial_bootstrap,
        "no owner yet: the terminal confirms"
    );
    let waiting = || {
        controller
            .owner_authority()
            .pending(&crate::service::net::owner::Caller::local(
                door.actor_id().clone(),
            ))
            .expect("the owner lists what it can answer")
            .pending
            .len()
    };
    assert_eq!(waiting(), 1, "the first challenge is waiting");

    registry(&temp)
        .execute(
            "INSERT INTO host_owner (id, how, established_at_ms) VALUES (0, 'migrated', 1)",
            [],
        )
        .expect("the host has an owner");
    let refused = door
        .perform::<OwnerConfirmationRequestResult>(door.mutation(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            TTL_MS,
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::EstablishClock,
            },
        ))
        .await;
    assert_eq!(code(refused), ErrorCode::HostNotConfigured);
    assert_eq!(waiting(), 1, "and no challenge was left behind");
    assert!(
        !proven(&controller),
        "and the host still distrusts its clock"
    );
}

/// KR-REQ-09.17, KR-REQ-09.18, KR-REQ-09.19: an expiring device's grant is decided against the
/// host's reading of UTC, and is not while the host distrusts it. A grant that ends tomorrow is
/// refused as `CLOCK_UNTRUSTED` while the clock is in doubt, and decided once the owner has
/// established it: the owner's word is what ends the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiring_grant_is_decided_again_once_the_owner_establishes_the_clock() {
    let (temp, controller, _continuous, wall, _clocks) = distrusting().await;
    let tomorrow = wall.load(Ordering::SeqCst) + 86_400_000;
    let device = expiring_device(&controller, tomorrow);

    let refused = controller
        .lifetimes()
        .paired(&device)
        .err()
        .expect("a grant whose end cannot be measured is not decided");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::ClockUntrusted,
        "{refused}"
    );

    the_owner_establishes(&temp, &controller).await;
    assert!(decides(&controller, &device));
}
