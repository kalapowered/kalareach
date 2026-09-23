//! Create admission: the limit, the idempotent create token, and display-number allocation.
//!
//! Every one of these happens before a worker exists, which is the point: a host that refused a
//! session after spawning one would have a shell nobody asked for.

use kr_controller::error::ControllerError;
use kr_controller::registry::{LaunchPhase, Registry};
use kr_protocol::ids::ActorId;
use kr_protocol::scalars::{Digest256, TimestampMs};

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a principal")
}

fn digest(byte: u8) -> Digest256 {
    Digest256::from_bytes([byte; 32])
}

/// The recorded create request. Its contents do not matter here; that it is recorded does.
fn intent() -> Vec<u8> {
    vec![0xa0]
}

fn registry() -> (kr_ipc::testing::TempHost, Registry) {
    let host = kr_ipc::testing::TempHost::create();
    let registry = Registry::open(
        host.environment().registry_database(),
        host.environment_id(),
    )
    .expect("opens the registry");
    (host, registry)
}

#[test]
fn a_repeated_create_token_resolves_to_the_same_reservation() {
    let (_host, mut registry) = registry();
    let token = kr_ipc::new_uuid();
    let first = registry
        .reserve(
            &actor("local:501"),
            token,
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    assert!(!first.deduplicated);
    let second = registry
        .reserve(
            &actor("local:501"),
            token,
            digest(1),
            &intent(),
            TimestampMs::new(2),
        )
        .expect("resolves to the same intent");
    assert!(second.deduplicated);
    assert_eq!(second.reservation, first.reservation);
    assert_eq!(
        registry.occupancy().expect("counts"),
        1,
        "one session, not two"
    );
}

#[test]
fn the_same_token_with_a_different_payload_is_refused() {
    let (_host, mut registry) = registry();
    let token = kr_ipc::new_uuid();
    registry
        .reserve(
            &actor("local:501"),
            token,
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    let error = registry
        .reserve(
            &actor("local:501"),
            token,
            digest(2),
            &intent(),
            TimestampMs::new(2),
        )
        .expect_err("refuses");
    assert!(matches!(error, ControllerError::IdConflict { .. }));
    assert_eq!(registry.occupancy().expect("counts"), 1);
}

#[test]
fn the_same_token_from_another_actor_is_a_different_intent() {
    let (_host, mut registry) = registry();
    let token = kr_ipc::new_uuid();
    let first = registry
        .reserve(
            &actor("local:501"),
            token,
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    let second = registry
        .reserve(
            &actor("local:502"),
            token,
            digest(1),
            &intent(),
            TimestampMs::new(2),
        )
        .expect("reserves");
    assert!(!second.deduplicated);
    assert_ne!(second.reservation.session_id, first.reservation.session_id);
}

/// KR-REQ-06.02: every new execution is given a new random session identifier. No create reuses
/// one, even when the same actor sends the same request again under a new create token.
#[test]
fn every_new_execution_is_given_a_new_session_identifier() {
    let (_host, mut registry) = registry();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let admission = registry
            .reserve(
                &actor("local:501"),
                kr_ipc::new_uuid(),
                digest(7),
                &intent(),
                TimestampMs::new(1),
            )
            .expect("reserves");
        assert!(!admission.deduplicated);
        assert_eq!(admission.reservation.session_id.get().version(), 4);
        assert!(
            seen.insert(admission.reservation.session_id),
            "a new execution reused a session identifier"
        );
    }
}

#[test]
fn the_limit_refuses_before_anything_is_spawned_and_never_evicts() {
    let (_host, mut registry) = registry();
    registry.set_session_limit(3).expect("sets the limit");
    let mut reserved = Vec::new();
    for _ in 0..3 {
        let admission = registry
            .reserve(
                &actor("local:501"),
                kr_ipc::new_uuid(),
                digest(9),
                &intent(),
                TimestampMs::new(1),
            )
            .expect("reserves");
        reserved.push(admission.reservation);
    }
    let error = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(9),
            &intent(),
            TimestampMs::new(2),
        )
        .expect_err("refuses");
    match error {
        ControllerError::SessionLimit { live, limit, .. } => {
            assert_eq!(live, 3);
            assert_eq!(limit, 3);
        }
        other => panic!("the limit is named: {other}"),
    }
    // Nothing was evicted to make room.
    assert_eq!(registry.occupancy().expect("counts"), 3);

    // Closing one releases the capacity it held.
    registry
        .set_phase(reserved[0].reservation_id, LaunchPhase::Closed)
        .expect("closes");
    assert_eq!(registry.occupancy().expect("counts"), 2);
    registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(9),
            &intent(),
            TimestampMs::new(3),
        )
        .expect("the freed capacity is usable");
}

#[test]
fn display_numbers_increase_and_are_never_reused() {
    let (_host, mut registry) = registry();
    let mut reservations = Vec::new();
    for _ in 0..4 {
        let admission = registry
            .reserve(
                &actor("local:501"),
                kr_ipc::new_uuid(),
                digest(3),
                &intent(),
                TimestampMs::new(1),
            )
            .expect("reserves");
        reservations.push(admission.reservation);
    }
    let numbers: Vec<u64> = reservations
        .iter()
        .map(|reservation| reservation.display_number.get())
        .collect();
    assert_eq!(numbers, vec![1, 2, 3, 4]);

    // Closing the highest one does not hand its number back.
    registry
        .set_phase(reservations[3].reservation_id, LaunchPhase::Closed)
        .expect("closes");
    let next = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(3),
            &intent(),
            TimestampMs::new(2),
        )
        .expect("reserves");
    assert_eq!(next.reservation.display_number.get(), 5);
    assert_eq!(
        registry.closed_reservations().expect("lists").len(),
        1,
        "the closed session keeps its row, and its number"
    );
}

#[test]
fn the_generation_advances_and_is_remembered_across_opens() {
    let host = kr_ipc::testing::TempHost::create();
    let path = host.environment().registry_database();
    {
        let mut registry = Registry::open(&path, host.environment_id()).expect("opens");
        assert_eq!(registry.generation().expect("reads").get(), 0);
        assert_eq!(registry.advance_generation().expect("advances").get(), 1);
        assert_eq!(registry.advance_generation().expect("advances").get(), 2);
    }
    let mut reopened = Registry::open(&path, host.environment_id()).expect("reopens");
    assert_eq!(reopened.generation().expect("reads").get(), 2);
    assert_eq!(
        reopened.advance_generation().expect("advances").get(),
        3,
        "a replacement daemon is strictly ahead of the one it replaced"
    );
}

#[test]
fn one_launched_process_gets_one_rendezvous_admission() {
    let (_host, mut registry) = registry();
    let admission = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    let reservation = admission.reservation.reservation_id;
    registry
        .set_phase(reservation, LaunchPhase::Spawned)
        .expect("marks the launch attempt");

    let key = kr_protocol::scalars::AuthorisationKey::from_bytes([7; 32]);
    let claimed = registry
        .claim_rendezvous(reservation, key)
        .expect("admits the first claim");
    assert_eq!(claimed.phase, LaunchPhase::Claimed);
    assert_eq!(
        claimed.claimed_key,
        Some(key),
        "the key is durable before the worker is told anything"
    );

    let second = registry
        .claim_rendezvous(
            reservation,
            kr_protocol::scalars::AuthorisationKey::from_bytes([8; 32]),
        )
        .expect_err("refuses the second claim");
    assert!(matches!(second, ControllerError::RendezvousRefused { .. }));
    assert_eq!(
        registry
            .reservation(reservation)
            .expect("reads")
            .expect("present")
            .phase,
        LaunchPhase::Fenced,
        "two processes claiming one reservation fences it"
    );
}

#[test]
fn a_ready_report_cannot_revive_a_fenced_reservation() {
    let (_host, mut registry) = registry();
    let admission = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    let reservation = admission.reservation;
    registry
        .set_phase(reservation.reservation_id, LaunchPhase::Fenced)
        .expect("fences");
    let record = kr_controller::registry::WorkerRecord {
        session_id: reservation.session_id,
        display_number: reservation.display_number,
        public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([9; 32]),
        process_identity: kr_protocol::identity::ProcessStartIdentity::new(
            4242,
            kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
            77,
        ),
        endpoint: "/tmp/kr-test.sock".to_owned(),
        profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        state: kr_protocol::session::SessionState::Live,
        acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
    };
    assert!(
        registry
            .record_worker(reservation.reservation_id, &record)
            .is_err(),
        "a late ready report does not answer the question fencing asked"
    );
}

#[test]
fn a_fenced_reservation_keeps_its_slot_and_a_failed_one_does_not() {
    let (_host, mut registry) = registry();
    let admission = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves");
    let reservation = admission.reservation.reservation_id;
    registry
        .set_phase(reservation, LaunchPhase::Fenced)
        .expect("fences");
    assert_eq!(
        registry.occupancy().expect("counts"),
        1,
        "an unresolved execution still occupies the environment"
    );
    registry
        .set_phase(reservation, LaunchPhase::Failed)
        .expect("resolves");
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "a launch confirmed not to have started occupies nothing"
    );
}

#[test]
fn a_registry_written_by_the_previous_schema_is_brought_forward() {
    let host = kr_ipc::testing::TempHost::create();
    let path = host.environment().registry_database();
    // The version 1 shape, written directly: reservations without a recorded create request and
    // without a claimed key.
    let legacy = rusqlite::Connection::open(&path).expect("opens");
    legacy
        .execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             INSERT INTO schema_version (version) VALUES (1);
             CREATE TABLE environment (
                 environment_id BLOB PRIMARY KEY,
                 generation     INTEGER NOT NULL,
                 next_display   INTEGER NOT NULL,
                 session_limit  INTEGER NOT NULL
             );
             CREATE TABLE reservations (
                 reservation_id    BLOB PRIMARY KEY,
                 actor_id          TEXT NOT NULL,
                 create_token      BLOB NOT NULL,
                 payload_digest    BLOB NOT NULL,
                 session_id        BLOB NOT NULL UNIQUE,
                 display_number    INTEGER NOT NULL UNIQUE,
                 phase             TEXT NOT NULL,
                 launcher_pid      INTEGER,
                 launcher_source   TEXT,
                 launcher_start    INTEGER,
                 created_at_ms     INTEGER NOT NULL,
                 UNIQUE (actor_id, create_token)
             );
             CREATE TABLE workers (
                 session_id       BLOB PRIMARY KEY,
                 display_number   INTEGER NOT NULL,
                 public_key       BLOB NOT NULL,
                 process_pid      INTEGER NOT NULL,
                 process_source   TEXT NOT NULL,
                 process_start    INTEGER NOT NULL,
                 endpoint         TEXT NOT NULL,
                 profile          TEXT NOT NULL,
                 state            TEXT NOT NULL
             );
             CREATE TABLE tombstones (
                 session_id BLOB PRIMARY KEY,
                 record     BLOB NOT NULL,
                 closed_at_ms INTEGER NOT NULL
             );",
        )
        .expect("creates the previous schema");
    legacy
        .execute(
            "INSERT INTO reservations (reservation_id, actor_id, create_token, payload_digest,
                 session_id, display_number, phase, created_at_ms)
             VALUES (?1, 'local:501', ?2, ?3, ?4, 3, 'live', 100)",
            rusqlite::params![
                vec![1_u8; 16],
                vec![2_u8; 16],
                vec![3_u8; 32],
                vec![4_u8; 16],
            ],
        )
        .expect("records a reservation the previous build made");
    drop(legacy);

    let registry =
        Registry::open(&path, host.environment_id()).expect("brings the registry forward");
    let session =
        kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([4_u8; 16]));
    let carried = registry
        .reservation_for_session(session)
        .expect("reads")
        .expect("the reservation survived");
    assert_eq!(carried.display_number.get(), 3);
    assert_eq!(carried.phase, LaunchPhase::Live);
    assert_eq!(
        carried.create_intent, None,
        "a reservation the previous build wrote genuinely has no recorded request"
    );
    assert_eq!(carried.claimed_key, None);
    // And the whole chain lands on a registry this build can run a daemon from. Version 1 issued
    // no authority revisions and accepted no configuration document, so both come forward saying
    // exactly that rather than claiming anything about what a worker answered.
    assert_eq!(
        registry.authority_revision().expect("the revision").get(),
        0
    );
    assert_eq!(registry.fence_owed().expect("the fence record"), None);
    assert_eq!(
        registry
            .accepted_configuration()
            .expect("the acceptance record"),
        kr_controller::registry::AcceptedConfiguration::default(),
        "nothing has been accepted, so the next start puts the document it finds through acceptance"
    );
    assert!(registry.workers().expect("the workers").is_empty());
}

/// A worker's own failure report resolves the claim it made, and a fenced reservation's claim is
/// not its to resolve.
///
/// What the daemon does with that answer is give the directory it prepared for that worker back.
/// A reservation somebody fenced while the report was in flight is still a question waiting for an
/// answer, so the report settles nothing about it and it keeps what it was given.
#[test]
fn only_the_reservation_a_failure_report_claimed_is_resolved_by_it() {
    let (_host, mut registry) = registry();
    let reservation = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(1),
            &intent(),
            TimestampMs::new(1),
        )
        .expect("reserves")
        .reservation;
    let key = kr_protocol::scalars::AuthorisationKey::from_bytes([9_u8; 32]);
    registry
        .set_phase(reservation.reservation_id, LaunchPhase::Spawned)
        .expect("moves to spawned");
    registry
        .claim_rendezvous(reservation.reservation_id, key)
        .expect("the worker claims its reservation");
    assert!(
        registry
            .resolve_claim(reservation.reservation_id, LaunchPhase::Failed)
            .expect("resolves"),
        "the report resolves the claim the worker made"
    );
    assert!(
        !registry
            .resolve_claim(reservation.reservation_id, LaunchPhase::Failed)
            .expect("resolves nothing twice"),
        "and says so only once"
    );

    let fenced = registry
        .reserve(
            &actor("local:501"),
            kr_ipc::new_uuid(),
            digest(2),
            &intent(),
            TimestampMs::new(2),
        )
        .expect("reserves")
        .reservation;
    registry
        .set_phase(fenced.reservation_id, LaunchPhase::Spawned)
        .expect("moves to spawned");
    registry
        .claim_rendezvous(fenced.reservation_id, key)
        .expect("the worker claims its reservation");
    registry.fence(fenced.reservation_id).expect("fences it");
    assert!(
        !registry
            .resolve_claim(fenced.reservation_id, LaunchPhase::Failed)
            .expect("resolves"),
        "a fenced reservation is not the report's to resolve"
    );
}
