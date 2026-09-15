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
        .reserve(&actor("local:501"), token, digest(1), TimestampMs::new(1))
        .expect("reserves");
    assert!(!first.deduplicated);
    let second = registry
        .reserve(&actor("local:501"), token, digest(1), TimestampMs::new(2))
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
        .reserve(&actor("local:501"), token, digest(1), TimestampMs::new(1))
        .expect("reserves");
    let error = registry
        .reserve(&actor("local:501"), token, digest(2), TimestampMs::new(2))
        .expect_err("refuses");
    assert!(matches!(error, ControllerError::IdConflict { .. }));
    assert_eq!(registry.occupancy().expect("counts"), 1);
}

#[test]
fn the_same_token_from_another_actor_is_a_different_intent() {
    let (_host, mut registry) = registry();
    let token = kr_ipc::new_uuid();
    let first = registry
        .reserve(&actor("local:501"), token, digest(1), TimestampMs::new(1))
        .expect("reserves");
    let second = registry
        .reserve(&actor("local:502"), token, digest(1), TimestampMs::new(2))
        .expect("reserves");
    assert!(!second.deduplicated);
    assert_ne!(second.reservation.session_id, first.reservation.session_id);
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
