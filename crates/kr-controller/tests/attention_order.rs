//! The host's records of the boots it started in and of where each device's access began, as a
//! daemon writes them.
//!
//! The daemon records the boot it starts in before it records anything else of that boot, takes
//! the next ordinal for a boot it has not started in, keeps the ordinal for one it has, and, when a
//! boot it recorded before the latest one comes back, finds that it can no longer tell that boot
//! from another and starts all the same.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-23.45 | every test here |

#![cfg(unix)]

mod net_support;

use std::path::Path;

use kr_controller::service::Clocks;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::rights::ActionRight;
use net_support::{Device, Host, pair_with, pairing, proposal};

/// The rows of `boots`, in the order of their ordinals: the ordinal, the high and the spoiled flag.
fn boots(path: &Path) -> Vec<(i64, i64, i64)> {
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    let mut statement = connection
        .prepare("SELECT ordinal, high_ms, spoiled FROM boots ORDER BY ordinal")
        .expect("the boots table");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row")
}

/// A start records its boot, and a restart in the same boot makes no new row, keeps the
/// ordinal and does not lower the high.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_records_its_boot_and_a_restart_in_the_same_boot_keeps_the_ordinal() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    assert!(
        host.controller().network_guard().is_some(),
        "the control: a host on the network has the guard that holds the regular pass"
    );
    let path = host.registry_database();
    let first = boots(&path);
    assert_eq!(first.len(), 1, "one boot is recorded: {first:?}");
    assert_eq!(
        (first[0].0, first[0].2),
        (1, 0),
        "the first ordinal, told apart"
    );
    assert!(first[0].1 > 0, "the reading is the high: {first:?}");
    let host = host.restart().await;
    let again = boots(&path);
    assert_eq!(again.len(), 1, "the same boot makes no new row: {again:?}");
    assert_eq!((again[0].0, again[0].2), (1, 0), "the ordinal is kept");
    assert!(again[0].1 >= first[0].1, "the high is not lowered");
    host.stop().await;
}

/// A start in a boot the host has not started in takes the next ordinal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_in_a_new_boot_takes_the_next_ordinal() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let path = host.registry_database();
    let mut stopped = host.shut_down().await;
    stopped.reboot(2, Clocks::system());
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let recorded = boots(&path);
    assert_eq!(
        recorded
            .iter()
            .map(|row| (row.0, row.2))
            .collect::<Vec<_>>(),
        vec![(1, 0), (2, 0)],
        "two boots, in the order they started in, both told apart: {recorded:?}"
    );
    host.stop().await;
}

/// A boot recorded before the latest one comes back. The start finds that it can no longer
/// tell that boot from another, and the daemon starts all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_in_a_boot_recorded_before_the_latest_one_spoils_it_and_still_starts() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let path = host.registry_database();
    let mut stopped = host.shut_down().await;
    stopped.reboot(2, Clocks::system());
    let settings = stopped.settings().clone();
    let host = stopped.start(settings.clone()).await;
    let mut stopped = host.shut_down().await;
    stopped.reboot(3, Clocks::system());
    let host = stopped.start(settings.clone()).await;
    // The second boot's identity comes back after the third was recorded.
    let mut stopped = host.shut_down().await;
    stopped.reboot(2, Clocks::system());
    let host = stopped.start(settings).await;
    let recorded = boots(&path);
    assert_eq!(
        recorded
            .iter()
            .map(|row| (row.0, row.2))
            .collect::<Vec<_>>(),
        vec![(1, 0), (2, 1), (3, 0)],
        "the boot that came back is spoiled and no row was added: {recorded:?}"
    );
    host.stop().await;
}

/// The start records its boot before it records anything else of the boot. The registry
/// writes a line to a table of its own for each row that a start adds to `boots` and to
/// `utc_floors`, and the boot is the first of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_start_records_its_boot_before_the_clock_floor() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let path = host.registry_database();
    let mut stopped = host.shut_down().await;
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch(
            "CREATE TABLE write_log (id INTEGER PRIMARY KEY AUTOINCREMENT, what TEXT NOT NULL);
             CREATE TRIGGER log_boots AFTER INSERT ON boots
             BEGIN INSERT INTO write_log (what) VALUES ('boots'); END;
             CREATE TRIGGER log_floors AFTER INSERT ON utc_floors
             BEGIN INSERT INTO write_log (what) VALUES ('utc_floors'); END;
             CREATE TRIGGER log_starts AFTER INSERT ON grant_starts
             BEGIN INSERT INTO write_log (what) VALUES ('grant_starts'); END;
             CREATE TRIGGER log_workers AFTER INSERT ON workers
             BEGIN INSERT INTO write_log (what) VALUES ('workers'); END;",
        )
        .expect("the log and its triggers");
    stopped.reboot(2, Clocks::system());
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let log: Vec<String> = {
        let connection = rusqlite::Connection::open(&path).expect("the registry opens");
        let mut statement = connection
            .prepare("SELECT what FROM write_log ORDER BY id")
            .expect("the log");
        statement
            .query_map([], |row| row.get(0))
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("every row")
    };
    let at = |what: &str| log.iter().position(|written| written == what);
    assert!(
        at("utc_floors").is_some(),
        "the start recorded a clock floor in the new boot: {log:?}"
    );
    assert_eq!(
        at("boots"),
        Some(0),
        "the boot is the first row written: {log:?}"
    );
    host.stop().await;
}

/// The source of this crate, as text: every file under `src`, and its production part, which is
/// what comes before its first test module.
fn production_sources() -> Vec<(String, String)> {
    fn walk(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("a source directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files
        .into_iter()
        .map(|file| {
            let text = std::fs::read_to_string(&file).expect("a source file");
            let production = text
                .split("#[cfg(test)]\nmod ")
                .next()
                .unwrap_or_default()
                .to_owned();
            let name = file
                .strip_prefix(&root)
                .expect("under src")
                .to_string_lossy()
                .into_owned();
            (name, production)
        })
        .collect()
}

/// Every reading of the order counter that goes into the record is taken by one function
/// that takes the clock and no reading, and that function is called only from the places that
/// call it inside an immediate transaction: the registry's start, the grant store's writers and
/// passes, and the device store's pairing.
#[test]
fn the_record_takes_a_clock_and_never_a_reading_and_is_written_from_the_known_sites_only() {
    let sources = production_sources();
    let boots = &sources
        .iter()
        .find(|(name, _)| name == "boots.rs")
        .expect("the record's source")
        .1;
    let signature = boots
        .split("pub fn observe(")
        .nth(1)
        .and_then(|rest| rest.split(") -> Result<Observed>").next())
        .expect("the signature of observe");
    assert!(signature.contains("clock: &dyn SharedClock"), "{signature}");
    assert!(
        !signature.contains("reading"),
        "no caller hands observe a reading: {signature}"
    );
    let allowed = [
        "boots.rs",
        "registry.rs",
        "grants/store.rs",
        "net/invitations.rs",
    ];
    for (name, production) in &sources {
        let writes = production.contains("Boots::observe(")
            || production.contains("StartPoint::take(")
            || production.contains("StartPoint::read(");
        assert!(
            !writes || allowed.contains(&name.as_str()),
            "{name} writes the record from a place this case does not know"
        );
    }
}

/// The pass at a start takes the settled reading of UTC before its transaction, as a
/// value, and the store's method that runs the transaction never asks for it: asking for it takes
/// the policy lock and may write through the grant store, which a transaction of that store cannot
/// wait for.
#[test]
fn the_pass_at_a_start_takes_the_settled_reading_before_the_transaction_and_the_store_takes_none() {
    let sources = production_sources();
    let text_of = |wanted: &str| {
        sources
            .iter()
            .find(|(name, _)| name == wanted)
            .unwrap_or_else(|| panic!("{wanted}"))
            .1
            .clone()
    };
    let standing = text_of("service/standing.rs");
    let pass = standing
        .split("pub(crate) fn give_starts_at_start(")
        .nth(1)
        .expect("the controller's pass")
        .split("\n    }\n")
        .next()
        .expect("its body");
    let settled = pass
        .find("settled_now_ms()")
        .expect("it takes the settled reading");
    let transaction = pass
        .find("start_points_at_start(")
        .expect("it runs the store's pass");
    assert!(settled < transaction, "the reading comes first");
    let store = text_of("grants/store.rs");
    let store_pass = store
        .split("pub fn start_points_at_start(")
        .nth(1)
        .expect("the store's pass")
        .split("\n    /// Writes a grant.")
        .next()
        .expect("its body");
    assert!(
        !store_pass.contains("settled_now_ms"),
        "the store's pass never asks for the settled reading"
    );
}

/// The start point a grant has: the wall moment, the boot's epoch and the counter reading.
fn point_of(path: &Path, grant: &[u8]) -> Option<(u64, u64, u64)> {
    rusqlite::Connection::open(path)
        .expect("the registry opens")
        .query_row(
            "SELECT wall_ms, boot_epoch, boot_ms FROM grant_starts WHERE grant_id = ?1",
            rusqlite::params![grant],
            |row| {
                let epoch: Vec<u8> = row.get(1)?;
                Ok((
                    row.get::<_, i64>(0)?.try_into().unwrap_or_default(),
                    u64::from_be_bytes(epoch.try_into().unwrap_or_default()),
                    row.get::<_, i64>(2)?.try_into().unwrap_or_default(),
                ))
            },
        )
        .ok()
}

/// A pairing takes the point of its commit, with the commit's own moment, in the
/// transaction that records the device; and a grant that has none, as one an earlier release
/// wrote, is given the start of the next daemon that starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_takes_the_point_of_its_commit_and_the_next_start_gives_a_grant_without_one_the_start()
 {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let paired = pair_with(
        &host,
        &device,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let grant = paired.grant.grant_id.get().as_bytes().to_vec();
    let path = host.registry_database();
    let Some(first) = point_of(&path, &grant) else {
        panic!("the pairing took no point");
    };
    assert_eq!(
        first.0,
        paired.paired_at_ms.get(),
        "the commit's own moment"
    );
    assert!(first.2 > 0, "and the counter read at it: {first:?}");
    // The pairing's moment is later than anything the host's clock reads at the next start, as it
    // is when a clock reads behind the pairing: the grant has no history cursor, so it reaches from
    // the pairing, and the point must not lie before that.
    let later = paired.paired_at_ms.get() + 3_600_000;
    let connection = rusqlite::Connection::open(&path).expect("the registry opens");
    connection
        .execute("DELETE FROM grant_starts", [])
        .expect("the point goes, as it is for a grant an earlier release wrote");
    connection
        .execute(
            "UPDATE network_devices SET paired_at_ms = ?1 WHERE grant_id = ?2",
            rusqlite::params![i64::try_from(later).expect("a moment"), grant],
        )
        .expect("the pairing moves ahead of the clock");
    drop(connection);
    let host = host.restart().await;
    let Some(again) = point_of(&path, &grant) else {
        panic!("the pass at the start gave the grant no point");
    };
    assert_eq!(
        again.0, later,
        "the point is the pairing's moment, which is later than the settled reading: {again:?}"
    );
    assert_eq!(again.1, first.1, "in the same boot");
    assert!(
        again.2 >= first.2,
        "read later: {again:?} against {first:?}"
    );
    host.stop().await;
}

/// The rows a pairing writes together, counted: the devices, the commitments, the events and the
/// start points.
fn pairing_rows(path: &Path) -> (i64, i64, i64, i64) {
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    let count = |table: &str| -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("a count")
    };
    (
        count("network_devices"),
        count("pairing_commitments"),
        count("pairing_events"),
        count("grant_starts"),
    )
}

/// The fault between the device's row and its point: a point that cannot be written takes
/// the pairing with it, so no device, commitment or event is recorded; with the fault gone another
/// pairing commits and takes its point with them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_whose_point_cannot_be_written_records_no_device() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let signer = pairing::Signer::OwnerDevice(&owner);
    let mut client = host.client().await;
    let invited = pairing::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView]),
        &signer,
    )
    .await
    .expect("an invitation");
    let (connection, _candidate, _verification_value) =
        pairing::redeem(&device.candidate(), &invited).await;
    pairing::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let path = host.registry_database();
    let before = pairing_rows(&path);
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch(
            "CREATE TRIGGER a_fault BEFORE INSERT ON grant_starts
             BEGIN SELECT RAISE(ABORT, 'a fault at the point'); END;",
        )
        .expect("the fault is set");
    let refused = pairing::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await;
    assert!(refused.is_err(), "the pairing fails with its point");
    assert_eq!(
        pairing_rows(&path),
        before,
        "neither the device, nor its commitment, nor its event, nor its point stands"
    );

    // The pairing store is fenced by its failed write until the daemon starts again, so the control
    // is a pairing after a restart, with the fault gone and nothing else changed.
    connection.close(0u32.into(), b"refused");
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch("DROP TRIGGER a_fault")
        .expect("the fault is gone");
    let host = host.restart().await;
    let paired = pair_with(
        &host,
        &Device::create().await,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    assert!(
        point_of(&path, paired.grant.grant_id.get().as_bytes().as_slice()).is_some(),
        "the control's pairing took its point"
    );
    assert_eq!(
        pairing_rows(&path),
        (before.0 + 1, before.1 + 1, before.2 + 1, before.3 + 1),
        "the device, its commitment, its event and its point are written together"
    );
    host.stop().await;
}
