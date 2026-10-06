//! A recorded directory is the recorded one on the filesystem it was recorded on.
//!
//! Requirement rows closed here: KR-REQ-14.10 and KR-REQ-14.16.
//!
//! The device number and the inode of a directory do not tell it from the same place on another
//! filesystem: a filesystem attached in place of another one that was detached is given the device
//! number the first had, and one built in the same order gives its directories the same inodes.
//! These cases put a new filesystem where the recorded one was, with the numbers the recorded
//! directory had, and show that each service that records a directory refuses it. The cases that
//! attach a filesystem need a mount namespace this account may create on Linux, and run where one
//! is allowed (`--ignored`); on macOS they attach a disk image.

mod support;

use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use kr_ipc::testing::volumes;
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::Nullable;
use kr_protocol::transfer::{DownloadBeginParams, DownloadSource};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use kr_transfer::{AuthorisedDirectory, Escape};
use kr_transfer::{ManualClock, RecordedIdentity, Settled, StagingArea, Store, TransferService};
use support::{Harness, pattern};

/// Opens the transfer store of the environment a host holds, to read or rewrite what it recorded.
fn journal(host: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
    rusqlite::Connection::open(StagingArea::store_path(&host.environment()))
        .expect("opens the store")
}

/// Returns the device number and the inode a path has now.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn numbers_of(path: &std::path::Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path).expect("the directory is there");
    (metadata.dev() as i64, metadata.ino() as i64)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn begin_from_scope(
    service: &TransferService,
    harness: &Harness,
    scope: kr_protocol::ids::GrantId,
) -> kr_transfer::Result<kr_protocol::transfer::DownloadBeginResult> {
    service.download_begin(
        &harness.actor,
        &DownloadBeginParams {
            environment_id: harness.environment_id(),
            resume_transfer_id: Nullable::null(),
            source: Nullable::some(DownloadSource::Scope {
                scope_id: scope,
                relative_path: "notes.txt".to_owned(),
            }),
            device_id: Nullable::null(),
        },
    )
}

/// KR-REQ-14.10: a staging directory is refused on another filesystem that gives it the numbers
/// the recorded one had, and accepted on the filesystem it was recorded on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"
)]
fn a_staging_directory_on_another_filesystem_is_refused_whatever_its_numbers() {
    volumes::with_volumes(
        "a_staging_directory_on_another_filesystem_is_refused_whatever_its_numbers",
        || {
            let scratch = tempfile::tempdir().expect("a directory on the host's own filesystem");
            let at = scratch.path().join("volume");
            std::fs::create_dir(&at).expect("a mount point");
            let first = volumes::Volume::attach(&at, scratch.path(), "first")
                .unwrap_or_else(|| volumes::not_attachable());

            // The service records its staging directory on the first filesystem, and accepts it
            // there again.
            let host = kr_ipc::testing::TempHost::create_in(first.at());
            drop(TransferService::open(&host.environment()).expect("opens and records"));
            drop(
                TransferService::open(&host.environment())
                    .expect("the recorded filesystem accepts its own directory again"),
            );
            let kept = scratch.path().join("kept");
            std::fs::create_dir(&kept).expect("a place to keep the state");
            volumes::copy_tree(host.root(), &kept);

            // Another filesystem takes its place, and the whole state of the service, its journal
            // with it, is put on it.
            let second = first
                .replace(scratch.path(), "second")
                .unwrap_or_else(|| volumes::not_attachable());
            volumes::copy_tree(
                &kept.join(host.root().file_name().expect("the host's own name")),
                second.at(),
            );

            // The journal carries the numbers the directory has on the new filesystem, as it
            // would where the new filesystem is given the device number the first had and was
            // built in the same order: only the filesystem differs.
            let name: String = journal(&host)
                .query_row("SELECT staging_name FROM environment", [], |row| row.get(0))
                .expect("the journal records the staging directory");
            let (device, inode) = numbers_of(&StagingArea::root_of(&host.environment()).join(name));
            journal(&host)
                .execute(
                    "UPDATE environment SET staging_device = ?1, staging_file_id = ?2",
                    [device, inode],
                )
                .expect("rewrites the numbers");

            let refusal = TransferService::open(&host.environment())
                .expect_err("another filesystem is not the one the directory was recorded on");
            assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
            second.detach();
        },
    );
}

/// KR-REQ-14.16: a registered scope is refused on another filesystem that gives its directory the
/// numbers the registered one had, and accepted on the filesystem it was registered on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"
)]
fn a_scope_on_another_filesystem_is_refused_whatever_its_numbers() {
    volumes::with_volumes(
        "a_scope_on_another_filesystem_is_refused_whatever_its_numbers",
        || {
            let scratch = tempfile::tempdir().expect("a directory on the host's own filesystem");
            let at = scratch.path().join("volume");
            std::fs::create_dir(&at).expect("a mount point");
            let first = volumes::Volume::attach(&at, scratch.path(), "first")
                .unwrap_or_else(|| volumes::not_attachable());
            let harness = Harness::create();
            let tree = first.at().join("tree");
            std::fs::create_dir(&tree).expect("the scope's directory");
            std::fs::write(tree.join("notes.txt"), pattern(512)).expect("writes the source");
            let scope = harness
                .service
                .register_scope("a review tree", &tree)
                .expect("registers the scope");
            begin_from_scope(&harness.service, &harness, scope)
                .expect("the scope is the registered one on the filesystem it was registered on");

            // Another filesystem takes its place and gives the directory the numbers it had.
            let second = first
                .replace(scratch.path(), "second")
                .unwrap_or_else(|| volumes::not_attachable());
            std::fs::create_dir(&tree).expect("a directory at the same place");
            std::fs::write(tree.join("notes.txt"), pattern(512)).expect("writes a source");
            let (device, inode) = numbers_of(&tree);
            journal(&harness.host)
                .execute(
                    "UPDATE scopes SET root_device = ?1, root_file_id = ?2",
                    [device, inode],
                )
                .expect("rewrites the numbers");

            let refusal = begin_from_scope(&harness.service, &harness, scope)
                .expect_err("another filesystem is not the one the scope was registered on");
            assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
            second.detach();
        },
    );
}

/// KR-REQ-14.16: the check every service applies refuses a directory on another filesystem under
/// the numbers the recorded directory had, and records the filesystem it is on for the directory
/// that is there now.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"
)]
fn a_directory_on_another_filesystem_is_not_the_recorded_one_whatever_its_numbers() {
    volumes::with_volumes(
        "a_directory_on_another_filesystem_is_not_the_recorded_one_whatever_its_numbers",
        || {
            let scratch = tempfile::tempdir().expect("a directory on the host's own filesystem");
            let at = scratch.path().join("volume");
            std::fs::create_dir(&at).expect("a mount point");
            let first = volumes::Volume::attach(&at, scratch.path(), "first")
                .unwrap_or_else(|| volumes::not_attachable());
            let environment = kr_protocol::ids::EnvironmentId::new(
                kr_protocol::scalars::Uuid::from_bytes([3; 16]),
            );
            let directory = first.at().join("directory");
            std::fs::create_dir(&directory).expect("the recorded directory");
            let recorded = AuthorisedDirectory::open_root(environment, &directory)
                .expect("opens it")
                .recorded()
                .expect("reads its identity");
            assert_eq!(
                AuthorisedDirectory::open_root(environment, &directory)
                    .expect("opens it again")
                    .check_recorded(recorded)
                    .expect("the same directory on the same filesystem"),
                Settled::AsRecorded
            );

            let second = first
                .replace(scratch.path(), "second")
                .unwrap_or_else(|| volumes::not_attachable());
            std::fs::create_dir(&directory).expect("a directory at the same place");
            let found = AuthorisedDirectory::open_root(environment, &directory).expect("opens it");
            // Built in the same order, so the directory has the inode the recorded one had, and
            // the record carries the numbers it has now.
            assert_eq!(found.identity().file_id, recorded.object.file_id);
            let same_numbers = RecordedIdentity {
                object: found.identity(),
                filesystem: recorded.filesystem,
            };
            assert!(matches!(
                found.check_recorded(same_numbers),
                Err(Escape::IdentityChanged { .. })
            ));
            assert_eq!(
                found
                    .check_recorded(found.recorded().expect("reads its identity"))
                    .expect("the directory is the one recorded on its own filesystem"),
                Settled::AsRecorded
            );
            second.detach();
        },
    );
}

/// KR-REQ-14.10, KR-REQ-14.16: a store written before filesystems were recorded is taken forward
/// when its records are next used: each directory is decided as it was, and the filesystem it is
/// found on becomes the record's, once.
#[test]
fn a_record_made_before_filesystems_were_recorded_takes_the_filesystem_it_is_found_on_once() {
    let harness = Harness::create();
    let tree = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(tree.path().join("notes.txt"), pattern(512)).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    let Harness {
        host,
        service,
        actor,
        ..
    } = harness;
    drop(service);

    // The store as a build that recorded no filesystem wrote it: the columns are not there.
    let connection = journal(&host);
    for (table, column) in [("environment", "staging_fs"), ("scopes", "root_fs")] {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                [table, column],
                |row| row.get(0),
            )
            .expect("reads the table's columns");
        if present > 0 {
            connection
                .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column}"))
                .expect("takes the column away");
        }
    }
    drop(connection);

    let open = || {
        TransferService::with_clock(
            &host.environment(),
            Arc::new(ManualClock::new(support::START_MS)),
        )
        .expect("a staging directory without a recorded filesystem is decided as it was")
    };
    let recorded = || -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let connection = journal(&host);
        (
            connection
                .query_row("SELECT staging_fs FROM environment", [], |row| row.get(0))
                .expect("the staging directory's record has a filesystem column"),
            connection
                .query_row("SELECT root_fs FROM scopes", [], |row| row.get(0))
                .expect("the scope's record has a filesystem column"),
        )
    };
    let begin = |service: &TransferService| {
        service.download_begin(
            &actor,
            &DownloadBeginParams {
                environment_id: host.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Scope {
                    scope_id: scope,
                    relative_path: "notes.txt".to_owned(),
                }),
                device_id: Nullable::null(),
            },
        )
    };

    let service = open();
    assert_eq!(
        recorded().0.as_ref().map(Vec::len),
        Some(kr_transfer::FilesystemId::LEN),
        "the staging directory's record takes the filesystem it was found on"
    );
    assert_eq!(
        recorded().1,
        None,
        "a scope is taken forward when it is used"
    );
    begin(&service).expect("the scope is decided as it was");
    let (staging, root) = recorded();
    assert_eq!(
        root.as_ref().map(Vec::len),
        Some(kr_transfer::FilesystemId::LEN)
    );
    drop(service);

    // Once: what was recorded is not written again by the next use.
    let service = open();
    begin(&service).expect("the scope is the registered one");
    assert_eq!(recorded(), (staging, root));
    drop(service);

    // A record without a filesystem is decided as it was, and a directory with another inode is
    // not the recorded one.
    journal(&host)
        .execute_batch(
            "UPDATE environment SET staging_fs = NULL, staging_file_id = staging_file_id + 1;",
        )
        .expect("rewrites the record");
    let refusal = TransferService::with_clock(
        &host.environment(),
        Arc::new(ManualClock::new(support::START_MS)),
    )
    .expect_err("another directory is not the recorded one");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

/// KR-REQ-14.10: a settlement replaces the staging record it was made against, with the payloads
/// recorded beside it, and no other record: a record that is neither what it replaces nor what it
/// becomes is refused and moves nothing.
#[test]
fn a_settlement_replaces_the_staging_record_it_was_made_against_and_no_other() {
    let harness = Harness::create();
    harness.publish(&pattern(64), "application/octet-stream", "notes.bin");
    let Harness { host, service, .. } = harness;
    drop(service);
    let mut store = Store::open(
        StagingArea::store_path(&host.environment()),
        host.environment_id(),
    )
    .expect("opens the store");
    let recorded = store
        .staging_identity()
        .expect("reads the record")
        .expect("the staging directory is recorded");
    let payload_device = || -> i64 {
        journal(&host)
            .query_row("SELECT payload_device FROM uploads", [], |row| row.get(0))
            .expect("reads the payload's record")
    };
    let before = payload_device();

    // Made against another inode than the record holds: refused, and no payload moves.
    let other = RecordedIdentity::from_parts(
        recorded.object.device,
        recorded.object.file_id.wrapping_add(1),
        recorded.filesystem,
    );
    let moved = RecordedIdentity::from_parts(
        recorded.object.device.wrapping_add(1),
        recorded.object.file_id.wrapping_add(1),
        recorded.filesystem,
    );
    store
        .settle_staging(&Settled::Revised {
            was: other,
            now: moved,
        })
        .expect_err("another directory's record is not the one this was made against");
    assert_eq!(payload_device(), before);

    // Made against the record: it takes the new number, and the payloads move with it.
    let renumbered = RecordedIdentity::from_parts(
        recorded.object.device.wrapping_add(1),
        recorded.object.file_id,
        recorded.filesystem,
    );
    store
        .settle_staging(&Settled::Revised {
            was: recorded,
            now: renumbered,
        })
        .expect("the record is the one the settlement was made against");
    assert_eq!(store.staging_identity().expect("reads"), Some(renumbered));
    assert_eq!(payload_device(), before.wrapping_add(1));

    // Made again, as a second use of the same check would: the record is what it becomes.
    store
        .settle_staging(&Settled::Revised {
            was: recorded,
            now: renumbered,
        })
        .expect("a record another settlement already replaced is as it should be");
    assert_eq!(
        payload_device(),
        before.wrapping_add(1),
        "and moves nothing again"
    );
}
