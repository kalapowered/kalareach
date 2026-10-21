//! A recorded directory is the recorded one on the filesystem it was recorded on.
//!
//! Requirement rows closed here: KR-REQ-14.28, KR-REQ-14.33 and KR-REQ-14.34.
//!
//! The device number and the inode of a directory do not tell it from the same place on another
//! filesystem: a filesystem attached in place of another one is given the device number the first
//! had, and one built in the same order gives its directories the same inodes. Each case here puts
//! another filesystem where a directory the change-set service recorded was, gives the journal the
//! numbers the other filesystem's directory has, and shows that the service does not take it for
//! the recorded one. The cases that attach a filesystem need a mount namespace this account may
//! create on Linux, and run where one is allowed (`--ignored`); on macOS they attach a disk image.

#![cfg(not(windows))]

mod support;

use kr_changeset::materialise::{self, Reread};
use kr_protocol::changeset::MaterialisationPurpose;
use kr_protocol::error::ErrorCode;
use support::{Fixture, include_everything, ordinary_repository, reference, write};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use kr_ipc::testing::volumes;

/// Returns the device number and the inode a path has now.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn numbers_of(path: &std::path::Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path).expect("the object is there");
    (metadata.dev() as i64, metadata.ino() as i64)
}

/// Opens the change-set journal of the fixture's environment.
fn changeset_journal(fixture: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(
        kr_changeset::ChangeSetService::root_of(&fixture.host().environment())
            .join(kr_changeset::store::STORE_FILE_NAME),
    )
    .expect("the change-set journal opens")
}

/// Opens the project journal of the fixture's environment.
fn project_journal(fixture: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the project journal opens")
}

/// KR-REQ-14.33: the repository behind a workspace is refused on another filesystem that gives the
/// directory at its path the inodes the recorded ones had, and opened on the filesystem it was
/// recorded on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"
)]
fn a_workspace_on_another_filesystem_is_not_opened_whatever_its_numbers() {
    volumes::with_volumes(
        "a_workspace_on_another_filesystem_is_not_opened_whatever_its_numbers",
        || {
            let fixture = Fixture::create();
            ordinary_repository(fixture.work(), "elsewhere");
            let workspace = fixture.workspace("elsewhere");
            let resolved = fixture.service().resolve(workspace).expect("it resolves");
            fixture
                .service()
                .open_repository(&resolved)
                .expect("the repository on the filesystem it was recorded on");

            // Another filesystem takes the place of the directory the repository is in, with a
            // repository at the same path, and the journal carries the numbers that repository has:
            // it was given the device number the first had, and was built in the same order.
            let scratch = tempfile::tempdir().expect("a directory on the host's own filesystem");
            let volume = volumes::Volume::attach(fixture.work(), scratch.path(), "other")
                .unwrap_or_else(|| volumes::not_attachable());
            let other = ordinary_repository(fixture.work(), "elsewhere");
            let (device, tree) = numbers_of(&other);
            let (_, git_dir) = numbers_of(&other.join(".git"));
            let journal = project_journal(&fixture);
            journal
                .execute(
                    "UPDATE projects SET git_dir_device = ?1, git_dir_file_id = ?2,
                                         work_tree_device = ?1, work_tree_file_id = ?3",
                    [device, git_dir, tree],
                )
                .expect("the repository's record is rewritten");
            journal
                .execute(
                    "UPDATE workspaces SET tree_device = ?1, tree_file_id = ?2",
                    [device, tree],
                )
                .expect("the workspace's record is rewritten");

            let resolved = fixture.service().resolve(workspace).expect("it resolves");
            let refusal = fixture
                .service()
                .open_repository(&resolved)
                .expect_err("another filesystem is not the one it was recorded on");
            assert_eq!(refusal.code(), ErrorCode::SourceChanged);
            volume.detach();
        },
    );
}

/// KR-REQ-14.34: a materialisation's directory is not taken for the one this host made on another
/// filesystem that gives it the recorded numbers, it is not read as the version, and releasing the
/// materialisation does not empty it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"
)]
fn a_materialisation_on_another_filesystem_is_not_read_or_emptied_whatever_its_numbers() {
    volumes::with_volumes(
        "a_materialisation_on_another_filesystem_is_not_read_or_emptied_whatever_its_numbers",
        || {
            let fixture = Fixture::create();
            let path = ordinary_repository(fixture.work(), "work");
            write(&path, "README.md", "the version under test\n");
            let workspace = fixture.workspace("work");
            let record = fixture.capture(workspace, &include_everything());
            let made = materialise::materialise(
                fixture.service(),
                reference(&record),
                MaterialisationPurpose::Test,
                "a copy",
                None,
            )
            .expect("the version is materialised");
            let directory = std::path::Path::new(&made.directory_path);
            let (_, state, _) = materialise::reread(fixture.service(), made.materialisation_id)
                .expect("the materialisation reads");
            assert!(matches!(state, Reread::Unmodified), "{state:?}");

            // Another filesystem is mounted at that directory, with a file of its own, and the
            // journal carries the numbers its root has.
            let scratch = tempfile::tempdir().expect("a directory on the host's own filesystem");
            let volume = volumes::Volume::attach(directory, scratch.path(), "other")
                .unwrap_or_else(|| volumes::not_attachable());
            std::fs::write(directory.join("theirs.txt"), b"not this host's\n").expect("their file");
            let (device, inode) = numbers_of(directory);
            changeset_journal(&fixture)
                .execute(
                    "UPDATE materialisations SET identity_device = ?1, identity_file_id = ?2",
                    [device, inode],
                )
                .expect("the record is rewritten");

            let (_, state, _) = materialise::reread(fixture.service(), made.materialisation_id)
                .expect("the materialisation reads");
            assert!(
                matches!(&state, Reread::Indeterminate(why) if why.contains("not the object this host")),
                "{state:?}"
            );
            materialise::release(fixture.service(), made.materialisation_id)
                .expect_err("a directory on another filesystem is not emptied");
            assert!(
                directory.join("theirs.txt").is_file(),
                "what the other filesystem holds is as it was"
            );
            volume.detach();
        },
    );
}

/// KR-REQ-14.34: releasing a materialisation changes nothing of a directory bound into it from the
/// filesystem it is on. Such a directory has the copy's device number and is another mount, so the
/// release refuses it and the owner's right to change it is not touched: a mode given back to
/// every directory of the same device would change a directory that is not the copy's.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a mount namespace this account may create (`unshare -r -m`), which Ubuntu 24.04 and later deny an unprivileged account by default; the rust job of .github/workflows/core-ci.yml lifts that restriction on its runner and runs it with --ignored"]
fn a_directory_bound_into_a_materialisation_from_its_own_filesystem_is_not_changed_by_its_release()
{
    volumes::with_volumes(
        "a_directory_bound_into_a_materialisation_from_its_own_filesystem_is_not_changed_by_its_release",
        || {
            use std::os::unix::fs::PermissionsExt as _;

            let fixture = Fixture::create();
            let path = ordinary_repository(fixture.work(), "work");
            write(&path, "README.md", "the version under test\n");
            let workspace = fixture.workspace("work");
            let record = fixture.capture(workspace, &include_everything());
            let made = materialise::materialise(
                fixture.service(),
                reference(&record),
                MaterialisationPurpose::Test,
                "a copy",
                None,
            )
            .expect("the version is materialised");
            let directory = std::path::Path::new(&made.directory_path);

            // A directory beside the copy that its owner cannot write, on the copy's own device.
            let outside = fixture.work().join("outside");
            let inner = outside.join("inner");
            std::fs::create_dir_all(&inner).expect("the directory outside the copy");
            std::fs::write(inner.join("kept"), b"not the copy's\n").expect("its file");
            assert_eq!(
                numbers_of(&outside).0,
                numbers_of(directory).0,
                "the directory is on the copy's device"
            );
            let read_only = || std::fs::Permissions::from_mode(0o555);
            std::fs::set_permissions(&inner, read_only()).expect("read-only");
            std::fs::set_permissions(&outside, read_only()).expect("read-only");

            let bound = directory.join("bound");
            std::fs::create_dir(&bound).expect("the place for the bound directory");
            let volume = volumes::Volume::bind(&outside, &bound)
                .unwrap_or_else(|| volumes::not_attachable());

            let refused = materialise::release(fixture.service(), made.materialisation_id);
            let mode_of = |path: &std::path::Path| {
                std::fs::metadata(path)
                    .expect("the directory is there")
                    .permissions()
                    .mode()
                    & 0o777
            };
            let (outside_mode, inner_mode) = (mode_of(&outside), mode_of(&inner));
            let kept = inner.join("kept").is_file();
            let held = changeset_journal(&fixture)
                .query_row(
                    "SELECT released_at_ms IS NULL FROM materialisations",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .expect("the record is there");

            volume.detach();
            for path in [&inner, &outside] {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
            }
            refused.expect_err("a directory bound into the copy is not removed");
            assert_eq!(
                outside_mode, 0o555,
                "the bound directory's mode is as it was"
            );
            assert_eq!(inner_mode, 0o555, "and so is the mode of what it holds");
            assert!(kept, "what the bound directory holds is as it was");
            assert!(held, "the copy goes on holding its version");
        },
    );
}

/// KR-REQ-14.33: a store written before filesystems were recorded is taken forward when its
/// records are used: a materialisation's directory is decided as it was, by its numbers, and the
/// filesystem it is found on becomes the record's, once.
#[test]
fn a_materialisation_recorded_before_filesystems_were_recorded_takes_the_filesystem_it_is_found_on()
{
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "the version under test\n");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "a copy",
        None,
    )
    .expect("the version is materialised");
    let recorded = || -> Option<Vec<u8>> {
        changeset_journal(&fixture)
            .query_row("SELECT identity_fs FROM materialisations", [], |row| {
                row.get(0)
            })
            .expect("the record has a filesystem column")
    };
    assert_eq!(
        recorded().as_ref().map(Vec::len),
        Some(kr_transfer::FilesystemId::LEN)
    );

    // The store as a build that recorded no filesystem wrote it: the column is not there.
    changeset_journal(&fixture)
        .execute_batch("ALTER TABLE materialisations DROP COLUMN identity_fs")
        .expect("takes the column away");
    let replacement = fixture.reopen();
    assert_eq!(recorded(), None, "the column comes back empty");
    let (_, state, _) = materialise::reread(&replacement, made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Unmodified), "{state:?}");
    let taken = recorded();
    assert_eq!(
        taken.as_ref().map(Vec::len),
        Some(kr_transfer::FilesystemId::LEN),
        "it took the filesystem"
    );

    // Once: the next reading leaves it as it is.
    let (_, state, _) = materialise::reread(&replacement, made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Unmodified), "{state:?}");
    assert_eq!(recorded(), taken);

    // And from then on a directory on another filesystem is not the one this host made.
    changeset_journal(&fixture)
        .execute_batch(
            "UPDATE materialisations SET identity_fs = x'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'",
        )
        .expect("the record is rewritten");
    let (_, state, _) = materialise::reread(&replacement, made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Indeterminate(_)), "{state:?}");
}

/// KR-REQ-14.34: a materialisation that is found under another device number than its record
/// carries, with the files this host wrote there recorded under the old one, is still unmodified,
/// and its record takes the number it has now.
#[cfg(unix)]
#[test]
fn a_materialisation_under_another_device_number_is_still_the_version_it_was_written_from() {
    use std::os::unix::fs::MetadataExt as _;

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "the version under test\n");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "a copy",
        None,
    )
    .expect("the version is materialised");
    let (_, state, _) = materialise::reread(fixture.service(), made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Unmodified), "{state:?}");

    // The record as it was written before the filesystem came back under another number: the
    // directory's row and every file the materialisation recorded carry the old one.
    let limits = kr_cbor::Limits {
        max_message_len: 1 << 30,
        max_depth: 32,
        max_items: 64 << 20,
        max_collection_len: 8 << 20,
        max_bytes_len: 1 << 20,
        max_text_len: 1 << 20,
    };
    let journal = changeset_journal(&fixture);
    let stored: Vec<u8> = journal
        .query_row("SELECT record FROM materialisations", [], |row| row.get(0))
        .expect("reads the record");
    let mut held: kr_protocol::changeset::MaterialisationRecord =
        kr_cbor::from_canonical_slice(&stored, &limits).expect("decodes the record");
    assert!(!held.observed.is_empty());
    for observed in &mut held.observed {
        observed.device = kr_protocol::scalars::U64::new(observed.device.get() + 1);
    }
    journal
        .execute(
            "UPDATE materialisations SET record = ?1, identity_device = identity_device + 1",
            [kr_cbor::to_canonical_vec(&held).expect("encodes the record")],
        )
        .expect("the record is rewritten");

    let (_, state, _) = materialise::reread(fixture.service(), made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Unmodified), "{state:?}");
    let device: i64 = journal
        .query_row("SELECT identity_device FROM materialisations", [], |row| {
            row.get(0)
        })
        .expect("reads the number");
    assert_eq!(
        device,
        std::fs::metadata(&made.directory_path)
            .expect("the directory")
            .dev() as i64,
        "the record takes the number the directory has now"
    );
}

/// KR-REQ-14.34: a directory this host cannot read the filesystem of is not said to be another
/// object. A materialisation recorded under another device number is decided by the device of the
/// directory above it, and where that cannot be read the re-read and the release say they could not
/// read it, remove nothing and keep the record. The control is the same record with the directory
/// readable, which is the version it was written from. Run as the superuser, a mode stops nothing,
/// and the case then has nothing to show.
#[cfg(unix)]
#[test]
fn a_directory_whose_device_cannot_be_read_is_not_reported_as_another_object() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "the version under test\n");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "a copy",
        None,
    )
    .expect("the version is materialised");
    let directory = std::path::Path::new(&made.directory_path);
    // The filesystem came back under another number, as the case above has it.
    let journal = changeset_journal(&fixture);
    journal
        .execute(
            "UPDATE materialisations SET identity_device = identity_device + 1",
            [],
        )
        .expect("the record is rewritten");

    // Readable, and not searchable: the device of the directory above is read through it.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o400))
        .expect("takes the search right away");
    let enforced = std::fs::metadata(directory.join("README.md")).is_err();
    if !enforced {
        // Nothing stops the read, so the release below would remove the directory: leave before it.
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("gives it back");
        eprintln!("skipped: a mode stops nothing for this account");
        return;
    }
    let reread = materialise::reread(fixture.service(), made.materialisation_id);
    let released = materialise::release(fixture.service(), made.materialisation_id);
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .expect("gives it back");

    let (_, state, _) = reread.expect("the materialisation reads");
    assert!(
        matches!(&state, Reread::Indeterminate(why) if why.contains("could not read")),
        "the re-read says it could not read the directory: {state:?}"
    );
    let refusal = released.expect_err("a directory that cannot be read is not removed");
    assert!(
        refusal.to_string().contains("could not read"),
        "the release says it could not read the directory: {refusal}"
    );
    for said in [format!("{state:?}"), refusal.to_string()] {
        assert!(
            !said.contains("not the object this host made"),
            "a failed read is not another object: {said}"
        );
    }
    assert!(directory.join("README.md").is_file(), "nothing was removed");
    let device: i64 = journal
        .query_row("SELECT identity_device FROM materialisations", [], |row| {
            row.get(0)
        })
        .expect("reads the number");
    let now = std::os::unix::fs::MetadataExt::dev(
        &std::fs::metadata(directory).expect("the directory is there"),
    ) as i64;
    assert_eq!(
        device,
        now + 1,
        "the record is as it was: nothing took its number"
    );
    // The control: with the directory readable, the same record is the version it was written from.
    let (_, state, _) = materialise::reread(fixture.service(), made.materialisation_id)
        .expect("the materialisation reads");
    assert!(matches!(state, Reread::Unmodified), "{state:?}");
}

/// KR-REQ-14.34: a release that stops part way leaves the record naming the filesystem the
/// directory was found on, so a later release cannot take another filesystem's directory at that
/// path for it.
#[cfg(unix)]
#[test]
fn a_release_that_stops_leaves_the_record_naming_the_filesystem_the_directory_was_found_on() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "the version under test\n");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "a copy",
        None,
    )
    .expect("the version is materialised");
    let directory = std::path::Path::new(&made.directory_path);
    // The record as a build that recorded no filesystem wrote it.
    let journal = changeset_journal(&fixture);
    journal
        .execute("UPDATE materialisations SET identity_fs = NULL", [])
        .expect("the record is rewritten");

    // A chain of directories deeper than a removal holds handles for stops the release.
    let chain = directory.join("deep");
    let mut deepest = chain.clone();
    for _ in 0..kr_transfer::authority::MAX_REMOVAL_DEPTH + 2 {
        deepest.push("d");
    }
    std::fs::create_dir_all(&deepest).expect("a chain of directories");
    let stopped = materialise::release(fixture.service(), made.materialisation_id);
    stopped.expect_err("a release that cannot empty the directory is not one");
    let filesystem: Option<Vec<u8>> = journal
        .query_row("SELECT identity_fs FROM materialisations", [], |row| {
            row.get(0)
        })
        .expect("reads the record");
    assert_eq!(
        filesystem.as_ref().map(Vec::len),
        Some(kr_transfer::FilesystemId::LEN),
        "the record took the filesystem the directory was found on before anything was removed"
    );
    std::fs::remove_dir_all(&chain).expect("the chain goes by hand");
    materialise::release(fixture.service(), made.materialisation_id)
        .expect("the directory goes once its entries can");
}

/// KR-REQ-14.34: a release whose record cannot be given the filesystem the directory was found on
/// removes nothing, whether the write fails or finds the record already changed, and a read of the
/// materialisation is refused the same way; the release goes through once the journal can be
/// written.
#[cfg(unix)]
#[test]
fn a_release_whose_record_cannot_be_settled_removes_nothing() {
    for fault in support::Unrecorded::BOTH {
        let fixture = Fixture::create();
        let path = ordinary_repository(fixture.work(), "work");
        write(&path, "README.md", "the version under test\n");
        let workspace = fixture.workspace("work");
        let record = fixture.capture(workspace, &include_everything());
        let made = materialise::materialise(
            fixture.service(),
            reference(&record),
            MaterialisationPurpose::Test,
            "a copy",
            None,
        )
        .expect("the version is materialised");
        let directory = std::path::Path::new(&made.directory_path);
        let journal = changeset_journal(&fixture);
        // The record as a build that recorded no filesystem wrote it.
        journal
            .execute("UPDATE materialisations SET identity_fs = NULL", [])
            .expect("the record is rewritten");

        fault.impose(&journal, "materialisations", "identity_fs");
        materialise::reread(fixture.service(), made.materialisation_id)
            .expect_err("a record that cannot be settled is not read as the directory it names");
        materialise::release(fixture.service(), made.materialisation_id)
            .expect_err("a record that cannot be settled does not authorise a removal");
        assert!(
            directory.join("README.md").is_file(),
            "{fault:?}: nothing is removed"
        );
        let filesystem: Option<Vec<u8>> = journal
            .query_row("SELECT identity_fs FROM materialisations", [], |row| {
                row.get(0)
            })
            .expect("reads the record");
        assert_eq!(filesystem, None, "{fault:?}: the record is as it was");

        support::Unrecorded::lift(&journal, "identity_fs");
        materialise::release(fixture.service(), made.materialisation_id)
            .expect("the journal can be written, so the directory is the recorded one");
        support::assert_absent(directory);
    }
}
