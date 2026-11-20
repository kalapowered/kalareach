//! The cases of the lock file's own rules: what it records, when a lock is believed, who is
//! removed, and that a live listener keeps the file fresh.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, SystemTime};

use rustix::io::Errno;

use super::{
    Evidence, Hold, LIVE_REFRESH, Lock, Record, Removal, Volume, lock_is_enforced, read_open,
    refresh, removal_where_a_full_queue_refuses, removal_where_a_refused_connect_proves_an_end,
    try_exclusive,
};
use crate::testing::PrivateTempDir;

/// Opens (and makes) a file in the case's folder.
fn file_in(folder: &PrivateTempDir, name: &str) -> File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(folder.path().join(name))
        .expect("a file")
}

/// A record is one line of three decimal numbers, and nothing else reads as one.
#[test]
fn a_record_is_three_decimal_numbers_on_one_line() {
    let record = Record {
        socket: (16_777_232, 91_826),
        file_inode: 91_827,
    };
    assert_eq!(record.text(), "16777232 91826 91827\n");
    assert_eq!(Record::parse(&record.text()), Some(record));
    for text in [
        "",
        "\n",
        "1 2\n",
        "1 2 3",
        "1 2 3 4\n",
        "1  2 3\n",
        "1 2 -3\n",
        "1 2 3\n\n",
        "+1 2 3\n",
        "1 2 0x3\n",
        " 1 2 3\n",
    ] {
        assert_eq!(Record::parse(text), None, "{text:?}");
    }
}

/// The lock is enforced when an exclusive try-lock on a second open meets a holder, and by nothing
/// else: two handles of one file, two files, and an error that is not contention.
#[test]
fn the_lock_self_test_reads_enforced_not_enforced_and_unknown() {
    let folder = PrivateTempDir::create();
    let held = file_in(&folder, "held");
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockShared)
        .expect("a shared lock");
    let second_of_the_same = File::open(folder.path().join("held")).expect("a second open");
    assert!(
        lock_is_enforced(&second_of_the_same, try_exclusive),
        "two opens of one file meet each other"
    );
    let other = file_in(&folder, "other");
    assert!(
        !lock_is_enforced(&other, try_exclusive),
        "a file nobody holds is not a held one"
    );
    for error in [Errno::ACCESS, Errno::NOLCK, Errno::INVAL] {
        assert!(
            !lock_is_enforced(&second_of_the_same, |_| Err(error)),
            "{error:?} is not contention"
        );
    }
}

/// A record is left only when the lock is shown to be enforced.
#[tokio::test]
async fn a_record_is_left_only_when_the_lock_is_enforced() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let mut hold = Hold::take(&socket).expect("a lock");
    hold.publish_with(false, (1, 2));
    assert_eq!(
        std::fs::read(super::path_of(&socket)).expect("the file"),
        b"",
        "no record when the lock is not enforced"
    );
    hold.publish_with(true, (1, 2));
    let text = std::fs::read_to_string(super::path_of(&socket)).expect("the file");
    let inode = std::fs::metadata(super::path_of(&socket))
        .expect("the file")
        .ino();
    assert_eq!(Record::parse(&text).expect("a record").socket, (1, 2));
    assert_eq!(Record::parse(&text).expect("a record").file_inode, inode);
}

/// An error that is not contention reads as a lock that cannot be read, never as a free lock.
#[test]
fn an_error_that_is_not_contention_is_not_a_free_lock() {
    let folder = PrivateTempDir::create();
    let file = file_in(&folder, "lock");
    for error in [Errno::ACCESS, Errno::NOLCK, Errno::INVAL, Errno::BADF] {
        assert_eq!(
            read_open(&file, (1, 2), |_| Err(error)).lock,
            Lock::Unreadable,
            "{error:?}"
        );
    }
    assert_eq!(
        read_open(&file, (1, 2), |_| Err(Errno::WOULDBLOCK)).lock,
        Lock::Held
    );
    assert_eq!(read_open(&file, (1, 2), |_| Ok(())).lock, Lock::Free);
}

/// Where a full queue refuses a connect, a removal needs a free lock, a record that names the
/// socket and the lock file, and a volume that says its object numbers persist: every other
/// combination keeps the socket, and a held lock names itself.
#[test]
fn removal_is_allowed_only_for_a_free_lock_a_matching_record_and_persistent_ids() {
    for lock in [Lock::Missing, Lock::Free, Lock::Held, Lock::Unreadable] {
        for record_matches in [false, true] {
            for volume in [
                Volume::Persistent,
                Volume::NotPersistent,
                Volume::Unknown,
                Volume::ReadFailed,
            ] {
                let evidence = Evidence {
                    lock,
                    record_matches,
                };
                let expected = if lock == Lock::Held {
                    Removal::LockHeld
                } else if lock == Lock::Free && record_matches && volume == Volume::Persistent {
                    Removal::Allowed
                } else {
                    Removal::Unanswered
                };
                assert_eq!(
                    removal_where_a_full_queue_refuses(evidence, volume),
                    expected,
                    "{lock:?} {record_matches} {volume:?}"
                );
            }
        }
    }
    // Where a refused connect proves that nothing listens, only a held lock keeps a socket.
    for lock in [Lock::Missing, Lock::Free, Lock::Held, Lock::Unreadable] {
        let expected = if lock == Lock::Held {
            Removal::LockHeld
        } else {
            Removal::Allowed
        };
        assert_eq!(
            removal_where_a_refused_connect_proves_an_end(Evidence {
                lock,
                record_matches: false
            }),
            expected,
            "{lock:?}"
        );
    }
}

/// How far from now a file's times are.
fn age_of(file: &File) -> (Duration, Duration) {
    let metadata = file.metadata().expect("metadata");
    let since = |time: SystemTime| {
        SystemTime::now()
            .duration_since(time)
            .unwrap_or(Duration::ZERO)
    };
    (
        since(metadata.accessed().expect("an access time")),
        since(metadata.modified().expect("a modification time")),
    )
}

/// Makes both times of a file four days old, through the handle.
fn age_by_four_days(file: &File) {
    let then = SystemTime::now() - Duration::from_secs(4 * 24 * 60 * 60);
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(then)
            .set_modified(then),
    )
    .expect("old times");
}

/// A live listener keeps the times of its lock file fresh, so that a cleaner of old temporary
/// files does not delete it: the step sets both times, and the listener's task runs it on its
/// schedule and ends with the listener.
#[tokio::test(start_paused = true)]
async fn a_live_listener_keeps_its_lock_file_fresh() {
    let folder = PrivateTempDir::create();
    let file = file_in(&folder, "fresh");
    age_by_four_days(&file);
    refresh(&file).expect("a refresh");
    let (accessed, modified) = age_of(&file);
    assert!(
        accessed < Duration::from_secs(60) && modified < Duration::from_secs(60),
        "{accessed:?} {modified:?}"
    );
    assert!(LIVE_REFRESH <= Duration::from_secs(6 * 60 * 60));

    // The task: bind, age the file through a second handle, let the schedule pass.
    let endpoint =
        crate::paths::Endpoint::from_path(folder.path().join("l.sock")).expect("an endpoint");
    let live = crate::endpoint::Listener::bind(&endpoint).expect("a listener");
    let lock_file = File::open(super::path_of(endpoint.as_path())).expect("the lock file");
    age_by_four_days(&lock_file);
    tokio::time::advance(LIVE_REFRESH + Duration::from_secs(1)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let (accessed, modified) = age_of(&lock_file);
    assert!(
        accessed < Duration::from_secs(60) && modified < Duration::from_secs(60),
        "the schedule ran the refresh: {accessed:?} {modified:?}"
    );

    // The task ends with the listener: nothing sets the times afterwards.
    drop(live);
    age_by_four_days(&lock_file);
    tokio::time::advance(LIVE_REFRESH * 2).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let (_, modified) = age_of(&lock_file);
    assert!(
        modified > Duration::from_secs(3 * 24 * 60 * 60),
        "no refresh after the listener ended: {modified:?}"
    );
}
