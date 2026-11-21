//! The cases of the lock file's own rules: what it records, when a lock is believed, who is
//! removed, and that a live listener keeps the file fresh.

use std::fs::File;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, SystemTime};

use rustix::io::Errno;

use super::{
    Evidence, Hold, LIVE_REFRESH, Lock, Record, Removal, Volume, lock_is_enforced, read_open,
    refresh, removal_where_a_full_queue_refuses, removal_where_a_refused_connect_proves_an_end,
    try_exclusive,
};
use crate::endpoint::platform::copies::ProgramWithACopy;
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

/// Makes a named pipe at `path`.
fn make_pipe(path: &std::path::Path) {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo starts");
    assert!(status.success(), "a named pipe is made");
}

/// Runs `call` on a thread of its own and gives what it returned, or `None` when it did not return
/// within five seconds. A call that waits for a peer of the pipe at `pipe` is released from here,
/// by opening the pipe's other end, and its thread is collected before this returns.
fn returns<T: Send + 'static>(
    pipe: &std::path::Path,
    call: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _ = sender.send(call());
    });
    let value = receiver.recv_timeout(Duration::from_secs(5)).ok();
    let _peer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap_or_default())
        .open(pipe);
    thread.join().expect("the call's thread");
    value
}

/// Puts a link at `link` that leads to `target`.
fn link(target: &std::path::Path, link: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).expect("a link");
}

/// A pipe where the lock file belongs is not read, and the read does not wait for anybody: it
/// says the lock cannot be read.
#[test]
fn a_pipe_at_the_lock_file_is_unreadable_and_the_read_does_not_wait() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let lock = super::path_of(&socket);
    make_pipe(&lock);
    let evidence = returns(&lock, move || super::read(&socket, (1, 2)));
    assert_eq!(
        evidence,
        Some(Evidence {
            lock: Lock::Unreadable,
            record_matches: false
        })
    );
}

/// A link where the lock file belongs is not followed: a record in the file it leads to, that names
/// the socket and the file it is in, is not read as this socket's record.
#[test]
fn a_link_at_the_lock_file_is_unreadable_and_is_not_followed() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let target = folder.path().join("target");
    let file = file_in(&folder, "target");
    let record = Record {
        socket: (1, 2),
        file_inode: file.metadata().expect("metadata").ino(),
    };
    std::fs::write(&target, record.text()).expect("a record");
    link(&target, &super::path_of(&socket));
    assert_eq!(
        super::read(&socket, (1, 2)),
        Evidence {
            lock: Lock::Unreadable,
            record_matches: false
        }
    );
}

/// A listener does not take a lock file that is a pipe, and does not wait for anybody to do so.
#[test]
fn a_pipe_at_the_lock_file_is_refused_to_a_listener_without_waiting() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let lock = super::path_of(&socket);
    make_pipe(&lock);
    let taken = returns(&lock, move || {
        Hold::take(&socket)
            .map(|_| ())
            .map_err(|error| error.kind())
    });
    assert_eq!(taken, Some(Err(std::io::ErrorKind::InvalidInput)));
}

/// A listener does not take a link as its lock file: the file the link leads to keeps its text and
/// is not locked, and a link that leads nowhere makes no file.
#[test]
fn a_link_at_the_lock_file_is_refused_to_a_listener_and_leaves_its_target_alone() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let target = folder.path().join("target");
    std::fs::write(&target, "unrelated\n").expect("a file");
    link(&target, &super::path_of(&socket));
    assert!(Hold::take(&socket).is_err(), "a link is not the lock file");
    assert_eq!(std::fs::read(&target).expect("the target"), b"unrelated\n");
    let other = file_in(&folder, "other");
    assert!(
        rustix::fs::flock(&other, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_ok(),
        "nothing locked another file"
    );

    let dangling = folder.path().join("b.sock");
    let nowhere = folder.path().join("nowhere");
    link(&nowhere, &super::path_of(&dangling));
    assert!(
        Hold::take(&dangling).is_err(),
        "a link to nothing is not made good"
    );
    assert!(!nowhere.exists(), "no file was made behind the link");
}

/// A pipe put where the lock file was, after the listener took it, does not hold the record's
/// self-test, and no record is left.
#[tokio::test]
async fn a_pipe_put_at_the_lock_file_after_the_lock_is_taken_leaves_no_record_and_no_wait() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let mut hold = Hold::take(&socket).expect("a lock");
    let lock = super::path_of(&socket);
    make_pipe(&folder.path().join("pipe"));
    std::fs::rename(folder.path().join("pipe"), &lock).expect("the pipe replaces the file");
    let handle = tokio::runtime::Handle::current();
    let published = returns(&lock, move || {
        let _entered = handle.enter();
        hold.publish((1, 2));
        hold
    });
    assert!(
        published.is_some(),
        "the publish waited for a peer of the pipe"
    );
    let hold = published.expect("the publish returned");
    assert_eq!(
        hold.file.read_at(&mut [0_u8; 8], 0).expect("a read"),
        0,
        "no record"
    );
}

/// A link put where the lock file was, that leads to the very file the listener holds, is not the
/// listener's lock: the self-test does not follow it and no record is left.
#[tokio::test]
async fn a_link_put_at_the_lock_file_after_the_lock_is_taken_leaves_no_record() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let mut hold = Hold::take(&socket).expect("a lock");
    let lock = super::path_of(&socket);
    let moved = folder.path().join("moved");
    std::fs::rename(&lock, &moved).expect("the file moves");
    link(&moved, &lock);
    hold.publish((1, 2));
    assert_eq!(std::fs::read(&moved).expect("the file"), b"", "no record");
}

/// A name that now leads to another file that somebody holds is not the listener's lock either:
/// the self-test counts only the file the listener itself locked.
#[tokio::test]
async fn a_name_that_leads_to_another_held_file_is_not_this_listeners_self_test() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let mut hold = Hold::take(&socket).expect("a lock");
    let other = file_in(&folder, "other");
    rustix::fs::flock(&other, rustix::fs::FlockOperation::NonBlockingLockShared)
        .expect("a lock held by another file");
    std::fs::rename(folder.path().join("other"), super::path_of(&socket)).expect("the swap");
    hold.publish((1, 2));
    assert_eq!(
        hold.file.read_at(&mut [0_u8; 8], 0).expect("a read"),
        0,
        "no record"
    );
}

/// A listener's lock ends with its hold, though a program that started while the lock was held
/// keeps a copy of the lock file.
#[test]
fn a_hold_lets_go_of_its_lock_though_a_program_keeps_a_copy_of_the_file() {
    let folder = PrivateTempDir::create();
    let socket = folder.path().join("a.sock");
    let hold = Hold::take(&socket).expect("a lock");
    let _program = ProgramWithACopy::of(&hold.file);
    drop(hold);
    let other = File::open(super::path_of(&socket)).expect("the lock file");
    assert!(
        rustix::fs::flock(&other, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_ok(),
        "the lock is free once the hold ended"
    );
}

/// The probe of a lock file leaves no lock behind, though a program that started while the probe
/// held its lock keeps a copy of the file: the lock a bind takes next is not refused.
#[test]
fn the_probe_of_a_lock_file_leaves_no_lock_though_a_program_keeps_a_copy_of_the_file() {
    let folder = PrivateTempDir::create();
    let file = file_in(&folder, "lock");
    let mut program = None;
    let evidence = read_open(&file, (1, 2), |probed| {
        try_exclusive(probed)?;
        program = Some(ProgramWithACopy::of(probed));
        Ok(())
    });
    assert_eq!(evidence.lock, Lock::Free);
    let next = File::open(folder.path().join("lock")).expect("the lock file");
    assert!(
        rustix::fs::flock(&next, rustix::fs::FlockOperation::NonBlockingLockShared).is_ok(),
        "the lock a bind takes next is not refused by the probe's copy"
    );
    drop(program);
}

/// The self-test of the lock leaves no lock behind either, where the lock is not enforced.
#[test]
fn the_self_test_of_a_lock_leaves_no_lock_though_a_program_keeps_a_copy_of_the_file() {
    let folder = PrivateTempDir::create();
    let file = file_in(&folder, "lock");
    let mut program = None;
    let enforced = lock_is_enforced(&file, |second| {
        try_exclusive(second)?;
        program = Some(ProgramWithACopy::of(second));
        Ok(())
    });
    assert!(!enforced, "nobody else holds the file");
    let next = File::open(folder.path().join("lock")).expect("the lock file");
    assert!(
        rustix::fs::flock(&next, rustix::fs::FlockOperation::NonBlockingLockShared).is_ok(),
        "the self-test's copy keeps no lock"
    );
    drop(program);
}
