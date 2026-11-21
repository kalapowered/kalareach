//! The cases of the endpoint's bind that need no second process.

use crate::endpoint::Listener;
use crate::error::IpcError;
use crate::listen::ListenRefusal;
use crate::paths::Endpoint;

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::listen::ObjectKind;
    use crate::testing::PrivateTempDir;

    /// The folder's endpoint named `name`.
    fn endpoint_in(folder: &PrivateTempDir, name: &str) -> Endpoint {
        Endpoint::from_path(folder.path().join(name)).expect("an endpoint that fits the platform")
    }

    use std::os::unix::fs::MetadataExt as _;

    /// What stands at the path, by its device and inode, read without following a link.
    fn identity(path: &std::path::Path) -> (u64, u64) {
        let metadata = std::fs::symlink_metadata(path).expect("the path exists");
        (metadata.dev(), metadata.ino())
    }

    /// A file, a directory and a link at an endpoint are each named for what they are, and none
    /// is removed or replaced.
    #[tokio::test]
    async fn a_file_a_directory_and_a_link_at_the_endpoint_are_named_and_left_alone() {
        let folder = PrivateTempDir::create();
        let target = folder.path().join("target");
        std::fs::write(&target, b"somebody's file").expect("a file");
        for (name, object) in [
            ("file.sock", ObjectKind::File),
            ("directory.sock", ObjectKind::Directory),
            ("link.sock", ObjectKind::Link),
        ] {
            let path = folder.path().join(name);
            match object {
                ObjectKind::File => std::fs::write(&path, b"mine").expect("a file"),
                ObjectKind::Directory => std::fs::create_dir(&path).expect("a directory"),
                _ => std::os::unix::fs::symlink(&target, &path).expect("a link"),
            }
            let before = identity(&path);
            let error =
                Listener::bind(&endpoint_in(&folder, name)).expect_err("the bind is refused");
            let IpcError::Listen { endpoint, refusal } = error else {
                panic!("a listen refusal, not {error:?}");
            };
            assert_eq!(refusal, ListenRefusal::NotASocket { object }, "{name}");
            assert_eq!(endpoint, path.to_str().expect("text"), "{name}");
            assert_eq!(identity(&path), before, "{name} is left where it was");
            let said = refusal.said(&endpoint);
            assert!(
                said.contains(object.phrase())
                    && said.contains("does not remove what it did not make"),
                "{said}"
            );
        }
        assert_eq!(
            std::fs::read(&target).expect("the target"),
            b"somebody's file"
        );
    }

    /// A bind whose address a live listener holds names the process that listens, the way the
    /// kernel gives it.
    #[tokio::test]
    async fn a_second_bind_names_the_process_that_holds_the_endpoint() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "held.sock");
        let _live = Listener::bind(&endpoint).expect("a live listener");
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        assert_eq!(
            refusal,
            ListenRefusal::Held {
                pid: Some(std::process::id())
            }
        );
        let said = refusal.said(endpoint.as_path().to_str().expect("text"));
        assert!(
            said.contains(&format!("process {} started", std::process::id())),
            "{said}"
        );
    }

    use std::fs::File;
    use std::io::BufRead as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixListener as StdListener;
    use std::path::{Path, PathBuf};

    use rustix::fs::{FlockOperation, flock};
    use rustix::io::Errno;

    use crate::listen::ListenStep;

    /// Whether this platform answers a full queue as a refused connect, which is what makes a
    /// refused connect unable to show that a listener ended.
    const FULL_QUEUE_IS_REFUSED: bool = cfg!(target_vendor = "apple");

    /// The lock file of a socket: the same name with `.live` added.
    fn live_of(socket: &Path) -> PathBuf {
        let mut name = socket.as_os_str().to_os_string();
        name.push(".live");
        PathBuf::from(name)
    }

    /// Leaves a socket at `path` that refuses every connect: what a listener that ended without
    /// removing it leaves.
    fn leave_a_refusing_socket(path: &Path) {
        drop(StdListener::bind(path).expect("a socket"));
    }

    /// Makes the lock file of a leftover socket and writes in it the record a listener of this
    /// release leaves for that socket: its device and inode and the lock file's own inode.
    fn leave_the_record_of(path: &Path) {
        let live = live_of(path);
        std::fs::write(&live, b"").expect("a lock file");
        let socket = identity(path);
        let inode = std::fs::metadata(&live).expect("the lock file").ino();
        std::fs::write(&live, format!("{} {} {inode}\n", socket.0, socket.1)).expect("a record");
    }

    /// Takes the shared lock a listener holds, through a handle of the case's own.
    fn hold_the_lock_of(path: &Path) -> File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(live_of(path))
            .expect("a lock file");
        flock(&file, FlockOperation::NonBlockingLockShared).expect("a shared lock");
        file
    }

    /// Whether an exclusive try-lock on the lock file meets a holder.
    fn lock_is_held(path: &Path) -> bool {
        let file = File::open(live_of(path)).expect("the lock file");
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => false,
            Err(Errno::WOULDBLOCK) => true,
            Err(other) => panic!("a try-lock gives contention or the lock, not {other:?}"),
        }
    }

    /// A socket that listens with a queue of one and does not accept.
    fn listen_with_a_queue_of_one(path: &Path) -> OwnedFd {
        let socket = crate::endpoint::stream_socket().expect("a socket");
        let address = rustix::net::SocketAddrUnix::new(path).expect("an address");
        rustix::net::bind(&socket, &address).expect("a bind");
        rustix::net::listen(&socket, 1).expect("a listen");
        socket
    }

    /// Connects until a connect is refused or would block: the listener's queue is full.
    fn fill_the_queue_of(path: &Path) -> Vec<OwnedFd> {
        let address = rustix::net::SocketAddrUnix::new(path).expect("an address");
        let mut held = Vec::new();
        for _ in 0..64 {
            let socket = crate::endpoint::stream_socket().expect("a socket");
            rustix::io::ioctl_fionbio(&socket, true).expect("a mode");
            match rustix::net::connect(&socket, &address) {
                Ok(()) | Err(Errno::INPROGRESS) => held.push(socket),
                Err(Errno::CONNREFUSED | Errno::AGAIN) => return held,
                Err(other) => panic!("a connect is made, refused or would block, not {other:?}"),
            }
        }
        panic!("the queue of one never filled");
    }

    /// What the bind of a leftover or listening socket gives where a full queue refuses a connect
    /// and where it does not: the first cannot tell its listener from an ended one.
    fn refusal_where_the_lock_names_the_listener() -> ListenRefusal {
        if FULL_QUEUE_IS_REFUSED {
            ListenRefusal::LockHeld
        } else {
            ListenRefusal::Held { pid: None }
        }
    }

    /// A leftover socket whose lock is free and whose record names it is replaced by the next
    /// bind, and the new socket is the one at the path.
    #[tokio::test]
    async fn a_leftover_socket_with_a_free_lock_is_replaced_by_the_next_bind() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "left.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        leave_the_record_of(path);
        let live = Listener::bind(&endpoint).expect("the leftover is replaced");
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the path names the new listener");
        drop(stream);
        drop(live);
    }

    /// A refused socket whose lock a listener holds is kept and named by its lock.
    #[tokio::test]
    async fn a_refused_socket_whose_lock_is_held_is_kept_and_named_lock_held() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "locked.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        let before = identity(path);
        let _held = hold_the_lock_of(path);
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        assert_eq!(refusal, ListenRefusal::LockHeld);
        assert_eq!(identity(path), before, "the socket is left where it was");
    }

    /// A live listener whose queue is full refuses a connect, and is never replaced: a listener of
    /// this release holds its lock and its record, and the case holds both as it does.
    #[tokio::test]
    async fn a_live_listener_with_a_full_queue_is_never_replaced() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "full.sock");
        let path = endpoint.as_path();
        let listener = listen_with_a_queue_of_one(path);
        let queued = fill_the_queue_of(path);
        let before = identity(path);
        let _held = hold_the_lock_of(path);
        leave_the_record_of(path);
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        assert_eq!(refusal, refusal_where_the_lock_names_the_listener());
        assert_eq!(identity(path), before, "the socket is left where it was");
        // The original still has its queue, and accepts one of the connections made to it.
        rustix::net::accept(&listener).expect("the listener still accepts a queued connection");
        drop(queued);
    }

    /// A full queue with no lock file at all is kept on macOS, where it reads as a refused
    /// connect, and on Linux, where it reads as a held address.
    #[tokio::test]
    async fn a_full_queue_with_no_lock_file_is_kept_on_both_platforms() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "nolock.sock");
        let path = endpoint.as_path();
        let listener = listen_with_a_queue_of_one(path);
        let queued = fill_the_queue_of(path);
        let before = identity(path);
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        let expected = if FULL_QUEUE_IS_REFUSED {
            ListenRefusal::Unanswered
        } else {
            ListenRefusal::Held { pid: None }
        };
        assert_eq!(refusal, expected);
        assert_eq!(identity(path), before);
        rustix::net::accept(&listener).expect("the listener still accepts a queued connection");
        drop(queued);
    }

    /// A lock that cannot be read keeps the socket on macOS, where a refused connect cannot show
    /// that a listener ended, and does not keep it on Linux, where it can.
    #[tokio::test]
    async fn a_lock_that_cannot_be_read_keeps_the_socket_on_macos_and_not_on_linux() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "unreadable.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        let before = identity(path);
        std::fs::create_dir(live_of(path)).expect("a directory where the lock file goes");
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        if FULL_QUEUE_IS_REFUSED {
            assert_eq!(refusal, ListenRefusal::Unanswered);
            assert_eq!(identity(path), before, "the socket is left where it was");
        } else {
            // The leftover is replaced as it always was, and then the listener's own lock cannot
            // be taken in a directory's place, which the refusal says.
            assert!(
                matches!(
                    refusal,
                    ListenRefusal::Other {
                        operation: ListenStep::Lock,
                        ..
                    }
                ),
                "{refusal:?}"
            );
        }
    }

    /// A lock file that is there and free with nothing in it keeps the socket on macOS.
    #[tokio::test]
    async fn an_empty_record_keeps_the_socket_on_macos() {
        let folder = PrivateTempDir::create();
        for (name, text) in [
            ("empty.sock", ""),
            ("short.sock", "1 2\n"),
            ("noline.sock", "1 2 3"),
            ("words.sock", "a b c\n"),
            ("extra.sock", "1 2 3 4\n"),
        ] {
            let endpoint = endpoint_in(&folder, name);
            let path = endpoint.as_path();
            leave_a_refusing_socket(path);
            let before = identity(path);
            std::fs::write(live_of(path), text).expect("a lock file");
            let result = Listener::bind(&endpoint);
            if FULL_QUEUE_IS_REFUSED {
                let error = result.expect_err("the bind is refused");
                let IpcError::Listen { refusal, .. } = error else {
                    panic!("a listen refusal, not {error:?}");
                };
                assert_eq!(refusal, ListenRefusal::Unanswered, "{name}");
                assert_eq!(identity(path), before, "{name}");
            } else {
                result.expect("a leftover is replaced on Linux whatever the file holds");
            }
        }
    }

    /// A lock file replaced by a copy that holds the same record is another file, and the socket
    /// stays on macOS.
    #[tokio::test]
    async fn a_copy_of_a_free_lock_file_with_a_matching_record_keeps_the_socket() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "copied.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        leave_the_record_of(path);
        let before = identity(path);
        // A tool that saves by rename: the same text, another file.
        let copy = folder.path().join("copy");
        std::fs::copy(live_of(path), &copy).expect("a copy");
        std::fs::rename(&copy, live_of(path)).expect("a replacement");
        let result = Listener::bind(&endpoint);
        if FULL_QUEUE_IS_REFUSED {
            let error = result.expect_err("the bind is refused");
            let IpcError::Listen { refusal, .. } = error else {
                panic!("a listen refusal, not {error:?}");
            };
            assert_eq!(refusal, ListenRefusal::Unanswered);
            assert_eq!(identity(path), before);
        } else {
            result.expect("a leftover is replaced on Linux whatever the file holds");
        }
    }

    /// A socket a listener of an earlier release holds, at a path a listener of this release left a
    /// record for, is never replaced: the record names the earlier socket.
    #[tokio::test]
    async fn a_live_listener_of_an_earlier_release_on_a_path_a_new_listener_left_is_never_replaced()
    {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "earlier.sock");
        let path = endpoint.as_path();
        // A listener of this release binds and ends cleanly: its socket goes and its lock file,
        // with the record of that socket, stays.
        drop(Listener::bind(&endpoint).expect("a listener"));
        assert!(live_of(path).exists(), "the lock file stays");
        // A listener of an earlier release takes the path: no lock, a queue that fills.
        let earlier = listen_with_a_queue_of_one(path);
        let queued = fill_the_queue_of(path);
        let before = identity(path);
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        let expected = if FULL_QUEUE_IS_REFUSED {
            ListenRefusal::Unanswered
        } else {
            ListenRefusal::Held { pid: None }
        };
        assert_eq!(refusal, expected);
        assert_eq!(identity(path), before, "the socket is left where it was");
        rustix::net::accept(&earlier).expect("the earlier listener still accepts");
        drop(queued);
    }

    /// A refused socket with no lock file is kept on macOS and replaced on Linux.
    #[tokio::test]
    async fn a_refused_socket_without_a_lock_file_is_kept_on_macos_and_replaced_on_linux() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "nolive.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        let before = identity(path);
        let result = Listener::bind(&endpoint);
        if FULL_QUEUE_IS_REFUSED {
            let error = result.expect_err("the bind is refused");
            let IpcError::Listen { refusal, .. } = error else {
                panic!("a listen refusal, not {error:?}");
            };
            assert_eq!(refusal, ListenRefusal::Unanswered);
            assert_eq!(identity(path), before, "the socket is left where it was");
        } else {
            result.expect("a leftover is replaced on Linux");
        }
    }

    /// A refusing socket in a folder that cannot be written is told as one that could not be
    /// removed, with the system's code.
    #[tokio::test]
    async fn a_refusing_socket_in_a_folder_that_cannot_be_written_gives_not_removed() {
        use std::os::unix::fs::PermissionsExt as _;

        /// Gives the folder its mode back, whatever the case did.
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }

        if rustix::process::geteuid().is_root() {
            eprintln!("stands down: a process of the superuser writes any folder");
            return;
        }
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "readonly.sock");
        let path = endpoint.as_path();
        leave_a_refusing_socket(path);
        leave_the_record_of(path);
        // The address guard's own file, made while the folder can be written.
        let mut guard = path.as_os_str().to_os_string();
        guard.push(".lock");
        std::fs::write(&guard, b"").expect("the guard's file");
        let _restore = Restore(folder.path().to_path_buf());
        std::fs::set_permissions(folder.path(), std::fs::Permissions::from_mode(0o500))
            .expect("a folder that cannot be written");
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        assert_eq!(
            refusal,
            ListenRefusal::NotRemoved {
                os: Errno::ACCESS.raw_os_error()
            }
        );
    }

    /// A listener holds its lock until it ends, and the lock is free after.
    #[tokio::test]
    async fn a_listener_holds_its_lock_until_it_ends() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "lock.sock");
        let path = endpoint.as_path();
        let live = Listener::bind(&endpoint).expect("a listener");
        assert!(lock_is_held(path), "a live listener holds the lock");
        drop(live);
        // A process another case starts in the same moment holds a copy of every descriptor this
        // program has open until it executes its program, so the lock is free once that has
        // happened, within a bound, and not at the instant of the drop.
        let begun = std::time::Instant::now();
        while lock_is_held(path) && begun.elapsed() < std::time::Duration::from_secs(10) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !lock_is_held(path),
            "the lock is free after the listener ends"
        );
    }

    /// A listener that is killed leaves a socket and a free lock, and the next bind replaces it.
    #[test]
    fn a_listener_killed_without_cleanup_leaves_a_socket_the_next_bind_replaces() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "killed.sock");
        let mut child = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--ignored",
                "--exact",
                "--nocapture",
                "endpoint::tests::unix::a_listener_that_binds_and_waits",
            ])
            .env("KR_IPC_ENDPOINT_CASE", endpoint.as_path())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the program starts itself");
        let stdout = child.stdout.take().expect("its output");
        let mut bound = false;
        for line in std::io::BufReader::new(stdout).lines() {
            if line.expect("a line") == "bound" {
                bound = true;
                break;
            }
        }
        assert!(bound, "the child reports its bind");
        child.kill().expect("SIGKILL");
        child.wait().expect("the child is gone");
        assert!(
            endpoint.as_path().exists(),
            "the killed listener left its socket"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let _entered = runtime.enter();
        let live = Listener::bind(&endpoint).expect("the leftover is replaced");
        drop(live);
    }

    /// The other half of the case above: a program that binds and waits to be killed. It runs
    /// only when that case starts it.
    #[tokio::test]
    #[ignore = "started by the case that kills a listener, as a program of its own"]
    async fn a_listener_that_binds_and_waits() {
        use std::io::Write as _;

        let path = std::env::var_os("KR_IPC_ENDPOINT_CASE").expect("an endpoint named by the case");
        let endpoint = Endpoint::from_path(path).expect("an endpoint");
        let _live = Listener::bind(&endpoint).expect("a listener");
        println!("bound");
        std::io::stdout().flush().expect("a flush");
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }

    /// A program the listener's process starts after the bind does not keep the lock.
    #[tokio::test]
    async fn a_child_started_after_the_bind_does_not_keep_the_lock() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "child.sock");
        let path = endpoint.as_path();
        let live = Listener::bind(&endpoint).expect("a listener");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("a program that waits");
        drop(live);
        let held = lock_is_held(path);
        child.kill().expect("the child ends");
        child.wait().expect("the child is gone");
        assert!(!held, "the child inherited the lock");
    }

    /// What the volume says decides a removal on macOS, where a refused connect cannot show that
    /// a listener ended.
    #[cfg(target_vendor = "apple")]
    mod volume {
        use super::*;
        use crate::endpoint::platform::live::Volume;
        use crate::endpoint::platform::{replace_stale_socket_with, volume_ids};

        /// A leftover socket whose lock is free and whose record names it.
        fn leave_a_socket_that_a_record_names(folder: &PrivateTempDir, name: &str) -> PathBuf {
            let path = folder.path().join(name);
            leave_a_refusing_socket(&path);
            leave_the_record_of(&path);
            path
        }

        /// A record that names the socket and the lock file does not remove a socket on a volume
        /// that does not say its object numbers persist: unsupported, unknown or unread.
        #[test]
        fn a_matching_record_on_a_volume_that_does_not_say_its_ids_persist_keeps_the_socket() {
            let folder = PrivateTempDir::create();
            for (name, volume) in [
                ("unsupported.sock", Volume::NotPersistent),
                ("unknown.sock", Volume::Unknown),
                ("failed.sock", Volume::ReadFailed),
            ] {
                let path = leave_a_socket_that_a_record_names(&folder, name);
                let before = identity(&path);
                let error = replace_stale_socket_with(&path, "text", &|_| volume)
                    .expect_err("the socket is kept");
                match error {
                    IpcError::Listen { refusal, .. } => {
                        assert_eq!(refusal, ListenRefusal::Unanswered, "{name}");
                    }
                    other => panic!("a listen refusal, not {other:?}"),
                }
                assert_eq!(identity(&path), before, "{name} is left where it was");
            }
        }

        /// The same record on a volume that says its object numbers persist removes the socket.
        #[test]
        fn a_matching_record_on_a_volume_that_says_its_ids_persist_replaces_the_socket() {
            let folder = PrivateTempDir::create();
            let path = leave_a_socket_that_a_record_names(&folder, "supported.sock");
            replace_stale_socket_with(&path, "text", &|_| Volume::Persistent)
                .expect("the socket is removed");
            assert!(!path.exists(), "the socket is gone");
        }

        /// The volume's own read of the case's folder decides the same way: persistent removes, and
        /// anything else keeps.
        #[test]
        fn the_real_volume_read_of_the_test_folder_decides_the_same_way() {
            let folder = PrivateTempDir::create();
            let read = volume_ids(folder.path());
            let path = leave_a_socket_that_a_record_names(&folder, "real.sock");
            let result = replace_stale_socket_with(&path, "text", &volume_ids);
            match read {
                Volume::Persistent => {
                    result.expect("a persistent volume replaces the socket");
                    assert!(!path.exists());
                }
                other => {
                    let error = result.expect_err("the socket is kept");
                    assert!(
                        matches!(
                            error,
                            IpcError::Listen {
                                refusal: ListenRefusal::Unanswered,
                                ..
                            }
                        ),
                        "{other:?}: {error:?}"
                    );
                    assert!(path.exists());
                }
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// A pipe name that exists is named taken, with no process and no instruction to stop one.
    #[tokio::test]
    async fn a_pipe_name_that_exists_is_named_taken_without_a_pid() {
        let name = format!("kr-ipc-taken-{}", crate::new_uuid());
        let endpoint = Endpoint::from_name(name).expect("a pipe name");
        let _first = Listener::bind(&endpoint).expect("the first instance");
        let error = Listener::bind(&endpoint).expect_err("the bind is refused");
        let IpcError::Listen { refusal, .. } = error else {
            panic!("a listen refusal, not {error:?}");
        };
        assert_eq!(refusal, ListenRefusal::NameTaken);
        let said = refusal.said(&endpoint.as_text());
        assert!(
            said.contains("the pipe is already in use by another program, or another account made it first, and kr cannot name the holder"),
            "{said}"
        );
        assert!(
            !said.contains("process") && !said.contains("stop"),
            "{said}"
        );
    }
}
