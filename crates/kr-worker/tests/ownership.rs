//! What a session's ownership observation finds on Linux, and what it reads to find it.
//!
//! This test process plays the worker. It opens a real session, whose launch makes it the child
//! subreaper as a worker's does, and the session's root shell starts one process of each kind the
//! observation has to find: a job, a job that leaves the session with `setsid`, and a process whose
//! parent exits so that the worker adopts it. The root shell writes where each one is to a file,
//! because the terminal is the session's own.
//!
//! The cases take turns: each is a tree this process is the root of, and one case's processes are
//! easier to tell from the next case's when only one tree is growing at a time.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-07.60 | the observation records the root shell, a job, a job that called `setsid`, and a process the worker adopted when its parent exited, and not a process of the worker's own; a process adopted while the observation runs, and one left in the session after the root shell has gone, are found too |
//! | KR-PERF-003 | an idle session's observation reads no process outside the worker's own tree, so what it costs does not grow with the processes on the host |

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// Held by each case for as long as its tree lives.
static TURN: Mutex<()> = Mutex::new(());

/// Waits for this case's turn.
fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The script of the tree most cases use: a job, a job that leaves with `setsid`, and a process its
/// parent leaves behind.
const KINDS: &str = "sleep 60 & echo \"a job $!\" >> \"$KR_TREE\"; \
                     setsid sleep 60 & echo \"a job that left with setsid $!\" >> \"$KR_TREE\"; \
                     (sleep 60 & echo \"a process the worker adopted $!\" >> \"$KR_TREE\")";

/// A session whose root shell has started one process of each kind, and where each one is.
struct Tree {
    session: kr_worker::session::Session,
    /// Each process the root shell started, by what it is.
    started: Vec<(String, u32)>,
    _host: kr_ipc::testing::TempHost,
}

impl Tree {
    /// Opens a session whose root shell runs `script`, which writes one line to `$KR_TREE` for each
    /// of the `count` processes it starts, and then keeps the terminal.
    fn start(script: &str, count: usize) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let written = host.root().join("started");
        // A moment first, so that the session is established before anything is started.
        let mut shell = kr_worker::testing::posix_script(&format!("sleep 1\n{script}\nexec cat"));
        shell
            .environment
            .push(("KR_TREE".to_owned(), written.display().to_string()));
        let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
        let config = kr_worker::session::SessionConfig {
            session_id,
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: kr_protocol::session::DisplayNumber::new(1),
            shell,
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
            journal_path: Some(host.environment().journal_database(session_id)),
            spool_directory: Some(host.environment().session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 1024 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = kr_worker::session::Session::open(config).expect("opens");
        session.launch().expect("launches");
        let started = Self::wait_for(&written, count);
        // A process is written down before the subshell that started it exits, so the worker is
        // waited for as the parent of each one it is to adopt.
        let me = std::process::id();
        for (kind, adopted) in &started {
            if !kind.starts_with("a process the worker adopted") {
                continue;
            }
            let deadline = Instant::now() + LIVENESS;
            while parent_of(*adopted) != Some(me) {
                assert!(
                    Instant::now() < deadline,
                    "the worker adopts {kind}, {adopted}, whose parent exited"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Self {
            session,
            started,
            _host: host,
        }
    }

    /// Waits until the root shell has written `count` lines, and returns what each names.
    fn wait_for(written: &Path, count: usize) -> Vec<(String, u32)> {
        let deadline = Instant::now() + LIVENESS;
        loop {
            let lines: Vec<(String, u32)> = std::fs::read_to_string(written)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let (kind, pid) = line.rsplit_once(' ')?;
                    Some((kind.to_owned(), pid.parse().ok()?))
                })
                .collect();
            if lines.len() >= count {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "the root shell starts its processes: {lines:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Returns the process the root shell wrote down as `kind`.
    fn pid(&self, kind: &str) -> u32 {
        self.started
            .iter()
            .find(|(written, _)| written == kind)
            .map(|(_, pid)| *pid)
            .unwrap_or_else(|| panic!("the root shell wrote down {kind}: {:?}", self.started))
    }

    /// Returns the root shell's process identifier.
    fn root(&self) -> u32 {
        u32::try_from(
            self.session
                .root_identity()
                .expect("the root shell")
                .pid
                .get(),
        )
        .expect("a process identifier")
    }

    /// Observes the session's processes and returns the identifiers of those it records.
    fn seen(&mut self) -> Vec<u32> {
        self.session.observe_owned();
        self.recorded()
    }

    /// Returns the identifiers of the processes the session has recorded that are still running.
    fn recorded(&self) -> Vec<u32> {
        self.session
            .owned()
            .expect("a launched session owns its processes")
            .surviving()
            .into_iter()
            .filter_map(|identity| u32::try_from(identity.pid.get()).ok())
            .collect()
    }

    /// Stops every process this test started, the root shell included, so that none outlives it.
    fn end(self) {
        if let Some(owned) = self.session.owned() {
            kr_worker::ownership::force_stop(owned);
        }
        for (_, pid) in &self.started {
            if let Some(pid) = i32::try_from(*pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            }
        }
    }
}

/// Returns the parent a process has now, as `/proc/<pid>/stat` field 4 says.
fn parent_of(pid: u32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = text.rsplit_once(')')?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// KR-REQ-07.60: the observation records every process the session started, whatever became of
/// it: the root shell, a job, a job that left the session and its terminal with `setsid`, and a
/// process whose parent exited and which the worker, as the child subreaper, adopted. It records no
/// process of the worker's own.
#[test]
fn kr_req_07_60_the_observation_finds_every_process_the_session_started() {
    let _turn = turn();
    let mut tree = Tree::start(KINDS, 3);
    // One of the worker's own, beside the session: it is the worker's child, and not the session's.
    let mut own = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("a process of the worker's own");

    let seen = tree.seen();
    assert!(
        seen.contains(&tree.root()),
        "the root shell is found: {seen:?}"
    );
    for (kind, pid) in &tree.started {
        assert!(seen.contains(pid), "{kind}, {pid}, is found: {seen:?}");
    }
    assert!(
        !seen.contains(&own.id()),
        "a process of the worker's own is not the session's: {seen:?}"
    );

    let _ = own.kill();
    let _ = own.wait();
    tree.end();
}

/// KR-PERF-003: an idle session's observation reads nothing about any process outside the worker's
/// own tree. Every session asks it on each idle sweep, so a reading that went through every process
/// on the host would cost each session as much as the host had processes.
#[test]
fn kr_perf_003_an_idle_sessions_observation_reads_no_process_outside_its_own_tree() {
    let _turn = turn();
    let mut tree = Tree::start(KINDS, 3);
    // The worker, the root shell and what the root shell started are this worker's tree; nothing
    // else is growing while this case has its turn.
    let mut tree_members: Vec<u32> = tree.started.iter().map(|(_, pid)| *pid).collect();
    tree_members.extend([std::process::id(), tree.root()]);

    let ((), read) = kr_ipc::identity::processes_read_during(|| tree.session.observe_owned());
    assert!(!read.is_empty(), "the observation's reads are counted");
    let outside: Vec<u32> = read
        .iter()
        .copied()
        .filter(|pid| !tree_members.contains(pid))
        .collect();
    assert!(
        outside.is_empty(),
        "the observation read {} processes, {} of them outside this worker's tree: {:?}",
        read.len(),
        outside.len(),
        &outside[..outside.len().min(16)]
    );

    tree.end();
}

/// KR-REQ-07.60: a process whose parent exits while the observation is reading the tree is found.
/// It is the worker's child by then rather than its parent's, and the worker's own children are
/// read after the rest.
#[test]
fn kr_req_07_60_a_process_adopted_while_the_observation_runs_is_found() {
    let _turn = turn();
    let mut tree = Tree::start(
        "sh -c 'sleep 60 & echo \"a process below a parent $!\" >> \"$KR_TREE\"; \
         echo \"its parent $$\" >> \"$KR_TREE\"; exec sleep 60' &",
        2,
    );
    let child = tree.pid("a process below a parent");
    let parent = tree.pid("its parent");
    let root = tree.root();
    let me = std::process::id();

    // The parent exits just after the root shell's children are read, which named it.
    let mut exited = false;
    kr_ipc::identity::after_each_read(
        move |pid, file| {
            if exited || pid != root || !file.ends_with("/children") {
                return;
            }
            exited = true;
            if let Some(parent) = i32::try_from(parent)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process(parent, rustix::process::Signal::KILL);
            }
            let deadline = Instant::now() + LIVENESS;
            while parent_of(child) != Some(me) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        },
        || tree.session.observe_owned(),
    );
    assert_eq!(
        parent_of(child),
        Some(me),
        "the worker adopted the process during the observation"
    );
    let recorded = tree.recorded();
    assert!(
        recorded.contains(&child),
        "the process adopted while the observation ran, {child}, is found: {recorded:?}"
    );

    tree.end();
}

/// KR-REQ-07.60: a process left in the session after the root shell has ended and been collected
/// is still found. The session keeps the root shell's identifier while anything is in it, and the
/// terminal no longer names the session once the root shell has gone.
#[test]
fn kr_req_07_60_a_process_left_after_the_root_shell_has_gone_is_found() {
    let _turn = turn();
    let mut tree = Tree::start(
        "(trap '' HUP; sleep 60 & echo \"a process the worker adopted, deaf to a hangup $!\" \
         >> \"$KR_TREE\")",
        1,
    );
    let left = tree.pid("a process the worker adopted, deaf to a hangup");
    let root = tree.root();
    if let Some(pid) = i32::try_from(root)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    // Collected as the session's supervision collects it.
    let deadline = Instant::now() + LIVENESS;
    while Path::new(&format!("/proc/{root}")).exists() {
        let _ = tree.session.poll_root_exit();
        assert!(
            Instant::now() < deadline,
            "the root shell's exit is collected"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let seen = tree.seen();
    assert!(
        seen.contains(&left),
        "the process left in the session, {left}, is found: {seen:?}"
    );

    tree.end();
}
