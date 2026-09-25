//! What a session's ownership observation finds on Linux, and what it reads to find it.
//!
//! This test process plays the worker. It opens a real session, whose launch makes it the child
//! subreaper as a worker's does, and the session's root shell starts one process of each kind the
//! observation has to find: a job, a job that leaves the session with `setsid`, and a process whose
//! parent exits so that the worker adopts it. The root shell writes where each one is to a file,
//! because the terminal is the session's own.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-07.60 | the observation records the root shell, a job, a job that called `setsid`, and a process the worker adopted when its parent exited, and not a process of the worker's own |
//! | KR-PERF-003 | an idle session's observation reads no process outside the worker's own tree, so what it costs does not grow with the processes on the host |

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::path::Path;
use std::time::{Duration, Instant};

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// A session whose root shell has started one process of each kind, and where each one is.
struct Tree {
    session: kr_worker::session::Session,
    /// Each process the root shell started, by what it is.
    started: Vec<(String, u32)>,
    _host: kr_ipc::testing::TempHost,
}

impl Tree {
    /// Opens a session whose root shell starts a job, a job that leaves with `setsid`, and a
    /// process that its parent leaves behind, and then keeps the terminal.
    fn start() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let written = host.root().join("started");
        // A moment first, so that the session is established before anything is started: a
        // process orphaned before the worker is the child subreaper would be the first
        // process's to collect, not the worker's.
        let mut shell = kr_worker::testing::posix_script(
            "sleep 1; sleep 60 & echo \"a job $!\" >> \"$KR_TREE\"; \
             setsid sleep 60 & echo \"a job that left with setsid $!\" >> \"$KR_TREE\"; \
             (sleep 60 & echo \"a process the worker adopted $!\" >> \"$KR_TREE\"); \
             exec cat",
        );
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
        let started = Self::wait_for(&written, 3);
        // The adopted process's parent has exited by the time it was written down only if the
        // subshell has; wait for the worker to be its parent.
        let me = std::process::id();
        let (_, adopted) = started
            .iter()
            .find(|(kind, _)| kind == "a process the worker adopted")
            .cloned()
            .expect("the adopted process");
        let deadline = Instant::now() + LIVENESS;
        while parent_of(adopted) != Some(me) {
            assert!(
                Instant::now() < deadline,
                "the worker adopts the process {adopted} whose parent exited"
            );
            std::thread::sleep(Duration::from_millis(20));
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

/// Returns whether `pid` is `ancestor` or one of its descendants, following the parents the
/// kernel reports now; `None` when a process on the way can no longer be read.
fn descends_from(mut pid: u32, ancestor: u32) -> Option<bool> {
    for _ in 0..4096 {
        if pid == ancestor {
            return Some(true);
        }
        if pid <= 1 {
            return Some(false);
        }
        pid = parent_of(pid)?;
    }
    Some(false)
}

/// KR-REQ-07.60: the observation records every process the session started, whatever became of
/// it: the root shell, a job, a job that left the session and its terminal with `setsid`, and a
/// process whose parent exited and which the worker, as the child subreaper, adopted. It records no
/// process of the worker's own.
#[test]
fn kr_req_07_60_the_observation_finds_every_process_the_session_started() {
    let mut tree = Tree::start();
    // One of the worker's own, beside the session: it is the worker's child, and not the session's.
    let mut own = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("a process of the worker's own");

    tree.session.observe_owned();
    let seen: Vec<u64> = tree
        .session
        .owned()
        .expect("a launched session owns its processes")
        .surviving()
        .into_iter()
        .map(|identity| identity.pid.get())
        .collect();
    let root = tree
        .session
        .root_identity()
        .expect("the root shell")
        .pid
        .get();
    assert!(seen.contains(&root), "the root shell is found: {seen:?}");
    for (kind, pid) in &tree.started {
        assert!(
            seen.contains(&u64::from(*pid)),
            "{kind}, {pid}, is found: {seen:?}"
        );
    }
    assert!(
        !seen.contains(&u64::from(own.id())),
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
    let mut tree = Tree::start();
    let me = std::process::id();

    let ((), read) = kr_ipc::identity::processes_read_during(|| tree.session.observe_owned());
    let outside: Vec<u32> = read
        .iter()
        .copied()
        .filter(|pid| descends_from(*pid, me) == Some(false))
        .collect();
    assert!(
        outside.is_empty(),
        "the observation read {} processes, {} of them outside this worker's tree: {:?}",
        read.len(),
        outside.len(),
        &outside[..outside.len().min(16)]
    );
    assert!(!read.contains(&1), "the first process is nobody's session");

    tree.end();
}
