//! The daemon's half of the plugin runtime on every platform the product ships on: a real daemon
//! starts a real plugin host through the platform's own way of starting a service, a worker's
//! request is the only thing that does it, and a host that ends is replaced without the worker
//! being touched.
//!
//! The worker here is this test process, which is how `barrier.rs` hosts one: the daemon's
//! supervisor reports this process as the worker it started, so the daemon records this process
//! for the session, and the request for the plugin runtime that the daemon answers only from the
//! process it recorded comes from the one process that is it. The component is registered with the
//! runtime by this process too, through the client a worker links. What the worker's own link does
//! with its broker is shown against real workers in `plugin_runtime.rs`, on the platforms that
//! adopt a program into a binding; the claims that depend on the platform are these:
//!
//! * the platform starts the host, and the host is not in this process's group, so what ends this
//!   process's group does not reach it (on Windows, a process outside every job the daemon runs in,
//!   which is shown by the jobs closing on a daemon and its host running on);
//! * the endpoint a worker reaches the host on, a socket or a named pipe, is the one the daemon
//!   published, and the host answers a challenge on it;
//! * a component compiles and runs in the host on this platform;
//! * a host that is killed is replaced by the next request;
//! * a daemon that starts again finds the host it left and starts none.
//!
//! Everything a launched process opens is on the internal disk, under the test's own tree.

use std::time::Duration;

use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::ids::RepositoryGeneration;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::protocol::ComponentSource;
use kr_plugin_service::vocabulary::{BindingActivity, BindingFacts};
use kr_protocol::ids::PluginId;

mod plugin_world;

use kr_ipc::identity::ProcessState;
use plugin_world::{PATIENCE, hosted, install, kill, until, well_behaved};

/// Registers the component with the runtime the way a worker does, and asks it for a document.
async fn register_and_snapshot(runtime: &PluginClient, component: &ComponentSource) {
    let binding = new_binding_id();
    runtime
        .register(
            binding,
            &PluginIdentity::new(
                PluginId::new("kalareach/well-behaved").expect("an identifier"),
                PackageVersion::parse("1.0.0").expect("a version"),
                component.digest,
                RepositoryGeneration::new(1),
            ),
            &BindingFacts {
                plugin_id: "kalareach/well-behaved".to_owned(),
                binding_revision: 1,
                activity: BindingActivity::Idle,
                thread_id: None,
                turn_id: None,
                updated_at_ms: 0,
                held_rights: Vec::new(),
            },
            "/bin/sh",
            component,
        )
        .await
        .expect("the component registers in the runtime on this platform");
    let snapshot = runtime
        .snapshot(binding, Duration::from_secs(5))
        .await
        .expect("the component answers");
    assert!(snapshot.answered());
}

/// KR-REQ-05.06, KR-REQ-05.07 and KR-REQ-05.08 on this platform: the daemon starts the plugin host
/// only when the worker asks, through the platform's own start; the host is not in this process's
/// group and a worker reaches it on the endpoint the daemon published; a component runs in it; a
/// host that is killed ends the worker's connection to it and is replaced by the next request;
/// and a daemon that starts again finds the host it left and starts none. The worker here is this
/// process and has no link of its own to the host, so this shows the daemon's half and the host:
/// the end of a worker's connection to a host that is killed, the replacement, and the adoption.
/// What a worker's own link does with its bindings through that is shown against real workers in
/// `plugin_runtime.rs`, where the platform adopts a program into a binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_host_is_started_by_the_platform_when_the_worker_asks_and_replaced_when_it_ends()
{
    let Some(wasm) = well_behaved() else {
        return;
    };
    let mut hosted = hosted().await;
    let component = install(&hosted.environment(), &wasm);

    // Asked for nothing, the daemon has started nothing: no service, no descriptor, and nothing
    // listening on the endpoint a worker would reach it on.
    assert_eq!(hosted.started(), 0);
    assert!(hosted.published().is_none());
    assert!(PluginClient::connect(&hosted.environment()).await.is_err());

    // The worker asks. The platform starts the host, and the component runs in it.
    let runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 1);
    let host = hosted.published().expect("the host is published");
    // Not in this process's group, so a signal aimed at this process's group does not reach it.
    // (Where the platform has no service manager the host is this process's child, in a group of
    // its own.)
    #[cfg(unix)]
    assert_ne!(
        group_of(host.pid.get()),
        group_of(u64::from(std::process::id())),
        "the host is in this process's group, so what ends this process's group ends it"
    );
    register_and_snapshot(&runtime, &component).await;

    // The host is killed, as a crash kills it. The worker's connection to it ends.
    kill(&host);
    // What the host had said is read out, and then the connection is over.
    assert!(
        tokio::time::timeout(PATIENCE, async {
            while runtime.notice().await.is_some() {}
        })
        .await
        .is_ok(),
        "the worker's connection to the host never ended"
    );
    until("the host to end", || async {
        (kr_ipc::identity::process_state(&host) == ProcessState::Ended).then_some(())
    })
    .await;

    // The next request starts a replacement, and the component runs in that.
    let runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 2);
    let replacement = hosted.published().expect("the replacement is published");
    assert_ne!(replacement, host);
    register_and_snapshot(&runtime, &component).await;

    // A daemon that starts again finds the host it left, and the next request starts no other.
    drop(runtime);
    hosted.restart().await;
    let _runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 0, "the restarted daemon started a host");
    assert_eq!(hosted.published(), Some(replacement));
}

/// The process group a process is in, as the operating system reports it.
#[cfg(unix)]
fn group_of(pid: u64) -> u32 {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .expect("lists the process");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a process group")
}

/// The variable that makes the helper below do what it is for: it is set by the test that starts
/// the helper and by nothing else, so a run of every ignored test leaves the helper alone.
#[cfg(windows)]
const NESTED_HELPER: &str = "KR_PLUGIN_HOST_NESTED_HELPER";

/// Hosts a daemon and its worker, which is this process, and has the daemon start the plugin host,
/// inside the jobs its parent built, until those jobs end it.
///
/// It says when the host is published, and where the tree and the task are, so that its parent can
/// clean up what a process that its jobs end cannot.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a helper process of the test below, which starts it itself"]
async fn a_daemon_and_its_plugin_host_for_its_parent() {
    if std::env::var_os(NESTED_HELPER).is_none() {
        return;
    }
    let mut word = String::new();
    std::io::stdin()
        .read_line(&mut word)
        .expect("the parent's word that the jobs are in place");
    let hosted = hosted().await;
    let _runtime = hosted.runtime().await;
    let host = hosted.published().expect("the host is published");
    println!(
        "plugin host ready pid={} task={} root={}",
        host.pid.get(),
        kr_controller::supervision::windows::task_name(hosted.environment_id),
        hosted.tree.root().display()
    );
    std::future::pending::<()>().await;
}

/// KR-REQ-05.06: the plugin runtime is a service of its own that the daemon starts when a worker
/// asks, outside the controller's kill tree. The daemon runs in the nesting a breakaway cannot see
/// through: an outer job that ends its members when it closes and does not let them leave, over an
/// inner one that lets them. The host the platform starts for it was never in either, so when the
/// jobs close and take the daemon and its worker with them the host runs on.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plugin_host_outlives_the_jobs_its_daemon_ran_in() {
    use std::io::{BufRead as _, Write as _};
    use std::os::windows::io::AsHandle as _;

    use kr_ipc::starter::{BREAKAWAY_OK, Job, KILL_ON_JOB_CLOSE};

    let mut daemon = std::process::Command::new(std::env::current_exe().expect("this test"))
        .args([
            "a_daemon_and_its_plugin_host_for_its_parent",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(NESTED_HELPER, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the daemon's process starts");
    let outer = Job::create(KILL_ON_JOB_CLOSE).expect("the outer job");
    outer
        .assign(daemon.as_handle())
        .expect("the daemon is in the outer job");
    let inner = Job::create(BREAKAWAY_OK).expect("the inner job");
    inner
        .assign(daemon.as_handle())
        .expect("the daemon is in the inner job, beneath the outer");
    writeln!(daemon.stdin.take().expect("its input"), "go").expect("the word is given");
    // Its output is read to the end on a thread of its own, so the helper never writes into a
    // closed pipe; the line that says the host is published is passed on.
    let output = daemon.stdout.take().expect("its output");
    let (ready, is_ready) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if let Some(said) = line.strip_prefix("plugin host ready ") {
                let _ = ready.send(said.to_owned());
            }
        }
    });
    let said = tokio::task::spawn_blocking(move || is_ready.recv_timeout(PATIENCE * 2))
        .await
        .expect("the wait")
        .expect("the daemon in the nested jobs started the plugin host");
    let field = |name: &str| {
        said.split(' ')
            .take_while(|part| !part.starts_with("root="))
            .find_map(|part| part.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("the helper said {name}: {said}"))
            .to_owned()
    };
    let host = kr_ipc::identity::process_start_identity(field("pid").parse().expect("a pid"))
        .expect("the plugin host's identity");
    assert_eq!(
        kr_ipc::identity::process_state(&host),
        ProcessState::Running,
        "the plugin host is running while its daemon's jobs are open"
    );

    // The jobs close. The outer one ends every process in it, the daemon and its worker among them.
    drop(inner);
    drop(outer);
    tokio::task::spawn_blocking(move || daemon.wait())
        .await
        .expect("the wait")
        .expect("the jobs ended the daemon, and its process is collected");
    let _ = reader.join();
    let survived = kr_ipc::identity::process_state(&host);
    // What a process the jobs could not end leaves is the test's to remove, whatever was found.
    kill(&host);
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("the system"))
        .join("System32")
        .join("schtasks.exe");
    let _ = std::process::Command::new(system)
        .args(["/Delete", "/TN", &field("task"), "/F"])
        .output();
    if let Some((_, root)) = said.split_once("root=") {
        let _ = std::fs::remove_dir_all(root);
    }
    assert_eq!(
        survived,
        ProcessState::Running,
        "the plugin host outlived every job its daemon ran in"
    );
}
