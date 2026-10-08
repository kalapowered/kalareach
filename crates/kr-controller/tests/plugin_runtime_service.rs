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
//!   process's group does not reach it (on Windows, a process outside this test's job);
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
