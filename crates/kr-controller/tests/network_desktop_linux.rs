//! The Linux desktop's display servers, over the network path.
//!
//! KR-REQ-03.26: what a paired device is told about a Linux desktop turns on which display server
//! the host is on and whether a compositor runs it. The platform reading asks the login manager,
//! so this runs the daemon against a login manager that answers an X11 session, a Wayland session
//! under one compositor and a Wayland session under another, and reads what the owner receives
//! beside what a device receives for each. A device is told a name's class and its length, so the
//! compositor itself is the owner's to read; which compositor and tool pair a capability answer
//! turns on is the platform reader's own unit case.
//!
//! The reading's program is the process's, so these are one case in a process of their own. It
//! needs a machine that is not a container, which hides the host's desktop from any reading.

#![cfg(target_os = "linux")]

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::desktop::{
    DisplayServer, EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::hostinfo::export::{ContentClass, withheld};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use net_support::Host;

const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// A login manager that answers `type` and `desktop` for the graphical session of this user.
///
/// The session's leader is this test process, which is a process the reading can anchor a
/// generation on.
fn login_manager(directory: &std::path::Path, session: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let answers = directory.join("session");
    std::fs::write(&answers, session).expect("the session's properties");
    let program = directory.join("loginctl");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  show-user) echo 'Display=c1' ;;\n  show-session) cat '{}' ;;\nesac\n",
            answers.display()
        ),
    )
    .expect("the login manager");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("it can be run");
    program
}

fn session(kind: &str, desktop: &str) -> String {
    format!(
        "Type={kind}\nClass=user\nState=active\nRemote=no\nLockedHint=no\nActive=yes\nLeader={}\n\
         Desktop={desktop}\nName=kr-test\n",
        std::process::id()
    )
}

/// Reads `environment.capabilities` as the owner and as a paired device, on a host whose login
/// manager is `program`.
async fn read_both(
    program: &std::path::Path,
) -> (EnvironmentCapabilitiesResult, EnvironmentCapabilitiesResult) {
    kr_worker::desktop::platform::set_probe_program(Some(program));
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, device) = net_support::paired_device(&host, &owner, VIEWER).await;
    let params = EnvironmentCapabilitiesParams {
        environment_id: host.environment_id,
    };
    let locally: EnvironmentCapabilitiesResult = typed(
        &control
            .request(Method::EnvironmentCapabilities, &params)
            .await
            .expect("the call reaches the daemon")
            .expect("environment.capabilities succeeds"),
    );
    let remotely: EnvironmentCapabilitiesResult = device
        .read(Method::EnvironmentCapabilities, &params)
        .await
        .expect("environment.capabilities is served to the device");
    device.close();
    host.stop().await;
    (locally, remotely)
}

/// The display-server record's schema, as the answer gives it.
fn schema(answer: &EnvironmentCapabilitiesResult) -> Option<String> {
    answer
        .desktop
        .record(capabilities::DISPLAY_SERVER)
        .expect("the display server has a record of its own")
        .identity
        .schema
        .as_ref()
        .cloned()
}

/// KR-REQ-03.26: the owner is told which display server a Linux host is on and which compositor
/// runs it, and a device is told the display server, the protocol the server speaks and whether a
/// compositor runs it, with the compositor's name as its class and length. Whichever the host is
/// on, no screen capture or input injection is reported available because a tool is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_told_which_display_server_the_host_is_on_and_whether_a_compositor_runs_it() {
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let mut compositors = Vec::new();
    for (kind, desktop, server) in [
        ("x11", "", DisplayServer::X11),
        ("wayland", "sway", DisplayServer::Wayland),
        ("wayland", "GNOME", DisplayServer::Wayland),
    ] {
        let program = login_manager(directory.path(), &session(kind, desktop));
        let (locally, remotely) = read_both(&program).await;
        let compositor = (!desktop.is_empty()).then_some(desktop);

        assert_eq!(
            locally.desktop.desktop.display_server, server,
            "the owner is told the display server of the {kind} session {desktop} (this needs a \
             machine that is not a container)"
        );
        assert_eq!(
            locally
                .desktop
                .desktop
                .compositor
                .as_ref()
                .map(String::as_str),
            compositor,
            "the owner is told the compositor of the {kind} session {desktop}"
        );
        assert_eq!(schema(&locally).as_deref(), Some(kind));

        assert_eq!(
            remotely.desktop.desktop.display_server, server,
            "a device is told the display server of the {kind} session {desktop}"
        );
        assert_eq!(
            remotely.desktop.desktop.compositor.as_ref().cloned(),
            compositor.map(|name| withheld(ContentClass::Name, name)),
            "a device is told whether a compositor runs the {kind} session {desktop}, and its \
             class and length"
        );
        assert_eq!(
            schema(&remotely),
            Some(withheld(ContentClass::Name, kind)),
            "and the protocol the server speaks"
        );
        for capability in [capabilities::SCREEN_CAPTURE, capabilities::INPUT_INJECTION] {
            let record = remotely
                .desktop
                .record(capability)
                .unwrap_or_else(|| panic!("{capability} has a record"));
            assert!(
                !record.state.is_available(),
                "{capability} on {kind} {desktop} is reported available: {record:?}"
            );
        }
        compositors.push(remotely.desktop.desktop.compositor.clone());
    }
    let [x11, sway, gnome] = &compositors[..] else {
        panic!("three sessions were read");
    };
    assert!(!x11.is_present() && sway.is_present() && gnome.is_present());
    assert_ne!(
        sway, gnome,
        "two compositors of different names are two answers"
    );
}
