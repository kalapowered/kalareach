//! The Linux desktop's display servers, over the network path.
//!
//! KR-REQ-03.26: what a paired device is told about a Linux desktop turns on which display server
//! the host is on and which compositor runs it. The platform reading asks the login manager, so
//! this runs the daemon against a login manager that answers an X11 session, a Wayland session
//! under one compositor and a Wayland session under another, and reads what a device receives for
//! each beside what the owner receives.
//!
//! The reading's program is the process's, so these are one case in a process of their own.

#![cfg(target_os = "linux")]

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::desktop::{
    DisplayServer, EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use net_support::Host;

const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// What one display-server record tells whoever reads it, with each name as the number of bytes it
/// has: the owner is told the name, and a device is told its class and its length.
#[derive(Debug, PartialEq, Eq)]
struct Told {
    server: DisplayServer,
    schema_bytes: Option<usize>,
    compositor_bytes: Option<usize>,
    application_bytes: Option<usize>,
}

/// The length of a name as the reader of the answer is told it.
fn bytes_of(name: &str) -> usize {
    name.strip_prefix("[name withheld, ")
        .and_then(|rest| rest.strip_suffix(" bytes]"))
        .and_then(|length| length.parse().ok())
        .unwrap_or(name.len())
}

fn told(answer: &EnvironmentCapabilitiesResult) -> Told {
    let record = answer
        .desktop
        .record(capabilities::DISPLAY_SERVER)
        .expect("the display server has a record of its own");
    Told {
        server: answer.desktop.desktop.display_server,
        schema_bytes: record.identity.schema.as_ref().map(|name| bytes_of(name)),
        compositor_bytes: answer
            .desktop
            .desktop
            .compositor
            .as_ref()
            .map(|name| bytes_of(name)),
        application_bytes: record
            .subject
            .application
            .as_ref()
            .map(|name| bytes_of(name)),
    }
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

/// KR-REQ-03.26: a device is told which display server the Linux host is on and which compositor
/// runs it, and the answers for X11, for one Wayland compositor and for another each differ from
/// the others. Whichever the host is on, no screen capture or input injection is reported
/// available because a tool is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_told_x11_wayland_and_the_compositor_apart() {
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let mut answers = Vec::new();
    for (kind, desktop, server) in [
        ("x11", "", DisplayServer::X11),
        ("wayland", "sway", DisplayServer::Wayland),
        ("wayland", "GNOME", DisplayServer::Wayland),
    ] {
        let program = login_manager(directory.path(), &session(kind, desktop));
        let (locally, remotely) = read_both(&program).await;
        assert_eq!(
            locally.desktop.desktop.display_server, server,
            "the owner is told the {kind} session {desktop} is on"
        );
        assert_eq!(
            told(&remotely),
            told(&locally),
            "the device is told what the owner is told about the {kind} session {desktop} is on"
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
        answers.push(told(&remotely));
    }
    let [x11, sway, gnome] = &answers[..] else {
        panic!("three sessions were read");
    };
    assert_eq!(x11.schema_bytes, Some("x11".len()));
    assert_eq!(sway.schema_bytes, Some("wayland".len()));
    assert!(
        x11.compositor_bytes.is_none()
            && sway.compositor_bytes.is_some()
            && gnome.compositor_bytes.is_some()
    );
    assert_ne!(
        sway, gnome,
        "two compositors under one display server are two answers"
    );
}
