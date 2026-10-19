//! The Codex application server and the native `--remote` terminal through a gateway, with the
//! real worker pieces and the stand-in for the application the gateway suite uses.

#![cfg(unix)]

mod common;

use common::gateway::{COMMAND, Gateway, directory_of, eventually};

/// KR-REQ-12.17: the Codex App Server and the native `--remote` terminal run through the gateway
/// on the pinned release's schemas. The launch names the gateway's socket as the terminal's
/// remote, the server the host starts is the application server on its standard streams, and the
/// session runs from `initialize` to the end of a turn that waited on an approval. The stand-in
/// checks every frame it reads or writes, in both directions, against the schemas of the release it
/// stands for and ends with an error on one the release would not write, so a terminal that ends
/// cleanly with nothing said on its error stream has had nothing but pinned frames through the
/// gateway.
#[test]
fn kr_req_12_17_the_app_server_and_the_native_remote_run_through_the_gateway_on_the_pinned_schemas()
{
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let directory = directory_of(&answer);
    let record = std::fs::read_to_string(directory.join("launch")).expect("the launch record");
    assert!(
        record.contains(&format!("unix://{}", directory.join("gw.sock").display())),
        "the launch names the gateway's socket as the terminal's remote: {record}"
    );

    // The terminal reads the server's request for an approval and waits to be released, so the
    // server is running, and recorded, while it waits.
    let release = shell.placed.host.root().join("answer");
    let mut launched = shell.launch(
        &answer,
        "pinned",
        &[
            ("KR_STAND_IN", "answer-when-released"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            (
                "KR_STAND_IN_RELEASE",
                release.to_str().expect("a text path"),
            ),
        ],
    );
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "{servers:?}");
    let server = servers[0].clone();
    assert_eq!(
        kr_ipc::identity::process_state(&server),
        kr_ipc::identity::ProcessState::Running
    );
    std::fs::write(&release, b"answer").expect("the terminal is released");
    launched.prints("TUI: turn/completed");
    let status = launched.ends();
    let said = launched.said();
    assert!(
        status.success() && said.is_empty(),
        "the terminal ended {status} having said {said:?}: a frame that is not the pinned \
         release's ends it with an error"
    );
    let printed = launched.printed();
    let lines: Vec<&str> = printed.lines().collect();
    let at = |line: &str| {
        lines
            .iter()
            .position(|printed| *printed == line)
            .unwrap_or_else(|| panic!("the terminal printed {line:?}: {printed}"))
    };
    assert!(
        at("TUI: a turn is running")
            < at("TUI: the server asks for item/commandExecution/requestApproval")
            && at("TUI: the server asks for item/commandExecution/requestApproval")
                < at("TUI: turn/completed"),
        "the session ran in the order the release runs it: {printed}"
    );
    eventually("the server ended with the program", || {
        kr_ipc::identity::process_state(&server) == kr_ipc::identity::ProcessState::Ended
    });
}
