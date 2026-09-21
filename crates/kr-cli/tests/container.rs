//! `kr bridge --stdio` running inside a real container.
//!
//! The helper on the far side of a container bridge is the same command as the helper on the far
//! side of a WSL one, and the promise it has to keep is the same: a handshake that says the
//! request arrived from the network is refused, inside the container, before anything is
//! connected. That is what this suite drives, over the container's own standard streams.
//!
//! Where the machine has no container runtime the suite says so by name and stops.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kr_protocol::actor::ActorIngress;
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::identity::{BridgeFrame, BridgeHello, BridgeTarget};
use kr_protocol::ids::{BuildId, EnvironmentId};
use kr_protocol::scalars::Uuid;

/// The runtime this suite uses, and the image it starts.
const RUNTIME: &str = "podman";
const IMAGE: &str = "docker.io/library/debian:stable-slim";

/// Where the command is mounted inside the container.
const MOUNTED_HELPER: &str = "/kr/kr";

fn runtime_available(suite: &str) -> bool {
    let present = Command::new(RUNTIME)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !present {
        eprintln!("{suite}: skipped, because {RUNTIME} is not installed on this machine");
    }
    present
}

/// The command, copied to a directory of this run's own so it can be mounted read-only.
fn mountable_command() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::TempDir::new().expect("a directory for the mounted command");
    let destination = directory.path().join("kr");
    kr_ipc::testing::place_program(std::path::Path::new(env!("CARGO_BIN_EXE_kr")), &destination);
    (directory, destination)
}

#[test]
fn the_helper_inside_a_container_refuses_a_handshake_that_declares_a_network_actor() {
    if !runtime_available("the_helper_inside_a_container") {
        return;
    }
    let (directory, _binary) = mountable_command();
    let mount = format!("{}:/kr:ro", directory.path().display());
    let mut child = match Command::new(RUNTIME)
        .args([
            "run",
            "--rm",
            "--interactive",
            "--user",
            "root",
            "--volume",
            &mount,
            "--",
            IMAGE,
            MOUNTED_HELPER,
            "bridge",
            "--stdio",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "the_helper_inside_a_container: skipped, because the runtime could not start a container: {error}"
            );
            return;
        }
    };
    let codec = FrameCodec::new(StreamKind::Control);
    let hello = BridgeFrame::Hello(Box::new(BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
        // The one thing a bridge may never carry.
        origin_ingress: ActorIngress::PairedDevice,
        already_bridged: false,
        target: BridgeTarget::Controller,
    }));
    {
        let input = child.stdin.as_mut().expect("its standard input");
        input
            .write_all(&codec.encode_message(&hello).expect("the frame encodes"))
            .expect("writes to the helper");
        input.flush().expect("flushes");
    }
    let mut output = child.stdout.take().expect("its standard output");
    let mut prefix = [0_u8; 4];
    read_exact(&mut output, &mut prefix).expect("a length prefix");
    let declared = u32::from_be_bytes(prefix) as usize;
    assert!(declared <= StreamKind::Control.max_payload_len());
    let mut payload = vec![0_u8; declared];
    read_exact(&mut output, &mut payload).expect("a payload");
    let frame: BridgeFrame =
        kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits())
            .expect("a bridge frame");
    match frame {
        BridgeFrame::Refused(error) => {
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            assert!(
                error.message.contains("locally authenticated"),
                "{}",
                error.message
            );
        }
        other => panic!("expected a refusal from inside the container, got {other:?}"),
    }
    drop(child.stdin.take());
    let status = child.wait().expect("the container ends");
    assert_ne!(
        status.code(),
        Some(0),
        "a refused bridge does not exit zero"
    );
}

fn read_exact(source: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = source.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        filled += read;
    }
    Ok(())
}
