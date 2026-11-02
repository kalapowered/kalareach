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
use std::time::{Duration, Instant};

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

/// How long the runtime is given to answer `--version`, and then to be collected when it has not.
const VERSION_BOUND: Duration = Duration::from_secs(60);

/// Returns false and says why when this machine has no container runtime.
fn runtime_available(suite: &str) -> bool {
    available_through(RUNTIME, suite)
}

/// [`runtime_available`], for the program `runtime`. Only a program that is not there is a reason
/// to skip: one that is there and fails its `--version` is a broken install, and one that does not
/// answer it is a stall. Both fail the case, where a skip would pass every case that needs the
/// runtime.
fn available_through(runtime: &str, suite: &str) -> bool {
    available_within(runtime, suite, VERSION_BOUND)
}

/// [`available_through`], giving the runtime `bound` to answer `--version`.
fn available_within(runtime: &str, suite: &str, bound: Duration) -> bool {
    let mut asked = match Command::new(runtime)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(asked) => asked,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("{suite}: skipped, because {runtime} is not installed on this machine");
            return false;
        }
        Err(error) => panic!("{runtime} is installed and could not be started: {error}"),
    };
    let begun = Instant::now();
    let status = loop {
        match asked.try_wait().expect("the state of the runtime's answer") {
            Some(status) => break status,
            None if begun.elapsed() < bound => {
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                // Collected within a bound too: a program the kernel does not let go is reported,
                // and not waited for.
                let _ = asked.kill();
                let collected_by = Instant::now() + VERSION_BOUND;
                while matches!(asked.try_wait(), Ok(None)) && Instant::now() < collected_by {
                    std::thread::sleep(Duration::from_millis(20));
                }
                panic!("{runtime} `--version` did not end within {bound:?}");
            }
        }
    };
    assert!(
        status.success(),
        "{runtime} is installed and `--version` ended with {status}"
    );
    true
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
        // The runtime answered `--version` a moment ago, so one that cannot start the call is
        // broken, and a skip would pass the case without running it.
        Err(error) => panic!("{RUNTIME} could not start a container: {error}"),
    };
    let codec = FrameCodec::new(StreamKind::Control);
    let hello = BridgeFrame::Hello(Box::new(BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
        // The one thing a bridge may never carry.
        origin_ingress: ActorIngress::PairedDevice,
        already_bridged: false,
        start: false,
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

/// Only a runtime that is not there is a reason to skip the suite. One that is there and fails its
/// `--version` is a broken install, and fails the case that asks.
#[test]
fn only_a_runtime_that_is_not_there_is_a_reason_to_skip() {
    assert!(!available_through(
        "/nonexistent-runtime/podman",
        "the_cases_of_a_machine_with_none"
    ));

    let directory = tempfile::tempdir().expect("a directory");
    let runtime_that = |name: &str, body: &str| {
        let text = directory.path().join(format!("{name}.text"));
        std::fs::write(&text, format!("#!/bin/sh\n{body}\n")).expect("the stand-in runtime");
        let program = directory.path().join(name);
        kr_ipc::testing::place_program(&text, &program);
        program.display().to_string()
    };
    let working = runtime_that("working", "exit 0");
    assert!(available_through(
        &working,
        "the_cases_of_a_machine_with_one"
    ));

    let broken = runtime_that("broken", "exit 3");
    let failed =
        std::panic::catch_unwind(|| available_through(&broken, "the_cases_of_a_broken_one"));
    let said = failed.expect_err("a runtime that fails its version fails the case");
    let said = said.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        said.contains("is installed and `--version` ended with"),
        "{said}"
    );

    // One that does not answer is a stall, ended at the bound it was given, and fails the case.
    let stalled = runtime_that("stalled", "echo $$ > \"$0.pid\"; exec sleep 120");
    let failed = std::panic::catch_unwind(|| {
        available_within(
            &stalled,
            "the_cases_of_a_stalled_one",
            Duration::from_secs(2),
        )
    });
    let said = failed.expect_err("a runtime that does not answer fails the case");
    let said = said.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        said.contains("`--version` did not end within 2s"),
        "the call is named with the bound it was given: {said}"
    );
    // And it does not outlast the case: a runtime left running is left on a machine others share.
    let pid = std::fs::read_to_string(format!("{stalled}.pid"))
        .expect("the stand-in wrote its process number")
        .trim()
        .parse::<i32>()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .expect("a process number");
    let begun = Instant::now();
    while rustix::process::test_kill_process(pid).is_ok() {
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "the runtime that did not answer is still running"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
