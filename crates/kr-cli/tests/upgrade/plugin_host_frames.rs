//! The frames this release reads from and writes to a plugin host of the release before, taken from
//! a real one.
//!
//! This release's control daemon starts a host of the release before's protocol, or adopts one a
//! daemon of that release started, for a worker of that release. What it says to such a host is a
//! claim it reads (`HostRendezvous`), the acknowledgement it writes (`RendezvousAccepted`), the
//! descriptor it publishes and later reads, and `Hello` and `Verify` with their answers. Everything
//! else of that protocol is spoken between the worker of the release before and the host of that
//! release, and this release never sees it.
//!
//! The case runs the release before's real `kr-plugin-host` as its launcher would, keeps the
//! payload of every frame, and checks each one decodes with this build's types and encodes back to
//! the bytes it came from. With `KR_RECORD_PLUGIN_HOST_FRAMES` set it prints the record that
//! `retained/<level>/plugin-host-frames.json` holds, which `kr-plugin-service`'s cases read. The
//! record holds the bytes the release before's program wrote, and the descriptor file its own
//! daemon published: never a frame this build wrote. What this build writes is shown to be read by
//! the real program in the cases that start one and adopt one.

use std::time::Duration;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{
    Frame, HostDescriptor, HostProtocol, HostRendezvous, RendezvousAccepted, Request, RequestBody,
    ResponseBody,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Nonce256;

use super::plugin_hosts::Wire;
use super::{Host, Setup, Updated, previous, start_agent, terminal_for};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: a plugin host of the release before, run as its
/// launcher runs it, presents a claim this build reads and verifies, accepts the acknowledgement
/// this build writes, answers `Hello` (and refuses another protocol's) and `Verify` in frames this
/// build reads, and a daemon of that release publishes a descriptor file this build reads and
/// writes back to the same bytes.
#[tokio::test(flavor = "multi_thread")]
async fn the_frames_of_the_plugin_host_of_the_release_before_are_read_and_written_back_as_they_were()
 {
    let before = previous();
    let program = before
        .programs
        .iter()
        .find(|(name, ..)| *name == "kr-plugin-host")
        .map(|(_, path, ..)| path.clone())
        .expect("the release before's plugin host");
    let host = Host::bare();
    let environment = host.tree.environment();
    environment.create().expect("the environment's directories");
    let limits = StreamKind::Control.cbor_limits();

    // The release before's program, started as its launcher starts it.
    let reservation_id = kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid());
    let rendezvous =
        launcher::rendezvous_endpoint(&environment, reservation_id).expect("an endpoint");
    let listener = Listener::bind(&rendezvous).expect("the rendezvous endpoint");
    let packages = host.scratch("plugin-packages");
    let working = host.scratch("plugin-host-directory");
    let arguments: Vec<(&str, String)> = vec![
        ("--reservation", reservation_id.to_string()),
        ("--environment", environment.environment_id().to_string()),
        ("--rendezvous", rendezvous.as_text()),
        (
            "--runtime-dir",
            environment.runtime_root().display().to_string(),
        ),
        (
            "--state-dir",
            environment.state_root().display().to_string(),
        ),
        ("--packages-dir", packages.display().to_string()),
    ];
    let mut command = std::process::Command::new(&program);
    for (flag, value) in &arguments {
        command.arg(flag).arg(value);
    }
    let mut child = command
        .current_dir(&working)
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("the release before's plugin host starts");

    // Its claim.
    let (connection, _peer) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
        .await
        .expect("the host presents a claim in time")
        .expect("the claim's connection");
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let claim_bytes = reader.read_payload().await.expect("the claim");
    let claim: HostRendezvous =
        kr_cbor::from_canonical_slice(&claim_bytes, &limits).expect("this build reads the claim");
    assert_eq!(
        kr_cbor::to_canonical_vec(&claim).expect("a claim encodes"),
        claim_bytes,
        "the claim encodes back to the bytes the release before wrote"
    );
    launcher::check_rendezvous(&claim).expect("the claim is signed by the key it presents");
    assert_eq!(claim.reservation_id, reservation_id);
    assert_eq!(
        claim.endpoint,
        launcher::host_endpoint(&environment, &HostProtocol::SECOND)
            .expect("an endpoint")
            .as_text(),
        "the host serves on the endpoint of the release before's protocol"
    );

    // The acknowledgement this build writes, which the program takes before it serves.
    let accepted = RendezvousAccepted {
        reservation_id,
        environment_id: environment.environment_id(),
        endpoint: claim.endpoint.clone(),
    };
    let accepted_bytes = kr_cbor::to_canonical_vec(&accepted).expect("an acknowledgement encodes");
    writer
        .write_message(&accepted)
        .await
        .expect("the acknowledgement");

    // `Hello`, a `Hello` for a protocol it does not speak, and `Verify`.
    let descriptor = HostDescriptor {
        protocol: HostProtocol::SECOND.name.to_owned(),
        environment_id: environment.environment_id(),
        reservation_id: claim.reservation_id,
        endpoint: claim.endpoint.clone(),
        boot_identity: claim.boot_identity.clone(),
        process_start_identity: claim.process_start_identity.clone(),
        host_public_key: claim.host_public_key,
    };
    let endpoint = Endpoint::from_path(&claim.endpoint).expect("the host's endpoint");
    let connection = Connection::connect(&endpoint)
        .await
        .expect("the host answers");
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let nonce = Nonce256::from_bytes([7; 32]);
    let mut exchange = Vec::new();
    for (request_id, body) in [
        (
            1,
            RequestBody::Hello {
                protocol: HostProtocol::SECOND.name.to_owned(),
            },
        ),
        (
            2,
            RequestBody::Hello {
                protocol: "kr-plugin-host/99".to_owned(),
            },
        ),
        (3, RequestBody::Verify { nonce }),
    ] {
        let request = Request { request_id, body };
        let request_bytes = kr_cbor::to_canonical_vec(&request).expect("a request encodes");
        writer.write_message(&request).await.expect("the request");
        let (response_bytes, answer) = loop {
            let payload = reader.read_payload().await.expect("the host answers");
            let frame: Frame = kr_cbor::from_canonical_slice(&payload, &limits)
                .expect("this build reads the host's frame");
            assert_eq!(
                kr_cbor::to_canonical_vec(&frame).expect("a frame encodes"),
                payload,
                "the frame encodes back to the bytes the release before wrote"
            );
            if let Frame::Response { reply_to, body } = frame
                && reply_to == request_id
            {
                break (payload, body);
            }
        };
        match (request_id, answer) {
            (
                1,
                ResponseBody::Hello {
                    protocol,
                    descriptor: told,
                },
            ) => {
                assert_eq!(protocol, HostProtocol::SECOND.name);
                // The host's own account of its descriptor names no reservation: the launcher's
                // is the one published.
                assert_eq!(told.reservation_id.to_string(), uuid_nil());
                assert_eq!(
                    HostDescriptor {
                        reservation_id: claim.reservation_id,
                        ..*told
                    },
                    descriptor
                );
            }
            (2, ResponseBody::Refused { request, .. }) => assert_eq!(request, "hello"),
            (3, ResponseBody::Verified(proof)) => {
                launcher::check_proof(&descriptor, &nonce, &proof)
                    .expect("the proof verifies against the descriptor the claim gives");
            }
            (id, other) => panic!("request {id} was answered {other:?}"),
        }
        exchange.push(serde_json::json!({
            "request": hex(&request_bytes),
            "response": hex(&response_bytes),
        }));
    }
    drop(writer);
    drop(reader);
    child.kill().expect("the host ends");
    let _ = child.wait();

    // The descriptor file the release before's own daemon publishes for such a host: this build
    // reads it and writes the same bytes back.
    let prepared = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await;
    let agent = prepared.host.plugin_agent();
    let terminal = terminal_for(
        &prepared.host,
        &prepared.kr_before(),
        &["attach", &prepared.display],
    );
    terminal.ready().await;
    let program = start_agent(&prepared.host, &terminal, &agent).await;
    prepared.host.plugin_holding_at(Wire::Two, 1).await;
    let published = std::fs::read(
        prepared
            .host
            .tree
            .environment()
            .runtime_dir()
            .join(Wire::Two.descriptor_file()),
    )
    .expect("the descriptor the release before published");
    let read: HostDescriptor =
        serde_json::from_slice(&published).expect("this build reads the descriptor");
    assert_eq!(read.protocol, HostProtocol::SECOND.name);
    assert_eq!(
        serde_json::to_vec(&read).expect("a descriptor encodes"),
        published,
        "the descriptor encodes back to the bytes the release before's daemon wrote"
    );
    super::end_program(&program);
    drop(terminal);
    prepared
        .host
        .close(&prepared.kr_before(), &prepared.display);
    prepared.host.worker_ended(&prepared.worker).await;
    prepared.host.end_the_plugin_host_at(Wire::Two).await;

    if std::env::var_os("KR_RECORD_PLUGIN_HOST_FRAMES").is_some() {
        let record = serde_json::json!({
            "release": before.release.as_str(),
            "arguments": arguments.iter().map(|(flag, _)| *flag).collect::<Vec<_>>(),
            "nonce": hex(nonce.as_bytes()),
            "claim": hex(&claim_bytes),
            "accepted": hex(&accepted_bytes),
            "exchange": exchange,
            "descriptor_file": String::from_utf8(published).expect("a text file"),
        });
        println!(
            "PLUGIN-HOST-FRAMES-JSON-BEGIN\n{}\nPLUGIN-HOST-FRAMES-JSON-END",
            serde_json::to_string_pretty(&record).expect("a record")
        );
    }
}

/// The nil identifier's text.
fn uuid_nil() -> String {
    kr_protocol::scalars::Uuid::from_bytes([0; 16]).to_string()
}
