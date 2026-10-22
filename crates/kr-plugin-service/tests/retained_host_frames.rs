//! The frames a plugin host of the release before wrote, read by this build.
//!
//! `retained/<level>/plugin-host-frames.json` holds what the real `kr-plugin-host` of the level's
//! release presented and answered when it was run as its launcher runs it, and the descriptor file
//! its daemon published. This build's control daemon reads the claim, the answers and the
//! descriptor when it adopts or starts such a host; every one has to decode with this build's
//! types and encode back to the bytes it came from, and the claim and the proof have to verify.
//! The upgrade suite's case of the same name makes the record
//! (`KR_RECORD_PLUGIN_HOST_FRAMES=1`), and starts and adopts the real program with what this build
//! writes.

use kr_plugin_service::launcher::{self, HostReservation};
use kr_plugin_service::protocol::{
    Frame, HostDescriptor, HostProtocol, HostRendezvous, RendezvousAccepted, Request, RequestBody,
    ResponseBody,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Nonce256;
use serde_json::Value;

const RECORD: &str = include_str!("../../kr-protocol/retained/0.76/plugin-host-frames.json");

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "{text}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal"))
        .collect()
}

fn recorded(record: &Value, name: &str) -> Vec<u8> {
    unhex(record[name].as_str().expect(name))
}

#[test]
fn the_frames_of_the_plugin_host_of_the_release_before_read_here_and_encode_back_to_their_bytes() {
    let record: Value = serde_json::from_str(RECORD).expect("the record");
    let limits = StreamKind::Control.cbor_limits();
    let retained = &kr_protocol::retained::RETAINED[0];
    assert_eq!(
        retained.plugin_host.trim(),
        HostProtocol::SECOND.name,
        "the level records the protocol its host speaks"
    );
    assert_eq!(
        format!("release={}", record["release"].as_str().expect("a release")),
        retained.release.lines().next().expect("a record"),
        "the frames are of the release the level was cut from"
    );

    // The claim the host presents to its launcher, and the acknowledgement this build writes.
    let claim_bytes = recorded(&record, "claim");
    let claim: HostRendezvous =
        kr_cbor::from_canonical_slice(&claim_bytes, &limits).expect("the claim reads");
    assert_eq!(
        kr_cbor::to_canonical_vec(&claim).expect("encodes"),
        claim_bytes
    );
    launcher::check_rendezvous(&claim).expect("the claim is signed by the key it presents");
    assert!(
        claim.endpoint.ends_with(HostProtocol::SECOND.endpoint),
        "the host serves on {}, not on {}",
        HostProtocol::SECOND.endpoint,
        claim.endpoint
    );
    let accepted_bytes = recorded(&record, "accepted");
    let accepted: RendezvousAccepted =
        kr_cbor::from_canonical_slice(&accepted_bytes, &limits).expect("the acknowledgement reads");
    assert_eq!(
        kr_cbor::to_canonical_vec(&accepted).expect("encodes"),
        accepted_bytes
    );
    assert_eq!(accepted.reservation_id, claim.reservation_id);

    // `Hello`, a `Hello` for another protocol, and `Verify`.
    let descriptor = HostDescriptor {
        protocol: HostProtocol::SECOND.name.to_owned(),
        environment_id: claim.environment_id,
        reservation_id: claim.reservation_id,
        endpoint: claim.endpoint.clone(),
        boot_identity: claim.boot_identity.clone(),
        process_start_identity: claim.process_start_identity.clone(),
        host_public_key: claim.host_public_key,
    };
    let nonce_bytes: [u8; 32] = recorded(&record, "nonce").try_into().expect("32 bytes");
    let nonce = Nonce256::from_bytes(nonce_bytes);
    let exchange = record["exchange"].as_array().expect("an exchange");
    assert_eq!(exchange.len(), 3);
    let mut answers = Vec::new();
    for pair in exchange {
        let request_bytes = recorded(pair, "request");
        let request: Request =
            kr_cbor::from_canonical_slice(&request_bytes, &limits).expect("the request reads");
        assert_eq!(
            kr_cbor::to_canonical_vec(&request).expect("encodes"),
            request_bytes
        );
        let response_bytes = recorded(pair, "response");
        let frame: Frame =
            kr_cbor::from_canonical_slice(&response_bytes, &limits).expect("the answer reads");
        assert_eq!(
            kr_cbor::to_canonical_vec(&frame).expect("encodes"),
            response_bytes
        );
        let Frame::Response { reply_to, body } = frame else {
            panic!("an answer was recorded as news");
        };
        assert_eq!(reply_to, request.request_id);
        answers.push((request.body, body));
    }
    let [(hello, told), (other, refused), (verify, proved)] =
        <[_; 3]>::try_from(answers).expect("three exchanges");
    assert!(
        matches!(&hello, RequestBody::Hello { protocol } if protocol == HostProtocol::SECOND.name)
    );
    // The host's account of its descriptor names no reservation: the launcher's is published.
    let ResponseBody::Hello {
        protocol,
        descriptor: told,
    } = told
    else {
        panic!("Hello was answered {told:?}");
    };
    assert_eq!(protocol, HostProtocol::SECOND.name);
    assert_eq!(told.reservation_id.get().as_bytes(), &[0; 16]);
    assert_eq!(
        HostDescriptor {
            reservation_id: claim.reservation_id,
            ..*told
        },
        descriptor
    );
    assert!(
        matches!(&other, RequestBody::Hello { protocol } if protocol != HostProtocol::SECOND.name)
    );
    assert!(matches!(&refused, ResponseBody::Refused { request, .. } if request == "hello"));
    assert!(matches!(&verify, RequestBody::Verify { nonce: asked } if *asked == nonce));
    let ResponseBody::Verified(proof) = proved else {
        panic!("Verify was answered {proved:?}");
    };
    launcher::check_proof(&descriptor, &nonce, &proof).expect("the proof verifies");

    // The descriptor file the release before's daemon published.
    let file = record["descriptor_file"]
        .as_str()
        .expect("a descriptor file");
    let published: HostDescriptor = serde_json::from_str(file).expect("the descriptor reads");
    assert_eq!(published.protocol, HostProtocol::SECOND.name);
    assert_eq!(serde_json::to_string(&published).expect("encodes"), file);
}

#[tokio::test]
async fn the_arguments_a_launcher_starts_the_host_of_the_release_before_with_are_the_ones_recorded()
{
    let record: Value = serde_json::from_str(RECORD).expect("the record");
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    let reservation =
        HostReservation::open(&environment, HostProtocol::SECOND).expect("a reservation");
    let packages = host.root().join("packages");
    let given = reservation.arguments(&environment, &packages);
    let flags: Vec<&str> = given.iter().step_by(2).map(String::as_str).collect();
    let recorded: Vec<&str> = record["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .map(|flag| flag.as_str().expect("a flag"))
        .collect();
    assert_eq!(flags, recorded);
}
