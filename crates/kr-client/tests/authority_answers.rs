//! What the authority feed answers, what this crate's client makes of it, and what the stand-in the
//! daemon's tests talk to answers, held to one recording.
//!
//! The Worker in the web repository is what answers in production. One script of requests, made by
//! this crate's own client as a host, a remote owner and strangers make them, was run against a
//! Worker on this machine, and `fixtures/service/authority-answers.json` keeps, for each request,
//! the status and the body the Worker answered, and for each step what the client decoded it to.
//!
//! Two tests hold the recording to the code that reads it and to the stand-in, as the managed
//! storage recording is held:
//!
//! * [`the_client_decodes_what_the_worker_answered`] replays the recorded bodies through the
//!   client and asserts what they decode to, with no stand-in between.
//! * [`the_stand_in_answers_as_the_worker_did`] runs the same script against the stand-in and holds
//!   each answer's status, its shape and what the client decoded it to against the record.
//!
//! The recording is made again when the service's contract changes, by running
//! [`record_a_local_workers_answers`] against a local deployment:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start --state <dir> --name first --port <port>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> \
//!   KR_RECORD_AUTHORITY_ANSWERS=fixtures/service/authority-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test authority_answers record -- --ignored
//! ```
//!
//! The feed needs no account, so the run signs nothing in. What a local Worker cannot be made to
//! do is not in the script: a feed past the records it may hold (a thousand, or thirty-two from
//! one publisher, which would make the recording's answers grow with every step), a refusal that
//! names a delay, and a feed whose storage failed. The stand-in's answers for those are read from
//! the Worker's source, and the table in the stand-in crate's documentation names the line of each.

mod recording;

use std::sync::{Arc, Mutex};

use kr_client::services::authority::{AuthorityFeedClient, AuthorityFeedState, RejectionReason};
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId, RevocationRequestId};
use kr_protocol::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, REVOCATION_DOMAIN,
    RevocationAcknowledgement, RevocationCompletion, RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::{CanonicalSet, Signature64, TimestampMs, U64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::ServiceWeb;
use recording::{
    Journal, Keyed, Recording, Replaying, decoded, differences, held_exchanges, held_outcomes,
    keyed, recorded, written,
};

const FIXTURE: &str = include_str!("../../../fixtures/service/authority-answers.json");

/// A fixed identifier, so a recording and a replay of it name the same requests.
fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn device(byte: u8) -> DeviceId {
    DeviceId::new(fixed(byte))
}

fn request_id(byte: u8) -> RevocationRequestId {
    RevocationRequestId::new(fixed(byte))
}

/// A revocation request `who` signs, naming `host`, about `target`.
fn revocation(
    who: &Keyed,
    issuer: u8,
    host: DeviceId,
    id: u8,
    target: RevocationTarget,
) -> RevocationRequest {
    let mut request = RevocationRequest {
        request_id: request_id(id),
        issuer_device_id: device(issuer),
        host_device_id: host,
        target,
        issued_at_ms: TimestampMs::new(1_700_000_000_000),
        issuer_key_id: who.key.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    request.signature = sign(
        &who.key,
        &SigningTranscript::from_canonical_bytes(
            REVOCATION_DOMAIN,
            request.signing_input().expect("a signing input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    request
}

fn devices(byte: u8) -> RevocationTarget {
    RevocationTarget::Devices {
        device_ids: [device(byte)].into_iter().collect::<CanonicalSet<_>>(),
    }
}

fn grants(byte: u8) -> RevocationTarget {
    RevocationTarget::Grants {
        grant_ids: [GrantId::new(fixed(byte))]
            .into_iter()
            .collect::<CanonicalSet<_>>(),
    }
}

/// A revision `host` signs.
fn revision(
    host: &Keyed,
    host_device: DeviceId,
    number: u64,
    previous: u64,
    applied: &[u8],
) -> AuthorityRevisionRecord {
    let mut record = AuthorityRevisionRecord {
        host_device_id: host_device,
        authority_revision: AuthorityRevision::new(number),
        previous_revision: AuthorityRevision::new(previous),
        applied_requests: applied
            .iter()
            .map(|id| request_id(*id))
            .collect::<CanonicalSet<_>>(),
        issued_at_ms: TimestampMs::new(1_700_000_001_000),
        host_key_id: host.key.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    record.signature = sign(
        &host.key,
        &SigningTranscript::from_canonical_bytes(
            AUTHORITY_REVISION_DOMAIN,
            record.signing_input().expect("a signing input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    record
}

fn acknowledgement(
    host_device: DeviceId,
    id: u8,
    number: u64,
    completion: RevocationCompletion,
    at: u64,
) -> RevocationAcknowledgement {
    RevocationAcknowledgement {
        request_id: request_id(id),
        host_device_id: host_device,
        authority_revision: AuthorityRevision::new(number),
        completion,
        acknowledged_at_ms: TimestampMs::new(at),
    }
}

/// What the client decoded of a feed's state, in the words of the values a caller acts on, naming
/// the keys by who holds them.
fn showing(labels: &[(String, &'static str)], state: &AuthorityFeedState) -> String {
    let label = |text: &str| {
        labels
            .iter()
            .find(|(held, _)| held == text)
            .map_or("a key nobody here holds", |(_, label)| *label)
    };
    let records: Vec<String> = state
        .records
        .iter()
        .map(|record| {
            format!(
                "{} {} by {}: acknowledgement {:?}, refused {:?}",
                record.sequence.get(),
                record.request.request_id,
                label(&key_text(&record.published_by)),
                record
                    .acknowledgement
                    .0
                    .as_ref()
                    .map(|ack| (ack.authority_revision.get(), ack.completion)),
                record.rejected.0
            )
        })
        .collect();
    let removal_keys: Vec<&str> = state
        .summary
        .removal_keys
        .iter()
        .map(|key| label(&key_text(key)))
        .collect();
    format!(
        "feed of {}, host device known {}, {} records [{}], more {}, after {}; summary: revision \
         {:?}, last acknowledgement {:?}, outstanding {}, removed {}, removal keys {removal_keys:?}, \
         poll every {} seconds, acknowledged at known {}",
        label(&key_text(&state.host_key_id)),
        state.host_device_id.0.is_some(),
        state.records.len(),
        records.join("; "),
        state.more,
        state.next_after_sequence.get(),
        state
            .summary
            .authority_revision
            .0
            .map(|revision| revision.get()),
        state
            .summary
            .last_acknowledgement
            .0
            .as_ref()
            .map(|ack| (ack.authority_revision.get(), ack.completion)),
        state.summary.outstanding.get(),
        state.summary.removed,
        state.summary.poll_interval_seconds,
        state.summary.acknowledged_at.0.is_some(),
    )
}

fn key_text<T: serde::Serialize>(key: &T) -> String {
    serde_json::to_value(key)
        .expect("a key")
        .as_str()
        .expect("text")
        .to_owned()
}

/// Runs the script against one service through `service`.
///
/// Every request is made by this crate's own client; what each client decoded is kept in
/// `journal`. Whatever a step expects it does not assert: what each answer was is the record's to
/// say, and the stand-in is held to it afterwards.
async fn run_the_script(service: &Arc<dyn ServiceHttp>, origin: &GatewayOrigin, journal: &Journal) {
    let owner = keyed(ServiceRequestSigner::Installation);
    let second = keyed(ServiceRequestSigner::Installation);
    let host = keyed(ServiceRequestSigner::Host);
    let host_device = device(0x01);
    for held in [&host, &owner, &second] {
        journal.name(written(held));
    }
    // Where an answer names the key that published a record, it names the public key itself.
    for held in [&owner, &second] {
        journal.name(key_text(held.key.public()));
    }
    let labels: Vec<(String, &'static str)> = vec![
        (written(&host), "the host"),
        (written(&owner), "the owner"),
        (written(&second), "a stranger"),
        (key_text(owner.key.public()), "the owner"),
        (key_text(second.key.public()), "a stranger"),
    ];
    let client = |signer: &Arc<Keyed>| {
        AuthorityFeedClient::new(origin.clone(), Arc::clone(service), Arc::clone(signer) as _)
    };
    let as_host = client(&host);
    let as_owner = client(&owner);
    let as_stranger = client(&second);
    let feed = as_host.own_feed();
    let show = |state: &AuthorityFeedState| showing(&labels, state);

    journal.step("the host reads a feed nobody has written to, for its summary");
    let answer = as_host.read(feed, None, true).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reads its records");
    let answer = as_host.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("a remote owner reads the host's feed");
    let answer = as_owner.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));

    // Publishing.
    let first = revocation(&owner, 0xb1, host_device, 0xa1, devices(0xc1));
    journal.step("the owner publishes a revocation request");
    let answer = as_owner.publish(feed, &first, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the owner publishes it again");
    let answer = as_owner.publish(feed, &first, None).await;
    journal.decoded(decoded(&answer, show));
    let different = revocation(&owner, 0xb1, host_device, 0xa1, devices(0xc2));
    journal.step("the owner publishes another request under the same identity");
    let answer = as_owner.publish(feed, &different, None).await;
    journal.decoded(decoded(&answer, show));
    let second_request = revocation(&second, 0xb2, host_device, 0xa2, grants(0xd1));
    journal.step("a stranger publishes a request of its own");
    let answer = as_stranger.publish(feed, &second_request, None).await;
    journal.decoded(decoded(&answer, show));
    // A request signed by one key and carried by another is not the carrier's.
    let borrowed = revocation(&second, 0xb2, host_device, 0xa3, devices(0xc3));
    journal.step("the owner carries a request another key signed");
    let answer = as_owner.publish(feed, &borrowed, None).await;
    journal.decoded(decoded(&answer, show));
    let mut altered = revocation(&owner, 0xb1, host_device, 0xa4, devices(0xc4));
    altered.target = devices(0xc5);
    journal.step("the owner publishes a request altered after it was signed");
    let answer = as_owner.publish(feed, &altered, None).await;
    journal.decoded(decoded(&answer, show));

    // Reading.
    journal.step("the host reads what was published");
    let answer = as_host.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the owner reads only what it published");
    let answer = as_owner.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the stranger reads only what it published");
    let answer = as_stranger.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reads from a cursor");
    let answer = as_host.read(feed, Some(1), false).await;
    journal.decoded(decoded(&answer, show));

    // Revisions.
    journal.step("the host issues its first revision");
    let one = revision(&host, host_device, 1, 0, &[0xa1]);
    let answer = as_host.revise(&one, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host sends it again");
    let answer = as_host.revise(&one, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host sends another record under the same number");
    let rewritten = revision(&host, host_device, 1, 0, &[0xa1, 0xa2]);
    let answer = as_host.revise(&rewritten, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host sends a revision that does not follow the one the feed holds");
    let gap = revision(&host, host_device, 6, 5, &[0xa2]);
    let answer = as_host.revise(&gap, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host sends a revision that is not above the one it follows");
    let backwards = revision(&host, host_device, 1, 1, &[0xa2]);
    let answer = as_host.revise(&backwards, None).await;
    journal.decoded(decoded(&answer, show));

    // Acknowledgements.
    journal.step("the host reports progress on the request");
    let pending = acknowledgement(
        host_device,
        0xa1,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(1),
        },
        1_000,
    );
    let answer = as_host.acknowledge(&pending, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reads the record, which is still outstanding");
    let answer = as_host.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reports an older acknowledgement");
    let older = acknowledgement(
        host_device,
        0xa1,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(2),
        },
        500,
    );
    let answer = as_host.acknowledge(&older, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host acknowledges the request as complete");
    let complete = acknowledgement(host_device, 0xa1, 1, RevocationCompletion::Complete, 2_000);
    let answer = as_host.acknowledge(&complete, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reports progress after completion");
    let after = acknowledgement(
        host_device,
        0xa1,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(1),
        },
        3_000,
    );
    let answer = as_host.acknowledge(&after, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host acknowledges under a revision it never issued");
    let invented = acknowledgement(host_device, 0xa1, 9, RevocationCompletion::Complete, 4_000);
    let answer = as_host.acknowledge(&invented, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host acknowledges a request the revision did not apply");
    let misapplied = acknowledgement(host_device, 0xa2, 1, RevocationCompletion::Complete, 4_000);
    let answer = as_host.acknowledge(&misapplied, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host acknowledges a request nobody published");
    let unknown = acknowledgement(host_device, 0xee, 1, RevocationCompletion::Complete, 4_000);
    let answer = as_host.acknowledge(&unknown, None).await;
    journal.decoded(decoded(&answer, show));

    // Refusals.
    journal.step("the host refuses the stranger's request");
    let answer = as_host
        .reject(request_id(0xa2), RejectionReason::NoOwnerAuthority)
        .await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host refuses it again");
    let answer = as_host
        .reject(request_id(0xa2), RejectionReason::NoOwnerAuthority)
        .await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host refuses a request nobody published");
    let answer = as_host
        .reject(request_id(0xee), RejectionReason::UnknownTarget)
        .await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host issues a revision that applies the request it refused");
    let two = revision(&host, host_device, 2, 1, &[0xa2]);
    let answer = as_host.revise(&two, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host acknowledges the request it refused");
    let contradicting =
        acknowledgement(host_device, 0xa2, 2, RevocationCompletion::Complete, 5_000);
    let answer = as_host.acknowledge(&contradicting, None).await;
    journal.decoded(decoded(&answer, show));

    // Naming the keys that may remove the host.
    journal.step("the host names the owner's key as one that may remove it");
    let answer = as_host.delegate(&[owner.key.key_id()]).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host names no key");
    let answer = as_host.delegate(&[]).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host names the owner's key again");
    let answer = as_host.delegate(&[owner.key.key_id()]).await;
    journal.decoded(decoded(&answer, show));

    // Removal.
    journal.step("a stranger removes the host");
    let answer = as_stranger.remove(feed).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the owner the host named removes it");
    let answer = as_owner.remove(feed).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reads its feed after its removal");
    let answer = as_host.read(feed, None, false).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the owner publishes to a host that was removed");
    let late = revocation(&owner, 0xb1, host_device, 0xa5, devices(0xc6));
    let answer = as_owner.publish(feed, &late, None).await;
    journal.decoded(decoded(&answer, show));
    journal.step("the host reads the summary of its removal");
    let answer = as_host.read(feed, None, true).await;
    journal.decoded(decoded(&answer, show));
}

/// A transport the script is run through when it is not run against a Worker.
fn stand_in() -> (Arc<ServiceWeb>, GatewayOrigin) {
    let web = Arc::new(ServiceWeb::new());
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    (web, origin)
}

/// What the client decodes from the answers a Worker gave is what it decoded when it gave them.
///
/// The bodies are the Worker's own, with no stand-in between, so a reader that stops reading what
/// the Worker says fails here.
#[tokio::test]
async fn the_client_decodes_what_the_worker_answered() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let journal = Arc::new(Journal::default());
    let replay: Arc<dyn ServiceHttp> = Arc::new(Replaying {
        answers: Mutex::new(held_exchanges(&held).into()),
        recorded_names: held["names"]
            .as_array()
            .expect("the recorded names")
            .iter()
            .map(|name| name.as_str().expect("a name").to_owned())
            .collect(),
        journal: Arc::clone(&journal),
    });
    let origin = GatewayOrigin::new("http://127.0.0.1:8787").expect("an origin");
    run_the_script(&replay, &origin, &journal).await;
    let differing = differences(&held_outcomes(&held), &journal.outcomes());
    assert!(
        differing.is_empty(),
        "the client no longer reads the Worker's answers as it did:\n{}",
        differing.join("\n")
    );
}

/// The stand-in answers the script as the Worker did.
#[tokio::test]
async fn the_stand_in_answers_as_the_worker_did() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let (web, origin) = stand_in();
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&web) as _,
        origin: web.origin().to_owned(),
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &origin, &journal).await;
    let ran = recorded(&journal, "");

    let held_exchanges = held["exchanges"].as_array().expect("recorded exchanges");
    let ran_exchanges = ran["exchanges"].as_array().expect("exchanges");
    let mut differing = Vec::new();
    for (index, held) in held_exchanges.iter().enumerate() {
        match ran_exchanges.get(index) {
            Some(ran) if ran["step"] == held["step"] && ran["path"] == held["path"] => {
                for member in ["status", "shape"] {
                    if ran[member] != held[member] {
                        differing.push(format!(
                            "{}: {member} was {} and the Worker's was {}",
                            held["step"], ran[member], held[member]
                        ));
                    }
                }
            }
            other => differing.push(format!(
                "{}: the stand-in made {other:?} where the Worker was asked {}",
                held["step"], held["path"]
            )),
        }
    }
    if ran_exchanges.len() > held_exchanges.len() {
        differing.push(format!(
            "the stand-in answered {} requests and the recording holds {}",
            ran_exchanges.len(),
            held_exchanges.len()
        ));
    }
    differing.extend(differences(&held_outcomes(&held), &journal.outcomes()));
    assert!(
        differing.is_empty(),
        "the stand-in differs from the recording:\n{}",
        differing.join("\n")
    );
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It is ignored unless it is asked for, and then it needs the Worker to ask, so an ordinary run of
/// this workspace asks nothing of any service.
#[tokio::test]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN and KR_RECORD_AUTHORITY_ANSWERS"]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin)) = (
        std::env::var_os("KR_RECORD_AUTHORITY_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
    ) else {
        panic!("KR_RECORD_AUTHORITY_ANSWERS and KR_DEPLOYED_ORIGIN name what to record");
    };
    let gateway = GatewayOrigin::new(origin.clone()).expect("an origin");
    let transport: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: transport,
        origin,
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &gateway, &journal).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
