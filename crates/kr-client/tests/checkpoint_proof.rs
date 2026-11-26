//! The read of a host's checkpoint takes an answer only when the host's box proves it.
//!
//! Each case reads once over a connection this test scripts, with real key pairs: the host answers
//! as its script says, and the read returns the answer it took or the one cause it gave no answer
//! for. A case that asserts an absence has the same host, honest, beside it.

use std::sync::{Arc, Mutex};

use kr_client::pairing::checkpoint::{Answer, ReadCause, read_checkpoint};
use kr_client::pairing::paired::PairedHost;
use kr_client::session::Session;
use kr_client::transport::{ControlTransport, DeviceEnd, StreamOpener, TransportFuture};
use kr_crypto::keys::{DeviceKeys, StoredEnvelopeKeyPair};
use kr_crypto::sealed::seal_stored_envelope;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::backup_checkpoint::{
    BackupCheckpointParams, BackupCheckpointResult, HOST_CHECKPOINT_PROOF_DOMAIN, HostCheckpoint,
    HostCheckpointProof, MAX_PROOF_CIPHERTEXT, SealedCheckpointProof,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{
    ActionWindowId, ArchiveId, BackupGeneration, BootEpoch, ConnectionId, DeviceId,
    DeviceKeyRevision, GrantId,
};
use kr_protocol::pairing::{DevicePublicKeys, NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    Bytes, CanonicalSet, Digest256, DurationMs, EndpointKey, Nonce192, Nonce256, Nullable,
    TimestampMs, Uuid,
};
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;
use tokio::sync::mpsc;

/// How a scripted host answers an ask it could read.
type Answers = Box<dyn Fn(&BackupCheckpointParams) -> Outcome + Send + Sync>;

/// A control connection whose host answers `backup.checkpoint` as its script says, and keeps each
/// ask it was sent.
struct Hosted {
    answers: Answers,
    asks: Arc<Mutex<Vec<BackupCheckpointParams>>>,
    sender: Mutex<Option<mpsc::UnboundedSender<ControlFrame>>>,
    frames: tokio::sync::Mutex<mpsc::UnboundedReceiver<ControlFrame>>,
}

impl std::fmt::Debug for Hosted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hosted")
    }
}

impl ControlTransport for Hosted {
    fn connection_id(&self) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([42; 16]))
    }

    fn limits(&self) -> ReceiveLimits {
        ReceiveLimits::default()
    }

    fn initial_action_window(&self) -> ActionWindow {
        ActionWindow {
            action_window_id: ActionWindowId::new("window-1").expect("a window"),
            connection_id: self.connection_id(),
            boot_epoch: BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(0),
            valid_for_ms: DurationMs::new(60_000),
        }
    }

    fn ended_by_this_device(&self) -> Option<DeviceEnd> {
        None
    }

    fn host_states_placement_reading(&self) -> bool {
        false
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        if let ControlFrame::Request(request) = frame {
            let outcome = match request.params.to_typed::<BackupCheckpointParams>() {
                Ok(ask) => {
                    self.asks.lock().expect("the asks").push(ask.clone());
                    (self.answers)(&ask)
                }
                Err(_) => Outcome::Error(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "the ask names no challenge and no reply key",
                )),
            };
            if let Some(sender) = self.sender.lock().expect("the sender").as_ref() {
                let _ = sender.send(ControlFrame::Response(Response {
                    request_id: request.request_id,
                    outcome,
                }));
            }
        }
        Box::pin(async { Ok(()) })
    }

    fn claim_receiver(&self) -> kr_client::Result<()> {
        Ok(())
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move { Ok(self.frames.lock().await.recv().await) })
    }

    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        None
    }

    fn revoke_streams(&self) {}

    fn close(&self) {
        self.sender.lock().expect("the sender").take();
    }

    fn is_closed(&self) -> bool {
        self.sender.lock().expect("the sender").is_none()
    }
}

/// A host: its own keys, whose stored-envelope pair makes its box and whose transport key is the
/// endpoint its identity serves.
struct Host {
    keys: DeviceKeys,
}

impl Host {
    fn new() -> Self {
        Self {
            keys: DeviceKeys::generate().expect("keys"),
        }
    }

    fn pair(&self) -> &StoredEnvelopeKeyPair {
        &self.keys.stored_envelope
    }

    fn endpoint(&self) -> EndpointKey {
        self.keys.public_keys().transport
    }

    /// The record a device holds of this host: the keys it declared and the endpoint it was
    /// paired at.
    fn record(&self) -> PairedHost {
        record_of(self.keys.public_keys(), self.endpoint())
    }
}

fn record_of(host_keys: DevicePublicKeys, endpoint: EndpointKey) -> PairedHost {
    PairedHost {
        host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
        host_key_revision: DeviceKeyRevision::new(1),
        host_endpoint_id: endpoint,
        host_keys,
        network_config: NetworkConfig::empty(),
        device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
        grant_id: GrantId::new(Uuid::from_bytes([3; 16])),
        proposed_grant: ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::HostManage]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        name: None,
        paired_at_ms: 1_764_000_000_000,
        device_key_revision: DeviceKeyRevision::new(1),
    }
}

fn checkpoint(generation: u64) -> HostCheckpoint {
    HostCheckpoint {
        service_origin: GatewayOrigin::new("https://storage.example").expect("an origin"),
        archive_id: ArchiveId::new(Uuid::from_bytes([0x11; 16])),
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: Digest256::from_bytes([0x22; 32]),
    }
}

/// The largest answer an honest host gives: the longest origin and the largest generation.
fn largest_checkpoint() -> HostCheckpoint {
    let origin = format!("https://{}.{}", "a".repeat(60), "a".repeat(59));
    assert_eq!(origin.len(), 128, "the longest origin a service has");
    HostCheckpoint {
        service_origin: GatewayOrigin::new(origin).expect("an origin"),
        backup_generation: BackupGeneration::new(u64::MAX),
        ..checkpoint(1)
    }
}

/// The box `sender` makes to `reply_key`, holding exactly these four things.
fn sealed(
    sender: &StoredEnvelopeKeyPair,
    reply_key: &kr_protocol::scalars::StoredEnvelopeKey,
    challenge: Nonce256,
    endpoint: EndpointKey,
    boxed: Option<HostCheckpoint>,
) -> SealedCheckpointProof {
    let plaintext = SigningTranscript::from_object(
        HOST_CHECKPOINT_PROOF_DOMAIN,
        &HostCheckpointProof {
            challenge,
            host_endpoint_id: endpoint,
            checkpoint: Nullable(boxed),
        },
    )
    .expect("the bytes");
    let (nonce, ciphertext) =
        seal_stored_envelope(sender, reply_key, plaintext.as_bytes()).expect("a box");
    SealedCheckpointProof {
        nonce,
        ciphertext: Bytes::new(ciphertext),
    }
}

fn ok(result: &impl Serialize) -> Outcome {
    Outcome::Ok(ParamsValue::from_typed(result).expect("a value"))
}

/// What an honest `host` answers for `held`: its box holds the challenge it was sent, its own
/// endpoint and `held`.
fn honest(host: &Host, held: Option<HostCheckpoint>) -> Answers {
    let pair = host.pair().clone();
    let endpoint = host.endpoint();
    Box::new(move |ask| {
        ok(&BackupCheckpointResult {
            checkpoint: Nullable(held.clone()),
            proof: sealed(&pair, &ask.reply_key, ask.challenge, endpoint, held.clone()),
        })
    })
}

/// What the read of `record` over a connection that answers as `answers` says, and the asks the
/// host was sent.
async fn read_from(
    record: &PairedHost,
    answers: Answers,
) -> (Result<Answer, ReadCause>, Vec<BackupCheckpointParams>) {
    let asks = Arc::new(Mutex::new(Vec::new()));
    let (sender, frames) = mpsc::unbounded_channel();
    let session = Session::start(Arc::new(Hosted {
        answers,
        asks: Arc::clone(&asks),
        sender: Mutex::new(Some(sender)),
        frames: tokio::sync::Mutex::new(frames),
    }))
    .expect("a session");
    let read = read_checkpoint(&session, record).await;
    session.close();
    let asks = asks.lock().expect("the asks").clone();
    (read, asks)
}

/// Bodies that no honest host sends, as a hostile host would write them.
#[derive(Serialize)]
struct WithoutBox {
    checkpoint: Nullable<HostCheckpoint>,
}

#[derive(Serialize)]
struct WithAnExtraMember {
    checkpoint: Nullable<HostCheckpoint>,
    proof: SealedCheckpointProof,
    note: &'static str,
}

fn the_answer_of(held: Option<HostCheckpoint>) -> Result<Answer, ReadCause> {
    Ok(held.map_or(Answer::NothingPublished, Answer::Checkpoint))
}

/// A box the host sealed for this ask, holding the challenge, the host's own endpoint and the
/// answer beside it, is taken: an answer that names a checkpoint, and one that names none. The
/// other cases of this file have this host beside them.
#[tokio::test]
async fn a_box_that_proves_the_answer_is_taken() {
    let host = Host::new();
    for held in [Some(checkpoint(7)), Some(checkpoint(u64::MAX)), None] {
        let (read, asks) = read_from(&host.record(), honest(&host, held.clone())).await;
        assert_eq!(read, the_answer_of(held.clone()), "{held:?}");
        assert_eq!(asks.len(), 1, "the host is asked once");
    }
}

/// Each ask carries a challenge and a reply key of its own: two reads of one host send two of each,
/// and neither is a fixed value.
#[tokio::test]
async fn each_ask_draws_a_fresh_challenge_and_a_fresh_reply_key() {
    let host = Host::new();
    let record = host.record();
    let mut asks = Vec::new();
    for _ in 0..3 {
        let (read, mut sent) = read_from(&record, honest(&host, Some(checkpoint(7)))).await;
        assert_eq!(read, the_answer_of(Some(checkpoint(7))));
        asks.append(&mut sent);
    }
    assert_eq!(asks.len(), 3);
    for (first, second) in [(0, 1), (0, 2), (1, 2)] {
        assert_ne!(
            asks[first].challenge, asks[second].challenge,
            "{first} and {second}"
        );
        assert_ne!(
            asks[first].reply_key, asks[second].reply_key,
            "{first} and {second}"
        );
    }
    for ask in &asks {
        assert_ne!(
            ask.challenge,
            Nonce256::from_bytes([0; 32]),
            "a drawn challenge"
        );
    }
}

/// A host whose box differs from what this device expects in one value, and in no other, gives no
/// answer: another challenge, another endpoint, another checkpoint than the answer names, a
/// checkpoint where the answer names none, and none where it names one.
#[tokio::test]
async fn a_box_that_differs_in_one_value_from_what_the_device_expects_proves_nothing() {
    /// What a host's box holds and what its answer names.
    struct Differs {
        name: &'static str,
        /// The challenge in the box, or the one the ask carried.
        challenge: Option<Nonce256>,
        endpoint: EndpointKey,
        boxed: Option<HostCheckpoint>,
        answered: Option<HostCheckpoint>,
    }

    let host = Host::new();
    let record = host.record();
    let named = Some(checkpoint(7));
    let honest_one = |name| Differs {
        name,
        challenge: None,
        endpoint: host.endpoint(),
        boxed: named.clone(),
        answered: named.clone(),
    };
    let cases = [
        Differs {
            challenge: Some(Nonce256::from_bytes([0x5A; 32])),
            ..honest_one("another challenge")
        },
        Differs {
            endpoint: EndpointKey::from_bytes([0x5B; 32]),
            ..honest_one("another endpoint")
        },
        Differs {
            boxed: Some(checkpoint(8)),
            ..honest_one("another checkpoint than the answer names")
        },
        Differs {
            answered: None,
            ..honest_one("a checkpoint in the box where the answer names none")
        },
        Differs {
            boxed: None,
            ..honest_one("no checkpoint in the box where the answer names one")
        },
    ];
    for case in cases {
        let pair = host.pair().clone();
        let answers: Answers = Box::new(move |ask| {
            ok(&BackupCheckpointResult {
                checkpoint: Nullable(case.answered.clone()),
                proof: sealed(
                    &pair,
                    &ask.reply_key,
                    case.challenge.unwrap_or(ask.challenge),
                    case.endpoint,
                    case.boxed.clone(),
                ),
            })
        });
        let (read, asks) = read_from(&record, answers).await;
        assert_eq!(read, Err(ReadCause::NotProven), "{}", case.name);
        assert_eq!(asks.len(), 1, "the host is asked once");
    }
    let (read, _) = read_from(&record, honest(&host, named.clone())).await;
    assert_eq!(read, the_answer_of(named), "the host itself");
}

/// A host that relays the ask to another host gets that host's box, which names that host's
/// endpoint. The claimant's record holds the other host's declared key and its own endpoint, so
/// the box opens and names an endpoint the record does not.
#[tokio::test]
async fn a_box_of_the_host_an_ask_was_relayed_to_proves_nothing_for_the_relayer() {
    let genuine = Host::new();
    let claimant = Host::new();
    let claimant_record = record_of(
        DevicePublicKeys {
            stored_envelope: *genuine.pair().public(),
            ..claimant.keys.public_keys()
        },
        claimant.endpoint(),
    );
    let relayed = honest(&genuine, Some(checkpoint(9)));
    let (read, _) = read_from(&claimant_record, relayed).await;
    assert_eq!(
        read,
        Err(ReadCause::NotProven),
        "the claimant relays the ask"
    );

    // The same answer on the genuine host's own record is taken.
    let (read, _) = read_from(&genuine.record(), honest(&genuine, Some(checkpoint(9)))).await;
    assert_eq!(
        read,
        the_answer_of(Some(checkpoint(9))),
        "the genuine host itself"
    );
}

/// A box sealed by a key other than the one the record declares does not open, and neither does a
/// box sealed to a key other than the one this ask carried.
#[tokio::test]
async fn a_box_of_another_key_or_to_another_reply_key_proves_nothing() {
    let host = Host::new();
    let record = host.record();
    let stranger = StoredEnvelopeKeyPair::generate().expect("a key pair");
    let other_reply = StoredEnvelopeKeyPair::generate().expect("a key pair");

    let (sealer, endpoint) = (stranger.clone(), host.endpoint());
    let by_another_key: Answers = Box::new(move |ask| {
        ok(&BackupCheckpointResult {
            checkpoint: Nullable(Some(checkpoint(7))),
            proof: sealed(
                &sealer,
                &ask.reply_key,
                ask.challenge,
                endpoint,
                Some(checkpoint(7)),
            ),
        })
    });
    let (read, _) = read_from(&record, by_another_key).await;
    assert_eq!(read, Err(ReadCause::NotProven), "another key sealed it");

    let (pair, endpoint, to) = (host.pair().clone(), host.endpoint(), *other_reply.public());
    let to_another_key: Answers = Box::new(move |ask| {
        ok(&BackupCheckpointResult {
            checkpoint: Nullable(Some(checkpoint(7))),
            proof: sealed(&pair, &to, ask.challenge, endpoint, Some(checkpoint(7))),
        })
    });
    let (read, _) = read_from(&record, to_another_key).await;
    assert_eq!(
        read,
        Err(ReadCause::NotProven),
        "sealed to another reply key"
    );

    let (read, _) = read_from(&record, honest(&host, Some(checkpoint(7)))).await;
    assert_eq!(read, the_answer_of(Some(checkpoint(7))), "the host itself");
}

/// An answer with no box, or with a member that the answer does not declare, is not one this
/// release reads. A box longer than the bound is not read either, and one of exactly the bound,
/// which is the largest an honest host makes, is taken. An empty box is read and proves nothing.
#[tokio::test]
async fn an_answer_with_no_box_or_a_box_past_the_bound_is_malformed_and_an_empty_box_proves_nothing()
 {
    let host = Host::new();
    let record = host.record();

    let without: Answers = Box::new(|_| {
        ok(&WithoutBox {
            checkpoint: Nullable(Some(checkpoint(7))),
        })
    });
    let (read, _) = read_from(&record, without).await;
    assert_eq!(read, Err(ReadCause::Malformed), "no box");

    let (pair, endpoint) = (host.pair().clone(), host.endpoint());
    let extra: Answers = Box::new(move |ask| {
        ok(&WithAnExtraMember {
            checkpoint: Nullable(Some(checkpoint(7))),
            proof: sealed(
                &pair,
                &ask.reply_key,
                ask.challenge,
                endpoint,
                Some(checkpoint(7)),
            ),
            note: "x",
        })
    });
    let (read, _) = read_from(&record, extra).await;
    assert_eq!(read, Err(ReadCause::Malformed), "an unknown member");

    for (name, length, expected) in [
        ("an empty box", 0, Err(ReadCause::NotProven)),
        (
            "a box of the bound and an unknown content",
            MAX_PROOF_CIPHERTEXT,
            Err(ReadCause::NotProven),
        ),
        (
            "a box one byte past the bound",
            MAX_PROOF_CIPHERTEXT + 1,
            Err(ReadCause::Malformed),
        ),
    ] {
        let answers: Answers = Box::new(move |_| {
            ok(&BackupCheckpointResult {
                checkpoint: Nullable(Some(checkpoint(7))),
                proof: SealedCheckpointProof {
                    nonce: Nonce192::from_bytes([3; 24]),
                    ciphertext: Bytes::new(vec![0x44; length]),
                },
            })
        });
        let (read, _) = read_from(&record, answers).await;
        assert_eq!(read, expected, "{name}");
    }

    // The largest honest answer makes a box of exactly the bound, and it is taken.
    let largest = largest_checkpoint();
    let probe = StoredEnvelopeKeyPair::generate().expect("a key pair");
    let measured = sealed(
        host.pair(),
        probe.public(),
        Nonce256::from_bytes([1; 32]),
        host.endpoint(),
        Some(largest.clone()),
    );
    assert_eq!(
        measured.ciphertext.len(),
        MAX_PROOF_CIPHERTEXT,
        "the largest honest box is as long as the bound"
    );
    let (read, _) = read_from(&record, honest(&host, Some(largest.clone()))).await;
    assert_eq!(
        read,
        the_answer_of(Some(largest)),
        "a box of exactly the bound"
    );
}

/// A host of the release before serves no `backup.checkpoint` and refuses it as it refuses any
/// method it does not list; another refusal is its own cause.
#[tokio::test]
async fn a_host_that_does_not_serve_the_method_lacks_it_and_another_refusal_is_its_own() {
    let host = Host::new();
    let record = host.record();
    for (name, code, expected) in [
        (
            "the method is not served",
            ErrorCode::PermissionDenied,
            Err(ReadCause::HostLacksIt),
        ),
        (
            "another refusal",
            ErrorCode::InvalidArgument,
            Err(ReadCause::Refused(ErrorCode::InvalidArgument)),
        ),
    ] {
        let answers: Answers =
            Box::new(move |_| Outcome::Error(ProtocolError::new(code, "the method is refused")));
        let (read, asks) = read_from(&record, answers).await;
        assert_eq!(read, expected, "{name}");
        assert_eq!(asks.len(), 1, "{name}: the host is asked once");
    }
}
