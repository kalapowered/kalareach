//! What the settings-sync route answers about the recovery bundle, what this crate's client makes
//! of it, and what the stand-in the daemon's and the companion's tests talk to answers, held to one
//! recording.
//!
//! A device restoring from a kit reads the bundle at the kit's locator. The owner's device writes
//! it, asks what became of a write whose answer it did not see, and ends a write that has none.
//! The route admits each on two proofs: an installation's signature (a host's key is refused) and
//! an account token carrying `backup.write`, which a read also admits with `backup.restore`.
//! `fixtures/service/bundle-answers.json` keeps, for each request of two scripts that use a locator
//! each, the status and the body a Worker on this machine answered and what the client decoded it
//! to. The first script reads; the second writes, asks and fences.
//!
//! * [`the_client_decodes_what_the_worker_answered`] replays the recorded bodies through the
//!   client, with no stand-in between.
//! * [`the_stand_in_answers_as_the_worker_did`] runs the scripts against the stand-in and holds
//!   each status, shape and decoded value to the record. The write that puts the bundle in place
//!   for the reads is that script's setup, so the stand-in is given the bundle it holds after that
//!   write rather than answering the write.
//!
//! The recording is made again when the route's contract changes:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
//! node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
//!   KR_RECORD_BUNDLE_ANSWERS=fixtures/service/bundle-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test bundle_answers record -- --ignored
//! ```
//!
//! What a local Worker cannot be made to do is not in the scripts: an account other than the
//! owner's reaching the owner's locator (the deployment signs one account in), a write signed
//! before a collection's cutoff, a collection put back from an archive, and a service that does not
//! answer. The stand-in's answers for those are read from the contract and the Worker's source, and
//! the table in the stand-in crate's documentation names the line of each.

use std::sync::{Arc, Mutex};

use kr_client::recovery::{bundle_collection, fresh_locator};
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceFuture, ServiceHttp, SyncBackupService,
    SyncDispatch, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence, SyncRequestStatus,
    SyncRevision, managed_response_limits,
};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::scalars::Uuid;
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, ServiceWeb};

mod recording;

use recording::{
    Journal, Recording, Replaying, debug, decoded, differences, held_exchanges, held_outcomes,
    keyed, recorded, refused, written,
};

const FIXTURE: &str = include_str!("../../../fixtures/service/bundle-answers.json");

/// The token the stand-in issues for the owner's account, for the scope in hand.
const WRITE_TOKEN: &str = "the-owner-write-token";
/// The token the stand-in issues to a device restoring from the kit.
const RESTORE_TOKEN: &str = "the-owner-restore-token";

/// An account token, as a source hands it over.
#[derive(Debug)]
struct Bearer(String);

impl AccountTokenSource for Bearer {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = AccountToken::new(self.0.clone());
        Box::pin(async move { token })
    }
}

/// The two tokens one account holds on the service under test.
struct Tokens {
    write: String,
    restore: String,
}

/// How the script puts the bundle in place.
enum Setup<'a> {
    /// A write through the client, signed by `owner`, under the write token.
    Write,
    /// The stand-in is handed the bundle a write leaves.
    Place(&'a ServiceWeb),
}

fn stream(len: usize) -> Vec<u8> {
    (0..len)
        .map(|at| u8::try_from(at % 251).expect("a byte"))
        .collect()
}

/// What a read decoded to, in the words of the values a restore acts on.
fn shown(fetched: &SyncFetched, written: &[u8]) -> String {
    match fetched {
        SyncFetched::Held {
            position,
            ciphertext,
        } => format!(
            "held at write {}, revision {}, recovery {:?}, {} bytes, {}",
            position.write_sequence,
            if position.revision.0.is_some() {
                "present"
            } else {
                "null"
            },
            position.recovery(),
            ciphertext.len(),
            if ciphertext == written {
                "the bytes written"
            } else {
                "other bytes"
            },
        ),
        SyncFetched::Absent { recovery } => format!("absent, recovery {recovery:?}"),
    }
}

/// Runs the script of reads against one service through `service`.
async fn run_the_read_script(
    service: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    tokens: &Tokens,
    setup: &Setup<'_>,
    journal: &Journal,
) {
    let locator = fresh_locator().expect("a locator");
    journal.name(locator.clone());
    let context = RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: locator.clone(),
    };
    let collection = bundle_collection(&context);
    let written = stream(2048);
    let client = |signer: ServiceRequestSigner, token: &str, scope: &'static str| {
        ManagedSyncService::new(origin.clone(), Arc::clone(service), keyed(signer) as _)
            .presenting(Arc::new(Bearer(token.to_owned())), scope)
    };
    let owner = client(
        ServiceRequestSigner::Installation,
        &tokens.write,
        BACKUP_WRITE_SCOPE,
    );

    journal.step("read a locator nobody has written, with the restore token");
    let read = client(
        ServiceRequestSigner::Installation,
        &tokens.restore,
        BACKUP_RESTORE_SCOPE,
    );
    let answer = read.fetch(&collection).await;
    journal.decoded(decoded(&answer, |fetched| shown(fetched, &written)));

    journal.step("setup: the owner writes the bundle");
    match setup {
        Setup::Write => {
            let request_id = kr_transport::random::fresh_uuid_v4().expect("an identity");
            let answer = owner
                .compare_exchange(&collection, request_id, now_ms(), None, &written)
                .await;
            assert!(answer.is_ok(), "the owner's write: {answer:?}");
        }
        Setup::Place(web) => web.put_bundle(&locator, ACCOUNT, written.clone()),
    }

    journal.step("read the bundle with the write token");
    let answer = owner.fetch(&collection).await;
    journal.decoded(decoded(&answer, |fetched| shown(fetched, &written)));

    journal.step("read the bundle with the restore token");
    let answer = read.fetch(&collection).await;
    journal.decoded(decoded(&answer, |fetched| shown(fetched, &written)));

    journal.step("read the bundle with a token the service did not issue");
    let answer = client(
        ServiceRequestSigner::Installation,
        "not-a-token-this-service-issued",
        BACKUP_RESTORE_SCOPE,
    )
    .fetch(&collection)
    .await;
    journal.decoded(decoded(&answer, debug));

    journal.step("read the bundle signed by a host's key");
    let answer = client(
        ServiceRequestSigner::Host,
        &tokens.restore,
        BACKUP_RESTORE_SCOPE,
    )
    .fetch(&collection)
    .await;
    journal.decoded(decoded(&answer, debug));
}

/// A fixed identifier, so a recording and a replay of it name the same locator and requests.
fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// A sealed bundle the service cannot open and does not try to: bytes of the length one has.
fn sealed(byte: u8) -> Vec<u8> {
    vec![byte; 96]
}

/// Where a write stands, in the words a caller acts on: its place in the order, whether the
/// service named it, and whether it names a history. The name itself is the service's own.
fn standing(position: &SyncPosition) -> String {
    format!(
        "write {}, revision {}, history {}",
        position.write_sequence,
        if position.revision.0.is_some() {
            "named"
        } else {
            "none"
        },
        if position.recovery.0.is_some() {
            "named"
        } else {
            "none"
        },
    )
}

fn show_dispatch(dispatch: &SyncDispatch) -> String {
    match dispatch {
        SyncDispatch::Answered(SyncExchanged::Applied { position }) => {
            format!("applied at {}", standing(position))
        }
        SyncDispatch::Answered(SyncExchanged::Refused {
            retained,
            current,
            recovery,
        }) => format!(
            "refused, copy {}, the bundle at {}, history {}",
            if retained.is_some() { "kept" } else { "none" },
            current
                .as_ref()
                .map_or_else(|| "nothing".to_owned(), standing),
            if recovery.is_some() { "named" } else { "none" },
        ),
        SyncDispatch::Answered(SyncExchanged::SignedBeforeCutoff) => {
            "refused as signed before the cutoff".to_owned()
        }
        SyncDispatch::NotSent(error) => format!("not sent: {}", refused(error)),
    }
}

fn show_fetched(fetched: &SyncFetched, written: &[u8]) -> String {
    match fetched {
        SyncFetched::Held {
            position,
            ciphertext,
        } => format!(
            "held at {}, {} bytes, {}",
            standing(position),
            ciphertext.len(),
            if ciphertext == written {
                "the bytes written"
            } else {
                "other bytes than written"
            }
        ),
        SyncFetched::Absent { recovery } => format!(
            "nothing held, history {}",
            if recovery.is_some() { "named" } else { "none" }
        ),
    }
}

fn show_status(status: &SyncRequestStatus) -> String {
    match status {
        SyncRequestStatus::Applied { position } => format!("applied at {}", standing(position)),
        SyncRequestStatus::Refused { retained, recovery } => format!(
            "refused, copy {}, history {}",
            if retained.is_some() { "kept" } else { "none" },
            if recovery.is_some() { "named" } else { "none" }
        ),
        SyncRequestStatus::Fenced {
            never_ran,
            recovery,
        } => format!(
            "fenced, never ran {never_ran}, history {}",
            if recovery.is_some() { "named" } else { "none" }
        ),
        SyncRequestStatus::Unknown { recovery } => format!(
            "unknown, history {}",
            if recovery.is_some() { "named" } else { "none" }
        ),
    }
}

fn show_fence(fence: &SyncRequestFence) -> String {
    match fence {
        SyncRequestFence::Applied { position } => format!("applied at {}", standing(position)),
        SyncRequestFence::Refused { retained, recovery } => format!(
            "refused, copy {}, history {}",
            if retained.is_some() { "kept" } else { "none" },
            if recovery.is_some() { "named" } else { "none" }
        ),
        SyncRequestFence::Fenced {
            never_ran,
            recovery,
        } => format!(
            "fenced, never ran {never_ran}, history {}",
            if recovery.is_some() { "named" } else { "none" }
        ),
    }
}

/// Runs the script of the owner's writes, status queries and fences against one service through
/// `service`.
///
/// Every request is made by this crate's own client, as the owner's device and as a device
/// restoring from a kit make them, and what the client decoded is kept in `journal`. Whatever a
/// step expects it does not assert: what each answer was is the record's to say, and the stand-in
/// is held to it afterwards.
async fn run_the_exchange_script(
    service: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    write_token: &str,
    restore_token: &str,
    journal: &Journal,
) {
    let device = keyed(ServiceRequestSigner::Installation);
    journal.name(written(&device));
    let client = |token: &str, scope: &'static str| {
        ManagedSyncService::new(
            origin.clone(),
            Arc::clone(service),
            Arc::clone(&device) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())), scope)
    };
    let owner = client(write_token, BACKUP_WRITE_SCOPE);
    let restoring = client(restore_token, BACKUP_RESTORE_SCOPE);
    let stranger = client("not-a-token-this-service-issued", BACKUP_WRITE_SCOPE);

    let locator = fixed(0x61);
    let collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: locator.to_string(),
    });
    let collection = collection.as_str();
    let empty_collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: fixed(0x62).to_string(),
    });
    let first = sealed(0x11);
    let second = sealed(0x22);
    let third = sealed(0x33);

    // Who may reach it.
    journal.step("read with a token the service did not issue");
    let fetched = stranger.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));
    journal.step("write with a token the service did not issue");
    let wrote = stranger
        .compare_exchange_dispatched(collection, fixed(0x01), now_ms(), None, &first)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("read where nothing was ever written");
    let fetched = owner.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));
    journal.step("write with a token that may only restore");
    let wrote = restoring
        .compare_exchange_dispatched(collection, fixed(0x02), now_ms(), None, &first)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));

    // A comparison against a place where nothing is held.
    journal.step("write naming a revision where none is held");
    let named = SyncPosition::at(1, SyncRevision::new(fixed(0x77)), None);
    let wrote = owner
        .compare_exchange_dispatched(
            &empty_collection,
            fixed(0x03),
            now_ms(),
            Some(named),
            &first,
        )
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("read where that write left nothing");
    let fetched = owner.fetch(&empty_collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));

    // The first write, and the same write again.
    journal.step("the first write");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x11), now_ms(), None, &first)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    let landed = match &wrote {
        Ok(SyncDispatch::Answered(SyncExchanged::Applied { position })) => Some(*position),
        _ => None,
    };
    journal.step("the same write under the same identity");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x11), now_ms(), None, &first)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("another bundle under the same identity");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x11), now_ms(), None, &second)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("write again as if nothing were held");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x12), now_ms(), None, &second)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));

    // Reading it.
    journal.step("read what was written");
    let fetched = owner.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));
    journal.step("read it with the token that may only restore");
    let fetched = restoring.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));
    journal.step("read it with a token the service did not issue");
    let fetched = stranger.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &first)));

    // The next write, and a write against a place the bundle has left.
    journal.step("write against the place the bundle is at");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x13), now_ms(), landed, &second)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("write against the place it has left");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x14), now_ms(), landed, &third)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("read after the refusal");
    let fetched = owner.fetch(collection).await;
    journal.decoded(decoded(&fetched, |fetched| show_fetched(fetched, &second)));

    // What became of a request.
    journal.step("status of a write that applied");
    let status = owner.request_status(collection, fixed(0x13)).await;
    journal.decoded(decoded(&status, show_status));
    journal.step("status of a write that was refused");
    let status = owner.request_status(collection, fixed(0x14)).await;
    journal.decoded(decoded(&status, show_status));
    journal.step("status of an identity the service never saw");
    let status = owner.request_status(collection, fixed(0x15)).await;
    journal.decoded(decoded(&status, show_status));
    journal.step("status with a token the service did not issue");
    let status = stranger.request_status(collection, fixed(0x13)).await;
    journal.decoded(decoded(&status, show_status));

    // Ending a request.
    journal.step("fence an identity the service never saw");
    let at = now_ms();
    let fence = owner.fence_request(collection, fixed(0x15), at, at).await;
    journal.decoded(decoded(&fence, show_fence));
    journal.step("fence it again");
    let fence = owner.fence_request(collection, fixed(0x15), at, at).await;
    journal.decoded(decoded(&fence, show_fence));
    journal.step("status of the fenced identity");
    let status = owner.request_status(collection, fixed(0x15)).await;
    journal.decoded(decoded(&status, show_status));
    journal.step("write under the fenced identity");
    let wrote = owner
        .compare_exchange_dispatched(collection, fixed(0x15), now_ms(), None, &third)
        .await;
    journal.decoded(decoded(&wrote, show_dispatch));
    journal.step("fence a write that applied");
    let fence = owner.fence_request(collection, fixed(0x13), at, at).await;
    journal.decoded(decoded(&fence, show_fence));
    journal.step("fence a write that was refused");
    let fence = owner.fence_request(collection, fixed(0x14), at, at).await;
    journal.decoded(decoded(&fence, show_fence));
    journal.step("fence with a token the service did not issue");
    let fence = stranger
        .fence_request(collection, fixed(0x16), at, at)
        .await;
    journal.decoded(decoded(&fence, show_fence));
}

/// Runs both scripts against one service through `service`: the reads of a device restoring from a
/// kit, and the owner's writes, status queries and fences. Each keeps to a locator of its own.
async fn run_the_script(
    service: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    tokens: &Tokens,
    setup: &Setup<'_>,
    journal: &Journal,
) {
    run_the_read_script(service, origin, tokens, setup, journal).await;
    run_the_exchange_script(service, origin, &tokens.write, &tokens.restore, journal).await;
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

/* -------------------------------------------------------------------------- */
/* The runs                                                                    */
/* -------------------------------------------------------------------------- */

/// What the client decodes from the answers a Worker gave is what it decoded when it gave them.
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
    let tokens = Tokens {
        write: WRITE_TOKEN.to_owned(),
        restore: RESTORE_TOKEN.to_owned(),
    };
    run_the_script(&replay, &origin, &tokens, &Setup::Write, &journal).await;
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
    let web = Arc::new(ServiceWeb::new());
    web.issue_token(WRITE_TOKEN, ACCOUNT, &[BACKUP_WRITE_SCOPE]);
    web.issue_token(RESTORE_TOKEN, ACCOUNT, &[BACKUP_RESTORE_SCOPE]);
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&web) as _,
        origin: web.origin().to_owned(),
        journal: Arc::clone(&journal),
    });
    let tokens = Tokens {
        write: WRITE_TOKEN.to_owned(),
        restore: RESTORE_TOKEN.to_owned(),
    };
    run_the_script(&http, &origin, &tokens, &Setup::Place(&web), &journal).await;
    let ran = recorded(&journal, "");

    // The write that puts the bundle in place is the script's setup, which the stand-in is handed.
    let held_exchanges: Vec<&serde_json::Value> = held["exchanges"]
        .as_array()
        .expect("recorded exchanges")
        .iter()
        .filter(|exchange| {
            !exchange["step"]
                .as_str()
                .is_some_and(|step| step.starts_with("setup"))
        })
        .collect();
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

/// What a write, a status query and a fence of `collection` are answered through `service`.
async fn write_status_and_fence(service: &ManagedSyncService, collection: &str, at: u64) -> String {
    let wrote = service
        .compare_exchange_dispatched(collection, fixed(0x31), at, None, &sealed(0x31))
        .await;
    let asked = service.request_status(collection, fixed(0x31)).await;
    let fenced = service.fence_request(collection, fixed(0x31), at, at).await;
    format!("{wrote:?} {asked:?} {fenced:?}")
}

/// A token another account holds reads nothing, and says what an absent collection says.
///
/// Source only: the Worker's deployment signs one account in, so no recording can show a second
/// (`sync/collection.ts`, `standing`). The control is the owner's token reading the same bundle.
#[tokio::test]
async fn another_accounts_token_is_told_what_an_absent_collection_is_told() {
    let web = Arc::new(ServiceWeb::new());
    web.issue_token(WRITE_TOKEN, ACCOUNT, &[BACKUP_WRITE_SCOPE]);
    web.issue_token("a-stranger", "account-two", &[BACKUP_WRITE_SCOPE]);
    web.issue_token("a-token-for-another-scope", ACCOUNT, &["mailbox.read"]);
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let locator = fresh_locator().expect("a locator");
    web.put_bundle(&locator, ACCOUNT, stream(2048));
    let collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: locator,
    });
    let http: Arc<dyn ServiceHttp> = Arc::clone(&web) as _;
    let read = |token: &str| {
        ManagedSyncService::new(
            origin.clone(),
            Arc::clone(&http),
            keyed(ServiceRequestSigner::Installation) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())), BACKUP_WRITE_SCOPE)
    };
    assert!(matches!(
        read(WRITE_TOKEN).fetch(&collection).await,
        Ok(SyncFetched::Held { .. })
    ));
    let stranger = read("a-stranger").fetch(&collection).await;
    let nobody = read("not-a-token-this-service-issued")
        .fetch(&collection)
        .await;
    assert_eq!(
        format!("{stranger:?}"),
        format!("{nobody:?}"),
        "a token of another account is answered as no token is"
    );
    assert!(stranger.is_err());
    // A token the account holds without a scope a read is answered for proves nothing.
    let other_scope = read("a-token-for-another-scope").fetch(&collection).await;
    assert_eq!(format!("{other_scope:?}"), format!("{nobody:?}"));
    // A write, a status query and a fence of the owner's locator are turned away the same way.
    let at = now_ms();
    assert_eq!(
        write_status_and_fence(&read("a-stranger"), &collection, at).await,
        write_status_and_fence(&read("not-a-token-this-service-issued"), &collection, at).await,
        "a token of another account is answered as no token is"
    );
    // Nor does one that has expired.
    web.expire_token(WRITE_TOKEN);
    let expired = read(WRITE_TOKEN).fetch(&collection).await;
    assert_eq!(format!("{expired:?}"), format!("{nobody:?}"));
}

/// A collection put back from an export names its history, and the history reaches the client
/// whether the bundle is there or not.
///
/// Source only: a local deployment is not put back. The Worker answers `recovery_id` from the
/// collection's own record (`sync/collection.ts`, `recoveryId`).
#[tokio::test]
async fn a_collection_put_back_names_its_history_with_or_without_the_bundle() {
    let web = Arc::new(ServiceWeb::new());
    web.issue_token(RESTORE_TOKEN, ACCOUNT, &[BACKUP_RESTORE_SCOPE]);
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let history = "0a1b2c3d-0000-4000-8000-0000000000aa";
    let http: Arc<dyn ServiceHttp> = Arc::clone(&web) as _;
    let fetch = |locator: &str| {
        let collection = bundle_collection(&RecoveryContext {
            service_origin: origin.as_str().to_owned(),
            bundle_locator: locator.to_owned(),
        });
        let client = ManagedSyncService::new(
            origin.clone(),
            Arc::clone(&http),
            keyed(ServiceRequestSigner::Installation) as _,
        )
        .presenting(
            Arc::new(Bearer(RESTORE_TOKEN.to_owned())),
            BACKUP_RESTORE_SCOPE,
        );
        async move { client.fetch(&collection).await }
    };
    let empty = fresh_locator().expect("a locator");
    web.put_bundle_back(&empty, history);
    match fetch(&empty).await {
        Ok(SyncFetched::Absent { recovery }) => assert!(recovery.is_some()),
        other => panic!("a put-back collection with no bundle is an empty read: {other:?}"),
    }
    let written = fresh_locator().expect("a locator");
    web.put_bundle(&written, ACCOUNT, stream(2048));
    web.put_bundle_back(&written, history);
    match fetch(&written).await {
        Ok(SyncFetched::Held { position, .. }) => assert!(position.recovery().is_some()),
        other => panic!("a put-back collection holds its bundle: {other:?}"),
    }
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It is ignored unless it is asked for, and then it needs the Worker to ask and the account
/// tokens that Worker's development sign-in wrote, so an ordinary run of this workspace asks
/// nothing of any service.
#[tokio::test]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN, KR_BACKUP_TOKENS and KR_RECORD_BUNDLE_ANSWERS"]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin), Some(tokens)) = (
        std::env::var_os("KR_RECORD_BUNDLE_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
        std::env::var_os("KR_BACKUP_TOKENS"),
    ) else {
        panic!(
            "KR_RECORD_BUNDLE_ANSWERS, KR_DEPLOYED_ORIGIN and KR_BACKUP_TOKENS name what to record"
        );
    };
    let tokens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tokens).expect("the tokens file")).expect("tokens");
    let tokens = Tokens {
        write: tokens[&origin]["write"]
            .as_str()
            .expect("a backup.write token for this origin")
            .to_owned(),
        restore: tokens[&origin]["restore"]
            .as_str()
            .expect("a backup.restore token for this origin")
            .to_owned(),
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
    run_the_script(&http, &gateway, &tokens, &Setup::Write, &journal).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
