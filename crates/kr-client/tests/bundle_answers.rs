//! What the sync service answers about an account's recovery bundle, what this crate's client
//! makes of it, and what the stand-in the companion's tests talk to answers, held to one recording.
//!
//! The Worker in the web repository is what answers in production. One script of requests, made by
//! this crate's own client as an owner's device and a restoring device make them, was run against a
//! Worker on this machine, and `fixtures/service/bundle-answers.json` keeps, for each request, the
//! status and the body the Worker answered, and for each step what the client decoded it to.
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
//! node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
//! node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
//!   KR_RECORD_BUNDLE_ANSWERS=fixtures/service/bundle-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test bundle_answers record -- --ignored
//! ```
//!
//! What a local Worker cannot be made to do is not in the script: a second account, which a local
//! deployment does not have, a write signed before a collection's cutoff, a collection put back from
//! an archive, and a service that does not answer. The stand-in's answers for those are read from
//! the contract and the Worker's source, and the table in the stand-in crate's documentation names
//! the line of each.

mod recording;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use kr_client::recovery::bundle_collection;
use kr_client::services::account::{
    AccountToken, AccountTokenSource, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceFuture, ServiceHttp, SyncBackupService,
    SyncDispatch, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence, SyncRequestStatus,
    SyncRevision, managed_response_limits,
};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::scalars::Uuid;
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{RESTORE_TOKEN, ServiceWeb, TOKEN};
use recording::{
    Journal, Recording, Replaying, decoded, differences, held_exchanges, held_outcomes, keyed,
    recorded, refused,
};

const FIXTURE: &str = include_str!("../../../fixtures/service/bundle-answers.json");

/// An account token, as a source hands it over.
#[derive(Debug)]
struct Bearer(String);

impl AccountTokenSource for Bearer {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = AccountToken::new(self.0.clone());
        Box::pin(async move { token })
    }
}

/* -------------------------------------------------------------------------- */
/* The script                                                                  */
/* -------------------------------------------------------------------------- */

/// A fixed identifier, so a recording and a replay of it name the same locator and requests.
fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// The time on this machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
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

/// Runs the script against one service through `service`.
///
/// Every request is made by this crate's own client, as the owner's device and as a device
/// restoring from a kit make them, and what the client decoded is kept in `journal`. Whatever a
/// step expects it does not assert: what each answer was is the record's to say, and the stand-in
/// is held to it afterwards.
async fn run_the_script(
    service: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    write_token: &str,
    restore_token: &str,
    journal: &Journal,
) {
    let device = keyed(ServiceRequestSigner::Installation);
    journal.name(recording::written(&device));
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

/* -------------------------------------------------------------------------- */
/* The runs                                                                    */
/* -------------------------------------------------------------------------- */

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
    run_the_script(&replay, &origin, TOKEN, RESTORE_TOKEN, &journal).await;
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
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&web) as _,
        origin: web.origin().to_owned(),
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &origin, TOKEN, RESTORE_TOKEN, &journal).await;
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
    let write = tokens[&origin]["write"]
        .as_str()
        .expect("a backup.write token for this origin")
        .to_owned();
    let restore = tokens[&origin]["restore"]
        .as_str()
        .expect("a backup.restore token for this origin")
        .to_owned();
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
    run_the_script(&http, &gateway, &write, &restore, &journal).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
