//! What the settings-sync route answers a read of the recovery bundle, what this crate's client
//! makes of it, and what the stand-in the daemon's tests talk to answers, held to one recording.
//!
//! A device restoring from a kit reads the bundle at the kit's locator. The route admits it on two
//! proofs: an installation's signature (a host's key is refused) and an account token carrying
//! `backup.write` or `backup.restore`. `fixtures/service/bundle-answers.json` keeps, for each
//! request of one script, the status and the body a Worker on this machine answered and what the
//! client decoded it to.
//!
//! * [`the_client_decodes_what_the_worker_answered`] replays the recorded bodies through the
//!   client, with no stand-in between.
//! * [`the_stand_in_answers_as_the_worker_did`] runs the script against the stand-in and holds each
//!   status, shape and decoded value to the record. The write that puts the bundle in place is the
//!   script's setup, so the stand-in is given the bundle it holds after that write rather than
//!   answering the write.
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
//! What a local Worker cannot be made to do is not in the script: an account other than the
//! owner's reading the owner's locator (the deployment signs one account in). The stand-in's answer
//! for it is read from the Worker's source, and the table in the stand-in crate's documentation
//! names the line.

use std::sync::{Arc, Mutex};

use kr_client::recovery::{bundle_collection, fresh_locator};
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceFuture, ServiceHttp, SyncBackupService,
    SyncFetched, managed_response_limits,
};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, ServiceWeb};

mod recording;

use recording::{
    Journal, Recording, Replaying, debug, decoded, differences, held_exchanges, held_outcomes,
    keyed, recorded,
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

/// Runs the script against one service through `service`.
async fn run_the_script(
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
