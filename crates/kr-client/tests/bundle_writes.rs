//! What the settings-sync route answers the owner's write of the recovery bundle, what this
//! crate's client makes of it, and what the stand-in the daemon's tests talk to answers, held to
//! one recording.
//!
//! The owner writes the bundle at its locator with a compare-and-swap: against absence for the
//! first write, and against the revision held for a later one. The route admits a write on two
//! proofs, an installation's signature and an account token carrying `backup.write` (a token that
//! carries `backup.restore` only reads). `fixtures/service/bundle-write-answers.json` keeps, for
//! each request of one script, the status and the body a Worker on this machine answered and what
//! the client decoded it to.
//!
//! * [`the_client_decodes_what_the_worker_answered`] replays the recorded bodies through the
//!   client, with no stand-in between.
//! * [`the_stand_in_answers_as_the_worker_did`] runs the script against the stand-in and holds each
//!   status, shape and decoded value to the record.
//!
//! The recording is made again when the route's contract changes:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
//! node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
//!   KR_RECORD_BUNDLE_WRITE_ANSWERS=fixtures/service/bundle-write-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test bundle_writes record -- --ignored
//! ```
//!
//! What a local Worker cannot be made to do is not in the script: an account with no backup
//! allowance (the deployment's free tier includes backup storage), and an account other than the
//! owner's writing the owner's locator (the deployment signs one account in). The stand-in's
//! answers for them are read from the Worker's source, and the table in the stand-in crate's
//! documentation names the lines.

use std::sync::{Arc, Mutex};

use kr_client::recovery::{bundle_collection, fresh_locator};
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceFuture, ServiceHttp, SyncBackupService,
    SyncExchanged, SyncFetched, managed_response_limits,
};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::scalars::Uuid;
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, ServiceWeb};

mod recording;

use recording::{
    Journal, Recording, Replaying, decoded, differences, held_exchanges, held_outcomes, keyed,
    recorded,
};

const FIXTURE: &str = include_str!("../../../fixtures/service/bundle-write-answers.json");

/// The token the stand-in issues for the owner's account, for the write scope.
const WRITE_TOKEN: &str = "the-owner-write-token";
/// The token the stand-in issues to a device that may only read.
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

fn stream(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|at| u8::try_from((at + seed) % 251).expect("a byte"))
        .collect()
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

/// What a write decoded to, in the words of the values the owner's command acts on.
fn shown(exchanged: &SyncExchanged) -> String {
    match exchanged {
        SyncExchanged::Applied { position } => format!(
            "applied at write {}, revision {}, recovery {:?}",
            position.write_sequence,
            if position.revision.0.is_some() {
                "present"
            } else {
                "null"
            },
            position.recovery(),
        ),
        SyncExchanged::Refused {
            retained,
            current,
            recovery,
        } => format!(
            "refused the comparison, copy kept {}, bundle {}, recovery {recovery:?}",
            retained.is_some(),
            match current {
                Some(position) => format!("at write {}", position.write_sequence),
                None => "never written".to_owned(),
            },
        ),
        SyncExchanged::SignedBeforeCutoff => "signed before the cutoff".to_owned(),
    }
}

/// What a read decoded to.
fn shown_read(fetched: &SyncFetched, written: &[u8]) -> String {
    match fetched {
        SyncFetched::Held {
            position,
            ciphertext,
        } => format!(
            "held at write {}, {}",
            position.write_sequence,
            if ciphertext == written {
                "the bytes of the last write"
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
    journal: &Journal,
) {
    let locator = fresh_locator().expect("a locator");
    journal.name(locator.clone());
    let collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: locator,
    });
    let client = |signer: ServiceRequestSigner, token: &str, scope: &'static str| {
        ManagedSyncService::new(origin.clone(), Arc::clone(service), keyed(signer) as _)
            .presenting(Arc::new(Bearer(token.to_owned())), scope)
    };
    let owner = client(
        ServiceRequestSigner::Installation,
        &tokens.write,
        BACKUP_WRITE_SCOPE,
    );
    let first = stream(2048, 0);
    let other = stream(2048, 7);
    let replacement = stream(2304, 13);
    let identity = || kr_transport::random::fresh_uuid_v4().expect("an identity");
    let written: Uuid = identity();

    journal.step("write the bundle against absence with the write token");
    let answer = owner
        .compare_exchange(&collection, written, now_ms(), None, &first)
        .await;
    let position = match &answer {
        Ok(SyncExchanged::Applied { position }) => Some(*position),
        _ => None,
    };
    journal.decoded(decoded(&answer, shown));

    journal.step("write the same request again");
    let answer = owner
        .compare_exchange(&collection, written, now_ms(), None, &first)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write other content under the same request identity");
    let answer = owner
        .compare_exchange(&collection, written, now_ms(), None, &other)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write another bundle against absence while one is held");
    let answer = owner
        .compare_exchange(&collection, identity(), now_ms(), None, &other)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write with the restore token");
    let answer = client(
        ServiceRequestSigner::Installation,
        &tokens.restore,
        BACKUP_RESTORE_SCOPE,
    )
    .compare_exchange(&collection, identity(), now_ms(), position, &other)
    .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write signed by a host's key");
    let answer = client(
        ServiceRequestSigner::Host,
        &tokens.write,
        BACKUP_WRITE_SCOPE,
    )
    .compare_exchange(&collection, identity(), now_ms(), position, &other)
    .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("replace the bundle held, against its revision");
    let answer = owner
        .compare_exchange(&collection, identity(), now_ms(), position, &replacement)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("read the bundle with the write token");
    let answer = owner.fetch(&collection).await;
    journal.decoded(decoded(&answer, |fetched| {
        shown_read(fetched, &replacement)
    }));
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
    run_the_script(&replay, &origin, &tokens, &journal).await;
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
    run_the_script(&http, &origin, &tokens, &journal).await;
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

/// An account with no backup allowance is refused a write, and says what an exhausted allowance
/// says.
///
/// Source only: the local deployment's free tier includes backup storage, so no recording can show
/// it (`sync/collection.ts`, the ledger's hold). The control is the same write when the allowance
/// is there.
#[tokio::test]
async fn an_account_with_no_allowance_is_refused_the_write() {
    let web = Arc::new(ServiceWeb::new());
    web.issue_token(WRITE_TOKEN, ACCOUNT, &[BACKUP_WRITE_SCOPE]);
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: fresh_locator().expect("a locator"),
    });
    let http: Arc<dyn ServiceHttp> = Arc::clone(&web) as _;
    let owner =
        ManagedSyncService::new(origin, http, keyed(ServiceRequestSigner::Installation) as _)
            .presenting(Arc::new(Bearer(WRITE_TOKEN.to_owned())), BACKUP_WRITE_SCOPE);
    let identity = || kr_transport::random::fresh_uuid_v4().expect("an identity");

    web.refuse_bundle_writes(true);
    let refused = owner
        .compare_exchange(&collection, identity(), now_ms(), None, &stream(2048, 0))
        .await
        .expect_err("a write the allowance does not admit");
    assert_eq!(refused.code(), kr_protocol::error::ErrorCode::QuotaExceeded);

    web.refuse_bundle_writes(false);
    assert!(matches!(
        owner
            .compare_exchange(&collection, identity(), now_ms(), None, &stream(2048, 0))
            .await,
        Ok(SyncExchanged::Applied { .. })
    ));
}

/// An account that did not write a bundle is told there is nothing at its locator, for a read and
/// for a write alike, and the owner's bundle is as it was (`sync/collection.ts`, the owner a first
/// write records). The deployment signs one account in, so the Worker cannot be asked.
#[tokio::test]
async fn an_account_that_does_not_own_the_bundle_is_told_it_is_not_there() {
    const OTHER_TOKEN: &str = "the-other-accounts-write-token";
    let web = Arc::new(ServiceWeb::new());
    web.issue_token(WRITE_TOKEN, ACCOUNT, &[BACKUP_WRITE_SCOPE]);
    web.issue_token(OTHER_TOKEN, "account-two", &[BACKUP_WRITE_SCOPE]);
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let collection = bundle_collection(&RecoveryContext {
        service_origin: origin.as_str().to_owned(),
        bundle_locator: fresh_locator().expect("a locator"),
    });
    let http: Arc<dyn ServiceHttp> = Arc::clone(&web) as _;
    let service = |token: &str| {
        ManagedSyncService::new(
            origin.clone(),
            Arc::clone(&http),
            keyed(ServiceRequestSigner::Installation) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())), BACKUP_WRITE_SCOPE)
    };
    let identity = || kr_transport::random::fresh_uuid_v4().expect("an identity");
    let owner = service(WRITE_TOKEN);
    let other = service(OTHER_TOKEN);

    assert!(matches!(
        owner
            .compare_exchange(&collection, identity(), now_ms(), None, &stream(2048, 0))
            .await,
        Ok(SyncExchanged::Applied { .. })
    ));
    let written = other
        .compare_exchange(&collection, identity(), now_ms(), None, &stream(2048, 1))
        .await
        .expect_err("a write by an account that is not the owner");
    assert_eq!(
        written.code(),
        kr_protocol::error::ErrorCode::UnknownSession
    );
    let read = other
        .fetch(&collection)
        .await
        .expect_err("a read by an account that is not the owner");
    assert_eq!(read.code(), kr_protocol::error::ErrorCode::UnknownSession);
    assert!(
        matches!(owner.fetch(&collection).await, Ok(SyncFetched::Held { .. })),
        "the owner's bundle is as it was"
    );
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It is ignored unless it is asked for, and then it needs the Worker to ask and the account
/// tokens that Worker's development sign-in wrote, so an ordinary run of this workspace asks
/// nothing of any service.
#[tokio::test]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN, KR_BACKUP_TOKENS and KR_RECORD_BUNDLE_WRITE_ANSWERS"]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin), Some(tokens)) = (
        std::env::var_os("KR_RECORD_BUNDLE_WRITE_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
        std::env::var_os("KR_BACKUP_TOKENS"),
    ) else {
        panic!(
            "KR_RECORD_BUNDLE_WRITE_ANSWERS, KR_DEPLOYED_ORIGIN and KR_BACKUP_TOKENS name what to \
             record"
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
    run_the_script(&http, &gateway, &tokens, &journal).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
