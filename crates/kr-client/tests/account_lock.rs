//! The one lock, across processes.
//!
//! Two processes on one machine that keep the same account in the same store must never present
//! the same refresh token: the service rotates it on every use, and a second presentation of a
//! rotated token is a replay that revokes the whole grant. The in-process lock cannot see another
//! process, so a desktop account also takes an advisory lock on a file.
//!
//! These tests start this test binary twice more, as child processes, each with its own in-process
//! lock and sharing a file store and the lock file in a temporary directory, against one stub
//! token service on loopback that rotates a token once and answers a second presentation of it
//! with `invalid_grant`. The children run from a copy of this binary on the internal disk, with
//! every path they touch in the temporary directory.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::HttpService;
use kr_client::services::account::{
    AccountHttp, AccountService, AccountToken, AccountTokenSource, Client, IssuedGrant,
    ManagedAccountService, RefreshToken, SignedInAccount,
};
use kr_crypto::store::SecretStore;
use kr_protocol::service::GatewayOrigin;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The environment variable that turns this binary into a child with a role.
const ROLE: &str = "KR_ACCOUNT_LOCK_ROLE";
const DIRECTORY: &str = "KR_ACCOUNT_LOCK_DIRECTORY";
const ORIGIN: &str = "KR_ACCOUNT_LOCK_ORIGIN";
const UNSHARED: &str = "KR_ACCOUNT_LOCK_UNSHARED";

/// When the seeded grant was issued, in milliseconds; the children live ten minutes later.
const ISSUED_AT_MS: u64 = 1_790_251_200_000;

fn children_clock() -> u64 {
    ISSUED_AT_MS + 600_000
}

fn issued_clock() -> u64 {
    ISSUED_AT_MS
}

fn open_store(directory: &Path) -> Arc<dyn SecretStore> {
    Arc::from(
        kr_crypto::store::open_store_in(&directory.join("store"))
            .expect("a store in the temporary directory")
            .store,
    )
}

fn account(directory: &Path, origin: &str, clock: fn() -> u64, shared: bool) -> SignedInAccount {
    let http = HttpService::new(GatewayOrigin::new(origin).expect("a loopback origin"))
        .expect("a transport");
    let service = ManagedAccountService::at_origin(
        origin,
        Arc::new(http) as Arc<dyn AccountHttp>,
        Client::Desktop,
    );
    let account = SignedInAccount::new(
        Arc::new(service) as Arc<dyn AccountService>,
        open_store(directory),
        Client::Desktop,
    )
    .with_clock(clock);
    if shared {
        account.with_shared_lock(directory.join("account.lock"))
    } else {
        account
    }
}

fn wait_for(path: &Path) {
    for _ in 0..400 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} never appeared", path.display());
}

/// The children's entry. It does nothing in an ordinary run of this binary.
#[test]
fn child_process() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let directory = PathBuf::from(std::env::var(DIRECTORY).expect("a directory"));
    let origin = std::env::var(ORIGIN).expect("an origin");
    let shared = std::env::var(UNSHARED).is_err();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        let account = account(&directory, &origin, children_clock, shared);
        match role.as_str() {
            "refresh" => match account.token("openid").await {
                Ok(token) => println!("result ok {}", token.expose()),
                Err(error) => println!("result err {}", error.code().as_str()),
            },
            "refresh-then-again" => {
                match account.token("openid").await {
                    Ok(token) => println!("result ok {}", token.expose()),
                    Err(error) => println!("result err {}", error.code().as_str()),
                }
                wait_for(&directory.join("signed-out"));
                match account.token("openid").await {
                    Ok(token) => println!("again ok {}", token.expose()),
                    Err(error) => println!("again err {}", error.code().as_str()),
                }
            }
            "sign-out" => {
                wait_for(&directory.join("refresh-started"));
                let out = account.sign_out().await.expect("a sign-out");
                println!("signout {} {}", out.was_signed_in, out.service_told);
                std::fs::write(directory.join("signed-out"), b"").expect("a marker");
            }
            other => panic!("no such role: {other}"),
        }
    });
}

/// What the stub token service saw.
#[derive(Default)]
struct Family {
    current: String,
    spent: HashSet<String>,
    rotations: usize,
    replays: usize,
    revoked: Vec<String>,
    waiting: usize,
}

/// How the stub answers the first presentation of a live token.
#[derive(Clone, Copy)]
enum Pace {
    /// After a pause long enough for another process to act meanwhile.
    Pause,
    /// Once a second request has arrived, so two presentations are certain to overlap.
    Together,
}

async fn stub(directory: PathBuf, pace: Pace) -> (String, Arc<Mutex<Family>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let origin = format!("http://{}", listener.local_addr().expect("an address"));
    let family = Arc::new(Mutex::new(Family {
        current: "original".to_owned(),
        ..Family::default()
    }));
    let arrived = Arc::new(tokio::sync::Notify::new());
    let served = Arc::clone(&family);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let family = Arc::clone(&served);
            let arrived = Arc::clone(&arrived);
            let directory = directory.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                let (head, body) = loop {
                    let read = stream.read(&mut chunk).await.expect("a read");
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buffer.len() >= end + 4 + length {
                        break (head, buffer[end + 4..end + 4 + length].to_vec());
                    }
                };
                let fields: std::collections::BTreeMap<String, String> =
                    url::form_urlencoded::parse(&body).into_owned().collect();
                let (status, answer) = if head.starts_with("post /auth/oauth2/revoke ") {
                    family
                        .lock()
                        .expect("the family")
                        .revoked
                        .push(fields.get("token").cloned().unwrap_or_default());
                    (200, serde_json::json!({}))
                } else if head.starts_with("post /auth/oauth2/token ") {
                    let presented = fields.get("refresh_token").cloned().unwrap_or_default();
                    let live = {
                        let mut held = family.lock().expect("the family");
                        held.waiting += 1;
                        presented == held.current
                    };
                    arrived.notify_waiters();
                    std::fs::write(directory.join("refresh-started"), b"").expect("a marker");
                    if live {
                        match pace {
                            Pace::Pause => tokio::time::sleep(Duration::from_millis(1500)).await,
                            Pace::Together => {
                                let deadline =
                                    tokio::time::Instant::now() + Duration::from_secs(20);
                                while family.lock().expect("the family").waiting < 2
                                    && tokio::time::Instant::now() < deadline
                                {
                                    let _ = tokio::time::timeout(
                                        Duration::from_millis(100),
                                        arrived.notified(),
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    let mut held = family.lock().expect("the family");
                    if presented == held.current && !held.spent.contains(&presented) {
                        held.rotations += 1;
                        let next = format!("rotated-{}", held.rotations);
                        held.spent.insert(presented);
                        held.current = next.clone();
                        (
                            200,
                            serde_json::json!({
                                "access_token": format!("{next}-access"),
                                "token_type": "Bearer",
                                "expires_in": 600,
                                "refresh_token": next,
                                "scope": "openid voice",
                            }),
                        )
                    } else {
                        if held.spent.contains(&presented) {
                            // A replay ends the whole family.
                            held.replays += 1;
                            held.current = String::new();
                        }
                        (400, serde_json::json!({"error": "invalid_grant"}))
                    }
                } else {
                    (404, serde_json::json!({}))
                };
                let body = serde_json::to_vec(&answer).expect("json");
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (origin, family)
}

/// Keeps the grant a sign-in on this machine produced: tokens that ended their life ten minutes
/// before the children start.
async fn seed(directory: &Path, origin: &str) {
    let seeded = account(directory, origin, issued_clock, true);
    seeded
        .commit(
            IssuedGrant {
                access_token: AccountToken::new("original-access").expect("a token"),
                expires_in_seconds: 600,
                refresh_token: RefreshToken::new("original").expect("a token"),
                scopes: vec!["openid".to_owned(), "voice".to_owned()],
                subject: "account-1".to_owned(),
            },
            "a-nonce",
        )
        .await
        .expect("a sign-in");
}

/// Starts this binary once per role, from a copy on the internal disk.
///
/// The tests run on several threads of one process, and a child started for one test keeps every
/// descriptor this process had open at that instant until its own program takes over. If this
/// process wrote the copy itself, a child started for another test could still hold it open for
/// writing when this test starts it, which Linux refuses. So a separate process writes the copy
/// and has ended before the first child starts.
async fn children(directory: &Path, origin: &str, roles: &[&str], shared: bool) -> Vec<String> {
    let copy = directory.join("children");
    std::fs::create_dir_all(&copy).expect("a directory");
    let binary = copy.join("account-lock-child");
    kr_ipc::testing::place_program(&std::env::current_exe().expect("this binary"), &binary);
    let mut running = Vec::new();
    for role in roles {
        let mut command = tokio::process::Command::new(&binary);
        command
            .args([
                "--exact",
                "child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE, role)
            .env(DIRECTORY, directory)
            .env(ORIGIN, origin)
            .current_dir(directory)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if !shared {
            command.env(UNSHARED, "1");
        }
        running.push(command.spawn().expect("a child"));
    }
    let mut lines = Vec::new();
    for child in running {
        let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("the child finishes")
            .expect("its output");
        assert!(output.status.success(), "{output:?}");
        // The harness writes its own words before a test's first line, so each line is taken from
        // its marker on.
        lines.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    ["result ", "again ", "signout "]
                        .iter()
                        .filter_map(|marker| line.find(marker))
                        .min()
                        .map(|start| line[start..].to_owned())
                }),
        );
    }
    lines
}

/// The one lock across processes: two processes refreshing at once cause one refresh, and both are
/// handed the rotated token.
#[tokio::test(flavor = "multi_thread")]
async fn two_processes_refreshing_at_once_cause_one_refresh() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (origin, family) = stub(directory.path().to_path_buf(), Pace::Pause).await;
    seed(directory.path(), &origin).await;
    let lines = children(directory.path(), &origin, &["refresh", "refresh"], true).await;
    assert_eq!(
        lines,
        ["result ok rotated-1-access", "result ok rotated-1-access"],
        "{lines:?}"
    );
    let held = family.lock().expect("the family");
    assert_eq!(held.rotations, 1);
    assert_eq!(held.replays, 0);
}

/// The one lock across processes: a sign-out in one process during a refresh in another waits for
/// it, revokes the rotated token, and the refreshing process's next ask is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_sign_out_in_one_process_during_a_refresh_in_another_revokes_the_rotated_token() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (origin, family) = stub(directory.path().to_path_buf(), Pace::Pause).await;
    seed(directory.path(), &origin).await;
    let lines = children(
        directory.path(),
        &origin,
        &["refresh-then-again", "sign-out"],
        true,
    )
    .await;
    assert!(
        lines.contains(&"result ok rotated-1-access".to_owned()),
        "{lines:?}"
    );
    assert!(lines.contains(&"signout true true".to_owned()), "{lines:?}");
    assert!(
        lines.contains(&"again err HOST_NOT_CONFIGURED".to_owned()),
        "{lines:?}"
    );
    let held = family.lock().expect("the family");
    assert_eq!(held.revoked, ["rotated-1"]);
    assert_eq!(held.replays, 0);
}

/// The control: without the file lock, two processes present the same token, and the second
/// presentation is the replay that ends the grant.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_shared_lock_two_processes_present_the_same_token() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (origin, family) = stub(directory.path().to_path_buf(), Pace::Together).await;
    seed(directory.path(), &origin).await;
    let mut lines = children(directory.path(), &origin, &["refresh", "refresh"], false).await;
    lines.sort();
    assert_eq!(
        lines,
        ["result err PERMISSION_DENIED", "result ok rotated-1-access"],
        "{lines:?}"
    );
    assert_eq!(family.lock().expect("the family").replays, 1);
}
