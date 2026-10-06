//! The commands the control daemon on this machine answers, called the way the page calls them.
//!
//! The daemon is kr-controller's in-process host on a temporary tree on the internal disk, with its
//! secret store a file inside that tree, so nothing here reaches this computer's keychain. It starts
//! no worker. Each command goes through the invoke path with the parameters the page writes, and
//! each answer the page is given is read back into the method's own type: so what is checked is
//! that the host takes the shape the page sends, and that the page is given a shape the protocol
//! defines.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use kr_client::ipc::IpcTransport;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::testing::TempHost;
use kr_ipc::verify::ControllerIdentity;
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

/// How long one command may take before the test calls it hung.
const WATCHDOG: std::time::Duration = std::time::Duration::from_secs(20);

/// A supervisor that starts nothing. These tests create no sessions.
#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// The daemon of one test and the application connected to it.
struct Host {
    tree: TempHost,
    /// The description host's test placement, which goes when the daemon's test does.
    _placed: Option<kr_controller::describe::hooks::Placed>,
    _controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Host {
    /// Starts the daemon, and an application whose connection is to it.
    async fn start() -> Self {
        Self::start_describing(None).await
    }

    /// Starts the daemon as `start` does, with its description host choosing from `catalogue` when
    /// one is given, and told that nothing stands in the way of a model: the memory is free and
    /// the power is the mains'.
    async fn start_describing(catalogue: Option<kr_describe::testing::TestCatalogue>) -> Self {
        let tree = TempHost::create();
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let placed = catalogue.map(|signed| {
            // Placed under the directory's own name, which has to exist for that name to be found.
            std::fs::create_dir_all(environment.state_dir()).expect("the state directory");
            let gib = kr_describe::budget::GIB;
            kr_controller::describe::hooks::place(
                environment.state_dir(),
                // The fetch stops before a process is needed, and a process that is never started
                // has no program to find.
                PathBuf::from("/nonexistent/kr-describe-inference"),
                Vec::new(),
                signed.catalogue(),
                kr_describe::resource::HostConditions::measured(
                    16 * gib,
                    12 * gib,
                    kr_describe::resource::PowerSource::Mains,
                    kr_describe::resource::ThermalState::Nominal,
                ),
                false,
            )
        });
        let secrets = environment.secrets_dir();
        let build_id = companion_tauri::connection::build_id().expect("a build identity");
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: build_id.clone(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the control endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));

        let app = tauri::test::mock_builder()
            .manage(companion_tauri::AppState::new())
            .manage(companion_tauri::agent::WorkerLinks::at(environment))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::attention_read,
                companion_tauri::commands::attention_acknowledge,
                companion_tauri::commands::review_read,
                companion_tauri::commands::review_acknowledge,
                companion_tauri::commands::changeset_read,
                companion_tauri::commands::device_list,
                companion_tauri::commands::grant_list,
                companion_tauri::commands::grant_create,
                companion_tauri::commands::plugin_list,
                companion_tauri::commands::catalogue_list,
                companion_tauri::commands::history_page,
                companion_tauri::commands::session_create,
                companion_tauri::commands::description_setup,
                companion_tauri::commands::description_configure,
                companion_tauri::commands::description_download,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let transport = IpcTransport::connect(&endpoint, build_id)
            .await
            .expect("connects to the control endpoint");
        app.state::<companion_tauri::AppState>().connected(
            companion_tauri::connection::Connection::over(transport).expect("a connection"),
        );
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self {
            tree,
            _placed: placed,
            _controller: controller,
            clients,
            app,
            window,
        }
    }

    fn environment_id(&self) -> String {
        self.tree.environment_id().to_string()
    }

    /// Reads the card's setup until `holds` says it does, or the watchdog runs out.
    async fn setup_until(
        &self,
        what: &str,
        holds: impl Fn(&kr_protocol::describe::DescriptionSetup) -> bool,
    ) -> kr_protocol::describe::DescriptionSetup {
        let deadline = tokio::time::Instant::now() + WATCHDOG;
        loop {
            let shown = setup_of(
                self.call("description_setup", json!({}))
                    .await
                    .expect("setup"),
            );
            if holds(&shown) {
                return shown;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} did not happen: {shown:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Calls `command` as the page does, and waits for its answer.
    async fn call(&self, command: &'static str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = self.window.clone();
        let _ = &self.app;
        let answer = tokio::task::spawn_blocking(move || {
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .map(|answer| {
                answer
                    .deserialize::<Value>()
                    .expect("an answer the page reads")
            })
        });
        tokio::time::timeout(WATCHDOG, answer)
            .await
            .expect("the command answered within the watchdog")
            .expect("the command's thread finished")
    }
}

/// Reads an answer back into the method's own result type, which is what says the page was given a
/// shape the protocol defines.
fn typed<T: serde::de::DeserializeOwned>(answer: Value) -> T {
    serde_json::from_value(answer).expect("the answer is the method's own result")
}

/// The words a refusal carries, which say whether it was the host's or the command's own parse.
fn refused_by_the_host(refusal: &Value) -> bool {
    let message = refusal["message"].as_str().unwrap_or_default();
    refusal["code"].is_string() && !message.contains("those are not this operation's parameters")
}

/// KR-REQ-13.01: the attention inbox is read from the host with the parameters the page writes,
/// and an acknowledgement of an item the host no longer holds is answered as stale rather than
/// recorded.
#[tokio::test(flavor = "multi_thread")]
async fn the_inbox_is_read_and_acknowledged_on_the_host() {
    let host = Host::start().await;
    let inbox: kr_protocol::attention::AttentionReadResult = typed(
        host.call(
            "attention_read",
            json!({ "params": {
                "session_id": null,
                "include_acknowledged": false,
                "max_items": "50",
                "after": null
            } }),
        )
        .await
        .expect("the inbox"),
    );
    assert!(inbox.items.is_empty(), "a new host has nothing waiting");
    assert!(!inbox.more);

    let settled = host
        .call(
            "attention_acknowledge",
            json!({
                "subject": {},
                "params": { "items": [{ "key": "attention.review_ready|gone", "revision": "3" }] }
            }),
        )
        .await
        .expect("the acknowledgement is taken");
    let answer: kr_protocol::attention::AttentionAcknowledgeResult =
        typed(settled["value"].clone());
    assert!(answer.acknowledged.is_empty());
    assert_eq!(
        answer.stale.len(),
        1,
        "an item the host does not hold is stale"
    );
}

/// KR-REQ-13.09: a page of the inbox or of review state continues only after a key or subject the
/// host holds, and anything else is a conflict the page reads again from the start; a review
/// subject the host does not hold cannot be acknowledged. The page's scripted host keeps the same
/// rules.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_continues_only_after_what_the_host_holds() {
    let host = Host::start().await;
    let inbox = host
        .call(
            "attention_read",
            json!({ "params": {
                "session_id": null,
                "include_acknowledged": false,
                "max_items": "50",
                "after": "attention.review_ready|gone"
            } }),
        )
        .await
        .expect_err("the host holds no such item to continue after");
    assert_eq!(inbox["code"], "DRAFT_CONFLICT", "{inbox}");

    let subject = json!({ "change_set": {
        "session_id": "44444444-4444-4444-8444-444444444444",
        "change_set_id": "66666666-6666-4666-8666-666666666666"
    } });
    let reviews = host
        .call(
            "review_read",
            json!({ "params": {
                "session_id": null,
                "subject": null,
                "max_reviews": "50",
                "after": subject
            } }),
        )
        .await
        .expect_err("the host holds no such subject to continue after");
    assert_eq!(reviews["code"], "DRAFT_CONFLICT", "{reviews}");

    let acknowledged = host
        .call(
            "review_acknowledge",
            json!({
                "subject": {},
                "params": {
                    "session_id": "44444444-4444-4444-8444-444444444444",
                    "subject": subject,
                    "version": "1"
                }
            }),
        )
        .await
        .expect_err("the host holds no such subject to acknowledge");
    assert!(refused_by_the_host(&acknowledged), "{acknowledged}");
}

/// KR-REQ-13.12, change sets: review state is read from the host, and a change set it does not
/// hold is its refusal rather than the command's.
#[tokio::test(flavor = "multi_thread")]
async fn review_state_and_a_change_set_are_read_on_the_host() {
    let host = Host::start().await;
    let reviews: kr_protocol::attention::ReviewReadResult = typed(
        host.call(
            "review_read",
            json!({ "params": {
                "session_id": null,
                "subject": null,
                "max_reviews": "50",
                "after": null
            } }),
        )
        .await
        .expect("the review state"),
    );
    assert!(reviews.reviews.is_empty());

    let refusal = host
        .call(
            "changeset_read",
            json!({ "params": {
                "change_set_id": "66666666-6666-4666-8666-666666666666",
                "version": null
            } }),
        )
        .await
        .expect_err("the host holds no such change set");
    assert!(refused_by_the_host(&refusal), "{refusal}");
}

/// KR-REQ-25.08: the devices an invitation can go to and the grants issued are read on the host,
/// and an invitation to a device this host never paired is the host's refusal, after the command
/// took the page's shape.
#[tokio::test(flavor = "multi_thread")]
async fn sharing_is_read_and_an_invitation_reaches_the_host() {
    let host = Host::start().await;
    let devices: kr_protocol::sharing::DeviceListResult = typed(
        host.call(
            "device_list",
            json!({ "params": { "include_revoked": false } }),
        )
        .await
        .expect("the devices"),
    );
    assert!(
        devices.devices.is_empty(),
        "nothing is paired with a new host"
    );
    let grants: kr_protocol::sharing::GrantListResult = typed(
        host.call(
            "grant_list",
            json!({ "params": { "session_id": null, "include_resolved": false } }),
        )
        .await
        .expect("the grants"),
    );
    assert!(grants.grants.is_empty());

    let refusal = host
        .call(
            "grant_create",
            json!({
                "subject": {},
                "params": {
                    "session_id": "44444444-4444-4444-8444-444444444444",
                    "recipient_device_id": "77777777-7777-4777-8777-777777777777",
                    "parent_grant_id": null,
                    "selection": {
                        "role": "viewer",
                        "history_from_cursor_ms": null,
                        "include_live_screen": false,
                        "include_question_respond": true,
                        "named_questions": [],
                        "named_approvals": []
                    },
                    "lifetime_ms": null,
                    "accepted_notices": ["agent_permissions"],
                    "owner_confirmation": null
                }
            }),
        )
        .await
        .expect_err("the host has no such device or session");
    assert!(refused_by_the_host(&refusal), "{refusal}");
}

/// KR-REQ-11.03: the installed packages and the enrolled repositories are read on the host, for the
/// environment the page names.
#[tokio::test(flavor = "multi_thread")]
async fn packages_and_repositories_are_read_on_the_host() {
    let host = Host::start().await;
    let environment = host.environment_id();
    let installed: kr_protocol::catalogue::PluginListResult = typed(
        host.call(
            "plugin_list",
            json!({ "params": { "environment_id": environment } }),
        )
        .await
        .expect("the installed packages"),
    );
    assert!(installed.plugins.is_empty());
    let repositories: kr_protocol::catalogue::CatalogueListResult = typed(
        host.call(
            "catalogue_list",
            json!({ "params": { "environment_id": environment } }),
        )
        .await
        .expect("the repositories"),
    );
    assert!(repositories.catalogues.is_empty());
}

/// KR-REQ-13.15: a session whose worker has no descriptor here has its history read from the
/// host's archive, which answers for itself.
#[tokio::test(flavor = "multi_thread")]
async fn an_ended_sessions_history_is_the_hosts_to_answer() {
    let host = Host::start().await;
    let answer = host
        .call(
            "history_page",
            json!({ "params": {
                "session_id": "44444444-4444-4444-8444-444444444444",
                "from_cursor": "0",
                "max_bytes": "16384"
            } }),
        )
        .await;
    match answer {
        Ok(page) => {
            let _: kr_protocol::recovery::HistoryPageResult = typed(page);
        }
        Err(refusal) => {
            assert!(refused_by_the_host(&refusal), "{refusal}");
            assert_ne!(
                refusal["code"], "HOST_NOT_CONFIGURED",
                "the host was reached"
            );
        }
    }
}

/// KR-REQ-07.21: a creation of a stock shell, written as the page writes it, reaches the host's own
/// create path. This daemon starts no workers, so what answers is the host's refusal to start one,
/// which it can only give for a request it read.
#[tokio::test(flavor = "multi_thread")]
async fn a_stock_shells_creation_reaches_the_host_as_the_page_writes_it() {
    let host = Host::start().await;
    let creation = |shell_mode: &str| {
        json!({
            "params": {
                "environment_id": host.environment_id(),
                "presentation": "invisible",
                "shell": null,
                "shell_mode": shell_mode,
                "cwd": "/",
                "dimensions": null,
                "worker_profile": "headless_user",
                "environment_snapshot": [],
                "palette": null,
                "launch_profile": {
                    "startup": "host_default",
                    "fenced_launch": false,
                    "command_integrations": []
                },
                "terminal": null
            },
            "subject": {}
        })
    };
    let refusal = host
        .call("session_create", creation("native_compat"))
        .await
        .expect_err("this daemon starts no workers");
    assert!(refused_by_the_host(&refusal), "{refusal}");
    assert_eq!(refusal["code"], "RESOURCE_UNAVAILABLE", "{refusal}");
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|message| message.contains("this test starts no workers")),
        "the host went as far as starting the session's worker: {refusal}"
    );

    // The control: a shell the protocol does not name is refused before anything is sent.
    let unnamed = host
        .call("session_create", creation("stock"))
        .await
        .expect_err("a shell mode the protocol does not name");
    assert!(!refused_by_the_host(&unnamed), "{unnamed}");
}

// ---------------------------------------------------------------------------------------------
// The setup card for session descriptions
// ---------------------------------------------------------------------------------------------

/// What the card's one profile holds, which fixes the size it shows.
const WEIGHTS: &[u8] = b"the weights of a tiny model";

/// A server a fetch can reach: it reads the request, sends the headers and half of the body, and
/// holds the connection until the fetch leaves. It records the paths it was asked for.
struct HoldingServer {
    address: std::net::SocketAddr,
    asked: Arc<std::sync::Mutex<Vec<String>>>,
    half_sent: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl HoldingServer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let address = listener.local_addr().expect("its address");
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let half_sent = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let (asked, half_sent) = (Arc::clone(&asked), Arc::clone(&half_sent));
            async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                while let Ok((mut stream, _)) = listener.accept().await {
                    let (asked, half_sent) = (Arc::clone(&asked), Arc::clone(&half_sent));
                    tokio::spawn(async move {
                        let mut seen = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => seen.extend_from_slice(&chunk[..read]),
                            }
                        }
                        let request = String::from_utf8_lossy(&seen).into_owned();
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split(' ').nth(1))
                            .unwrap_or("/")
                            .to_owned();
                        asked
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(path);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            WEIGHTS.len()
                        );
                        stream.write_all(head.as_bytes()).await.ok();
                        stream.write_all(&WEIGHTS[..WEIGHTS.len() / 2]).await.ok();
                        stream.flush().await.ok();
                        half_sent.notify_one();
                        // Held until the fetch leaves: reading answers nothing but its end.
                        let _ = stream.read(&mut chunk).await;
                    });
                }
            }
        });
        Self {
            address,
            asked,
            half_sent,
            task,
        }
    }

    /// Every path that has been asked for, in order.
    fn asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Waits until a connection has been sent its half of the body.
    async fn until_half_sent(&self) {
        tokio::time::timeout(WATCHDOG, self.half_sent.notified())
            .await
            .expect("half of the body was sent in time");
    }
}

impl Drop for HoldingServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What the card reads of the host, as the answer to a read or the value of a settled change.
fn setup_of(answer: Value) -> kr_protocol::describe::DescriptionSetup {
    typed(answer)
}

/// The value a settled change carries.
fn settled_value(settled: Value) -> Value {
    settled["value"].clone()
}

/// KR-REQ-22.01: the setup card, through the three commands it calls and with the parameters it
/// writes, against the host's own description setup. It shows the exact size and where the fetch
/// would reach before anything is fetched, and offers no account; a fetch begins only when the card
/// asks, and the card's cancel stops it while its body is arriving; turning descriptions off stops a
/// fetch that is running. The answers of setup, of each start of the fetch, of the cancel and of the
/// setting are read back into the method's own type; the daemon's own suite shows that a cancelled
/// fetch leaves no file.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_card_shows_the_size_first_and_cancels_and_disables_on_the_host() {
    use kr_protocol::describe::DescriptionDownload;

    let server = HoldingServer::start().await;
    let host = Host::start_describing(Some(kr_describe::testing::TestCatalogue::sign(&[
        kr_describe::testing::TestProfile {
            profile_id: "tiny-default".to_owned(),
            revision: 1,
            candidate: false,
            targets: Some(vec![kr_describe::environment::build_target().to_owned()]),
            assets: vec![kr_describe::testing::TestAsset {
                file_name: "tiny.gguf".to_owned(),
                url: format!("http://{}/tiny.gguf", server.address),
                bytes: WEIGHTS.to_vec(),
            }],
        },
    ])))
    .await;
    let start = || json!({ "params": { "action": "start" }, "subject": {} });
    let cancel = || json!({ "params": { "action": "cancel" }, "subject": {} });

    // The card opens: the exact size and the address first, no account, and no fetch.
    let shown = setup_of(
        host.call("description_setup", json!({}))
            .await
            .expect("setup"),
    );
    assert!(shown.offered && shown.enabled, "{shown:?}");
    assert_eq!(
        shown.asset_bytes.get(),
        WEIGHTS.len() as u64,
        "the exact size"
    );
    assert_eq!(shown.sources, vec![server.address.to_string()]);
    assert!(!shown.needs_hosted_account);
    assert_eq!(shown.download, DescriptionDownload::NotStarted);
    assert!(shown.can_disable && !shown.can_cancel, "{shown:?}");
    assert!(server.asked().is_empty(), "nothing is fetched unasked");

    // Fetch asked for, and then cancelled while its body is arriving.
    let started = setup_of(settled_value(
        host.call("description_download", start())
            .await
            .expect("the fetch starts"),
    ));
    assert_eq!(
        started.download,
        DescriptionDownload::Running,
        "{started:?}"
    );
    assert!(started.can_cancel);
    server.until_half_sent().await;
    assert_eq!(server.asked(), vec!["/tiny.gguf".to_owned()]);
    let cancelled = setup_of(settled_value(
        host.call("description_download", cancel())
            .await
            .expect("the fetch is cancelled"),
    ));
    assert!(
        matches!(
            cancelled.download,
            DescriptionDownload::Running | DescriptionDownload::Cancelled
        ),
        "{cancelled:?}"
    );
    let cancelled = host
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(!cancelled.can_cancel, "{cancelled:?}");

    // Fetch asked for again, and the card's switch turns descriptions off while it runs.
    let again = setup_of(settled_value(
        host.call("description_download", start())
            .await
            .expect("the fetch starts again"),
    ));
    assert_eq!(again.download, DescriptionDownload::Running, "{again:?}");
    server.until_half_sent().await;
    let off = setup_of(settled_value(
        host.call(
            "description_configure",
            json!({ "params": { "enabled": false, "on_battery": null }, "subject": {} }),
        )
        .await
        .expect("the setting is changed"),
    ));
    assert!(!off.enabled, "{off:?}");
    let stopped = host
        .setup_until("the fetch stopped by turning descriptions off", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(!stopped.enabled && !stopped.can_cancel, "{stopped:?}");
}
