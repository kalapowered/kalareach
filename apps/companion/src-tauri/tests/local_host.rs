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
        let tree = TempHost::create();
        let environment = tree.environment();
        let environment_id = tree.environment_id();
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
            _controller: controller,
            clients,
            app,
            window,
        }
    }

    fn environment_id(&self) -> String {
        self.tree.environment_id().to_string()
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
