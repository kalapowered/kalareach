//! The commands the control daemon on this machine answers, called the way the page calls them.
//!
//! The daemon is kr-controller's in-process host on a temporary tree on the internal disk, with its
//! secret store a file inside that tree, so nothing here reaches this computer's keychain. It
//! starts no worker, except in the cases that create a session, which start the product's own
//! worker as a process of its own and end it with the test. Each command goes through the invoke
//! path with the parameters the page writes, and each answer the page is given is read back into
//! the method's own type: so what is checked is that the host takes the shape the page sends, and
//! that the page is given a shape the protocol defines.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use kr_client::ipc::IpcTransport;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, LaunchOutcome, WorkerLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

#[path = "../../../../crates/kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long one command may take before the test calls it hung.
const WATCHDOG: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a creation that starts a real worker may take before the test calls it hung: the host
/// itself waits up to half a minute for the worker to report.
const WORKER_START: std::time::Duration = std::time::Duration::from_secs(60);

/// A supervisor that starts nothing, for the cases that create no session.
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

/// Whether the daemon starts the sessions' workers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Workers {
    /// None: a creation is refused by the supervisor, after the daemon has read it.
    None,
    /// The product's own worker, as a process of its own that the test's tree ends.
    Live,
}

/// The worker binary this workspace built, copied to the internal disk and started once there.
///
/// # Panics
///
/// Panics when the build has no worker: a case that skipped would report a pass for a creation it
/// never ran. A workspace test run builds the worker, and so does `cargo build -p kr-worker`.
fn worker_binary(into: &std::path::Path) -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let built = directory.join("kr-worker");
    assert!(
        built.is_file(),
        "this case starts a real worker process and there is none at {}; build it with \
         `cargo build -p kr-worker`",
        built.display()
    );
    let copied = into.join("kr-worker");
    kr_ipc::testing::place_and_start_once(&built, &copied, &["--version"]);
    copied
}

/// The daemon of one test and the application connected to it.
struct Host {
    /// The tree, which ends every worker its daemon started before it goes.
    tree: teardown::Tree,
    /// The description host's test placement, which goes when the daemon's test does.
    _placed: Option<kr_controller::describe::hooks::Placed>,
    _controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    /// Serves the workers' rendezvous, when the daemon starts any.
    rendezvous: Option<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    /// Serves the attachment-chunk endpoint, which a file's chunks travel on.
    chunks: tokio::task::JoinHandle<()>,
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    /// Where the application keeps the answers a host did not confirm.
    kept: tempfile::TempDir,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
        self.chunks.abort();
        if let Some(rendezvous) = &self.rendezvous {
            rendezvous.abort();
        }
    }
}

impl Host {
    /// Starts the daemon, and an application whose connection is to it.
    async fn start() -> Self {
        Self::start_with(None, Workers::None).await
    }

    /// Starts the daemon as `start` does, and lets it start the workers of the sessions it creates.
    async fn start_creating_sessions() -> Self {
        Self::start_with(None, Workers::Live).await
    }

    /// Starts the daemon as `start` does, with its description host choosing from `catalogue` when
    /// one is given, and told that nothing stands in the way of a model: the memory is free and
    /// the power is the mains'.
    async fn start_describing(catalogue: Option<kr_describe::testing::TestCatalogue>) -> Self {
        Self::start_with(catalogue, Workers::None).await
    }

    async fn start_with(
        catalogue: Option<kr_describe::testing::TestCatalogue>,
        workers: Workers,
    ) -> Self {
        let tree = teardown::Tree::create();
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
        let (supervisor, worker_program): (Box<dyn WorkerSupervisor>, PathBuf) = match workers {
            Workers::None => (
                Box::new(RefusingSupervisor),
                PathBuf::from("/nonexistent/kr-worker"),
            ),
            Workers::Live => (
                Box::new(DetachedSupervisor::new()),
                worker_binary(tree.root()),
            ),
        };
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
            supervisor: tree.supervisor(supervisor),
            worker_program,
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
        let rendezvous = (workers == Workers::Live).then(|| {
            let listener = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                .expect("binds the workers' rendezvous endpoint");
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(listener))
        });
        let chunk_listener = kr_controller::transfer::bind_chunk_endpoint(&environment)
            .expect("binds the attachment-chunk endpoint");
        let chunks = tokio::spawn(kr_controller::transfer::serve_chunks(
            Arc::downgrade(&controller),
            chunk_listener,
        ));

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
                companion_tauri::commands::session_close,
                companion_tauri::commands::session_read,
                companion_tauri::commands::draft_create,
                companion_tauri::commands::draft_add_attachment,
                companion_tauri::commands::description_setup,
                companion_tauri::commands::description_configure,
                companion_tauri::commands::description_download,
                companion_tauri::commands::question_kept,
                companion_tauri::commands::question_settle,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let transport = IpcTransport::connect(&endpoint, build_id)
            .await
            .expect("connects to the control endpoint");
        app.state::<companion_tauri::AppState>().connected(
            companion_tauri::connection::Connection::over(transport).expect("a connection"),
        );
        let kept = tempfile::tempdir().expect("a place for the kept answers");
        app.state::<companion_tauri::AppState>()
            .keep_under(kept.path());
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self {
            tree,
            _placed: placed,
            _controller: controller,
            clients,
            rendezvous,
            chunks,
            app,
            window,
            kept,
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
        self.call_within(command, body, WATCHDOG).await
    }

    /// Calls `command` as the page does, and waits up to `limit` for its answer.
    async fn call_within(
        &self,
        command: &'static str,
        body: Value,
        limit: std::time::Duration,
    ) -> Result<Value, Value> {
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
        tokio::time::timeout(limit, answer)
            .await
            .expect("the command answered within its limit")
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

/// An answer kept for a session whose worker is gone is settled by what the daemon on this machine
/// says of the session, as it was before the application checked which host an answer was given to:
/// the worker's descriptor is not needed to know which machine the session ran on.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_kept_for_a_session_whose_worker_has_gone_is_settled_as_gone() {
    use kr_client::answers::{ANSWER_FORMAT, AnswerDraft, AnswerDrafts, WRITTEN};
    use kr_protocol::envelope::ActionTarget;
    use kr_protocol::ids::{QuestionId, QuestionRevision, SessionEpoch, SessionId};
    use kr_protocol::question::QuestionAnswer;
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    let host = Host::start().await;
    let environment_id = host.tree.environment_id();
    let session_id = SessionId::new(Uuid::from_bytes([7; 16]));
    let question_id = QuestionId::new(Uuid::from_bytes([5; 16]));
    let draft = AnswerDraft {
        version: ANSWER_FORMAT,
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        session_id,
        question_id,
        question_revision: QuestionRevision::new(2),
        answer: QuestionAnswer::Choice {
            choice_id: "main".to_owned(),
        },
        drafted_at_ms: TimestampMs::new(5),
    };
    let kept = host.kept.path().join("kept-answers");
    let store = AnswerDrafts::open(kept.join(environment_id.to_string())).expect("a store");
    let writers = kr_ipc::install::hold_writers(
        &kr_ipc::install::Writing::in_roots(&kept, &kept),
        &mut || {},
    )
    .expect("the writers lock");
    let permit = writers.permit(&WRITTEN).expect("the leave to write");
    store.keep(&draft, &permit).expect("kept");

    // No worker is serving the session, and the daemon has no such session either.
    let settled = host
        .call(
            "question_settle",
            json!({ "params": { "sessionId": session_id.to_string() } }),
        )
        .await
        .expect("the standing of the kept answer");
    assert_eq!(settled.as_array().map(Vec::len), Some(1), "{settled}");
    assert_eq!(settled[0]["standing"], "gone", "{settled}");
}

/// What the page writes to create an invisible session of the given shell mode in `cwd`.
fn creation(host: &Host, shell_mode: &str, shell: Value, cwd: &str) -> Value {
    json!({
        "params": {
            "environment_id": host.environment_id(),
            "presentation": "invisible",
            "shell": shell,
            "shell_mode": shell_mode,
            "cwd": cwd,
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
}

/// KR-REQ-07.21: a creation of a stock shell, written as the page writes it, reaches the host's own
/// create path. This daemon starts no workers, so what answers is the host's refusal to start one,
/// which it can only give for a request it read.
#[tokio::test(flavor = "multi_thread")]
async fn a_stock_shells_creation_reaches_the_host_as_the_page_writes_it() {
    let host = Host::start().await;
    let refusal = host
        .call(
            "session_create",
            creation(&host, "native_compat", Value::Null, "/"),
        )
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
        .call("session_create", creation(&host, "stock", Value::Null, "/"))
        .await
        .expect_err("a shell mode the protocol does not name");
    assert!(!refused_by_the_host(&unnamed), "{unnamed}");
}

/// KR-REQ-07.21: the session a creation answers with is the session the page opens next. The page
/// reads the new session's identifier from the answer of `session_create` and names it in
/// `session_read`, so the answer carries it in the protocol's own JSON form (an identifier as
/// hyphenated text, a counter as a decimal string), and the host answers for the session it names.
/// The daemon starts the product's own worker here, so the creation is a real one.
#[tokio::test(flavor = "multi_thread")]
async fn a_created_sessions_identifier_is_one_the_page_can_open() {
    let host = Host::start_creating_sessions().await;
    let work = host.tree.root().join("w");
    std::fs::create_dir(&work).expect("a directory on the internal disk");

    let created = host
        .call_within(
            "session_create",
            creation(
                &host,
                "native_compat",
                json!("/bin/sh"),
                &work.display().to_string(),
            ),
            WORKER_START,
        )
        .await
        .expect("the host creates the session");
    let session_id = created["value"]["session"]["session_id"]
        .as_str()
        .expect("the new session's identifier");
    // The page names this text in the next call, so it has to be an identifier as the protocol
    // writes one.
    session_id
        .parse::<kr_protocol::ids::SessionId>()
        .unwrap_or_else(|error| panic!("{session_id:?} is not a session identifier: {error}"));
    let result: kr_protocol::session::SessionCreateResult = typed(created["value"].clone());
    assert!(!result.deduplicated, "{created}");

    let read: kr_protocol::session::SessionReadResult = typed(
        host.call(
            "session_read",
            json!({ "params": { "session_id": session_id } }),
        )
        .await
        .expect("the host reads the session the creation named"),
    );
    assert_eq!(read.session.session_id, result.session.session_id);

    // The case closes what it made, as the page would: the worker ends with its session.
    host.call(
        "session_close",
        json!({
            "params": { "session_id": session_id },
            "subject": { "sessionId": session_id, "sessionEpoch": "1" }
        }),
    )
    .await
    .expect("the host closes the session");
}

/// KR-REQ-13.14: a file the page hands over is given a path on the host through the commands the
/// page calls, with the identifiers the page reads and writes. The page reads the draft's
/// identifier from the answer of `draft_create` and names it in `draft_add_attachment`, so the
/// answer carries it in the protocol's own JSON form (an identifier as hyphenated text, a counter
/// as a decimal string), and the file at the path the binding names is the file that was handed
/// over.
#[tokio::test(flavor = "multi_thread")]
async fn a_handed_file_is_given_a_path_through_the_commands_the_page_calls() {
    let host = Host::start().await;
    let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string();
    let subject = json!({ "sessionId": session_id, "sessionEpoch": "1" });
    let bytes = b"a file the page handed over".to_vec();

    // The file reaches the host through the companion's own upload, on its own connection and the
    // environment's attachment-chunk endpoint; what follows are the commands the page calls.
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let path = directory.path().join("notes.txt");
    std::fs::write(&path, &bytes).expect("the file is written");
    let session = host
        .app
        .state::<companion_tauri::AppState>()
        .session()
        .expect("the application's connection");
    let target = kr_protocol::envelope::ActionTarget {
        environment_id: host.tree.environment_id(),
        session_id: kr_protocol::scalars::Nullable::some(
            session_id.parse().expect("a session identifier"),
        ),
        session_epoch: kr_protocol::scalars::Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: kr_protocol::scalars::Nullable::null(),
        agent_binding_revision: kr_protocol::scalars::Nullable::null(),
    };
    let handle = companion_tauri::transfers::upload_to(
        &session,
        &host.tree.environment(),
        target,
        Some(session_id.parse().expect("a session identifier")),
        path,
    )
    .await
    .expect("the file is uploaded");

    let made = host
        .call(
            "draft_create",
            json!({
                "params": {
                    "environment_id": host.environment_id(),
                    "device_id": null,
                    "session_id": session_id,
                    "application_instance_id": null,
                    "text": ""
                },
                "subject": subject
            }),
        )
        .await
        .expect("the host makes the draft");
    let draft_id = made["value"]["draft"]["draft_id"]
        .as_str()
        .expect("the draft's identifier");
    // The page names this text in the next call, so it has to be an identifier as the protocol
    // writes one.
    draft_id
        .parse::<kr_protocol::ids::DraftId>()
        .unwrap_or_else(|error| panic!("{draft_id:?} is not a draft identifier: {error}"));
    let revision = made["value"]["draft"]["revision"]
        .as_str()
        .expect("the draft's revision, as a decimal string");

    let bound = host
        .call(
            "draft_add_attachment",
            json!({
                "params": {
                    "draft_id": draft_id,
                    "expected_revision": revision,
                    "transfer_id": handle.transfer_id.to_string(),
                    "contribution": {
                        "operation_id": "attach",
                        "accepted_media_types": [handle.declared_media_type],
                        "max_byte_len": handle.byte_len.get().to_string(),
                        "max_count": "8",
                        "insertion_method": "manual_terminal_workflow",
                        "external_destination": null,
                        "model_media_capability": false
                    }
                },
                "subject": subject
            }),
        )
        .await
        .expect("the host binds the file");
    // The draft after the binding is the one that was made, one revision on: the page reads both.
    assert_eq!(bound["value"]["draft"]["draft_id"], json!(draft_id));
    assert_eq!(bound["value"]["draft"]["revision"], "2");
    let grant = &bound["value"]["attachment"]["read_grant"];
    assert_eq!(
        grant["transfer_id"],
        json!(handle.transfer_id.to_string()),
        "the grant names the file that was bound"
    );
    assert_eq!(grant["insertion_method"], "manual_terminal_workflow");
    assert!(
        grant["expires_at_ms"]
            .as_str()
            .and_then(|at| at.parse::<u64>().ok())
            .is_some_and(|at| at > kr_ipc::now_ms().get()),
        "the grant has time to run: {grant}"
    );
    let path = grant["host_path"].as_str().expect("the path to read it at");
    assert_eq!(
        std::fs::read(path).expect("the file is at the path the person is shown"),
        bytes
    );
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
