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
use kr_ipc::testing::started_environment::StartedEnvironment;
use kr_ipc::verify::ControllerIdentity;
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
/// On Windows the bundle is served from `http://tauri.localhost`; a call from the address the other
/// platforms use is a call from a remote origin, which the capabilities do not grant.
#[cfg(windows)]
const BUNDLE: &str = "http://tauri.localhost";
#[cfg(not(windows))]
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

/// Whether the application is given a connection to the daemon when the test starts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    /// One, as the command line makes it: the commands the page calls have a host to ask.
    Made,
    /// None: the application holds no connection until the test connects it, and a test that is
    /// about how a connection is made, or refused, starts here.
    Unmade,
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
        Self::start_with(None, Workers::None, Link::Made).await
    }

    /// Starts the daemon as `start` does, and an application that holds no connection to it.
    async fn start_unconnected() -> Self {
        Self::start_with(None, Workers::None, Link::Unmade).await
    }

    /// Starts the daemon as `start` does, and lets it start the workers of the sessions it creates.
    async fn start_creating_sessions() -> Self {
        Self::start_with(None, Workers::Live, Link::Made).await
    }

    /// Starts the daemon as `start` does, with its description host choosing from `catalogue` when
    /// one is given, and told that nothing stands in the way of a model: the memory is free and
    /// the power is the mains'.
    async fn start_describing(catalogue: Option<kr_describe::testing::TestCatalogue>) -> Self {
        Self::start_with(catalogue, Workers::None, Link::Made).await
    }

    async fn start_with(
        catalogue: Option<kr_describe::testing::TestCatalogue>,
        workers: Workers,
        link: Link,
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
        if workers == Workers::Live {
            // This host creates its sessions headless, whatever machine the test runs on, so the
            // worker of a session a case creates is the one the disclosed checks are performed in.
            let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
            document.revision = 1;
            document.preferences.worker_profile = kr_protocol::scalars::Nullable::some(
                kr_protocol::identity::WorkerProfile::HeadlessUser,
            );
            let path = kr_protocol::hostinfo::configuration::document_path(
                environment.state_dir(),
                environment.state_root(),
                environment.environment_id(),
            );
            std::fs::create_dir_all(path.parent().expect("the document's directory"))
                .expect("the state directory");
            kr_ipc::paths::write_owner_only_file(
                &path,
                kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
            )
            .expect("the configuration document");
        }
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
        // Its sessions run a login shell: they are given a home inside the tree, not the person's.
        controller.set_host_environment(StartedEnvironment::within(tree.root()).host_variables());
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
                companion_tauri::commands::connection_state,
                companion_tauri::commands::attention_read,
                companion_tauri::commands::attention_acknowledge,
                companion_tauri::commands::review_read,
                companion_tauri::commands::review_acknowledge,
                companion_tauri::commands::changeset_read,
                companion_tauri::commands::device_list,
                companion_tauri::commands::privacy_status,
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
                companion_tauri::commands::environment_capabilities,
                companion_tauri::commands::environment_capabilities_check,
                companion_tauri::commands::held_authorised_file,
                companion_tauri::commands::launch_commands_list,
                companion_tauri::commands::launch_commands_save,
                companion_tauri::commands::launch_commands_remove,
                companion_tauri::commands::question_kept,
                companion_tauri::commands::question_settle,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        companion_tauri::contact::serve(app.handle());
        if link == Link::Made {
            let transport = IpcTransport::connect(&endpoint, build_id)
                .await
                .expect("connects to the control endpoint");
            app.state::<companion_tauri::AppState>().connected(
                companion_tauri::connection::Connection::over(transport).expect("a connection"),
            );
        }
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

    /// The endpoint the daemon's clients connect to.
    fn endpoint(&self) -> kr_ipc::paths::Endpoint {
        self.tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint")
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

/// The result an `attention_read` answer carries under the owner's key.
fn inbox_of(reply: Value) -> Value {
    assert!(
        reply.get("key").is_some(),
        "an answer carries its key: {reply}"
    );
    reply["result"].clone()
}

/// Reads an answer back into the method's own result type, which is what says the page was given a
/// shape the protocol defines.
fn typed<T: serde::de::DeserializeOwned>(answer: Value) -> T {
    serde_json::from_value(answer).expect("the answer is the method's own result")
}

/// Waits until `found` gives a value, or the watchdog runs out.
async fn eventually<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
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
    let inbox: kr_protocol::attention::AttentionReadResult = typed(inbox_of(
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
    ));
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

/// KR-REQ-13.01: a read over a connection with no host in use answers a key that names no host, at
/// epoch 0, over the connection the application's state names, and writes no contact: there is no
/// record of a host to write it to.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_over_a_connection_with_no_host_in_use_has_a_null_host_key_and_writes_no_contact() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let revision = state.contact_owner().revision();
    let answer = host
        .call(
            "attention_read",
            json!({ "params": {
                "session_id": null,
                "include_acknowledged": false,
                "max_items": "50",
                "after": null
            } }),
        )
        .await
        .expect("the inbox");
    assert!(answer["key"]["host"].is_null(), "{answer}");
    assert_eq!(answer["key"]["epoch"], 0, "{answer}");
    let told = serde_json::to_value(state.connection_state()).expect("a state");
    assert_eq!(answer["key"]["link"], told["link"], "{answer} under {told}");
    assert_eq!(
        state.contact_owner().revision(),
        revision,
        "a read with no host in use makes no event"
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

/// KR-REQ-20.13: settings sync asks the host this computer is connected to which devices it lists,
/// with the parameters the host reads and the shape the host answers, so that a device it lists
/// can be given the key of the shared settings. A host nothing is paired with lists none.
#[tokio::test(flavor = "multi_thread")]
async fn the_connected_host_is_asked_which_devices_it_lists() {
    use companion_tauri::settings::Hosts as _;

    let host = Host::start().await;
    let hosts =
        companion_tauri::settings::connected::ConnectedHosts::new(host.app.handle().clone());
    let asked = hosts.device_lists().await;
    assert!(
        !asked.silent,
        "every host this computer owns answered: {asked:?}"
    );
    assert_eq!(asked.lists.len(), 1, "the host answered once: {asked:?}");
    assert!(
        asked.lists[0].devices.is_empty(),
        "nothing is paired with a new host: {asked:?}"
    );
}

/// KR-REQ-24.29: the page reads what privacy mode reports from the host: whether it is on and the
/// copies that have left the host, which it shows and does not erase. A new host has sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn what_privacy_mode_reports_is_read_from_the_host() {
    let host = Host::start().await;
    let report: kr_protocol::privacy::PrivacyReport = typed(
        host.call("privacy_status", json!({ "params": {} }))
            .await
            .expect("the report"),
    );
    assert!(!report.enabled);
    assert!(report.exported.is_empty(), "{report:?}");
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
    let leave = kr_client::answers::Leave {
        answers: writers.permit(&WRITTEN).expect("the leave to write"),
        sends: writers
            .permit(&kr_client::sends::WRITTEN)
            .expect("the leave to write"),
    };
    // Kept the way an earlier run left it, with no send recorded beside it.
    let basis = store.basis(question_id).expect("the pair reads");
    let sent = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let digest = store
        .begin(&draft, &basis, &[], sent, &leave)
        .expect("kept");
    store
        .settle(question_id, digest, &[sent], false, &leave)
        .expect("the record goes");

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

/// Ends the task that keeps a connection to the host, when it is dropped: another choice of host
/// ends the task of the choice before it, so nothing tries a removed daemon's endpoint afterwards.
struct EndsTheKeeper<'a>(tauri::State<'a, companion_tauri::AppState>);

impl Drop for EndsTheKeeper<'_> {
    fn drop(&mut self) {
        let _ = self.0.choose_host("a case is over", || {
            Ok(companion_tauri::state::Started {
                target: companion_tauri::contact::Target::Local,
                spawn: Box::new(|_| tauri::async_runtime::spawn(async {})),
            })
        });
    }
}

/// KR-REQ-23.22: a host that does not answer at first is reached when it does, and a
/// connection that ends is taken up again, as a new connection, after a pause that grows. The
/// application's state says "not connected" while there is none, and says "connected" again once
/// the host answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_to_the_host_is_taken_up_again_when_it_ends() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use companion_tauri::connection::{Attempt, connect_local_at, reach_host_on_this_machine};

    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    // However the case ends, the task that keeps the connection ends with it.
    let _ends = EndsTheKeeper(host.app.state::<companion_tauri::AppState>());
    let endpoint = host.endpoint();
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    // The application's own entry for reaching the host on its machine, with this daemon's endpoint
    // in place of the user's, and the application's own way of connecting to it.
    reach_host_on_this_machine(host.app.handle(), move || {
        let endpoint = endpoint.clone();
        let attempts = Arc::clone(&counted);
        async move {
            // The host does not answer the first two times.
            if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                return Attempt::Failed(companion_tauri::connection::Unopened::Unreached(
                    companion_tauri::CommandError::unavailable("the host did not answer"),
                ));
            }
            match connect_local_at(&endpoint).await {
                Ok(connection) => Attempt::Reached(connection),
                Err(error) => Attempt::Failed(error),
            }
        }
    })
    .expect("the choice of the host is made");
    assert!(
        !state.connection_state().connected,
        "nothing is connected before the host has answered"
    );

    let first = eventually("the host is reached after it did not answer", || {
        state
            .session()
            .ok()
            .filter(|_| attempts.load(Ordering::SeqCst) >= 3)
    })
    .await;
    assert!(state.connection_state().connected);

    // The connection ends, as a host that went away ends it.
    first.close();
    eventually("the application says the connection ended", || {
        (!state.connection_state().connected).then_some(())
    })
    .await;
    let second = eventually(
        "the host is reached again, on a connection of its own",
        || {
            state
                .session()
                .ok()
                .filter(|session| !Arc::ptr_eq(session, &first))
        },
    )
    .await;
    assert!(state.connection_state().connected);
    // The new connection works: the host answers a read on it.
    let read: kr_protocol::hostinfo::HostInfoResult = second
        .read(kr_protocol::method::Method::HostInfo, &json!({}))
        .await
        .expect("the host answers on the new connection");
    assert_eq!(read.environment_id.to_string(), host.environment_id());
}

/// What a stand-in host answers a hello with.
#[derive(Clone, Copy)]
enum Hello {
    /// A refusal, as a host that does not admit the caller answers.
    Refused,
    /// An acknowledgement that selects a protocol major this build does not speak.
    OtherMajor,
}

/// The words of the refusal a stand-in host gives, as the host says them.
const REFUSAL: &str = "this stand-in host admits no caller";

/// A listener that answers every hello it is sent as `answer` says, and nothing else.
struct StandIn {
    hellos: Arc<std::sync::atomic::AtomicUsize>,
    serving: tokio::task::JoinHandle<()>,
}

impl StandIn {
    /// Listens at `endpoint`, which no other listener holds, and gives each caller an answer that
    /// states `environment_id` where it states one.
    fn bind(
        endpoint: &kr_ipc::paths::Endpoint,
        environment_id: kr_protocol::ids::EnvironmentId,
        answer: Hello,
    ) -> Self {
        let listener = Listener::bind(endpoint).expect("binds the stand-in endpoint");
        let hellos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&hellos);
        let serving = tokio::spawn(async move {
            while let Ok((connection, peer)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    let Ok(kr_protocol::envelope::ControlFrame::Hello(_)) = reader
                        .read_message::<kr_protocol::envelope::ControlFrame>()
                        .await
                    else {
                        return;
                    };
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let reply = match answer {
                        Hello::Refused => kr_protocol::envelope::ControlFrame::Response(
                            kr_protocol::envelope::Response {
                                request_id: kr_protocol::ids::RequestId::new(0),
                                outcome: kr_protocol::envelope::Outcome::Error(
                                    kr_protocol::error::ProtocolError::new(
                                        kr_protocol::error::ErrorCode::PermissionDenied,
                                        REFUSAL,
                                    ),
                                ),
                            },
                        ),
                        Hello::OtherMajor => kr_protocol::envelope::ControlFrame::HelloAck(
                            Box::new(other_major_acknowledgement(environment_id, peer)),
                        ),
                    };
                    let _ = writer.write_message(&reply).await;
                    // Held open until the caller has read the answer and gone.
                    let _ = reader
                        .read_message::<kr_protocol::envelope::ControlFrame>()
                        .await;
                });
            }
        });
        Self { hellos, serving }
    }

    /// How many hellos this stand-in has answered.
    fn hellos(&self) -> usize {
        self.hellos.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// The acknowledgement of a host whose protocol major is not this build's.
fn other_major_acknowledgement(
    environment_id: kr_protocol::ids::EnvironmentId,
    peer: kr_ipc::peer::PeerIdentity,
) -> kr_protocol::local::LocalHelloAck {
    use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ProtocolVersion, ReceiveLimits};
    use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
    use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
    use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64};

    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    LocalHelloAck {
        selected_version: ProtocolVersion::new(PROTOCOL_VERSION.major + 1, 0),
        role: LocalRole::Controller,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        peer: LocalPeer {
            uid: U64::new(u64::from(peer.uid)),
            gid: U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: ActionWindow {
            action_window_id: ActionWindowId::new("window-1").expect("a literal window identifier"),
            connection_id,
            boot_epoch: BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(0),
            valid_for_ms: DurationMs::new(60_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: ReceiveLimits::default(),
        build: None,
    }
}

/// KR-REQ-23.22: the application connects to the host at the endpoint it is given, as it connects
/// to the host on its machine, and the state it tells the page is the one the command reports. The
/// application starts with no connection, the connection is made, and a second one is opened from
/// it at the same endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn the_application_connects_to_the_host_at_the_endpoint_it_is_given() {
    use companion_tauri::connection::connect_local_at;

    let host = Host::start_unconnected().await;
    let before = host
        .call("connection_state", json!({}))
        .await
        .expect("the state is read");
    assert_eq!(before["connected"], json!(false), "{before}");
    assert!(before["environment_id"].is_null(), "{before}");
    assert!(before["reason"].is_string(), "{before}");

    let connection = connect_local_at(&host.endpoint())
        .await
        .expect("the host at the endpoint is reached");
    host.app
        .state::<companion_tauri::AppState>()
        .connected(connection.clone());
    let after = host
        .call("connection_state", json!({}))
        .await
        .expect("the state is read");
    assert_eq!(after["connected"], json!(true), "{after}");
    assert_eq!(after["environment_id"], json!(host.environment_id()));
    assert_eq!(after["paired"], json!(false), "{after}");

    let another = connection
        .another()
        .await
        .expect("another connection is opened at the same endpoint");
    assert!(!Arc::ptr_eq(&connection.session(), &another.session()));
    assert_eq!(another.environment_id(), connection.environment_id());
    let read: kr_protocol::hostinfo::HostInfoResult = another
        .session()
        .read(kr_protocol::method::Method::HostInfo, &json!({}))
        .await
        .expect("the host answers on the second connection");
    assert_eq!(read.environment_id.to_string(), host.environment_id());
}

/// KR-REQ-23.22: a host that refuses the hello is the failure the application is given as the
/// refusal of the connection, and one that states a protocol major this build does not speak is the
/// failure that says no major is shared. Neither leaves the application holding a connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_refuses_the_hello_or_speaks_another_major_is_not_connected_to() {
    use companion_tauri::connection::connect_local_at;

    let host = Host::start_unconnected().await;
    for answer in [Hello::Refused, Hello::OtherMajor] {
        let tree = kr_ipc::testing::TempHost::create();
        let endpoint = tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let stand_in = StandIn::bind(&endpoint, tree.environment_id(), answer);
        let failure = connect_local_at(&endpoint)
            .await
            .expect_err("a host that does not admit the application is not connected to")
            .into_error();
        assert_eq!(stand_in.hellos(), 1, "the stand-in was the host reached");
        let told = match answer {
            Hello::Refused => "the host refused the connection",
            Hello::OtherMajor => "no shared protocol major",
        };
        assert!(failure.message.contains(told), "{failure:?}");
    }
    let state = host
        .call("connection_state", json!({}))
        .await
        .expect("the state is read");
    assert_eq!(state["connected"], json!(false), "{state}");
}

/// KR-REQ-23.22: a connection opened at an endpoint is opened again at that endpoint, and says what
/// it found there: no host once the daemon has gone, and the refusal of the connection when
/// something else answers in its place.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_opened_at_an_endpoint_says_what_it_finds_there_when_opened_again() {
    use companion_tauri::connection::connect_local_at;

    let mut host = Host::start_unconnected().await;
    let endpoint = host.endpoint();
    let connection = connect_local_at(&endpoint)
        .await
        .expect("the host at the endpoint is reached");

    // The daemon stops answering new callers, and its listener, which the task held, goes with it.
    host.clients.abort();
    let _ = (&mut host.clients).await;
    let gone = connection
        .another()
        .await
        .expect_err("no connection is opened to a host that has gone")
        .into_error();
    assert!(gone.message.contains("no host on this machine"), "{gone:?}");

    let stand_in = StandIn::bind(&endpoint, host.tree.environment_id(), Hello::Refused);
    let refused = connection
        .another()
        .await
        .expect_err("no connection is opened to a host that refuses the hello")
        .into_error();
    assert_eq!(stand_in.hellos(), 1);
    assert!(
        refused.message.contains("the host refused the connection"),
        "{refused:?}"
    );
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

/// KR-REQ-10.01 and KR-REQ-03.29: the setup assistant asks for the disclosed checks through one
/// command, naming the environment and no file. A parameter map with a file in it is refused before
/// anything is sent, so the page cannot make the host read a path it chose. Asked as the page asks,
/// on a host with no session to run them in, the host starts nothing and says why, and the next
/// read of the capabilities says the same.
#[tokio::test(flavor = "multi_thread")]
async fn the_disclosed_checks_are_asked_for_by_environment_alone() {
    use kr_protocol::desktop::{
        CapabilityChecks, CapabilityChecksFailure, CapabilityChecksState,
        EnvironmentCapabilitiesResult,
    };

    let host = Host::start().await;
    let environment = host.environment_id();
    let refusal = host
        .call(
            "environment_capabilities_check",
            json!({
                "params": { "environment_id": environment, "authorised_file": "/etc/hosts" },
                "subject": {}
            }),
        )
        .await
        .expect_err("a file the page named");
    assert!(
        !refused_by_the_host(&refusal),
        "refused before it was sent: {refusal}"
    );

    let asked: CapabilityChecks = typed(settled_value(
        host.call(
            "environment_capabilities_check",
            json!({ "params": { "environment_id": environment }, "subject": {} }),
        )
        .await
        .expect("the checks are asked for"),
    ));
    assert_eq!(asked.state, CapabilityChecksState::Failed, "{asked:?}");
    assert_eq!(
        asked.failure.as_ref(),
        Some(&CapabilityChecksFailure::NoSession),
        "{asked:?}"
    );
    let shown: EnvironmentCapabilitiesResult = typed(
        host.call(
            "environment_capabilities",
            json!({ "params": { "environment_id": environment } }),
        )
        .await
        .expect("the capabilities"),
    );
    assert_eq!(shown.checks.state, CapabilityChecksState::Failed);
}

/// Asks for the disclosed checks as the page does: the environment and nothing else.
async fn ask_for_the_checks(host: &Host) -> Result<Value, Value> {
    host.call(
        "environment_capabilities_check",
        json!({ "params": { "environment_id": host.environment_id() }, "subject": {} }),
    )
    .await
}

/// Reads the capabilities as the page does until the disclosed checks have finished a run that
/// began after `after`, and returns what the host then held.
async fn capabilities_after_a_run_began_after(
    host: &Host,
    after: Option<kr_protocol::scalars::TimestampMs>,
) -> kr_protocol::desktop::EnvironmentCapabilitiesResult {
    use kr_protocol::desktop::{CapabilityChecksState, EnvironmentCapabilitiesResult};

    let deadline = tokio::time::Instant::now() + WORKER_START;
    loop {
        let shown: EnvironmentCapabilitiesResult = typed(
            host.call(
                "environment_capabilities",
                json!({ "params": { "environment_id": host.environment_id() } }),
            )
            .await
            .expect("the capabilities"),
        );
        let began = shown.checks.started_at_ms.as_ref().copied();
        if shown.checks.state == CapabilityChecksState::Current && began > after {
            return shown;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no run began after {after:?} and finished: {:?}",
            shown.checks
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// KR-REQ-03.29 and KR-REQ-03.02: the file the person chose in the platform's file dialog is the
/// file the read check reads, in the worker of a real session, and one choice serves one run. The
/// page names the environment and nothing else, as it always did; the chosen path is held in the
/// application and travels to the host with that one request. A run asked for with no choice held
/// reads nothing and says so, which is the host's own answer for no nominated file.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_chosen_in_the_dialog_is_read_by_one_run_of_the_checks() {
    use kr_protocol::desktop::{CapabilityState, EnvironmentCapabilitiesResult, capabilities};

    let host = Host::start_creating_sessions().await;
    let session_id = create_a_session_for_the_checks(&host).await;

    let chosen = host.tree.root().join("chosen.txt");
    std::fs::write(&chosen, b"the person chose this file").expect("the file the person chose");
    let state = host.app.state::<companion_tauri::AppState>();
    state.hold_authorised_file(chosen.clone());

    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for");
    let first: EnvironmentCapabilitiesResult =
        capabilities_after_a_run_began_after(&host, None).await;
    let read = first
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_eq!(
        read.state,
        CapabilityState::QualifiedAvailable,
        "the worker read the chosen file: {read:?}"
    );
    assert!(
        read.disabled_reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().contains("26 bytes")),
        "the worker read what the chosen file held: {:?}",
        read.disabled_reason
    );
    assert!(
        state.held_authorised_file().path.is_none(),
        "the run that read the file used the choice up"
    );

    // The same file is still there, and nothing is held: the next run reads nothing.
    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for again");
    let second =
        capabilities_after_a_run_began_after(&host, first.checks.started_at_ms.as_ref().copied())
            .await;
    let read = second
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_ne!(
        read.state,
        CapabilityState::QualifiedAvailable,
        "a file nobody chose this time was not read: {read:?}"
    );

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

/// Creates a session whose worker the disclosed checks are performed in, and returns its identifier.
async fn create_a_session_for_the_checks(host: &Host) -> String {
    let work = host.tree.root().join("w");
    std::fs::create_dir(&work).expect("a directory on the internal disk");
    let created = host
        .call_within(
            "session_create",
            creation(
                host,
                "native_compat",
                json!("/bin/sh"),
                &work.display().to_string(),
            ),
            WORKER_START,
        )
        .await
        .expect("the host creates the session a run of the checks needs");
    created["value"]["session"]["session_id"]
        .as_str()
        .expect("the new session's identifier")
        .to_owned()
}

/// A worker that is stopped until this goes: it answers nothing, so a run of the checks that was
/// given to it stays running.
struct StoppedWorker(u32);

impl StoppedWorker {
    /// Stops the one worker the host's only session has, found by its descriptor.
    fn of(host: &Host) -> Self {
        let descriptor = kr_ipc::descriptor::read_all(&host.tree.environment())
            .expect("the session descriptors")
            .into_iter()
            .find_map(|entry| entry.descriptor.ok())
            .expect("the session's descriptor");
        let pid =
            u32::try_from(descriptor.process_start_identity.pid.get()).expect("a process number");
        assert!(signal(pid, "-STOP"), "the worker is stopped");
        Self(pid)
    }
}

impl Drop for StoppedWorker {
    fn drop(&mut self) {
        signal(self.0, "-CONT");
    }
}

/// Sends `signal` to a process this test's host started, and says whether it was sent.
fn signal(pid: u32, signal: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .is_ok_and(|status| status.success())
}

/// KR-REQ-03.29: a run of the checks that is going already takes no file from the page. The host
/// answers a request for a run that is going with that run and drops the file the request carried,
/// so a request that took the file would use the choice up and have nothing read; the request is
/// refused instead, with the file still held, and it reads the file once the run has ended. With no
/// file held the request is answered with the run that is going, which the page follows.
#[tokio::test(flavor = "multi_thread")]
async fn a_run_that_is_going_already_takes_no_file_and_the_file_stays_held() {
    use kr_protocol::desktop::{CapabilityChecks, CapabilityChecksState};

    let host = Host::start_creating_sessions().await;
    let session_id = create_a_session_for_the_checks(&host).await;
    let state = host.app.state::<companion_tauri::AppState>();
    let chosen = host.tree.root().join("chosen.txt");
    std::fs::write(&chosen, b"the person chose this file").expect("the file the person chose");

    let stopped = StoppedWorker::of(&host);
    let going: CapabilityChecks = typed(settled_value(
        ask_for_the_checks(&host)
            .await
            .expect("the checks are asked for with no file held"),
    ));
    assert_eq!(going.state, CapabilityChecksState::Running, "{going:?}");

    // The control: with no file held there is nothing to lose, and the run that is going answers.
    let again: CapabilityChecks = typed(settled_value(
        ask_for_the_checks(&host)
            .await
            .expect("the run that is going is answered"),
    ));
    assert_eq!(again.state, CapabilityChecksState::Running, "{again:?}");

    state.hold_authorised_file(chosen.clone());
    let refusal = ask_for_the_checks(&host)
        .await
        .expect_err("a file for a run that is going");
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already going"),
        "{refusal}"
    );
    assert_eq!(
        state.held_authorised_file().path,
        Some(chosen),
        "the refused request left the file held"
    );

    drop(stopped);
    capabilities_after_a_run_began_after(&host, None).await;
    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for once the run has ended");
    assert!(
        state.held_authorised_file().path.is_none(),
        "the run that followed took the file"
    );
    capabilities_after_a_run_began_after(&host, going.started_at_ms.as_ref().copied()).await;

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

/// What the page is told of the file this process holds for the next run of the checks: its name,
/// or none, and whether the dialog that may replace it is open.
async fn held_file_as_told(host: &Host) -> Value {
    host.call("held_authorised_file", json!({}))
        .await
        .expect("the held file is read")
}

/// KR-REQ-03.29: the page can read which chosen file this process holds, so that what it says of
/// the choice is what is held, whatever the page did before: it was reloaded, or it was told that a
/// request was refused before the request took the choice. The answer is the file's name and no
/// path, reading changes nothing, and only the run that takes the file uses the choice up.
#[tokio::test(flavor = "multi_thread")]
async fn the_page_reads_which_chosen_file_is_held() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    assert_eq!(
        held_file_as_told(&host).await,
        json!({ "dialog_open": false, "file": null }),
        "none chosen"
    );

    let chosen = host.tree.root().join("chosen.txt");
    state.hold_authorised_file(chosen.clone());
    let told = held_file_as_told(&host).await;
    assert_eq!(
        told,
        json!({ "dialog_open": false, "file": { "name": "chosen.txt" } }),
        "the name and no path"
    );
    assert_eq!(
        held_file_as_told(&host).await,
        told,
        "reading the held file leaves it held"
    );

    // A request refused before it took the choice (a field the page may not send) leaves the file
    // held, and the page is told that it still is.
    let refusal = host
        .call(
            "environment_capabilities_check",
            json!({
                "params": {
                    "environment_id": host.environment_id(),
                    "authorised_file": "/etc/hosts"
                },
                "subject": {}
            }),
        )
        .await
        .expect_err("a file the page named");
    assert!(
        !refused_by_the_host(&refusal),
        "refused before it was sent: {refusal}"
    );
    assert_eq!(
        held_file_as_told(&host).await,
        told,
        "a request refused before it took the choice leaves the choice held"
    );

    // The run that takes the file uses it up, whatever the host then answers: this host has no
    // session, so it starts nothing and says why.
    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for");
    assert_eq!(
        held_file_as_told(&host).await,
        json!({ "dialog_open": false, "file": null }),
        "the run that took the file used the choice up"
    );
}

/// Runs `during` while the file dialog is open, as it is where a person has pressed the button and
/// not yet answered, then has the dialog answer `answer`, and gives what the command that opened it
/// came to and what `during` came to. The platform's dialog opens only for a person, so the dialog is
/// a future the case answers. The host's application gives the file the dialog chose to
/// [`companion_tauri::commands::choose_file_in`] as the command does.
async fn while_the_file_dialog_is_open<T>(
    host: &Host,
    answer: Result<Option<PathBuf>, companion_tauri::error::CommandError>,
    during: impl std::future::Future<Output = T>,
) -> (
    Result<Option<companion_tauri::commands::ChosenFile>, companion_tauri::error::CommandError>,
    T,
) {
    let state = host.app.state::<companion_tauri::AppState>();
    let (sender, answered) = tokio::sync::oneshot::channel();
    let (opened, is_open) = tokio::sync::oneshot::channel();
    let choosing =
        companion_tauri::commands::choose_file_in(host.app.handle(), state.inner(), async {
            // The command asks the platform's dialog once it has marked the dialog open.
            opened.send(()).expect("the case awaits the dialog");
            answered.await.expect("the dialog is answered")
        });
    let meanwhile = async {
        is_open.await.expect("the dialog was asked");
        let done = during.await;
        sender.send(answer).expect("the command awaits the dialog");
        done
    };
    tokio::join!(choosing, meanwhile)
}

/// KR-REQ-03.29: a screen that reads which chosen file the application holds while the platform's
/// file dialog is open, which is a screen opened again after the person left the one that asked
/// where the platform's dialog does not keep the window waiting, is told that the dialog is open: the
/// answer of the dialog may replace what is held, so what is held is not what the next run reads.
/// Once the dialog has answered, the screen is told the file.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_that_reads_while_the_file_dialog_is_open_is_told_that_it_is_open() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    state.hold_authorised_file(host.tree.root().join("earlier.txt"));
    let chosen = host.tree.root().join("chosen.txt");
    let (choice, during) =
        while_the_file_dialog_is_open(&host, Ok(Some(chosen)), held_file_as_told(&host)).await;
    assert_eq!(
        during["dialog_open"],
        json!(true),
        "told while the dialog is open: {during}"
    );
    assert_eq!(
        choice.expect("the dialog answered").map(|file| file.name),
        Some("chosen.txt".to_owned())
    );
    assert_eq!(
        held_file_as_told(&host).await,
        json!({ "dialog_open": false, "file": { "name": "chosen.txt" } }),
        "the file the dialog chose replaced the earlier one and the dialog is closed"
    );
}

/// KR-REQ-03.29: no run takes the chosen file while the platform's file dialog is open, and the
/// request is refused with the file still held, so that a screen that was not the one that opened the
/// dialog cannot start a run that reads a file the person is about to replace.
#[tokio::test(flavor = "multi_thread")]
async fn the_checks_are_refused_while_the_file_dialog_is_open_and_the_file_stays_held() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let earlier = host.tree.root().join("earlier.txt");
    state.hold_authorised_file(earlier.clone());
    let (_, refusal) =
        while_the_file_dialog_is_open(&host, Ok(None), ask_for_the_checks(&host)).await;
    let refusal = refusal.expect_err("a run while the dialog is open");
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains("file dialog is still open"),
        "{refusal}"
    );
    assert_eq!(
        state.held_authorised_file().path,
        Some(earlier),
        "the refused request left the file held"
    );
}

/// KR-REQ-03.29: a second file dialog is refused while one is open, so that two answers never
/// compete for the one file held.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_file_dialog_is_refused_while_one_is_open() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let (_, second) = while_the_file_dialog_is_open(&host, Ok(None), async {
        companion_tauri::commands::choose_file_in(host.app.handle(), state.inner(), async {
            Ok(Some(host.tree.root().join("second.txt")))
        })
        .await
    })
    .await;
    let refusal = second.expect_err("a second dialog");
    assert!(refusal.to_string().contains("already open"), "{refusal}");
    assert_eq!(
        state.held_authorised_file().path,
        None,
        "the refused dialog held no file"
    );
}

/// KR-REQ-03.29: a dialog that is closed with no choice, or that fails, ends: what was held stays
/// held, and the dialog is not left open, which would refuse every run after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_dialog_closed_with_no_choice_or_failing_ends_and_leaves_the_file_held() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let earlier = host.tree.root().join("earlier.txt");
    state.hold_authorised_file(earlier.clone());
    for (answer, fails) in [
        (Ok(None), false),
        (
            Err(companion_tauri::error::CommandError::local_failure(
                "the file dialog did not answer",
            )),
            true,
        ),
    ] {
        let (choice, ()) = while_the_file_dialog_is_open(&host, answer, async {}).await;
        assert_eq!(choice.is_err(), fails);
        let held = state.held_authorised_file();
        assert!(!held.dialog_open, "the dialog was left open");
        assert_eq!(held.path, Some(earlier.clone()), "what was held changed");
    }
}

/// KR-REQ-03.29: a file dialog that is abandoned before it answers, because the command that opened
/// it is dropped, ends: no dialog is left open to refuse every run and every dialog after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_dialog_abandoned_before_it_answers_ends() {
    let host = Host::start().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let abandoned = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        companion_tauri::commands::choose_file_in(
            host.app.handle(),
            state.inner(),
            std::future::pending::<Result<Option<PathBuf>, companion_tauri::error::CommandError>>(),
        ),
    )
    .await;
    assert!(abandoned.is_err(), "the dialog answered by itself");
    assert!(
        !state.held_authorised_file().dialog_open,
        "the dialog was left open"
    );
}

/// Counts the times every screen is told that what the application holds for the read check
/// changed.
fn count_the_screens_told(host: &Host) -> Arc<std::sync::atomic::AtomicUsize> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tauri::Listener as _;

    let told = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&told);
    host.app
        .listen(companion_tauri::AUTHORISED_FILE_EVENT, move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
        });
    told
}

/// How many times the screens have been told once the count has reached `expected`, or after the
/// wait for it. Events reach a listener through the runtime, so each count waits for the one it
/// expects, and a moment more shows that nothing arrives for an event that was not sent.
async fn told_so_far(told: &Arc<std::sync::atomic::AtomicUsize>, expected: usize) -> usize {
    use std::sync::atomic::Ordering;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while told.load(Ordering::SeqCst) < expected && tokio::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    told.load(Ordering::SeqCst)
}

/// KR-REQ-03.29: a file dialog that is abandoned before it answers tells every screen that it ended,
/// as one that answers does: a screen that saw the dialog open stays blank and allows no run until
/// it reads again, and it reads again when it is told, and finds the dialog closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_dialog_abandoned_before_it_answers_tells_the_screens() {
    let host = Host::start().await;
    let told = count_the_screens_told(&host);
    let state = host.app.state::<companion_tauri::AppState>();
    let abandoned = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        companion_tauri::commands::choose_file_in(
            host.app.handle(),
            state.inner(),
            std::future::pending::<Result<Option<PathBuf>, companion_tauri::error::CommandError>>(),
        ),
    )
    .await;
    assert!(abandoned.is_err(), "the dialog answered by itself");
    assert_eq!(
        told_so_far(&told, 2).await,
        2,
        "the screens were told that the dialog opened and not that it ended"
    );
    assert_eq!(
        held_file_as_told(&host).await,
        json!({ "dialog_open": false, "file": null }),
        "a screen that reads when it is told finds the dialog closed"
    );
}

/// KR-REQ-03.29: every screen is told when what the application holds for the read check changes:
/// when the dialog opens, when it closes, and when a run takes the file, and told nothing when a
/// dialog is refused or a run takes no file. A screen that is told asks again.
#[tokio::test(flavor = "multi_thread")]
async fn the_screens_are_told_when_the_file_held_for_the_read_check_changes() {
    let host = Host::start().await;
    let told = count_the_screens_told(&host);

    let chosen = host.tree.root().join("chosen.txt");
    let (choice, ()) = while_the_file_dialog_is_open(&host, Ok(Some(chosen)), async {}).await;
    choice.expect("the dialog answered");
    assert_eq!(
        told_so_far(&told, 2).await,
        2,
        "the dialog opened and closed"
    );

    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for");
    assert_eq!(told_so_far(&told, 3).await, 3, "a run took the file");

    ask_for_the_checks(&host)
        .await
        .expect("the checks are asked for");
    assert_eq!(
        told_so_far(&told, 3).await,
        3,
        "a run that took no file told nobody"
    );

    let state = host.app.state::<companion_tauri::AppState>();
    let (choice, second) = while_the_file_dialog_is_open(&host, Ok(None), async {
        companion_tauri::commands::choose_file_in(host.app.handle(), state.inner(), async {
            Ok(None)
        })
        .await
    })
    .await;
    choice.expect("the dialog answered");
    second.expect_err("a second dialog while one is open");
    assert_eq!(
        told_so_far(&told, 5).await,
        5,
        "a refused dialog told nobody"
    );
}

/// KR-REQ-13.11: the launch commands are read, saved, replaced and removed through the three
/// application commands, as the page calls them and with the parameters it writes, against the
/// host's own store. A save or a remove that names a revision the list has left changes nothing and
/// is answered with the list as it stands; one that names the current revision lands, and the list
/// read back after each step is the one the host holds.
#[tokio::test(flavor = "multi_thread")]
async fn the_launch_commands_are_read_saved_and_removed_through_the_application_commands_on_a_local_host()
 {
    use kr_protocol::launch_commands::{
        ShellLaunchCommandsListResult, ShellLaunchCommandsRemoveResult,
        ShellLaunchCommandsSaveResult,
    };

    let host = Host::start().await;
    let list = || async {
        let read = host
            .call("launch_commands_list", json!({}))
            .await
            .expect("the list is read");
        assert_eq!(read["state"], "served", "{read}");
        typed::<ShellLaunchCommandsListResult>(read["list"].clone())
    };
    let save = |revision: &str, label: &str, arguments: Value| {
        host.call(
            "launch_commands_save",
            json!({
                "params": {
                    "expected_revision": revision,
                    "command": { "label": label, "program": "claude", "arguments": arguments },
                },
                "subject": {},
            }),
        )
    };

    let empty = list().await;
    assert!(empty.commands.is_empty(), "{empty:?}");
    assert_eq!(empty.revision.to_string(), "0", "{empty:?}");

    // A save against the revision the page read lands, and the list read back holds it.
    let first: ShellLaunchCommandsSaveResult = typed(settled_value(
        save("0", "Claude Code", json!(["--resume", "two words", ""]))
            .await
            .expect("the save is answered"),
    ));
    assert!(
        first.applied && first.changed && !first.replaced,
        "{first:?}"
    );
    assert_eq!(first.commands.len(), 1, "{first:?}");
    assert_eq!(first.commands[0].arguments, ["--resume", "two words", ""]);
    let held = list().await;
    assert_eq!(held.commands, first.commands);
    assert_eq!(held.revision, first.revision);
    assert_ne!(held.revision.to_string(), "0");

    // A save against the revision the list has left changes nothing: the host answers with the
    // list as it stands.
    let stale: ShellLaunchCommandsSaveResult = typed(settled_value(
        save("0", "Other", json!([]))
            .await
            .expect("the stale save is answered"),
    ));
    assert!(!stale.applied && !stale.changed, "{stale:?}");
    assert_eq!(stale.commands, held.commands, "{stale:?}");
    assert_eq!(list().await, held, "a stale save changed the list");

    // The same label replaces the command and keeps its place.
    let revision = held.revision.to_string();
    let replaced: ShellLaunchCommandsSaveResult = typed(settled_value(
        save(&revision, "claude code", json!(["--continue"]))
            .await
            .expect("the replacement is answered"),
    ));
    assert!(
        replaced.applied && replaced.changed && replaced.replaced,
        "{replaced:?}"
    );
    assert_eq!(replaced.commands.len(), 1, "{replaced:?}");
    assert_eq!(replaced.commands[0].label, "claude code");
    assert_eq!(replaced.commands[0].arguments, ["--continue"]);

    // A remove against the old revision changes nothing; against the current one it removes.
    let remove = |revision: &str, label: &str| {
        host.call(
            "launch_commands_remove",
            json!({
                "params": { "expected_revision": revision, "label": label },
                "subject": {},
            }),
        )
    };
    let old_remove: ShellLaunchCommandsRemoveResult = typed(settled_value(
        remove(&revision, "claude code")
            .await
            .expect("the stale remove is answered"),
    ));
    assert!(!old_remove.applied && !old_remove.removed, "{old_remove:?}");
    assert_eq!(old_remove.commands, replaced.commands, "{old_remove:?}");
    let removed: ShellLaunchCommandsRemoveResult = typed(settled_value(
        remove(&replaced.revision.to_string(), "Claude Code")
            .await
            .expect("the remove is answered"),
    ));
    assert!(removed.applied && removed.removed, "{removed:?}");
    assert!(removed.commands.is_empty(), "{removed:?}");
    let after = list().await;
    assert!(after.commands.is_empty(), "{after:?}");
    assert_ne!(
        after.revision.to_string(),
        "0",
        "an emptied list keeps a fresh revision"
    );
    assert_ne!(after.revision, replaced.revision);
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

/// The milliseconds since the epoch, as this computer's clock says.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_millis(),
    )
    .expect("a time that fits")
}

/// The application keeping its connection to the host at `endpoint`, with the application's own
/// way of connecting to it. The keeper ends with the value returned.
fn keeping_the_host_at(host: &Host, endpoint: kr_ipc::paths::Endpoint) -> EndsTheKeeper<'_> {
    use companion_tauri::connection::{Attempt, connect_local_at, reach_host_on_this_machine};

    reach_host_on_this_machine(host.app.handle(), move || {
        let endpoint = endpoint.clone();
        async move {
            match connect_local_at(&endpoint).await {
                Ok(connection) => Attempt::Reached(connection),
                Err(error) => Attempt::Failed(error),
            }
        }
    })
    .expect("the choice of the host is made");
    EndsTheKeeper(host.app.state::<companion_tauri::AppState>())
}

/// The state the application tells about its connection, once it satisfies `wanted`.
async fn state_where(host: &Host, wanted: impl Fn(&Value) -> bool) -> Value {
    eventually(
        "the application's state is the one the case waits for",
        || {
            let state = serde_json::to_value(
                host.app
                    .state::<companion_tauri::AppState>()
                    .connection_state(),
            )
            .expect("a state");
            wanted(&state).then_some(state)
        },
    )
    .await
}

/// An endpoint that nothing listens at, and the tree that keeps it.
fn an_endpoint_nobody_listens_at() -> (kr_ipc::testing::TempHost, kr_ipc::paths::Endpoint) {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    (tree, endpoint)
}

/// KR-REQ-23.22: a host on this machine that refuses the hello is a host that answered and refused,
/// and is told as that, not as a host out of contact.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_host_that_refuses_the_hello_reads_refused() {
    let host = Host::start_unconnected().await;
    let (tree, endpoint) = an_endpoint_nobody_listens_at();
    let _stand_in = StandIn::bind(&endpoint, tree.environment_id(), Hello::Refused);
    let _keeper = keeping_the_host_at(&host, endpoint);

    // The wait is for the refusal's words, which a refusal and a host not reached both leave; what
    // the host's answer reads as is asserted after it.
    let state = state_where(&host, |state| {
        state["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("the host refused the connection"))
    })
    .await;
    assert!(state["contact"].is_object(), "{state}");
    assert_eq!(state["contact"]["state"], "refused", "{state}");
    assert_eq!(state["contact"]["request"], "connection", "{state}");
    assert!(
        state["contact"]["refusal"]["message"]
            .as_str()
            .is_some_and(|words| words.contains("the host refused the connection")),
        "{state}"
    );
    assert_eq!(state["connected"], false, "{state}");
}

/// KR-REQ-23.22: a host on this machine that was never reached is not lost: it reads unknown, and
/// its reason is the one the application has always given.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_host_never_reached_reads_unknown_with_todays_reason() {
    let host = Host::start_unconnected().await;
    let (_tree, endpoint) = an_endpoint_nobody_listens_at();
    let _keeper = keeping_the_host_at(&host, endpoint);

    let state = state_where(&host, |state| {
        state["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no host on this machine"))
    })
    .await;
    assert!(state["contact"].is_object(), "{state}");
    assert_eq!(state["contact"]["state"], "unknown", "{state}");
    assert_eq!(state["connected"], false, "{state}");
}

/// KR-REQ-23.22: a refusal does not stay once the host is not there to refuse: the host on this
/// machine, never reached, reads unknown again.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_hello_then_an_absent_socket_reads_unknown() {
    let host = Host::start_unconnected().await;
    let (tree, endpoint) = an_endpoint_nobody_listens_at();
    let stand_in = StandIn::bind(&endpoint, tree.environment_id(), Hello::Refused);
    let _keeper = keeping_the_host_at(&host, endpoint);
    let refused = state_where(&host, |state| state["contact"]["state"] == "refused").await;
    assert_eq!(refused["contact"]["state"], "refused", "{refused}");

    drop(stand_in);
    let absent = state_where(&host, |state| {
        state["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no host on this machine"))
    })
    .await;
    assert_eq!(absent["contact"]["state"], "unknown", "{absent}");
}

/// KR-REQ-23.22: a refused hello is not a reach: a choice of another host and back does not make
/// the host on this machine one that was lost.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_hello_does_not_set_ever_reached() {
    let host = Host::start_unconnected().await;
    let (tree, endpoint) = an_endpoint_nobody_listens_at();
    let stand_in = StandIn::bind(&endpoint, tree.environment_id(), Hello::Refused);
    let keeper = keeping_the_host_at(&host, endpoint.clone());
    state_where(&host, |state| state["contact"]["state"] == "refused").await;
    drop(keeper);
    drop(stand_in);
    let _keeper = keeping_the_host_at(&host, endpoint);
    let state = state_where(&host, |state| {
        state["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no host on this machine"))
    })
    .await;
    assert_eq!(state["contact"]["state"], "unknown", "{state}");
}

/// KR-REQ-23.22: the host on this machine, reached and then gone, reads out of contact from the end
/// of the connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_host_reached_and_then_absent_reads_out_of_contact_from_the_end() {
    let host = Host::start_unconnected().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let _keeper = keeping_the_host_at(&host, host.endpoint());
    let first = eventually("the host is reached", || state.session().ok()).await;
    let before = now_ms();
    first.close();
    // The wait is for the connection to be told gone; what it reads as is asserted after it.
    let lost = state_where(&host, |state| state["connected"] == false).await;
    assert_eq!(lost["contact"]["state"], "out_of_contact", "{lost}");
    let since = lost["contact"]["since_ms"].as_u64().expect("a start");
    assert!(
        since >= before,
        "the loss starts when the connection ended: {lost}"
    );
    assert!(since <= now_ms(), "{lost}");
}

/// KR-REQ-23.22: reaching the host on this machine is told, as the choice and as the reach, each once
/// and in order, with the host on this machine as the host in use.
#[tokio::test(flavor = "multi_thread")]
async fn the_choice_of_the_host_on_this_machine_is_told_once_with_its_host() {
    let host = Host::start_unconnected().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let _keeper = keeping_the_host_at(&host, host.endpoint());
    state_where(&host, |state| state["connected"] == true).await;
    let replay = serde_json::to_value(state.contact_owner().since(0)).expect("the replay");
    let told: Vec<(u64, bool, Value)> = replay["states"]
        .as_array()
        .expect("states")
        .iter()
        .map(|each| {
            (
                each["revision"].as_u64().expect("a revision"),
                each["connected"].as_bool().expect("connected"),
                each["host"].clone(),
            )
        })
        .collect();
    assert_eq!(
        told.len(),
        2,
        "the choice and the reach, each once: {told:?}"
    );
    assert_eq!(
        (told[0].1, told[1].1),
        (false, true),
        "the choice, then the reach: {told:?}"
    );
    assert_eq!(told[1].0, told[0].0 + 1, "in order: {told:?}");
    for (_, _, shown) in &told {
        assert_eq!(shown["kind"], "local", "the host in use: {told:?}");
    }
}

/// KR-REQ-23.22: a host on this machine that was reached stays one that was reached across a choice
/// of another host: when it is gone after that, it is lost and not unknown.
#[tokio::test(flavor = "multi_thread")]
async fn ever_reached_survives_a_choice_of_another_host() {
    let host = Host::start_unconnected().await;
    let state = host.app.state::<companion_tauri::AppState>();
    let keeper = keeping_the_host_at(&host, host.endpoint());
    eventually("the host is reached", || state.session().ok()).await;
    drop(keeper);
    // Another host is chosen, and then the host on this machine is chosen again, at an endpoint
    // where nothing listens.
    let other = kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
    state
        .choose_host("another host", || {
            Ok(companion_tauri::state::Started {
                target: companion_tauri::contact::Target::Paired {
                    host: other,
                    pairing: other,
                    reference: "another".to_owned(),
                    name: "another host".to_owned(),
                },
                spawn: Box::new(|_| tauri::async_runtime::spawn(async {})),
            })
        })
        .expect("another host is chosen");
    let (_tree, absent) = an_endpoint_nobody_listens_at();
    let _keeper = keeping_the_host_at(&host, absent);
    let lost = state_where(&host, |state| {
        state["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no host on this machine"))
    })
    .await;
    assert_eq!(lost["contact"]["state"], "out_of_contact", "{lost}");
}
