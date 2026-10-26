//! A session's launch surface, read on a real worker the way the application reads it.
//!
//! The worker is the product's own: a session service over a real terminal, serving a real local
//! endpoint and publishing the descriptor the application finds it by. What is checked is what a
//! scripted worker cannot say: that the application's link takes from the worker's answer to the
//! hello whether it serves the read, so a worker that does not state it is never asked, and that
//! what the worker answers is the application's answer.

#![cfg(unix)]

mod question_page;

use std::sync::Arc;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::root::{LaunchEditor, LaunchInput, LaunchUnverified};
use kr_protocol::scalars::TimestampMs;
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};
use question_page::Page;
use tauri::Manager as _;

/// A worker serving one session, and the host tree it is published in.
struct Worker {
    temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    service: Arc<WorkerService>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Starts a worker for a session whose shell lasts as long as the session does.
async fn worker() -> Worker {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let journal = config.journal_path.clone().expect("the harness journals");
    if let Some(parent) = journal.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let mut session = TerminalSession::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal),
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            },
        )
        .expect("a worker service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));
    let descriptor = WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        boot_identity: boot,
        process_start_identity: process,
        protocol_version: PROTOCOL_VERSION,
        endpoint: endpoint.as_text(),
        worker_public_key: *identity.public_key(),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: TimestampMs::new(0),
    };
    kr_ipc::descriptor::publish(&environment, &descriptor).expect("publishes the descriptor");
    Worker {
        temp,
        session_id,
        service,
        serving,
    }
}

/// Reads the launch surface of the worker's session the way the application does.
async fn read(page: &Page, worker: &Worker) -> kr_client::LaunchSurfaceRead {
    let links = page.app.state::<companion_tauri::agent::WorkerLinks>();
    let state = page.app.state::<companion_tauri::AppState>();
    links
        .launch_surface(&state, worker.session_id, None)
        .await
        .expect("the launch surface is read")
}

/// KR-REQ-13.11: the application reads a session's launch surface on the session's own worker. A
/// session that runs a stock shell is shown instructions and not a button, and nobody holds its
/// input.
#[tokio::test(flavor = "multi_thread")]
async fn the_launch_surface_is_read_on_the_sessions_own_worker() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let kr_client::LaunchSurfaceRead::Served(surface) = read(&page, &worker).await else {
        panic!("the worker serves the read");
    };
    assert_eq!(surface.session_id, worker.session_id);
    assert_eq!(
        surface.editor,
        LaunchEditor::Unverified {
            reason: LaunchUnverified::StockShell
        }
    );
    assert_eq!(surface.input, LaunchInput::Free);
}

/// KR-REQ-13.11: a worker that does not state that it serves the launch surface is not asked for
/// it. A worker that does would have answered; the application says the host does not serve it.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_does_not_state_the_launch_surface_is_not_asked_for_it() {
    let worker = worker().await;
    worker
        .service
        .withhold_capability(kr_protocol::local::SHELL_LAUNCH_SURFACE_READ);
    let page = Page::new(worker.temp.environment());
    assert_eq!(
        read(&page, &worker).await,
        kr_client::LaunchSurfaceRead::NotServed
    );
}

/// KR-REQ-13.11: the command gives the page what the worker answered, tagged as the page reads it,
/// and tells the page that the host does not serve the read when the worker did not state it.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_gives_the_page_the_workers_answer_or_that_the_host_does_not_serve_it() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let told = question_page::answered(page.call(
        "launch_surface",
        serde_json::json!({ "params": { "session_id": worker.session_id } }),
    ))
    .await
    .expect("the surface is read");
    assert_eq!(told["state"], "served", "{told}");
    assert_eq!(told["surface"]["editor"]["reason"], "stock_shell", "{told}");
    assert_eq!(told["surface"]["input"], "free", "{told}");

    worker
        .service
        .withhold_capability(kr_protocol::local::SHELL_LAUNCH_SURFACE_READ);
    let silent = Page::new(worker.temp.environment());
    let told = question_page::answered(silent.call(
        "launch_surface",
        serde_json::json!({ "params": { "session_id": worker.session_id } }),
    ))
    .await
    .expect("an answer");
    assert_eq!(told, serde_json::json!({ "state": "not_served" }));
}
