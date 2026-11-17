//! The raw terminal view's native half, driven the way the page drives it.
//!
//! Each test opens a view through the invoke path, as the page does, and reads the states the view
//! publishes off its own channel. The view reaches a worker this test scripts, over a real local
//! endpoint in a disposable host tree on the internal disk, and that worker answers the view's
//! calls and pushes the protocol's own events. So what is checked is the whole of the native half:
//! the link, the challenge, the attachment, the projection the client library holds, the size
//! reports, the recovery and the shape the page is sent.

#![cfg(unix)]

mod scripted_worker;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentViewportParams, SessionDetachParams,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::input::{InputAcquireParams, InputReleaseParams, InputWriteParams};
use kr_protocol::method::Method;
use kr_protocol::projection::{
    PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, ProjectionResetReason,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::session::Dimensions;
use scripted_worker::host::{ScriptedHost, Takes};
use scripted_worker::{
    CallKind, Challenge, Frame, Keys, Link, Mouse, Negotiated, ScriptedWorker, Stated, WATCHDOG,
    WorkerLease, delta, frame, frame_delta, keys_delta, mouse_delta, page as rows_page, reset, row,
    screen, snapshot, written,
};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
#[cfg(not(windows))]
const BUNDLE: &str = "tauri://localhost";

/// How long a view that should send nothing is watched.
const QUIET: Duration = Duration::from_millis(300);

/// How long a case waits for a state that it asserts, where a missing state is to fail the case by
/// its own assertion. The states of a correct view come within a fraction of a second.
const STATE_BOUND: Duration = Duration::from_secs(10);

/// The page: an application with the view's commands, and every state each channel was sent.
struct Page {
    app: tauri::App<MockRuntime>,
    windows: BTreeMap<String, tauri::WebviewWindow<MockRuntime>>,
    published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>>,
    /// Holds the page's publication, and so the view's own task, while a case needs the view slower
    /// than the host.
    gate: Arc<Gate>,
}

/// A gate in the page's publication. Open, a state passes at once. Closed, a state the view
/// publishes is recorded and then waits inside the publication, which holds the view's task, until
/// the gate lets it pass: the view is as slow as the case makes it.
#[derive(Default)]
struct Gate {
    /// None while the gate is open, and otherwise how many more states may pass.
    passes: Mutex<Option<usize>>,
    changed: std::sync::Condvar,
}

impl Gate {
    fn pass(&self) {
        let mut passes = self.passes.lock().expect("the gate");
        loop {
            match *passes {
                None => return,
                Some(0) => passes = self.changed.wait(passes).expect("the gate"),
                Some(left) => {
                    *passes = Some(left - 1);
                    return;
                }
            }
        }
    }

    fn open(&self) {
        *self.passes.lock().expect("the gate") = None;
        self.changed.notify_all();
    }
}

/// Closes the page's gate, and opens it again when dropped, also when the case fails: a view held
/// at a closed gate would otherwise keep the runtime from ending.
struct Held {
    gate: Arc<Gate>,
}

impl Held {
    fn new(gate: &Arc<Gate>) -> Self {
        *gate.passes.lock().expect("the gate") = Some(0);
        Self {
            gate: Arc::clone(gate),
        }
    }

    /// Lets `states` more states pass.
    fn let_pass(&self, states: usize) {
        let mut passes = self.gate.passes.lock().expect("the gate");
        *passes = Some(passes.unwrap_or(0) + states);
        self.gate.changed.notify_all();
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.gate.open();
    }
}

impl Page {
    /// The application, with its view registry reading descriptors from `worker`'s host tree.
    fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        Self::with_pages(paths, &["main"])
    }

    fn with_pages(paths: kr_ipc::paths::EnvironmentPaths, labels: &[&str]) -> Self {
        let published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>> = Arc::default();
        let heard = Arc::clone(&published);
        let gate = Arc::new(Gate::default());
        let gated = Arc::clone(&gate);
        let builder = tauri::test::mock_builder()
            .manage(companion_tauri::AppState::new())
            .channel_interceptor(move |_webview, callback, _index, body| {
                if let tauri::ipc::InvokeResponseBody::Json(json) = body {
                    let state: Value = serde_json::from_str(json).expect("a state the page reads");
                    heard
                        .lock()
                        .expect("the record")
                        .entry(callback.0)
                        .or_default()
                        .push(state);
                    // The wait holds the view's task, and the runtime is told that this worker waits so
                    // that the session's reader, which the view does not hold, goes on reading.
                    tokio::task::block_in_place(|| gated.pass());
                }
                true
            })
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::terminal_view_open,
                companion_tauri::commands::terminal_view_resize,
                companion_tauri::commands::terminal_view_move,
                companion_tauri::commands::terminal_view_input,
                companion_tauri::commands::terminal_view_close,
                companion_tauri::commands::terminal_view_launch_surface,
                companion_tauri::commands::terminal_view_launch,
            ]);
        let app = companion_tauri::terminal::install(
            builder,
            companion_tauri::terminal::TerminalViews::at(paths),
        )
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("an application");
        let windows = labels
            .iter()
            .map(|label| {
                let window = tauri::WebviewWindowBuilder::new(&app, *label, Default::default())
                    .build()
                    .expect("a window");
                ((*label).to_owned(), window)
            })
            .collect();
        Self {
            app,
            windows,
            published,
            gate,
        }
    }

    fn invoke(&self, page: &str, command: &str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = &self.windows[page];
        tokio::task::block_in_place(|| {
            tauri::test::get_ipc_response(
                window,
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
        })
        .map(|answer| answer.deserialize().expect("an answer the page reads"))
    }

    /// Calls a command that waits for the worker's answer, and returns at once with what it will
    /// answer: the worker is scripted by this test, which has to answer it meanwhile.
    fn invoke_later(
        &self,
        command: &str,
        body: Value,
    ) -> tokio::task::JoinHandle<Result<Value, Value>> {
        let window = self.windows["main"].clone();
        let command = command.to_owned();
        tokio::task::spawn_blocking(move || {
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command,
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .map(|answer| answer.deserialize().expect("an answer the page reads"))
        })
    }

    /// Opens a view of `session` from the main page, publishing on `channel`.
    fn open(
        &self,
        session: kr_protocol::ids::SessionId,
        columns: u64,
        rows: u64,
        channel: u32,
    ) -> String {
        self.open_from("main", session, columns, rows, channel)
    }

    fn open_from(
        &self,
        page: &str,
        session: kr_protocol::ids::SessionId,
        columns: u64,
        rows: u64,
        channel: u32,
    ) -> String {
        let answer = self
            .invoke(
                page,
                "terminal_view_open",
                json!({
                    "sessionId": session.to_string(),
                    "columns": columns,
                    "rows": rows,
                    "onState": format!("__CHANNEL__:{channel}"),
                }),
            )
            .expect("the view opens");
        answer.as_str().expect("the view's handle").to_owned()
    }

    fn resize(&self, view: &str, columns: u64, rows: u64) {
        self.invoke(
            "main",
            "terminal_view_resize",
            json!({"view": view, "columns": columns, "rows": rows}),
        )
        .expect("the size is taken");
    }

    fn close(&self, view: &str) {
        self.invoke("main", "terminal_view_close", json!({"view": view}))
            .expect("the view closes");
    }

    /// Every state `channel` has been sent so far.
    fn states(&self, channel: u32) -> Vec<Value> {
        self.published
            .lock()
            .expect("the record")
            .get(&channel)
            .cloned()
            .unwrap_or_default()
    }

    /// The `index`th state `channel` is sent, once it has been.
    async fn state(&self, channel: u32, index: usize) -> Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                if let Some(state) = self.states(channel).get(index) {
                    return state.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "state {index} on channel {channel} within the watchdog; it was sent {:?}",
                self.states(channel)
            )
        })
    }

    /// How many views the application holds open.
    fn held(&self) -> usize {
        self.app
            .state::<companion_tauri::terminal::TerminalViews>()
            .held()
    }

    async fn held_becomes(&self, views: usize) {
        tokio::time::timeout(WATCHDOG, async {
            while self.held() != views {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the views held reach the count within the watchdog");
    }
}

fn text_of(state: &Value) -> Vec<String> {
    state["screen"]["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .map(|line| {
            line["pieces"]
                .as_array()
                .expect("pieces")
                .iter()
                .map(|piece| piece["text"].as_str().expect("text").to_owned())
                .collect::<String>()
        })
        .collect()
}

/// A view opened, attached and showing its first screen: rows `first` and `second`.
async fn showing(page: &Page, worker: &mut ScriptedWorker, channel: u32) -> (String, Link) {
    let view = page.open(worker.session_id, 10, 2, channel);
    let mut link = worker.link().await;
    link.attach().await;
    assert_eq!(page.state(channel, 0).await["state"], "waiting");
    screen(&mut link, 1, 40, vec![row(0, "first"), row(1, "second")], 0).await;
    let shown = page.state(channel, 1).await;
    assert_eq!(shown["state"], "showing");
    assert_eq!(text_of(&shown), vec!["first", "second"]);
    (view, link)
}

/// KR-REQ-08.02, KR-REQ-13.18: the view attaches on the worker's own endpoint, after the worker has
/// proved who it is, in terminal mode with no geometry claim, at the size the page measured, asking
/// to observe and to be able to take input, under the terminal profile that names this view; it
/// subscribes from the attach's own cursor; and its first state carries the attachment's summary, a
/// viewport for a profile the host has not qualified, and says the view watches.
#[tokio::test(flavor = "multi_thread")]
async fn a_view_attaches_on_the_workers_endpoint_with_no_claim_asking_for_input_under_its_profile()
{
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 7);
    let mut link = worker.link().await;
    let (attachment_id, asked) = link.attach().await;
    assert_eq!(asked.session_id, worker.session_id);
    assert_eq!(asked.mode, AttachMode::Terminal);
    assert!(!asked.claim_geometry, "a view makes no geometry claim");
    assert_eq!(asked.dimensions.0, Some(Dimensions::new(30, 5)));
    assert_eq!(
        asked.terminal_profile_id.0.as_deref(),
        Some("kalareach-companion"),
        "and names itself, so the host can say whether it may take the keys"
    );
    assert_eq!(
        asked.requested.iter().copied().collect::<Vec<_>>(),
        vec![
            AttachmentCapability::ObserveTerminal,
            AttachmentCapability::Input
        ]
    );
    let waiting = page.state(7, 0).await;
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(
        waiting["attachment"]["attachment_id"],
        attachment_id.to_string()
    );
    assert_eq!(waiting["attachment"]["presentation"], "viewport");
    assert_eq!(
        waiting["attachment"]["presentation_reason"],
        "unqualified_terminal_profile"
    );
    assert_eq!(
        waiting["control"],
        json!({"number": 0, "state": "watching", "ended": null}),
        "a view opens watching: opening takes control from nobody"
    );
    screen(&mut link, 1, 40, vec![row(0, "hello")], 0).await;
    let shown = page.state(7, 1).await;
    assert_eq!(
        shown["attachment"], waiting["attachment"],
        "the summary rides on showing too"
    );
}

/// The subscription starts from the cursor the attach answered with, on the output stream alone.
#[tokio::test(flavor = "multi_thread")]
async fn the_view_subscribes_from_the_attach_cursor() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 7);
    let mut link = worker.link().await;
    let attach = link.expect(Method::SessionAttach).await;
    let attachment_id = kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid());
    let asked: kr_protocol::attachment::SessionAttachParams = attach.params();
    link.answer(
        &attach,
        &kr_protocol::attachment::SessionAttachResult {
            attachment: scripted_worker::summary(attachment_id, &asked),
            geometry: kr_protocol::attachment::GeometryState {
                owner: kr_protocol::scalars::Nullable::null(),
                epoch: kr_protocol::ids::GeometryEpoch::new(1),
                dimensions: Dimensions::new(80, 24),
            },
            output_cursor: kr_protocol::scalars::U64::new(912),
        },
    )
    .await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    let asked: EventsSubscribeParams = subscribe.params();
    assert_eq!(asked.attachment_id, attachment_id);
    assert_eq!(asked.from_cursor.0.map(|cursor| cursor.get()), Some(912));
    assert_eq!(
        asked.streams.iter().copied().collect::<Vec<_>>(),
        vec![EventStream::Output]
    );
}

/// A session this computer does not run has no descriptor, and the view ends saying so.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_with_no_descriptor_ends_the_view() {
    let host = kr_ipc::testing::TempHost::create();
    let page = Page::new(host.environment());
    let _view = page.open(
        kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()),
        30,
        5,
        3,
    );
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "This session is not running on this computer."
    );
    assert!(
        ended.get("attachment").is_none(),
        "an ended view carries no summary"
    );
    page.held_becomes(0).await;
}

/// A worker that cannot prove it holds the descriptor's key is never attached to.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_fails_its_challenge_is_never_attached() {
    let mut worker = ScriptedWorker::start(Challenge::Forged);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    assert!(
        link.closed().await.is_empty(),
        "the view asked the worker for nothing"
    );
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert!(
        ended["reason"]
            .as_str()
            .expect("words")
            .starts_with("This session's worker could not prove who it is"),
        "{ended}"
    );
    page.held_becomes(0).await;
}

/// What a view of this build says when it will not attach to a worker of another build.
fn refusal_of_a_worker(worker: &str) -> String {
    format!(
        "This session runs on {worker}, and this application is {} with protocol {}: this \
         application cannot show a session whose worker speaks another protocol version. Close \
         the session, or open it with the application of the worker's build.",
        companion_tauri::connection::build_id()
            .expect("this build's identifier")
            .as_str(),
        kr_protocol::hello::PACKAGE_VERSION,
    )
}

/// A worker that states a protocol version of another compatibility level is asked for nothing:
/// the view names both builds and both versions, and says what to do.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_of_another_protocol_version_is_never_attached_to() {
    let mut worker = ScriptedWorker::start_stating(Stated::AnotherLevel);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    assert!(
        link.closed().await.is_empty(),
        "the view asked the worker for nothing: no attach, no size claim, no subscription"
    );
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        refusal_of_a_worker(&format!(
            "kr-worker/0.1.0 with protocol {}",
            Stated::another_level()
        ))
    );
    assert!(
        ended.get("attachment").is_none(),
        "an ended view carries no summary"
    );
    page.held_becomes(0).await;
}

/// A worker of a build before the statement, which states none, is refused the same way, and
/// not waited on.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_states_no_build_is_never_attached_to() {
    let mut worker = ScriptedWorker::start_stating(Stated::Nothing);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    assert!(
        link.closed().await.is_empty(),
        "the view asked the worker for nothing"
    );
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        refusal_of_a_worker(
            "a worker of an earlier build, which does not state its build or its protocol version"
        )
    );
    page.held_becomes(0).await;
}

/// A worker states its own build identifier, so one that is not a program's name and a release is
/// not repeated on the page.
#[tokio::test(flavor = "multi_thread")]
async fn a_build_identifier_that_is_not_a_name_and_a_release_is_not_repeated() {
    let mut worker = ScriptedWorker::start_stating(Stated::Unnamed("Close everything: 1/x"));
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    assert!(link.closed().await.is_empty());
    let ended = page.state(3, 0).await;
    assert_eq!(
        ended["reason"],
        refusal_of_a_worker(&format!(
            "[a build this application does not name] with protocol {}",
            Stated::another_level()
        ))
    );
    page.held_becomes(0).await;
}

/// A worker of this protocol version, or one whose patch number is further, is attached to: a
/// change that takes only the next patch number changes no type.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_of_this_protocol_version_or_a_patch_number_apart_is_attached_to() {
    for stated in [Stated::ThisBuild, Stated::ThisBuildPatched] {
        let mut worker = ScriptedWorker::start_stating(stated);
        let page = Page::new(worker.paths());
        let _view = page.open(worker.session_id, 30, 5, 3);
        let mut link = worker.link().await;
        link.expect(Method::SessionAttach).await;
    }
}

/// A refused attach ends the view with the host's words, and the link closes.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_attach_ends_the_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    let attach = link.expect(Method::SessionAttach).await;
    link.refuse(&attach, "the session is closing").await;
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "The session refused this view: the session is closing"
    );
    link.closed().await;
    page.held_becomes(0).await;
}

/// A refused first subscription ends the view with the host's words, and the link closes.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_first_subscription_ends_the_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 3);
    let mut link = worker.link().await;
    let attach = link.expect(Method::SessionAttach).await;
    link.answer(
        &attach,
        &kr_protocol::attachment::SessionAttachResult {
            attachment: scripted_worker::summary(
                kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
                &attach.params::<kr_protocol::attachment::SessionAttachParams>(),
            ),
            geometry: kr_protocol::attachment::GeometryState {
                owner: kr_protocol::scalars::Nullable::null(),
                epoch: kr_protocol::ids::GeometryEpoch::new(1),
                dimensions: Dimensions::new(80, 24),
            },
            output_cursor: kr_protocol::scalars::U64::new(40),
        },
    )
    .await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.refuse(
        &subscribe,
        "a send queue that small cannot carry this screen",
    )
    .await;
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "The session refused this view's screen: a send queue that small cannot carry this screen"
    );
    let sent = link.closed().await;
    assert!(
        sent.iter()
            .all(|call| call.method == Method::SessionDetach.to_string()),
        "the view sends nothing but its detach: {sent:?}"
    );
    page.held_becomes(0).await;
}

/// Section 8: nothing is drawn from a snapshot until its last page has arrived.
#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_is_published_only_at_its_last_page() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 10, 2, 3);
    let mut link = worker.link().await;
    link.attach().await;
    assert_eq!(page.state(3, 0).await["state"], "waiting");
    link.push(
        PROJECTION_RESET_EVENT,
        &reset(1, 40, ProjectionResetReason::Attached, 0),
    )
    .await;
    link.push(PROJECTION_SNAPSHOT_EVENT, &snapshot(1, 40, 10, 2, 0, 0))
        .await;
    link.push(
        PROJECTION_ROWS_EVENT,
        &rows_page(1, 40, vec![row(0, "top")], true),
    )
    .await;
    assert!(link.quiet_for(QUIET).await);
    assert_eq!(
        page.states(3).len(),
        1,
        "nothing is drawn from half a snapshot"
    );
    link.push(
        PROJECTION_ROWS_EVENT,
        &rows_page(1, 40, vec![row(1, "bottom")], false),
    )
    .await;
    let shown = page.state(3, 1).await;
    assert_eq!(shown["state"], "showing");
    assert_eq!(text_of(&shown), vec!["top", "bottom"]);
    assert_eq!(
        shown["screen"]["window"],
        json!({"rows": 2, "columns": 10, "column": 0, "line": 0, "above": 0})
    );
    assert_eq!(
        shown["screen"]["room"],
        json!({"up": 0, "down": 0, "left": 0, "right": 0}),
        "a window that holds the whole session has nowhere to move"
    );
    assert_eq!(
        shown["screen"]["dimensions"],
        json!({"columns": "10", "rows": "2"})
    );
    assert_eq!(
        shown["screen"]["cursor"],
        json!({"column": 2, "line": 0, "visible": true, "style": 1})
    );
    assert_eq!(shown["screen"]["palette"]["source"], "dark_preset");
}

/// An update continuing from the held screen is applied and published.
#[tokio::test(flavor = "multi_thread")]
async fn a_delta_is_applied_and_published() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (_view, mut link) = showing(&page, &mut worker, 3).await;
    link.push(
        PROJECTION_DELTA_EVENT,
        &delta(1, 40, 52, 10, 2, 0, vec![row(1, "changed")]),
    )
    .await;
    let updated = page.state(3, 2).await;
    assert_eq!(updated["state"], "showing");
    assert_eq!(text_of(&updated), vec!["first", "changed"]);
    assert_eq!(updated["screen"]["cursor"]["column"], 3);
}

/// Each update the view cannot apply, and each resynchronisation marker, discards the screen and
/// asks for a fresh one on the same link, once: the stream it replaces goes on being dropped until
/// the new one begins, at sequence 0.
#[tokio::test(flavor = "multi_thread")]
async fn what_cannot_be_applied_resubscribes_once() {
    for case in [
        "a delta for another base",
        "a delta for another generation",
        "a page for no snapshot",
        "an undecodable payload",
        "a resynchronisation marker",
    ] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
        match case {
            "a delta for another base" => {
                link.push(
                    PROJECTION_DELTA_EVENT,
                    &delta(1, 99, 120, 10, 2, 0, vec![row(1, "x")]),
                )
                .await;
            }
            "a delta for another generation" => {
                link.push(
                    PROJECTION_DELTA_EVENT,
                    &delta(7, 40, 60, 10, 2, 0, vec![row(1, "x")]),
                )
                .await;
            }
            "a page for no snapshot" => {
                link.push(
                    PROJECTION_ROWS_EVENT,
                    &rows_page(1, 40, vec![row(0, "x")], false),
                )
                .await;
            }
            "an undecodable payload" => {
                link.push_raw(
                    PROJECTION_DELTA_EVENT,
                    kr_protocol::envelope::ParamsValue::from_typed(&"not an update")
                        .expect("a payload"),
                )
                .await;
            }
            _ => link.push("session.resync", &resync_marker(60)).await,
        }
        let subscribe = link.expect(Method::EventsSubscribe).await;
        let asked: EventsSubscribeParams = subscribe.params();
        assert_eq!(asked.from_cursor.0, None, "{case}: from the current cursor");
        assert_eq!(
            asked.streams.iter().copied().collect::<Vec<_>>(),
            vec![EventStream::Output],
            "{case}"
        );
        assert_eq!(
            page_view.state(3, 2).await["state"],
            "waiting",
            "{case}: the view waits for a fresh screen"
        );
        // The replaced stream's tail: refused as well, and dropped rather than asked about again.
        link.push(
            PROJECTION_DELTA_EVENT,
            &delta(1, 60, 70, 10, 2, 0, vec![row(1, "tail")]),
        )
        .await;
        link.push("session.resync", &resync_marker(70)).await;
        assert!(
            link.quiet_for(QUIET).await,
            "{case}: one recovery at a time"
        );
        link.answer(&subscribe, &scripted_worker::subscribed())
            .await;
        link.restart_stream();
        screen(&mut link, 2, 80, vec![row(0, "fresh"), row(1, "screen")], 0).await;
        let shown = page_view.state(3, 3).await;
        assert_eq!(shown["state"], "showing", "{case}");
        assert_eq!(text_of(&shown), vec!["fresh", "screen"], "{case}");
        assert_eq!(
            page_view.states(3).len(),
            4,
            "{case}: nothing from the replaced stream"
        );
    }
}

/// A reset waits for the snapshot that follows it: asking again would loop, since every
/// subscription opens with a reset of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_waits_for_its_snapshot() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
    link.push(
        PROJECTION_RESET_EVENT,
        &reset(2, 60, ProjectionResetReason::BufferSwitch, 0),
    )
    .await;
    assert_eq!(page_view.state(3, 2).await["state"], "waiting");
    assert!(link.quiet_for(QUIET).await, "a reset sends nothing");
    link.push(PROJECTION_SNAPSHOT_EVENT, &snapshot(2, 60, 10, 2, 0, 0))
        .await;
    link.push(
        PROJECTION_ROWS_EVENT,
        &rows_page(2, 60, vec![row(0, "vim"), row(1, "~")], false),
    )
    .await;
    let shown = page_view.state(3, 3).await;
    assert_eq!(text_of(&shown), vec!["vim", "~"]);
}

/// A size equal to the one last sent sends nothing, so an idle session keeps its screen.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_size_sends_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = showing(&page_view, &mut worker, 3).await;
    page_view.resize(&view, 10, 2);
    assert!(link.quiet_for(QUIET).await);
    assert_eq!(page_view.states(3).len(), 2, "and the screen stays");
}

/// Rapid sizes end at the newest, with one report outstanding at a time, and every report keeps the
/// window at the live screen's first line and column. A report is settled by the screen its answer
/// names, which for a new size is the next subscription's first, so the newest size goes then.
#[tokio::test(flavor = "multi_thread")]
async fn rapid_sizes_end_at_the_newest_with_one_report_outstanding() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = showing(&page_view, &mut worker, 3).await;
    page_view.resize(&view, 12, 3);
    let first = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = first.params();
    assert_eq!(asked.dimensions, Dimensions::new(12, 3));
    assert_eq!(
        asked.position.0, None,
        "the window stays on the live screen"
    );
    assert_eq!(
        asked.column,
        kr_protocol::scalars::U64::ZERO,
        "from its first column"
    );
    page_view.resize(&view, 14, 4);
    page_view.resize(&view, 16, 5);
    assert!(link.quiet_for(QUIET).await, "one report at a time");
    link.answer(&first, &viewport_answer(1)).await;
    assert!(
        link.quiet_for(QUIET).await,
        "an answer alone does not settle a new size"
    );
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    screen(&mut link, 2, 60, vec![row(0, "at"), row(1, "twelve")], 1).await;
    let second = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = second.params();
    assert_eq!(asked.dimensions, Dimensions::new(16, 5), "the newest size");
    assert_eq!(asked.position.0, None, "still on the live screen");
    assert_eq!(
        asked.column,
        kr_protocol::scalars::U64::ZERO,
        "still from its first column"
    );
    link.answer(&second, &viewport_answer(2)).await;
    assert!(link.quiet_for(QUIET).await);
}

/// The page shows the presentation and its reason from the view's summary of the attachment, and
/// a size report can change both, so the answer to the report is what the page is told from then
/// on: the reason the host names, and none once the attachment is shown the stream.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_reports_answer_is_what_the_page_shows_of_the_presentation() {
    use kr_protocol::attachment::{PresentationReason, TerminalPresentationMode};
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = showing(&page_view, &mut worker, 3).await;
    let opened = page_view.state(3, 0).await;
    assert_eq!(
        opened["attachment"]["presentation_reason"], "unqualified_terminal_profile",
        "the attach answer's reason is what the page shows first"
    );

    let mut count = page_view.states(3).len();
    for (round, (size, presentation, reason, shown)) in [
        (
            (12, 3),
            TerminalPresentationMode::Viewport,
            Some(PresentationReason::SizeMismatch),
            "viewport",
        ),
        ((10, 2), TerminalPresentationMode::Direct, None, "direct"),
    ]
    .into_iter()
    .enumerate()
    {
        // Each report leaves the window at the next revision, and the screen drawn for it is the
        // next generation at a cursor of its own.
        let revision = round as u64 + 1;
        let generation = revision + 1;
        let cursor = 40 + 20 * revision;
        page_view.resize(&view, size.0, size.1);
        let asked = link.expect(Method::AttachmentViewport).await;
        link.answer(
            &asked,
            &viewport_answer_shown(revision, presentation, reason),
        )
        .await;
        link.push("session.resync", &resync_marker(cursor)).await;
        let subscribe = link.expect(Method::EventsSubscribe).await;
        link.answer(&subscribe, &scripted_worker::subscribed())
            .await;
        link.restart_stream();
        screen(&mut link, generation, cursor, vec![row(0, "at")], revision).await;
        // The state the page is sent once the screen for this report has arrived.
        let state = tokio::time::timeout(WATCHDOG, async {
            loop {
                let states = page_view.states(3);
                if let Some(state) = states[count..]
                    .iter()
                    .find(|state| state["state"] == "showing" && text_of(state) == ["at"])
                {
                    break state.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the screen for the report reaches the page within the watchdog");
        assert_eq!(state["attachment"]["presentation"], shown);
        match reason {
            Some(reason) => assert_eq!(state["attachment"]["presentation_reason"], reason.as_str()),
            None => assert!(
                state["attachment"].get("presentation_reason").is_none(),
                "an attachment shown the stream has no reason: {state}"
            ),
        }
        count = page_view.states(3).len();
    }
}

/// A refused size is not sent again until the page measures another, and a newer size made while
/// it was outstanding goes after the refusal.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_size_is_not_sent_again_and_a_newer_one_goes_after_it() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = showing(&page_view, &mut worker, 3).await;
    page_view.resize(&view, 12, 3);
    let first = link.expect(Method::AttachmentViewport).await;
    link.refuse(&first, "that size is not one this session takes")
        .await;
    assert!(
        link.quiet_for(QUIET).await,
        "a refused size is not sent again"
    );
    page_view.resize(&view, 12, 3);
    assert!(
        link.quiet_for(QUIET).await,
        "nor when the page measures it again"
    );
    page_view.resize(&view, 13, 3);
    let second = link.expect(Method::AttachmentViewport).await;
    page_view.resize(&view, 15, 4);
    link.refuse(&second, "that size is not one this session takes")
        .await;
    let third = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = third.params();
    assert_eq!(
        asked.dimensions,
        Dimensions::new(15, 4),
        "the newer size is never lost"
    );
    assert_eq!(
        page_view.states(3).len(),
        2,
        "a refusal changes nothing on screen"
    );
}

/// A size the session refuses for now, or cannot say it took, is not settled by that word and is
/// not marked sent: it goes again with the session's next word, and an answer settles it.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_the_session_did_not_take_for_now_goes_again_with_its_next_word() {
    for code in [ErrorCode::ResourceUnavailable, ErrorCode::OutcomeUnknown] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let (view, mut link) = showing(&page_view, &mut worker, 3).await;
        page_view.resize(&view, 12, 3);
        let first = link.expect(Method::AttachmentViewport).await;
        link.refuse_with(&first, code, "the session cannot take that now")
            .await;
        assert!(
            link.quiet_for(QUIET).await,
            "{code:?}: nothing goes again before something arrives"
        );
        screen(&mut link, 2, 60, vec![row(0, "first"), row(1, "second")], 0).await;
        let again = link.expect(Method::AttachmentViewport).await;
        let asked: AttachmentViewportParams = again.params();
        assert_eq!(
            asked.dimensions,
            Dimensions::new(12, 3),
            "{code:?}: the size that was refused"
        );
        link.answer(&again, &viewport_answer(1)).await;
        screen(&mut link, 3, 80, vec![row(0, "first"), row(1, "second")], 1).await;
        assert!(
            link.quiet_for(QUIET).await,
            "{code:?}: the answer and the screen it names settle it, and nothing is owed"
        );
    }
}

/// What the page measures or moves while a size report is in flight is not made to wait for the
/// session by that report's refusal for now: the newest size is owed, and goes at once.
#[tokio::test(flavor = "multi_thread")]
async fn what_the_page_does_during_a_size_report_the_session_did_not_take_goes_at_once() {
    for page_moves in [false, true] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let at = wide_session();
        let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
        page_view.resize(&view, 12, 2);
        let first = link.expect(Method::AttachmentViewport).await;
        let expected = if page_moves {
            page_view.pan(&view, 1, 1, 0);
            Dimensions::new(12, 2)
        } else {
            page_view.resize(&view, 14, 3);
            Dimensions::new(14, 3)
        };
        link.refuse_with(&first, ErrorCode::ResourceUnavailable, "not now")
            .await;
        let (_, asked) = report(&mut link).await;
        assert_eq!(
            asked.dimensions, expected,
            "the owed size goes with nothing between (the page moves: {page_moves})"
        );
        // A move to the next column carries the same size, so what tells the size report from it
        // is the place: the size report leaves the window where it is.
        assert_eq!(
            (asked.position.0, asked.column.get()),
            (None, 0),
            "the size, not the move (the page moves: {page_moves})"
        );
    }
}

/// A size the session cannot say it took may have been taken, so the newest size is said again
/// though the page measured back to the size last sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_of_unknown_outcome_is_said_again_though_the_page_measured_back() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = showing(&page_view, &mut worker, 3).await;
    page_view.resize(&view, 12, 3);
    let first = link.expect(Method::AttachmentViewport).await;
    page_view.resize(&view, 10, 2);
    link.refuse_with(&first, ErrorCode::OutcomeUnknown, "no word of it")
        .await;
    let again = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = again.params();
    assert_eq!(
        asked.dimensions,
        Dimensions::new(10, 2),
        "the host may have taken 12 by 3, so it is told the size the page has"
    );
}

/// A session that keeps refusing a size for now is not asked once for every word it says: the size
/// goes again with its next word three times, and after that waits for the page to measure again or
/// to move, which sends the size first.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_the_session_keeps_refusing_for_now_waits_for_the_page_after_three_tries() {
    for page_moves in [false, true] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let at = wide_session();
        let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
        page_view.resize(&view, 12, 2);
        let mut call = link.expect(Method::AttachmentViewport).await;
        let mut repaint = at;
        for round in 1..=4_u64 {
            link.refuse_with(&call, ErrorCode::ResourceUnavailable, "not now")
                .await;
            repaint.generation = 1 + round;
            repaint.cursor = 40 + 20 * round;
            frame(&mut link, &repaint).await;
            if round < 4 {
                call = link.expect(Method::AttachmentViewport).await;
            }
        }
        assert!(
            link.quiet_for(QUIET).await,
            "after three tries it waits for the page, whatever the session says"
        );
        if page_moves {
            page_view.pan(&view, 1, 1, 0);
        } else {
            page_view.resize(&view, 12, 2);
        }
        let (after, asked) = report(&mut link).await;
        assert_eq!(
            asked.dimensions,
            Dimensions::new(12, 2),
            "the size that is owed goes first (the page moves: {page_moves})"
        );
        assert_eq!(
            (asked.position.0, asked.column.get()),
            (None, 0),
            "the size, not the move (the page moves: {page_moves})"
        );
        link.answer(&after, &viewport_answer(1)).await;
    }
}

/// A size measured before the subscription answers waits for it, and is compared with the size the
/// view attached at.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_measured_while_attaching_goes_once_the_view_is_subscribed() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let view = page_view.open(worker.session_id, 10, 2, 3);
    let mut link = worker.link().await;
    let attach = link.expect(Method::SessionAttach).await;
    page_view.resize(&view, 20, 6);
    link.answer(
        &attach,
        &kr_protocol::attachment::SessionAttachResult {
            attachment: scripted_worker::summary(
                kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
                &attach.params::<kr_protocol::attachment::SessionAttachParams>(),
            ),
            geometry: kr_protocol::attachment::GeometryState {
                owner: kr_protocol::scalars::Nullable::null(),
                epoch: kr_protocol::ids::GeometryEpoch::new(1),
                dimensions: Dimensions::new(80, 24),
            },
            output_cursor: kr_protocol::scalars::U64::new(40),
        },
    )
    .await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    let report = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = report.params();
    assert_eq!(asked.dimensions, Dimensions::new(20, 6));
}

/// An accepted size is followed by the host's marker, before or after the report's answer; either
/// way the view recovers once and shows the new screen. A marker after the new stream's reset is a
/// new reason, and starts a second recovery.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_size_recovers_whether_the_marker_comes_before_or_after_the_answer() {
    for marker_first in [true, false] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let (view, mut link) = showing(&page_view, &mut worker, 3).await;
        page_view.resize(&view, 12, 3);
        let report = link.expect(Method::AttachmentViewport).await;
        if !marker_first {
            link.answer(&report, &viewport_answer(1)).await;
        }
        link.push("session.resync", &resync_marker(60)).await;
        let subscribe = link.expect(Method::EventsSubscribe).await;
        if marker_first {
            link.answer(&report, &viewport_answer(1)).await;
        }
        link.answer(&subscribe, &scripted_worker::subscribed())
            .await;
        link.restart_stream();
        screen(
            &mut link,
            2,
            60,
            vec![row(0, "wider"), row(1, "screen"), row(2, "now")],
            1,
        )
        .await;
        let shown = page_view.state(3, 3).await;
        assert_eq!(
            text_of(&shown),
            vec!["wider", "screen", "now"],
            "marker first: {marker_first}"
        );
        assert!(link.quiet_for(QUIET).await);

        // A marker on the new stream is the new subscription's own, so it is a new recovery.
        link.push("session.resync", &resync_marker(80)).await;
        let again = link.expect(Method::EventsSubscribe).await;
        link.answer(&again, &scripted_worker::subscribed()).await;
        link.restart_stream();
        screen(&mut link, 3, 80, vec![row(0, "third")], 1).await;
        assert_eq!(text_of(&page_view.state(3, 5).await), vec!["third"]);
    }
}

/// The new stream's first notification opens the guard whatever it is: an undecodable reset still
/// counts as the new stream beginning, and is itself a reason to recover again.
#[tokio::test(flavor = "multi_thread")]
async fn an_undecodable_reset_on_the_new_stream_still_opens_the_guard() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    link.push_raw(
        PROJECTION_RESET_EVENT,
        kr_protocol::envelope::ParamsValue::from_typed(&"not a reset").expect("a payload"),
    )
    .await;
    let again = link.expect(Method::EventsSubscribe).await;
    link.answer(&again, &scripted_worker::subscribed()).await;
    link.restart_stream();
    screen(&mut link, 2, 60, vec![row(0, "recovered")], 0).await;
    assert_eq!(text_of(&page_view.state(3, 3).await), vec!["recovered"]);
}

/// A new stream may open with the gap it reports, just before its reset.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_stream_that_opens_with_a_gap_installs_its_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    link.push(
        "session.gap",
        &json!({"requested_cursor": "10", "oldest_retained_cursor": "20"}),
    )
    .await;
    screen(&mut link, 2, 60, vec![row(0, "after"), row(1, "a gap")], 0).await;
    assert_eq!(
        text_of(&page_view.state(3, 3).await),
        vec!["after", "a gap"]
    );
}

/// Three recoveries in a row with no complete screen end the view: a host whose screens never
/// decode cannot keep it resubscribing.
#[tokio::test(flavor = "multi_thread")]
async fn three_recoveries_with_no_screen_end_the_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
    link.push_raw(
        PROJECTION_DELTA_EVENT,
        kr_protocol::envelope::ParamsValue::from_typed(&"not an update").expect("a payload"),
    )
    .await;
    for _ in 0..3 {
        let subscribe = link.expect(Method::EventsSubscribe).await;
        link.answer(&subscribe, &scripted_worker::subscribed())
            .await;
        link.restart_stream();
        link.push_raw(
            PROJECTION_RESET_EVENT,
            kr_protocol::envelope::ParamsValue::from_typed(&"not a reset").expect("a payload"),
        )
        .await;
    }
    let ended = page_view.state(3, 3).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(ended["reason"], "The session's screen could not be read.");
    let sent = link.closed().await;
    assert!(
        sent.iter()
            .all(|call| call.method == Method::SessionDetach.to_string()),
        "no fourth subscription: {sent:?}"
    );
    page_view.held_becomes(0).await;
}

/// A refused resubscription ends the view although the connection stays open.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_resubscription_ends_the_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.refuse(
        &subscribe,
        "a send queue that small cannot carry this screen",
    )
    .await;
    let ended = page_view.state(3, 3).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "The session refused this view's screen: a send queue that small cannot carry this screen"
    );
    let sent = link.closed().await;
    assert_eq!(
        sent.len(),
        1,
        "the view detaches before it closes the link: {sent:?}"
    );
    assert_eq!(sent[0].method, Method::SessionDetach.to_string());
    page_view.held_becomes(0).await;
}

/// The session closing, the view being detached elsewhere, and the link ending each end the view.
#[tokio::test(flavor = "multi_thread")]
async fn the_session_closing_a_detach_and_a_lost_link_end_the_view() {
    for ending in ["closed", "detached", "lost"] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let (_view, mut link) = showing(&page_view, &mut worker, 3).await;
        let reason = match ending {
            "closed" => {
                link.push("session.closed", &json!({"reason": "exited"}))
                    .await;
                "This session has closed."
            }
            "detached" => {
                link.push(
                    "session.detached",
                    &SessionDetachParams {
                        attachment_id: kr_protocol::scalars::Nullable::null(),
                        line_token: kr_protocol::scalars::Nullable::null(),
                        after_input: None,
                        fenced_report: false,
                    },
                )
                .await;
                "This view was detached from the session."
            }
            _ => {
                drop(link);
                "The connection to this session ended."
            }
        };
        let ended = page_view.state(3, 2).await;
        assert_eq!(ended["state"], "ended", "{ending}");
        assert_eq!(ended["reason"], reason, "{ending}");
        page_view.held_becomes(0).await;
    }
}

/// Closing the view detaches it, closes its link, publishes nothing more, and is idempotent.
#[tokio::test(flavor = "multi_thread")]
async fn closing_detaches_and_closes_the_link() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let view = page_view.open(worker.session_id, 10, 2, 3);
    let mut link = worker.link().await;
    let (attachment_id, _) = link.attach().await;
    screen(&mut link, 1, 40, vec![row(0, "shown")], 0).await;
    page_view.state(3, 1).await;
    page_view.close(&view);
    assert_eq!(page_view.held(), 0, "a closed view is not held");
    let sent = link.closed().await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].method, Method::SessionDetach.to_string());
    let detach: SessionDetachParams = sent[0].params();
    assert_eq!(detach.attachment_id.0, Some(attachment_id));
    page_view.close(&view);
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        page_view.states(3).len(),
        2,
        "nothing is published after a close"
    );
}

/// A close during a pending open leaves no attachment and publishes nothing, whether the attach
/// or the subscription was the call in flight.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_during_a_pending_open_leaves_nothing() {
    for pending in [Method::SessionAttach, Method::EventsSubscribe] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let view = page_view.open(worker.session_id, 10, 2, 3);
        let mut link = worker.link().await;
        if pending == Method::EventsSubscribe {
            let attach = link.expect(Method::SessionAttach).await;
            link.answer(
                &attach,
                &kr_protocol::attachment::SessionAttachResult {
                    attachment: scripted_worker::summary(
                        kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
                        &attach.params::<kr_protocol::attachment::SessionAttachParams>(),
                    ),
                    geometry: kr_protocol::attachment::GeometryState {
                        owner: kr_protocol::scalars::Nullable::null(),
                        epoch: kr_protocol::ids::GeometryEpoch::new(1),
                        dimensions: Dimensions::new(80, 24),
                    },
                    output_cursor: kr_protocol::scalars::U64::new(40),
                },
            )
            .await;
        }
        link.expect(pending).await;
        page_view.close(&view);
        // The link closes, which detaches whatever the attach had made.
        link.closed().await;
        tokio::time::sleep(QUIET).await;
        assert!(
            page_view.states(3).is_empty(),
            "{pending}: nothing is published"
        );
        assert_eq!(page_view.held(), 0);
    }
}

/// A close while the view is still in its opening exchange, before the worker has acknowledged the
/// hello or answered the challenge, closes the connection and publishes nothing: no attach was made.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_during_the_opening_exchange_leaves_nothing() {
    for held in [Challenge::HeldAtHello, Challenge::HeldAtProof] {
        let mut worker = ScriptedWorker::start(held);
        let page_view = Page::new(worker.paths());
        let view = page_view.open(worker.session_id, 10, 2, 3);
        worker.holding().await;
        page_view.close(&view);
        worker.abandoned().await;
        assert!(!worker.connected(), "{held:?}: no link reached an attach");
        tokio::time::sleep(QUIET).await;
        assert!(
            page_view.states(3).is_empty(),
            "{held:?}: nothing is published"
        );
        assert_eq!(page_view.held(), 0, "{held:?}");
    }
}

/// Every close returns only once the view has ended: two closes at once, or a close after the page
/// has loaded again, each wait for the view's task, so nothing it publishes or holds outlives the
/// call that closed it.
#[tokio::test(flavor = "multi_thread")]
async fn every_close_returns_only_once_the_view_has_ended() {
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for after_a_page_load in [false, true] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let views = Arc::new(companion_tauri::terminal::TerminalViews::at(worker.paths()));
        // The view's first state is held inside its publication until the test opens the gate.
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let published = Arc::new(AtomicUsize::new(0));
        let publish: companion_tauri::terminal::Publish = {
            let gate = Arc::clone(&gate);
            let published = Arc::clone(&published);
            Arc::new(move |_state| {
                published.fetch_add(1, Ordering::SeqCst);
                let (open, opened) = &*gate;
                let mut open = open.lock().expect("the gate");
                while !*open {
                    open = opened.wait(open).expect("the gate");
                }
            })
        };
        let view = views.open("main", worker.session_id, Dimensions::new(10, 2), publish);
        let mut link = worker.link().await;
        link.attach().await;
        tokio::time::timeout(WATCHDOG, async {
            while published.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the view is publishing its first state");
        if after_a_page_load {
            views.page_load("main", tauri::webview::PageLoadEvent::Started);
        }
        let closing = |views: &Arc<companion_tauri::terminal::TerminalViews>| {
            let views = Arc::clone(views);
            let view = view.clone();
            tokio::spawn(async move { views.close(&view).await })
        };
        let first = closing(&views);
        let second = closing(&views);
        tokio::time::sleep(QUIET).await;
        assert!(
            !first.is_finished() && !second.is_finished(),
            "page load first: {after_a_page_load}: no close returns while the view is still running"
        );
        {
            let (open, opened) = &*gate;
            *open.lock().expect("the gate") = true;
            opened.notify_all();
        }
        tokio::time::timeout(WATCHDOG, first)
            .await
            .expect("the first close returns")
            .expect("the first close");
        tokio::time::timeout(WATCHDOG, second)
            .await
            .expect("the second close returns")
            .expect("the second close");
        assert_eq!(views.held(), 0);
        let sent = link.closed().await;
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].method, Method::SessionDetach.to_string());
        assert_eq!(
            published.load(Ordering::SeqCst),
            1,
            "nothing is published after a close"
        );
    }
}

/// A page that starts loading again closes the views it opened, and only those; a finished load
/// closes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_load_closes_that_pages_views_and_no_other() {
    // Both sessions' descriptors live in the one host tree the application reads.
    let mut first = ScriptedWorker::start(Challenge::Answered);
    let mut second = ScriptedWorker::start_beside(&first, Challenge::Answered);
    let page_view = Page::with_pages(first.paths(), &["main", "other"]);
    let _main = page_view.open_from("main", first.session_id, 10, 2, 3);
    let mut main_link = first.link().await;
    main_link.attach().await;
    let _other = page_view.open_from("other", second.session_id, 10, 2, 4);
    let mut other_link = second.link().await;
    other_link.attach().await;
    page_view.state(3, 0).await;
    page_view.state(4, 0).await;
    assert_eq!(page_view.held(), 2);

    let views = page_view
        .app
        .state::<companion_tauri::terminal::TerminalViews>();
    views.page_load("other", tauri::webview::PageLoadEvent::Finished);
    views.page_load("main", tauri::webview::PageLoadEvent::Started);
    let sent = main_link.closed().await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].method, Method::SessionDetach.to_string());
    page_view.held_becomes(1).await;
    assert!(
        other_link.quiet_for(QUIET).await,
        "the other page's view is left open"
    );
    assert_eq!(
        page_view.states(3).len(),
        1,
        "nothing is published to a page that is gone"
    );
}

/// Each view publishes on its own channel, and one session's screen never reaches another's view.
#[tokio::test(flavor = "multi_thread")]
async fn one_views_states_never_reach_another_views_channel() {
    let mut first = ScriptedWorker::start(Challenge::Answered);
    let mut second = ScriptedWorker::start_beside(&first, Challenge::Answered);
    let page_view = Page::new(first.paths());
    let _one = page_view.open(first.session_id, 10, 1, 5);
    let mut one = first.link().await;
    one.attach().await;
    let _two = page_view.open(second.session_id, 10, 1, 6);
    let mut two = second.link().await;
    two.attach().await;
    screen(&mut one, 1, 40, vec![row(0, "one")], 0).await;
    screen(&mut two, 1, 40, vec![row(0, "two")], 0).await;
    assert_eq!(text_of(&page_view.state(5, 1).await), vec!["one"]);
    assert_eq!(text_of(&page_view.state(6, 1).await), vec!["two"]);
    assert_eq!(page_view.states(5).len(), 2);
    assert_eq!(page_view.states(6).len(), 2);
}

/// A control character in a run reaches no piece the page is sent.
#[tokio::test(flavor = "multi_thread")]
async fn control_characters_never_reach_the_page() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let _view = page_view.open(worker.session_id, 10, 1, 3);
    let mut link = worker.link().await;
    link.attach().await;
    let text = "a\u{7}b\u{1b}[6nc";
    let mut hostile = row(0, text);
    hostile.runs[0].cells = kr_protocol::scalars::U64::new(kr_width::cells_for(text) as u64);
    screen(&mut link, 1, 40, vec![hostile], 0).await;
    let shown = page_view.state(3, 1).await;
    let drawn = text_of(&shown).join("");
    assert!(
        drawn.chars().all(|scalar| !scalar.is_control()),
        "no control character in {drawn:?}"
    );
    assert!(
        drawn.contains('a') && drawn.contains('c'),
        "the text around them is kept: {drawn:?}"
    );
}

/// The host's answer to an accepted size report: the window stays at the live screen's first line
/// and column, and the report left it at `window_revision`.
fn viewport_answer(window_revision: u64) -> kr_protocol::attachment::AttachmentViewportResult {
    viewport_answer_shown(
        window_revision,
        kr_protocol::attachment::TerminalPresentationMode::Viewport,
        Some(kr_protocol::attachment::PresentationReason::SizeMismatch),
    )
}

/// The same answer, for a report that left the attachment shown as `presentation` for `reason`.
fn viewport_answer_shown(
    window_revision: u64,
    presentation: kr_protocol::attachment::TerminalPresentationMode,
    reason: Option<kr_protocol::attachment::PresentationReason>,
) -> kr_protocol::attachment::AttachmentViewportResult {
    kr_protocol::attachment::AttachmentViewportResult {
        geometry: kr_protocol::attachment::GeometryState {
            owner: kr_protocol::scalars::Nullable::null(),
            epoch: kr_protocol::ids::GeometryEpoch::new(1),
            dimensions: Dimensions::new(80, 24),
        },
        presentation,
        presentation_reason: kr_protocol::scalars::Nullable(reason),
        position: kr_protocol::scalars::Nullable::null(),
        column: kr_protocol::scalars::U64::ZERO,
        window_revision: kr_protocol::scalars::U64::new(window_revision),
    }
}

fn resync_marker(cursor: u64) -> Value {
    json!({
        "reason": "projection_reset",
        "cursor": cursor.to_string(),
        "oldest_retained_cursor": "0",
    })
}

// ---- The window moves ------------------------------------------------------------------------

impl Page {
    /// Moves `view`'s window by `across` columns and `down` rows, as the page's move `number`.
    fn pan(&self, view: &str, number: u64, across: i64, down: i64) {
        self.invoke(
            "main",
            "terminal_view_move",
            json!({"view": view, "number": number, "across": across, "down": down, "live": false}),
        )
        .expect("the move is taken");
    }

    /// Brings `view`'s window back to the live screen, as the page's move `number`.
    fn live(&self, view: &str, number: u64) {
        self.invoke(
            "main",
            "terminal_view_move",
            json!({"view": view, "number": number, "across": 0, "down": 0, "live": true}),
        )
        .expect("the return is taken");
    }

    /// The newest state `channel` has been sent, once it is one `holds` accepts, and none when no
    /// state of that kind comes within [`STATE_BOUND`]: a case that must fail by an assertion of
    /// its own, and not by the harness's watchdog, asks for a state this way.
    async fn newest_within(&self, channel: u32, holds: impl Fn(&Value) -> bool) -> Option<Value> {
        tokio::time::timeout(STATE_BOUND, async {
            loop {
                if let Some(state) = self.states(channel).last()
                    && holds(state)
                {
                    return state.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .ok()
    }

    /// The newest state `channel` has been sent, once it is one `holds` accepts.
    async fn newest(&self, channel: u32, holds: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                if let Some(state) = self.states(channel).last()
                    && holds(state)
                {
                    return state.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a state on channel {channel} within the watchdog; the newest was {:?}",
                self.states(channel).last()
            )
        })
    }
}

/// A view of `at`'s window size, attached and showing `at`.
async fn panned(
    page: &Page,
    worker: &mut ScriptedWorker,
    channel: u32,
    at: &Frame,
) -> (String, Link) {
    let view = page.open(
        worker.session_id,
        at.window_columns,
        at.window_rows,
        channel,
    );
    let mut link = worker.link().await;
    link.attach().await;
    frame(&mut link, at).await;
    page.newest(channel, |state| state["state"] == "showing")
        .await;
    (view, link)
}

/// The view's next viewport report, and what it asks for.
async fn report(link: &mut Link) -> (scripted_worker::Call, AttachmentViewportParams) {
    let call = link.expect(Method::AttachmentViewport).await;
    let asked: AttachmentViewportParams = call.params();
    (call, asked)
}

/// Whether a state tells the page its moves up to `number` are settled.
fn settled(state: &Value, number: u64) -> bool {
    state["settled"].as_u64() == Some(number)
}

/// Where a published screen says its window is: its column, its line, and how far above the live
/// screen it starts.
fn place(state: &Value) -> (u64, u64, u64) {
    let window = &state["screen"]["window"];
    (
        window["column"].as_u64().expect("a column"),
        window["line"].as_u64().expect("a line"),
        window["above"].as_u64().expect("a distance above"),
    )
}

fn line_position(line: u64) -> Option<kr_protocol::attachment::ViewportPosition> {
    Some(kr_protocol::attachment::ViewportPosition::Line(
        kr_protocol::scalars::U64::new(line),
    ))
}

fn row_position(row: u64) -> Option<kr_protocol::attachment::ViewportPosition> {
    Some(kr_protocol::attachment::ViewportPosition::Row(
        kr_protocol::scalars::U64::new(row),
    ))
}

fn above_position(rows: u64) -> Option<kr_protocol::attachment::ViewportPosition> {
    Some(kr_protocol::attachment::ViewportPosition::Above(
        kr_protocol::scalars::U64::new(rows),
    ))
}

/// A session of 20 columns and 6 rows, with 30 rows kept above its live screen, and a view of 10
/// by 2 at its live screen's first line.
fn wide_session() -> Frame {
    Frame::live((20, 6), (10, 2), 30)
}

/// KR-REQ-08.75: a move goes from where the window is, at the size the view last reported, and is
/// settled by the screen its answer names: the page is told only with that screen, which says
/// where the window now is and how far it can still go.
#[tokio::test(flavor = "multi_thread")]
async fn a_move_goes_from_where_the_window_is_and_settles_on_its_named_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 3, 0);
    let (call, asked) = report(&mut link).await;
    assert_eq!(
        asked.dimensions,
        Dimensions::new(10, 2),
        "the size last reported"
    );
    assert_eq!(asked.position.0, None, "still the live screen's first line");
    assert_eq!(asked.column.get(), 3);
    link.answer(&call, &viewport_answer(1)).await;
    assert!(
        link.quiet_for(QUIET).await,
        "one report at a time, and none owed"
    );
    assert!(
        !settled(page_view.states(3).last().expect("a state"), 1),
        "an answer alone settles nothing the page draws"
    );
    frame(&mut link, &at.at(0, 3).revision(1)).await;
    let moved = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(moved["state"], "showing");
    assert_eq!(place(&moved), (3, 0, 0));
    assert_eq!(
        moved["screen"]["room"],
        json!({"up": 30, "down": 4, "left": 3, "right": 7})
    );
    assert_eq!(text_of(&moved)[0], "defghijklm", "columns 3 to 12");
}

/// A repaint of the old place, queued before the report, is not the report's screen: it is drawn,
/// and the move stays unsettled until the screen its answer names arrives.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_repaint_does_not_settle_a_move() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    let before = page_view.states(3).len();
    let mut repaint = at;
    repaint.generation = 2;
    frame(&mut link, &repaint).await;
    let drawn = page_view
        .newest(3, |state| {
            page_view.states(3).len() > before && state["state"] == "showing"
        })
        .await;
    assert_eq!(place(&drawn), (0, 0, 0), "the repaint is drawn where it is");
    assert!(settled(&drawn, 0), "and settles nothing");
    link.answer(&call, &viewport_answer(1)).await;
    assert!(link.quiet_for(QUIET).await);
    assert!(settled(page_view.states(3).last().expect("a state"), 0));
    frame(&mut link, &at.at(0, 2).revision(1)).await;
    let moved = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(place(&moved), (2, 0, 0));
}

/// A screen drawn for an earlier revision than the newest answer is drawn, but it never moves the
/// record of where the window is: the next move goes from where the named screen put the window.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_screen_after_the_answer_never_moves_the_record() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 4, 0);
    let (call, _) = report(&mut link).await;
    link.answer(&call, &viewport_answer(1)).await;
    frame(&mut link, &at.at(0, 4).revision(1)).await;
    page_view.newest(3, |state| settled(state, 1)).await;
    let mut late = at;
    late.generation = 2;
    frame(&mut link, &late).await;
    page_view
        .newest(3, |state| {
            state["state"] == "showing" && place(state) == (0, 0, 0)
        })
        .await;
    page_view.pan(&view, 2, 1, 0);
    let (_, asked) = report(&mut link).await;
    assert_eq!(
        asked.column.get(),
        5,
        "from the named screen's column 4, not the late 0"
    );
}

/// A screen that arrives before its report's answer might be that report's, so it waits for the
/// answer and is drawn with it; once a report has its answer, its screen is drawn as it comes.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_before_its_answer_is_drawn_with_the_answer() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    frame(&mut link, &at.at(0, 2).revision(1)).await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        page_view.states(3).last().expect("a state")["state"],
        "waiting",
        "its reset is told, and the screen, newer than any answer, waits for the answer"
    );
    link.answer(&call, &viewport_answer(1)).await;
    let moved = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(moved["state"], "showing");
    assert_eq!(place(&moved), (2, 0, 0));

    page_view.pan(&view, 2, 1, 0);
    let (call, asked) = report(&mut link).await;
    assert_eq!(asked.column.get(), 3);
    link.answer(&call, &viewport_answer(2)).await;
    // The host changed the window again after this report, so the screen names a later revision.
    frame(&mut link, &at.at(0, 3).revision(3)).await;
    let again = page_view.newest(3, |state| settled(state, 2)).await;
    assert_eq!(
        place(&again),
        (3, 0, 0),
        "drawn as it came, its answer already heard"
    );
}

/// A refusal releases a screen that waited for its answer: nothing moved, so the move is settled
/// with it, and the screen is the host's own change. A view that ends while a screen waits
/// publishes its end.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_or_the_end_releases_a_waiting_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    frame(&mut link, &at.at(1, 0).revision(1)).await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        page_view.states(3).last().expect("a state")["state"],
        "waiting"
    );
    link.refuse(&call, "that window is not one this session shows")
        .await;
    let released = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(released["state"], "showing");
    assert_eq!(place(&released), (0, 1, 0), "the host's own change");

    page_view.pan(&view, 2, 2, 0);
    let _ = report(&mut link).await;
    frame(&mut link, &at.at(1, 2).revision(2)).await;
    tokio::time::sleep(QUIET).await;
    link.push(
        kr_protocol::session::SESSION_CLOSED_EVENT,
        &json!({"session_id": worker.session_id.to_string()}),
    )
    .await;
    let ended = page_view.newest(3, |state| state["state"] == "ended").await;
    assert_eq!(ended["reason"], "This session has closed.");
}

/// A size the page measures between the host's reset and the last page of the screen that
/// follows it waits for that screen, and goes with where it puts the window: a canonical resize
/// can move the window's column.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_measured_during_a_reset_goes_from_the_screen_that_follows() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session().at(0, 8);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    link.push(
        PROJECTION_RESET_EVENT,
        &reset(2, 60, ProjectionResetReason::BufferSwitch, 0),
    )
    .await;
    page_view
        .newest(3, |state| state["state"] == "waiting")
        .await;
    page_view.resize(&view, 9, 2);
    assert!(
        link.quiet_for(QUIET).await,
        "nothing goes until the screen is whole"
    );
    let mut narrower = Frame::live((15, 6), (10, 2), 30).at(0, 5);
    narrower.generation = 2;
    frame(&mut link, &narrower).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.dimensions, Dimensions::new(9, 2));
    assert_eq!(asked.column.get(), 5, "where the new screen put the window");
}

/// A screen that was waiting for its answer and was then discarded, by the host's reset or by the
/// view's own recovery, settles its report inside the view; the page hears of the move only with
/// the next frame, which holds it.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_discarded_before_its_answer_is_told_with_the_next_frame() {
    for recovery in [false, true] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let at = wide_session();
        let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
        page_view.pan(&view, 1, 2, 0);
        let (call, _) = report(&mut link).await;
        frame(&mut link, &at.at(0, 2).revision(1)).await;
        let mut next = at.at(0, 2).revision(1);
        next.generation = 2;
        if recovery {
            link.push("session.resync", &resync_marker(60)).await;
            let subscribe = link.expect(Method::EventsSubscribe).await;
            let waiting = page_view
                .newest(3, |state| state["state"] == "waiting")
                .await;
            assert!(settled(&waiting, 0), "recovery {recovery}");
            link.answer(&call, &viewport_answer(1)).await;
            link.answer(&subscribe, &scripted_worker::subscribed())
                .await;
            tokio::time::sleep(QUIET).await;
            assert!(
                settled(page_view.states(3).last().expect("a state"), 0),
                "recovery {recovery}: no frame holds the move yet"
            );
            link.restart_stream();
        } else {
            link.push(
                PROJECTION_RESET_EVENT,
                &reset(2, 60, ProjectionResetReason::BufferSwitch, 1),
            )
            .await;
            let waiting = page_view
                .newest(3, |state| state["state"] == "waiting")
                .await;
            assert!(settled(&waiting, 0), "recovery {recovery}");
            link.answer(&call, &viewport_answer(1)).await;
            tokio::time::sleep(QUIET).await;
            assert!(
                settled(page_view.states(3).last().expect("a state"), 0),
                "recovery {recovery}: no frame holds the move yet"
            );
        }
        frame(&mut link, &next).await;
        let moved = page_view.newest(3, |state| settled(state, 1)).await;
        assert_eq!(moved["state"], "showing", "recovery {recovery}");
        assert_eq!(place(&moved), (2, 0, 0), "recovery {recovery}");
        let _ = view;
    }
}

/// A new size goes with where the window is, and is settled by the next subscription's first
/// screen, from which the moves made meanwhile go.
#[tokio::test(flavor = "multi_thread")]
async fn a_size_change_settles_on_the_next_subscriptions_first_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session().at(0, 3);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.resize(&view, 12, 2);
    let (call, asked) = report(&mut link).await;
    assert_eq!(asked.dimensions, Dimensions::new(12, 2));
    assert_eq!(
        (asked.position.0, asked.column.get()),
        (None, 3),
        "where the window is"
    );
    page_view.pan(&view, 1, 1, 0);
    link.answer(&call, &viewport_answer(1)).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    assert!(
        link.quiet_for(QUIET).await,
        "nothing goes while the screen is asked for"
    );
    link.restart_stream();
    let mut wider = at.revision(1);
    wider.window_columns = 12;
    frame(&mut link, &wider).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.dimensions, Dimensions::new(12, 2));
    assert_eq!(asked.column.get(), 4, "the move goes from the new screen");
}

/// The host brought a window in the history back to the live screen while the view was taking a
/// new screen: that screen names the host's change, and the moves made meanwhile go from the live
/// screen.
#[tokio::test(flavor = "multi_thread")]
async fn a_buffer_switch_during_a_resynchronisation_takes_the_record_to_the_live_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let history = wide_session().in_history(20, 0);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &history).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    page_view.pan(&view, 1, 0, -2);
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    frame(&mut link, &wide_session().revision(1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(
        asked.position.0,
        above_position(2),
        "two rows above the live screen"
    );
}

/// The session gave its oldest rows up while the view was taking a new screen, which shows the
/// window from the oldest row left at the same revision: the moves made meanwhile go from there.
#[tokio::test(flavor = "multi_thread")]
async fn an_eviction_during_a_resynchronisation_moves_the_record_to_the_oldest_row() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let history = wide_session().in_history(5, 0);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &history).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    page_view.pan(&view, 1, 0, 3);
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    let mut evicted = wide_session().in_history(10, 0);
    evicted.oldest = 10;
    frame(&mut link, &evicted).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(
        asked.position.0,
        row_position(13),
        "from the oldest row left"
    );
}

/// A move the window cannot make at the top of the history is spent and takes nothing with it:
/// the move back after it goes from where the window is.
#[tokio::test(flavor = "multi_thread")]
async fn reversing_moves_at_the_top_of_the_history_with_a_report_outstanding() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let history = wide_session().in_history(2, 0);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &history).await;
    page_view.pan(&view, 1, 0, -5);
    let (call, asked) = report(&mut link).await;
    assert_eq!(asked.position.0, row_position(0), "held at the oldest row");
    page_view.pan(&view, 2, 0, -3);
    page_view.pan(&view, 3, 0, 4);
    assert!(link.quiet_for(QUIET).await, "one report at a time");
    link.answer(&call, &viewport_answer(1)).await;
    frame(&mut link, &wide_session().in_history(0, 0).revision(1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(
        asked.position.0,
        row_position(4),
        "the spent move took nothing with it"
    );
    page_view.newest(3, |state| settled(state, 2)).await;
}

/// The same at the live screen's last line that still fills the window.
#[tokio::test(flavor = "multi_thread")]
async fn reversing_moves_at_the_live_screens_last_line_with_a_report_outstanding() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session().at(3, 0);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 0, 3);
    let (call, asked) = report(&mut link).await;
    assert_eq!(asked.position.0, line_position(4), "held at the last line");
    page_view.pan(&view, 2, 0, 2);
    page_view.pan(&view, 3, 0, -1);
    link.answer(&call, &viewport_answer(1)).await;
    frame(&mut link, &wide_session().at(4, 0).revision(1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.position.0, line_position(3));
}

/// The same at both edges of a grid wider than the view.
#[tokio::test(flavor = "multi_thread")]
async fn reversing_moves_at_both_column_limits_with_a_report_outstanding() {
    for (from, first, beyond, back, limit, then) in [(1, -3, -2, 4, 0, 4), (9, 3, 1, -2, 10, 8)] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let at = wide_session().at(0, from);
        let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
        page_view.pan(&view, 1, first, 0);
        let (call, asked) = report(&mut link).await;
        assert_eq!(asked.column.get(), limit, "held at the edge");
        page_view.pan(&view, 2, beyond, 0);
        page_view.pan(&view, 3, back, 0);
        link.answer(&call, &viewport_answer(1)).await;
        frame(&mut link, &wide_session().at(0, limit).revision(1)).await;
        let (_, asked) = report(&mut link).await;
        assert_eq!(asked.column.get(), then, "from {from}");
    }
}

/// The alternate buffer numbers its own rows and keeps no history: a move up from its first line
/// is spent, and nothing is sent.
#[tokio::test(flavor = "multi_thread")]
async fn the_alternate_buffer_keeps_no_history_to_move_into() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut alternate = Frame::live((20, 6), (10, 2), 0);
    alternate.buffer = kr_protocol::projection::ProjectedBuffer::Alternate;
    let (view, mut link) = panned(&page_view, &mut worker, 3, &alternate).await;
    let shown = page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    assert_eq!(shown["screen"]["room"]["up"], 0);
    page_view.pan(&view, 1, 0, -3);
    assert!(link.quiet_for(QUIET).await, "nothing to send");
    page_view.newest(3, |state| settled(state, 1)).await;
}

/// Output that scrolls the live screen between a screen and the report sent from it: a move from
/// the history onto the live screen is measured from the newest live screen the view holds.
#[tokio::test(flavor = "multi_thread")]
async fn output_between_a_screen_and_its_report_moves_the_live_screen_it_is_measured_from() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let history = wide_session().in_history(25, 0);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &history).await;
    let mut scrolled = history;
    scrolled.live_top = 33;
    link.push(PROJECTION_DELTA_EVENT, &frame_delta(&scrolled, 40, 50))
        .await;
    page_view
        .newest(3, |state| state["screen"]["room"]["down"] == json!(12))
        .await;
    page_view.pan(&view, 1, 0, 10);
    let (_, asked) = report(&mut link).await;
    assert_eq!(
        asked.position.0,
        line_position(2),
        "row 35, the third line of the live screen"
    );
}

/// A refused move changes nothing and is settled at once; the newer size that waited behind it
/// goes next, with where the window is.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_move_while_a_newer_size_waits() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session().at(0, 1);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    page_view.resize(&view, 12, 2);
    link.refuse(&call, "that window is not one this session shows")
        .await;
    page_view.newest(3, |state| settled(state, 1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.dimensions, Dimensions::new(12, 2));
    assert_eq!(asked.column.get(), 1, "where the window still is");
}

/// A move is the person's gesture, not an owed report: one the session refuses for now is settled
/// as not taken, as a refusal is, and is not made later; the person moves again.
#[tokio::test(flavor = "multi_thread")]
async fn a_move_the_session_refuses_for_now_is_settled_and_not_made_later() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    link.refuse_with(&call, ErrorCode::ResourceUnavailable, "not now")
        .await;
    let back = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(place(&back), (0, 0, 0), "nothing moved");
    let mut repaint = at;
    repaint.generation = 2;
    frame(&mut link, &repaint).await;
    assert!(
        link.quiet_for(QUIET).await,
        "the move is not made later, whatever the session says"
    );
}

/// While the view takes a new screen it holds no record of where the window is, so a move waits
/// for that screen and goes from it.
#[tokio::test(flavor = "multi_thread")]
async fn moves_during_a_recovery_wait_for_the_record() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session();
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    page_view.pan(&view, 1, 2, 0);
    assert!(link.quiet_for(QUIET).await, "no record to move from");
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    frame(&mut link, &at.at(0, 1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.column.get(), 3, "from the new screen's column");
}

/// A return brings a window in the history back to the live screen's first line at its column,
/// leaves a window on the live screen where it is, and waits for a move still in flight.
#[tokio::test(flavor = "multi_thread")]
async fn a_return_brings_the_history_back_and_leaves_the_live_screen_where_it_is() {
    // From the history.
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let history = wide_session().in_history(20, 3);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &history).await;
    page_view.live(&view, 1);
    let (call, asked) = report(&mut link).await;
    assert_eq!((asked.position.0, asked.column.get()), (None, 3));
    link.answer(&call, &viewport_answer(1)).await;
    frame(&mut link, &wide_session().at(0, 3).revision(1)).await;
    let back = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(place(&back), (3, 0, 0));

    // From the live screen: nothing to send, and settled at once.
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &wide_session().at(2, 3)).await;
    page_view.live(&view, 1);
    assert!(
        link.quiet_for(QUIET).await,
        "a live window stays where it is"
    );
    page_view.newest(3, |state| settled(state, 1)).await;

    // Behind a move into the history that is still in flight.
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &wide_session()).await;
    page_view.pan(&view, 1, 0, -5);
    let (call, asked) = report(&mut link).await;
    assert_eq!(asked.position.0, above_position(5));
    page_view.live(&view, 2);
    assert!(link.quiet_for(QUIET).await, "the return waits its turn");
    link.answer(&call, &viewport_answer(1)).await;
    frame(&mut link, &wide_session().in_history(25, 0).revision(1)).await;
    let (_, asked) = report(&mut link).await;
    assert_eq!(asked.position.0, None, "then back to the live screen");
}

/// A view that ends with moves outstanding publishes its end, which settles them all, and sends
/// nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn the_view_ending_with_moves_outstanding_publishes_its_end() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &wide_session()).await;
    page_view.pan(&view, 1, 2, 0);
    let _ = report(&mut link).await;
    page_view.pan(&view, 2, 1, 0);
    link.push(
        kr_protocol::session::SESSION_CLOSED_EVENT,
        &json!({"session_id": worker.session_id.to_string()}),
    )
    .await;
    let ended = page_view.newest(3, |state| state["state"] == "ended").await;
    assert_eq!(ended["reason"], "This session has closed.");
    assert!(link.closed().await.is_empty(), "nothing more is sent");
}

/// KR-REQ-08.75: every screen says where its window starts and how far it can still move: from
/// the history and from a line of the live screen.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_says_where_its_window_is_and_how_far_it_can_move() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut kept = wide_session().in_history(25, 4);
    kept.oldest = 10;
    let (_view, _link) = panned(&page_view, &mut worker, 3, &kept).await;
    let shown = page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    assert_eq!(place(&shown), (4, 0, 5));
    assert_eq!(
        shown["screen"]["room"],
        json!({"up": 15, "down": 9, "left": 4, "right": 6})
    );

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut live = wide_session().at(3, 0);
    live.oldest = 10;
    let (_view, _link) = panned(&page_view, &mut worker, 3, &live).await;
    let shown = page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    assert_eq!(place(&shown), (0, 3, 0));
    assert_eq!(
        shown["screen"]["room"],
        json!({"up": 23, "down": 1, "left": 0, "right": 10})
    );
}

// ---- The person's input ----------------------------------------------------------------------

impl Page {
    /// Sends `input` to `view`, as the page does.
    fn input(&self, view: &str, input: Value) -> Result<Value, Value> {
        self.invoke(
            "main",
            "terminal_view_input",
            json!({"view": view, "input": input}),
        )
    }

    /// Takes control of `view` as the page's control request `number`.
    fn take(&self, view: &str, number: u64) {
        self.input(view, json!({"kind": "take", "number": number}))
            .expect("the take is taken");
    }

    /// Gives control of `view` back as the page's control request `number`.
    fn release(&self, view: &str, number: u64) {
        self.input(view, json!({"kind": "release", "number": number}))
            .expect("the release is taken");
    }

    /// Turns the program's wheel `turns` times at canonical `column` and `line`, as made under the
    /// page's take `take`.
    fn wheel(
        &self,
        view: &str,
        take: u64,
        column: u32,
        line: u32,
        turns: i32,
    ) -> Result<Value, Value> {
        self.input(
            view,
            json!({
                "kind": "wheel", "take": take, "column": column, "line": line, "turns": turns,
                "shift": false, "alt": false, "control": false,
            }),
        )
    }

    /// Sends `text` that came with no key, as made under the page's take `take`.
    fn text(&self, view: &str, take: u64, text: &str) -> Result<Value, Value> {
        self.input(view, json!({"kind": "text", "take": take, "text": text}))
    }

    /// Pastes `text`, as made under the page's take `take`.
    fn paste(&self, view: &str, take: u64, text: &str) -> Result<Value, Value> {
        self.input(view, json!({"kind": "paste", "take": take, "text": text}))
    }
}

/// A key input, made under the page's take `take`: `key` (a character or a key's name) with the
/// modifiers and locks `held` names ("shift", "alt", "control", "caps_lock", "num_lock"), as `event`
/// ("press", "repeat" or "release"), with no base character and no keypad key.
fn key(take: u64, key: &str, held: &[&str], event: &str) -> Value {
    json!({
        "kind": "key", "take": take, "key": key, "base": null, "keypad": null,
        "shift": held.contains(&"shift"), "alt": held.contains(&"alt"),
        "control": held.contains(&"control"), "caps_lock": held.contains(&"caps_lock"),
        "num_lock": held.contains(&"num_lock"), "event": event,
    })
}

/// The same key input, naming the unshifted character `base`.
fn based(mut input: Value, base: &str) -> Value {
    input["base"] = json!(base);
    input
}

/// The same key input, from the keypad key at `code`.
fn on_keypad(mut input: Value, code: &str) -> Value {
    input["keypad"] = json!(code);
    input
}

/// Which control request a state answers, and what it says of control.
fn control(state: &Value) -> (u64, String) {
    (
        state["control"]["number"]
            .as_u64()
            .expect("a request number"),
        state["control"]["state"]
            .as_str()
            .expect("a control state")
            .to_owned(),
    )
}

/// The code a command was refused with.
fn code(refusal: &Value) -> &str {
    refusal["code"].as_str().expect("a refusal's code")
}

/// The newest state `channel` has been sent.
fn newest_now(page: &Page, channel: u32) -> Value {
    page.states(channel).last().cloned().expect("a state")
}

/// A session of 20 columns and 6 rows whose program reports the mouse as `mouse` says, shown to a
/// view of 10 by 2 at its live screen's first line.
fn reporting(mouse: Mouse) -> Frame {
    Frame::live((20, 6), (10, 2), 0).reporting(mouse)
}

/// A view showing `at` whose control the page took as its request 1, and the worker gave it.
async fn controlling(
    page: &Page,
    worker: &mut ScriptedWorker,
    channel: u32,
    at: &Frame,
    lease: &mut WorkerLease,
) -> (String, Link) {
    let (view, mut link) = panned(page, worker, channel, at).await;
    page.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    page.newest(channel, |state| {
        control(state) == (1, "controlling".to_owned())
    })
    .await;
    (view, link)
}

/// KR-REQ-13.18: taking control is one acquire, sent as a mutation with no expected epoch, an
/// immediate takeover. The page is told at once that the view is taking control, and that it
/// controls the program once the session answers; a second take while the first is in flight asks
/// nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn taking_control_acquires_once() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &reporting(Mouse::Sgr)).await;
    page_view.take(&view, 1);
    let taking = page_view
        .newest(3, |state| control(state) == (1, "taking".to_owned()))
        .await;
    assert_eq!(taking["state"], "showing", "the screen goes on showing");
    let acquire = link.expect(Method::InputAcquire).await;
    assert_eq!(acquire.kind, CallKind::Mutation);
    let asked: InputAcquireParams = acquire.params();
    assert_eq!(asked.session_id, worker.session_id);
    assert_eq!(asked.expected_epoch.0, None, "an immediate takeover");
    page_view.take(&view, 2);
    assert!(
        link.quiet_for(QUIET).await,
        "one acquire in flight at a time"
    );
    let mut lease = WorkerLease::at(4);
    lease.answer(&mut link, &acquire).await;
    let held = page_view
        .newest(3, |state| control(state) == (2, "controlling".to_owned()))
        .await;
    assert_eq!(held["control"]["ended"], Value::Null);
    assert_eq!(lease.holder, Some(asked.attachment_id));
    assert!(
        link.quiet_for(QUIET).await,
        "and nothing more once it is held"
    );
}

/// KR-REQ-08.76, KR-REQ-13.18: a wheel turn at a canonical cell is one wheel event there, never an
/// arrow key, in the encoding the program asked for, written as a request under the lease's epoch
/// at the stream's next number; each turn of an input is one event, and the next input takes the
/// next number.
#[tokio::test(flavor = "multi_thread")]
async fn a_wheel_turn_is_one_wheel_event_at_its_cell_under_the_epoch_and_next_number() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    page_view
        .wheel(&view, 1, 7, 1, 1)
        .expect("the turn is taken");
    let write = link.expect(Method::InputWrite).await;
    assert_eq!(
        write.kind,
        CallKind::Request,
        "input is an ordered stream, not a mutation"
    );
    let asked: InputWriteParams = write.params();
    assert_eq!(asked.epoch.get(), 5);
    assert_eq!(asked.sequence.get(), 0);
    assert_eq!(
        written(&asked),
        b"\x1b[<65;8;2M",
        "the wheel turned down, at column 8 and row 2 counted from 1"
    );
    lease.answer(&mut link, &write).await;
    page_view
        .wheel(&view, 1, 0, 5, -2)
        .expect("the turns are taken");
    let write = link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!(asked.sequence.get(), 1);
    assert_eq!(
        written(&asked),
        b"\x1b[<64;1;6M\x1b[<64;1;6M",
        "two turns up are two events"
    );
    lease.answer(&mut link, &write).await;
    assert_eq!(lease.written.len(), 2);
    assert!(link.quiet_for(QUIET).await);
}

/// Shift, Alt and Control go with the wheel as the report's own bits.
#[tokio::test(flavor = "multi_thread")]
async fn the_modifiers_go_with_the_wheel() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    for (shift, alt, held_control, button) in [
        (true, false, false, 69),
        (false, true, false, 73),
        (false, false, true, 81),
        (true, true, true, 93),
    ] {
        page_view
            .input(
                &view,
                json!({
                    "kind": "wheel", "take": 1, "column": 0, "line": 0, "turns": 1,
                    "shift": shift, "alt": alt, "control": held_control,
                }),
            )
            .expect("the turn is taken");
        let write = link.expect(Method::InputWrite).await;
        let asked: InputWriteParams = write.params();
        assert_eq!(written(&asked), format!("\x1b[<{button};1;1M").as_bytes());
        lease.answer(&mut link, &write).await;
    }
}

/// Without 1006 the wheel goes in the original report, which carries a column as far as 223
/// counted from 1: a turn past it sends nothing and leaves control as it was.
#[tokio::test(flavor = "multi_thread")]
async fn the_original_report_carries_the_wheel_as_far_as_its_range() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let at = Frame::live((300, 6), (10, 2), 0).reporting(Mouse::Original);
    let (view, mut link) = controlling(&page_view, &mut worker, 3, &at, &mut lease).await;
    page_view
        .wheel(&view, 1, 222, 0, 1)
        .expect("the turn is taken");
    let write = link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!(
        written(&asked),
        &[0x1b, b'[', b'M', 65 + 32, 223 + 32, 1 + 32]
    );
    lease.answer(&mut link, &write).await;
    page_view
        .wheel(&view, 1, 223, 0, 1)
        .expect("the turn is taken, and nothing is written");
    assert!(
        link.quiet_for(QUIET).await,
        "the original report has no room for column 224"
    );
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (1, "controlling".to_owned())
    );
    page_view
        .wheel(&view, 1, 3, 1, -1)
        .expect("the turn is taken");
    let write = link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!(asked.sequence.get(), 1, "nothing was written in between");
    assert_eq!(
        written(&asked),
        &[0x1b, b'[', b'M', 64 + 32, 4 + 32, 2 + 32]
    );
}

/// KR-REQ-13.18: a program that does not report the mouse is sent nothing, and neither is one that
/// asks for an encoding the view does not write; the page is told which, as the program changes it.
/// A cell outside the session's grid is sent nothing either.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_reaches_a_program_that_does_not_read_the_wheel_from_this_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let at = reporting(Mouse::Off);
    let (view, mut link) = controlling(&page_view, &mut worker, 3, &at, &mut lease).await;
    assert_eq!(newest_now(&page_view, 3)["screen"]["wheel"], "unreported");
    page_view
        .wheel(&view, 1, 1, 1, 3)
        .expect("the turns are taken");
    assert!(link.quiet_for(QUIET).await);
    link.push(
        PROJECTION_DELTA_EVENT,
        &mouse_delta(&at, 40, 41, Mouse::Utf8),
    )
    .await;
    page_view
        .newest(3, |state| state["screen"]["wheel"] == "unwritable")
        .await;
    page_view
        .wheel(&view, 1, 1, 1, 3)
        .expect("the turns are taken");
    assert!(link.quiet_for(QUIET).await);
    link.push(
        PROJECTION_DELTA_EVENT,
        &mouse_delta(&at, 41, 42, Mouse::Sgr),
    )
    .await;
    page_view
        .newest(3, |state| state["screen"]["wheel"] == "reaches")
        .await;
    page_view
        .wheel(&view, 1, 20, 1, 1)
        .expect("the turn is taken");
    page_view
        .wheel(&view, 1, 1, 6, 1)
        .expect("the turn is taken");
    assert!(
        link.quiet_for(QUIET).await,
        "a cell outside the session's grid has no effect"
    );
    page_view
        .wheel(&view, 1, 19, 5, 1)
        .expect("the turn is taken");
    let write = link.expect(Method::InputWrite).await;
    assert_eq!(
        written(&write.params::<InputWriteParams>()),
        b"\x1b[<65;20;6M"
    );
}

/// KR-REQ-13.18: `LEASE_LOST` ends control, and the page is told why. The view gives back nothing
/// it no longer holds, and an input made later under that take is refused by the command, the
/// words kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_lease_ends_control_and_says_so() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    lease.taken_over();
    page_view
        .wheel(&view, 1, 1, 1, 1)
        .expect("taken: the view has not heard yet");
    let write = link.expect(Method::InputWrite).await;
    lease.answer(&mut link, &write).await;
    let ended = page_view
        .newest(3, |state| control(state).1 == "watching")
        .await;
    assert_eq!(control(&ended), (1, "watching".to_owned()));
    assert_eq!(
        ended["control"]["ended"],
        "Control ended: another view took it, or the program changed how it reads keys."
    );
    let refused = page_view
        .text(&view, 1, "q")
        .expect_err("the view no longer controls the program");
    assert_eq!(code(&refused), "LEASE_LOST");
    assert!(
        link.quiet_for(QUIET).await,
        "no release of a lease another holds, and no write"
    );
    assert_eq!(
        newest_now(&page_view, 3)["control"]["ended"],
        ended["control"]["ended"],
        "the words stay"
    );
    assert!(lease.written.is_empty());
}

/// Any other refusal of a write ends control too, whether the stream took the write's number or
/// not: the view gives its epoch back, and what it wrote is never written again. Control taken again
/// is a new epoch from the stream's first number.
/// KR-REQ-09.20, the part about a write that was not delivered: a refused write gives its lease
/// epoch back, and the next take is a new epoch with a new sequence, which carries only what the
/// person types after it.
#[tokio::test(flavor = "multi_thread")]
async fn another_refusal_ends_control_and_gives_the_epoch_back() {
    for consumes in [false, true] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let mut lease = WorkerLease::at(4);
        let (view, mut link) = controlling(
            &page_view,
            &mut worker,
            3,
            &reporting(Mouse::Sgr),
            &mut lease,
        )
        .await;
        page_view.text(&view, 1, "a").expect("the text is taken");
        let write = link.expect(Method::InputWrite).await;
        lease
            .refuse_write(
                &mut link,
                &write,
                ErrorCode::ResourceUnavailable,
                "the application is not reading its input",
                consumes,
            )
            .await;
        let ended = page_view
            .newest(3, |state| control(state).1 == "watching")
            .await;
        assert_eq!(
            ended["control"]["ended"],
            "Control ended. The session refused this view's input: the application is not reading its input"
        );
        let release = link.expect(Method::InputRelease).await;
        assert_eq!(release.kind, CallKind::Mutation);
        assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
        lease.answer(&mut link, &release).await;
        assert_eq!(lease.holder, None);
        page_view.take(&view, 2);
        let acquire = link.expect(Method::InputAcquire).await;
        lease.answer(&mut link, &acquire).await;
        page_view
            .newest(3, |state| control(state) == (2, "controlling".to_owned()))
            .await;
        page_view.text(&view, 2, "b").expect("the text is taken");
        let write = link.expect(Method::InputWrite).await;
        lease.answer(&mut link, &write).await;
        assert_eq!(
            lease.written,
            vec![(7, 0, b"b".to_vec())],
            "a refusal that consumed a number ({consumes}) or did not: nothing written twice"
        );
    }
}

/// KR-REQ-09.20, the part about a reconnect: what the person types while a view's link is lost goes
/// nowhere, and a view opened on a new link takes a lease of its own on that connection, writes from
/// the first number of a new input stream, and carries none of what the lost link was sent and never
/// answered, nor anything typed after it was lost.
#[tokio::test(flavor = "multi_thread")]
async fn keystrokes_typed_while_the_link_was_lost_are_never_sent_on_a_new_link() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    let first_connection = link.connection_id();
    assert_eq!(
        lease.connection,
        Some(first_connection),
        "the lease belongs to the connection that took it"
    );
    page_view.text(&view, 1, "a").expect("the text is taken");
    let write = link.expect(Method::InputWrite).await;
    lease.answer(&mut link, &write).await;
    // One more is on the wire when the link goes: delivery of it is uncertain, and it is not sent
    // again on any other link.
    page_view.text(&view, 1, "b").expect("the text is taken");
    let unanswered = link.expect(Method::InputWrite).await;
    assert_eq!(unanswered.params::<InputWriteParams>().sequence.get(), 1);
    drop(link);
    page_view.newest(3, |state| state["state"] == "ended").await;
    let refused = page_view
        .text(&view, 1, "c")
        .expect_err("a view whose link is lost takes no input");
    assert_eq!(code(&refused), "LEASE_LOST");

    // The person opens the session again: a view of its own, on a new connection.
    let (second_view, mut second_link) =
        panned(&page_view, &mut worker, 4, &reporting(Mouse::Sgr)).await;
    assert_ne!(second_link.connection_id(), first_connection);
    page_view.take(&second_view, 1);
    let acquire = second_link.expect(Method::InputAcquire).await;
    lease.answer(&mut second_link, &acquire).await;
    page_view
        .newest(4, |state| control(state) == (1, "controlling".to_owned()))
        .await;
    assert_eq!(
        lease.connection,
        Some(second_link.connection_id()),
        "the new lease is on the new connection"
    );
    page_view
        .text(&second_view, 1, "d")
        .expect("the text is taken");
    let write = second_link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!(
        (asked.epoch.get(), asked.sequence.get(), written(&asked)),
        (6, 0, b"d".as_slice()),
        "a new epoch, and the new stream's first number, carrying only what was typed after"
    );
    lease.answer(&mut second_link, &write).await;
    assert!(
        second_link.quiet_for(QUIET).await,
        "nothing typed before the new link is sent on it"
    );
    assert_eq!(
        lease.written,
        vec![(5, 0, b"a".to_vec()), (6, 0, b"d".to_vec())]
    );
}

/// Looking around gives the lease back at once: the page is told the view watches, the epoch is
/// released, and an input made under the take before it is refused.
#[tokio::test(flavor = "multi_thread")]
async fn looking_around_gives_the_epoch_back_and_stops_writing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    page_view.release(&view, 2);
    let watching = page_view
        .newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    assert_eq!(watching["control"]["ended"], Value::Null);
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    lease.answer(&mut link, &release).await;
    assert_eq!(
        code(
            &page_view
                .wheel(&view, 1, 1, 1, 1)
                .expect_err("the take is over")
        ),
        "LEASE_LOST"
    );
    assert!(link.quiet_for(QUIET).await);
    assert!(lease.written.is_empty());
}

/// Closing a view that controls the program detaches it, which gives the lease back on the host, and
/// writes nothing after.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_controlling_view_detaches_and_writes_nothing_after() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    let holder = lease.holder.expect("the view holds the lease");
    page_view.close(&view);
    let sent = link.closed().await;
    assert_eq!(
        sent.iter()
            .map(|call| call.method.as_str())
            .collect::<Vec<_>>(),
        vec!["session.detach"]
    );
    let detach: SessionDetachParams = sent[0].params();
    assert_eq!(detach.attachment_id.0, Some(holder));
}

/// What native code says of an input it cannot read, or that it reads: the words the scripted host
/// is held to, in the fixture the page's tests read the same cases from.
#[test]
fn native_code_says_why_it_cannot_read_an_input_in_the_words_the_scripted_host_holds() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../test/fixtures/terminal-input-refusals.json"
    ))
    .expect("the cases");
    assert!(cases.len() > 100, "{} cases", cases.len());
    let mut differing = Vec::new();
    for case in cases {
        let read =
            serde_json::from_value::<companion_tauri::terminal::Input>(case["input"].clone());
        let said = match read {
            Ok(_) => Value::Null,
            Err(error) => Value::String(error.to_string()),
        };
        if said != case["words"] {
            differing.push(format!(
                "{}: native code says {said}, not {}",
                case["input"], case["words"]
            ));
        }
    }
    assert!(differing.is_empty(), "{}", differing.join("\n"));
}

/// A number the command layer cannot read as the argument's integer type is worded as the decoder
/// words it, floating point notation included: the scripted host holds its own words to these.
#[tokio::test(flavor = "multi_thread")]
async fn a_number_the_command_layer_cannot_read_is_worded_in_the_decoders_notation() {
    let worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let said = |command: &str, body: &str| {
        let body: Value = serde_json::from_str(body).expect("a body");
        page.invoke("main", command, body).expect_err("refused")
    };
    for (command, body, words) in [
        // Digits past 64 bits are a floating point number to the decoder, and it writes an
        // exponent from 1e16 up and below 1e-5.
        (
            "terminal_view_move",
            r#"{"view":"x","number":18446744073709552000,"across":0,"down":0,"live":true}"#,
            "invalid args `number` for command `terminal_view_move`: invalid type: floating point `1.8446744073709552e+19`, expected u64",
        ),
        // JSON writes 2^63 as 9223372036854776000, an integer the decoder reads and i64 does not hold.
        (
            "terminal_view_move",
            r#"{"view":"x","number":1,"across":9223372036854776000,"down":0}"#,
            "invalid value: integer `9223372036854776000`, expected i64",
        ),
        // The least i64 as JavaScript writes it is past 64 bits too.
        (
            "terminal_view_move",
            r#"{"view":"x","number":1,"across":-9223372036854776000,"down":0}"#,
            "invalid type: floating point `-9.223372036854776e+18`, expected i64",
        ),
        (
            "terminal_view_move",
            r#"{"view":"x","number":1,"across":0,"down":1e+21}"#,
            "invalid type: floating point `1e+21`, expected i64",
        ),
        (
            "terminal_view_resize",
            r#"{"view":"x","columns":1e-7,"rows":24}"#,
            "invalid type: floating point `1e-7`, expected u64",
        ),
        (
            "terminal_view_resize",
            r#"{"view":"x","columns":0.00001,"rows":24}"#,
            "invalid type: floating point `0.00001`, expected u64",
        ),
    ] {
        let refusal = said(command, body);
        let refusal = refusal.as_str().expect("the command layer's words");
        assert!(refusal.ends_with(words), "{body}: {refusal}");
    }
}

/// A wheel that turns no times is refused with the decoder's words, after the command layer's own,
/// as a refusal of the application's own that asks nothing more of the person.
#[tokio::test(flavor = "multi_thread")]
async fn a_wheel_that_turns_no_times_is_refused_in_the_decoders_words() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, _link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    let refusal = page_view
        .input(
            &view,
            json!({"kind": "wheel", "take": 1, "column": 0, "line": 0, "turns": 0,
                   "shift": false, "alt": false, "control": false}),
        )
        .expect_err("no turns");
    assert_eq!(code(&refusal), "INVALID_ARGUMENT");
    assert_eq!(
        refusal["message"],
        "those are not this operation's parameters: a wheel turns between 1 and 1024 times \
         either way, not 0"
    );
    assert_eq!(refusal["user_action"], "nothing");
}

/// Input to a view that has ended, closed by the page or by its link, or to a view that was never
/// open, is refused as control that has ended, and nothing of it reaches a session: the page is
/// never told that input was taken when it was not.
#[tokio::test(flavor = "multi_thread")]
async fn input_to_a_view_that_has_ended_or_was_never_open_is_refused() {
    let refused_as_ended = |page: &Page, view: &str| {
        for (what, answer) in [
            ("text", page.text(view, 1, "q")),
            ("a key", page.input(view, key(1, "q", &[], "press"))),
            ("a paste", page.paste(view, 1, "q")),
            ("a wheel turn", page.wheel(view, 1, 1, 1, 1)),
            (
                "a take",
                page.input(view, json!({"kind": "take", "number": 2})),
            ),
            (
                "a release",
                page.input(view, json!({"kind": "release", "number": 3})),
            ),
        ] {
            let refusal = answer.expect_err(what);
            assert_eq!(code(&refusal), "LEASE_LOST", "{what}");
            assert_eq!(
                refusal["message"], "This view has ended, and took nothing.",
                "{what}"
            );
        }
    };
    for ending in ["closed by the page", "its link lost"] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page_view = Page::new(worker.paths());
        let mut lease = WorkerLease::default();
        let (view, mut link) = controlling(
            &page_view,
            &mut worker,
            3,
            &reporting(Mouse::Sgr),
            &mut lease,
        )
        .await;
        if ending == "closed by the page" {
            page_view.close(&view);
            let sent = link.closed().await;
            assert_eq!(
                sent.iter()
                    .map(|call| call.method.as_str())
                    .collect::<Vec<_>>(),
                vec!["session.detach"],
                "{ending}"
            );
        } else {
            drop(link);
            page_view.newest(3, |state| state["state"] == "ended").await;
        }
        page_view.held_becomes(0).await;
        refused_as_ended(&page_view, &view);
    }
    let worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    for view in ["99", "not a view"] {
        refused_as_ended(&page_view, view);
    }
}

/// An acquire answered after the person looked around gives the page nothing: the view releases
/// the epoch it was handed, and control stays given back. Closing while an acquire is in flight
/// detaches, which gives back whatever it took.
#[tokio::test(flavor = "multi_thread")]
async fn an_acquire_answered_after_looking_around_is_released_and_restores_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &reporting(Mouse::Sgr)).await;
    page_view.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    page_view.release(&view, 2);
    page_view
        .newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    let mut lease = WorkerLease::at(4);
    lease.answer(&mut link, &acquire).await;
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    lease.answer(&mut link, &release).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        page_view
            .states(3)
            .iter()
            .all(|state| control(state).1 != "controlling"),
        "control was never restored"
    );
    assert_eq!(
        code(
            &page_view
                .wheel(&view, 1, 1, 1, 1)
                .expect_err("the take was given back")
        ),
        "LEASE_LOST"
    );

    page_view.take(&view, 3);
    let _acquire = link.expect(Method::InputAcquire).await;
    page_view.close(&view);
    let sent = link.closed().await;
    assert_eq!(
        sent.iter()
            .map(|call| call.method.as_str())
            .collect::<Vec<_>>(),
        vec!["session.detach"]
    );
}

/// A release and a take made one after the other each go in order under their own epochs: the
/// take's acquire goes while the release stands behind the key that the worker has not answered, and
/// when the worker has answered the acquire and the page is told that the take controls, a late
/// refusal of the old epoch's key and the release of that older epoch change nothing, the release's
/// second send included: the view's second release, which it sends only after it has served the
/// first one's answer, is the checkpoint after which the states are read. An input made under the
/// old take is refused once the new one controls the program, and one made under the new take is
/// written under the new epoch.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_and_a_new_take_keep_their_epochs_apart() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    page_view.text(&view, 1, "a").expect("the text is taken");
    let old_write = link.expect(Method::InputWrite).await;
    page_view.release(&view, 2);
    page_view.take(&view, 3);
    // The release stands behind the key the worker has not answered, so the take's acquire goes
    // first. The worker answers it, and the page is told that the take controls.
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    let controls = page_view
        .newest(3, |state| control(state) == (3, "controlling".to_owned()))
        .await;
    // Only then is the old key refused, late, and the release of the older epoch follows it.
    link.refuse_with(&old_write, ErrorCode::LeaseLost, "the lease has moved on")
        .await;
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    // The worker refuses it for the typing before it, which the view answers by sending the
    // release once more with no position. It does that only once it has served this answer, so the
    // second release on the wire is the checkpoint after which the states can be read: the view
    // has taken the older release's answer.
    link.refuse_with(
        &release,
        ErrorCode::DraftConflict,
        "the typing before it was not taken",
    )
    .await;
    let again = link.expect(Method::InputRelease).await;
    let again_asked: InputReleaseParams = again.params();
    assert_eq!(again_asked.epoch.get(), 5);
    assert!(
        again_asked.after_input.is_none(),
        "the second release names no position"
    );
    lease.answer(&mut link, &again).await;
    assert_eq!(
        code(
            &page_view
                .text(&view, 1, "late")
                .expect_err("an input of the old take")
        ),
        "LEASE_LOST"
    );
    // A key of the new take is written under the new epoch, so the lane still stands.
    page_view.text(&view, 3, "b").expect("the text is taken");
    let write = link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!((asked.epoch.get(), asked.sequence.get()), (6, 0));
    lease.answer(&mut link, &write).await;
    assert_eq!(lease.written, vec![(6, 0, b"b".to_vec())]);
    let told = page_view.states(3);
    let from = told
        .iter()
        .position(|state| state == &controls)
        .expect("the state in which the take controls");
    assert!(
        told[from..]
            .iter()
            .all(|state| control(state) == (3, "controlling".to_owned())),
        "an old epoch's answer changes nothing: {:?}",
        &told[from..]
    );
}

/// Section 8 ¶3: while the program reads keys in a form the view does not produce, the session
/// refuses it control, and the page is told why: every key as an escape code, and alternate keys.
/// An encoding negotiated after a takeover ends the lease on the host, which the view hears at its
/// next write when its own screen has not yet told it; back on an encoding it produces, a take
/// succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_reading_another_encoding_keeps_control_from_the_view() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    lease.negotiate(Negotiated::Kitty(9));
    page_view.text(&view, 1, "a").expect("the text is taken");
    let write = link.expect(Method::InputWrite).await;
    lease.answer(&mut link, &write).await;
    page_view
        .newest(3, |state| control(state) == (1, "watching".to_owned()))
        .await;
    for (number, flags) in [(2, 9), (3, 5)] {
        lease.negotiate(Negotiated::Kitty(flags));
        page_view.take(&view, number);
        let acquire = link.expect(Method::InputAcquire).await;
        lease.answer(&mut link, &acquire).await;
        let refused = page_view
            .newest(3, |state| {
                control(state) == (number, "watching".to_owned())
                    && !state["control"]["ended"].is_null()
            })
            .await;
        assert_eq!(
            refused["control"]["ended"],
            "This view cannot take control: the program reads keys in a form the view does not \
             send.",
            "flags {flags}"
        );
    }
    lease.negotiate(Negotiated::Kitty(1));
    page_view.take(&view, 4);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    let held = page_view
        .newest(3, |state| control(state) == (4, "controlling".to_owned()))
        .await;
    assert_eq!(held["control"]["ended"], Value::Null);
}

/// A change of control is told at once whatever the screen is doing. While a moved window's screen
/// waits for its report's answer, the change goes with the state the page was last sent, so the
/// waiting screen and its settlement stay back until the answer; while the view waits for a screen
/// after a resynchronisation, it goes with that waiting state.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_of_control_is_told_at_once_while_a_screen_is_held_or_awaited() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = wide_session().reporting(Mouse::Sgr);
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.pan(&view, 1, 2, 0);
    let (call, _) = report(&mut link).await;
    frame(&mut link, &at.at(0, 2).revision(1)).await;
    tokio::time::sleep(QUIET).await;
    let before = newest_now(&page_view, 3);
    assert_eq!(
        before["state"], "waiting",
        "the moved window's screen is held"
    );
    page_view.take(&view, 1);
    let taking = page_view
        .newest(3, |state| control(state) == (1, "taking".to_owned()))
        .await;
    assert_eq!(taking["state"], "waiting", "the held screen stays held");
    assert_eq!(taking["settled"], before["settled"]);
    let acquire = link.expect(Method::InputAcquire).await;
    let mut lease = WorkerLease::default();
    lease.answer(&mut link, &acquire).await;
    let held = page_view
        .newest(3, |state| control(state) == (1, "controlling".to_owned()))
        .await;
    assert_eq!(held["state"], "waiting");
    assert_eq!(held["settled"], before["settled"]);
    link.answer(&call, &viewport_answer(1)).await;
    let moved = page_view.newest(3, |state| settled(state, 1)).await;
    assert_eq!(moved["state"], "showing");
    assert_eq!(place(&moved), (2, 0, 0));
    assert_eq!(control(&moved), (1, "controlling".to_owned()));

    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    page_view
        .newest(3, |state| state["state"] == "waiting")
        .await;
    page_view.release(&view, 2);
    let watching = page_view
        .newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    assert_eq!(watching["state"], "waiting");
    let release = link.expect(Method::InputRelease).await;
    lease.answer(&mut link, &release).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.restart_stream();
    frame(&mut link, &at.at(0, 2).revision(1)).await;
    let back = page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    assert_eq!(control(&back), (2, "watching".to_owned()));
}

/// Keys and the wheel before the view controls the program reach nothing: the command refuses them,
/// while the take is in flight as well, and the view writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn input_before_the_view_controls_the_program_is_refused_and_reaches_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &reporting(Mouse::Sgr)).await;
    for take in [0, 1] {
        assert_eq!(
            code(&page_view.text(&view, take, "exit").expect_err("no control")),
            "LEASE_LOST"
        );
        assert_eq!(
            code(
                &page_view
                    .wheel(&view, take, 1, 1, 1)
                    .expect_err("no control")
            ),
            "LEASE_LOST"
        );
    }
    page_view.take(&view, 1);
    let _acquire = link.expect(Method::InputAcquire).await;
    assert_eq!(
        code(
            &page_view
                .input(&view, key(1, "Enter", &[], "press"))
                .expect_err("still taking control")
        ),
        "LEASE_LOST"
    );
    assert!(link.quiet_for(QUIET).await);
}

/// KR-REQ-10.01: what is not the view's input shape is refused before anything is sent: the page's
/// old wheel, bytes and spelled-keys requests, an unknown kind or field, no turn or more than an
/// input carries, a cell below zero, a key that is a control character, empty or of no known event,
/// an unknown keypad key or a base of two characters, text that is empty, holds a control character
/// or is longer than one input frame, and a paste empty or too long to frame in one. The most turns
/// one input carries still go.
#[tokio::test(flavor = "multi_thread")]
async fn inputs_that_are_not_the_views_shape_are_refused_before_anything_is_sent() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = controlling(
        &page_view,
        &mut worker,
        3,
        &reporting(Mouse::Sgr),
        &mut lease,
    )
    .await;
    let session = worker.session_id.to_string();
    let turning = |turns: i64, column: i64| {
        json!({
            "kind": "wheel", "take": 1, "column": column, "line": 0, "turns": turns,
            "shift": false, "alt": false, "control": false,
        })
    };
    for shape in [
        json!({"session_id": session, "wheel": {"lines": 3}}),
        json!({"session_id": session, "bytes": "\u{1b}[A"}),
        json!({"kind": "scroll", "take": 1}),
        json!({"kind": "take"}),
        json!({"kind": "keys", "take": 1, "keys": "a"}),
        json!({"kind": "key", "take": 1, "key": "a", "session_id": session}),
        turning(0, 0),
        turning(1025, 0),
        turning(-1025, 0),
        turning(1, -1),
        key(1, "\u{1b}", &[], "press"),
        key(1, "", &[], "press"),
        key(1, "a", &[], "hold"),
        on_keypad(key(1, "1", &[], "press"), "Numpad10"),
        based(key(1, "A", &["shift"], "press"), "ab"),
        json!({"kind": "text", "take": 1, "text": ""}),
        json!({"kind": "text", "take": 1, "text": "exit\r"}),
        json!({"kind": "text", "take": 1, "text": "x".repeat(64 * 1024 + 1)}),
        json!({"kind": "paste", "take": 1, "text": ""}),
        json!({"kind": "paste", "take": 1, "text": "x".repeat(64 * 1024 - 11)}),
    ] {
        let refused = page_view.input(&view, shape.clone()).expect_err("refused");
        assert_eq!(code(&refused), "INVALID_ARGUMENT", "{shape}");
    }
    assert!(link.quiet_for(QUIET).await, "nothing reached the session");
    page_view
        .wheel(&view, 1, 0, 0, 1024)
        .expect("the most turns one input carries");
    let write = link.expect(Method::InputWrite).await;
    assert_eq!(
        written(&write.params::<InputWriteParams>()),
        b"\x1b[<65;1;1M".repeat(1024).as_slice()
    );
}

/// A control request whose number is not above the newest the view took changes nothing: a take
/// that arrives after a later release takes no control.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_request_not_above_the_newest_changes_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let (view, mut link) = panned(&page_view, &mut worker, 3, &reporting(Mouse::Sgr)).await;
    page_view.release(&view, 2);
    page_view
        .newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    page_view.take(&view, 1);
    assert!(link.quiet_for(QUIET).await, "no acquire");
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (2, "watching".to_owned())
    );
}

// ---- The person's keys, text and paste -------------------------------------------------------

/// The view's next write, answered as the worker answers it: its number and its bytes.
async fn next_write(link: &mut Link, lease: &mut WorkerLease) -> (u64, Vec<u8>) {
    let write = link.expect(Method::InputWrite).await;
    assert_eq!(write.kind, CallKind::Request, "input is a request");
    let asked: InputWriteParams = write.params();
    lease.answer(link, &write).await;
    (asked.sequence.get(), written(&asked).to_vec())
}

/// A view of a program that reads keys as `keys` says, whose control the page took as its request 1
/// and the worker gave it.
async fn controlling_keys(
    page: &Page,
    worker: &mut ScriptedWorker,
    channel: u32,
    keys: Keys,
    lease: &mut WorkerLease,
) -> (String, Link) {
    lease.negotiate(keys.negotiated(false));
    controlling(
        page,
        worker,
        channel,
        &reporting(Mouse::Sgr).keys(keys),
        lease,
    )
    .await
}

/// Pushes `update` and returns once the view has published what it made of it.
async fn applied(
    page: &Page,
    link: &mut Link,
    channel: u32,
    update: &kr_protocol::projection::ProjectionDelta,
) {
    let seen = page.states(channel).len();
    link.push(PROJECTION_DELTA_EVENT, update).await;
    tokio::time::timeout(WATCHDOG, async {
        while page.states(channel).len() <= seen {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the view publishes the update within the watchdog");
}

/// Sends each input under take 1 and checks the bytes the view writes for it, one write each.
async fn writes(
    page: &Page,
    view: &str,
    link: &mut Link,
    lease: &mut WorkerLease,
    cases: Vec<(Value, &[u8])>,
) {
    for (input, expected) in cases {
        page.input(view, input.clone())
            .unwrap_or_else(|refused| panic!("{input}: {refused}"));
        let (_, bytes) = next_write(link, lease).await;
        assert_eq!(
            bytes,
            expected,
            "{input}: {}",
            String::from_utf8_lossy(&bytes).escape_debug()
        );
    }
}

/// KR-REQ-08.60, KR-REQ-13.18: a program in the Kitty protocol with flags 1 takes the view's
/// takeover and gets each key in the protocol's own spelling, one write each at the stream's next
/// number: Escape and a control chord as reports, text and Return as themselves, a locked arrow
/// with the lock's bit, F13 and the keypad by the protocol's codes. Without event types a release
/// writes nothing and takes no number.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_in_the_kitty_protocol_gets_the_views_keys_in_its_spelling() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(1), &mut lease).await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![
            (key(1, "Escape", &[], "press"), b"\x1b[27u"),
            (
                based(key(1, "c", &["control"], "press"), "c"),
                b"\x1b[99;5u",
            ),
            (key(1, "a", &[], "press"), b"a"),
            (based(key(1, "A", &["shift"], "press"), "a"), b"A"),
            (key(1, "Enter", &[], "press"), b"\r"),
            (key(1, "Tab", &["shift"], "press"), b"\x1b[9;2u"),
            (key(1, "ArrowUp", &[], "press"), b"\x1b[A"),
            (key(1, "ArrowUp", &["num_lock"], "press"), b"\x1b[1;129A"),
            (key(1, "F13", &[], "press"), b"\x1b[57376u"),
            (
                on_keypad(key(1, "End", &[], "press"), "Numpad1"),
                b"\x1b[57424u",
            ),
            (
                on_keypad(key(1, "1", &["num_lock"], "press"), "Numpad1"),
                b"1",
            ),
        ],
    )
    .await;
    page_view
        .input(&view, based(key(1, "c", &[], "release"), "c"))
        .expect("taken");
    assert!(
        link.quiet_for(QUIET).await,
        "nothing to write for a release"
    );
    page_view.text(&view, 1, "z").expect("taken");
    let (sequence, bytes) = next_write(&mut link, &mut lease).await;
    assert_eq!(
        (sequence, bytes.as_slice()),
        (11, &b"z"[..]),
        "and it took no number"
    );
}

/// KR-REQ-08.59: the ordinary encoding and `modifyOtherKeys` spell the keys as xterm does: DEC mode
/// 1's cursor and centre keys, X11's control characters, the back-tab, the menu key, locks left out;
/// a change to `modifyOtherKeys` level 2 mid-lease reports the chords it asks for.
#[tokio::test(flavor = "multi_thread")]
async fn the_ordinary_encoding_and_modify_other_keys_spell_keys_as_xterm_does() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let keys = Keys {
        cursor_keys: true,
        ..Keys::ordinary()
    };
    let (view, mut link) = controlling_keys(&page_view, &mut worker, 3, keys, &mut lease).await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![
            (key(1, "ArrowUp", &[], "press"), b"\x1bOA"),
            (key(1, "ArrowUp", &["control"], "press"), b"\x1b[1;5A"),
            (key(1, "c", &["control"], "press"), b"\x03"),
            (key(1, "3", &["control"], "press"), b"\x1b"),
            (key(1, "Tab", &["shift"], "press"), b"\x1b[Z"),
            (key(1, "Escape", &["caps_lock"], "press"), b"\x1b"),
            (
                on_keypad(key(1, "Clear", &[], "press"), "Numpad5"),
                b"\x1bOE",
            ),
            (key(1, "ContextMenu", &[], "press"), b"\x1b[29~"),
        ],
    )
    .await;
    page_view
        .input(&view, key(1, "c", &["control"], "release"))
        .expect("taken");
    assert!(link.quiet_for(QUIET).await, "no release in this encoding");

    let at = reporting(Mouse::Sgr).keys(keys);
    let level_two = Keys {
        cursor_keys: true,
        ..Keys::modify_other_keys(2)
    };
    lease.negotiate(level_two.negotiated(false));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, level_two),
    )
    .await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![
            (key(1, "i", &["control"], "press"), b"\x1b[27;5;105~"),
            (key(1, "Tab", &["shift"], "press"), b"\x1b[27;2;9~"),
            (key(1, "ArrowUp", &[], "press"), b"\x1bOA"),
        ],
    )
    .await;
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (1, "controlling".to_owned())
    );
}

/// KR-REQ-08.59, KR-REQ-08.61: with event types, a release is spelled from the press it ends, with
/// the modifiers held as it comes up: Control-I released after Control is still the I key's
/// release. A key sent as its text has none, a repeat of a report is reported as one, and a release
/// the view wrote no press for is nothing.
#[tokio::test(flavor = "multi_thread")]
async fn event_types_report_a_release_from_the_press_it_ends() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(3), &mut lease).await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![
            (
                based(key(1, "i", &["control"], "press"), "i"),
                b"\x1b[105;5u",
            ),
            (based(key(1, "i", &[], "release"), "i"), b"\x1b[105;1:3u"),
            (key(1, "ArrowUp", &[], "press"), b"\x1b[A"),
            (key(1, "ArrowUp", &[], "repeat"), b"\x1b[1;1:2A"),
            (key(1, "ArrowUp", &["shift"], "release"), b"\x1b[1;2:3A"),
            (key(1, "a", &[], "press"), b"a"),
        ],
    )
    .await;
    for nothing in [
        key(1, "a", &[], "release"),
        key(1, "b", &[], "release"),
        key(1, "Escape", &[], "release"),
    ] {
        page_view.input(&view, nothing.clone()).expect("taken");
        assert!(link.quiet_for(QUIET).await, "{nothing}: nothing to write");
    }
}

/// KR-REQ-08.61: a program that changes between encodings the view produces keeps the view in
/// control, and each key goes in the encoding of the screen the view holds at the time: Kitty 1 to
/// the ordinary encoding and back, nothing asked of the session in between.
#[tokio::test(flavor = "multi_thread")]
async fn the_encoding_follows_the_program_mid_lease_both_ways() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(1), &mut lease).await;
    let at = reporting(Mouse::Sgr).keys(Keys::kitty(1));
    let escape = || key(1, "Escape", &[], "press");
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(escape(), b"\x1b[27u")],
    )
    .await;
    lease.negotiate(Negotiated::Ordinary);
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, Keys::ordinary()),
    )
    .await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(escape(), b"\x1b")],
    )
    .await;
    lease.negotiate(Negotiated::Kitty(1));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 41, 42, Keys::kitty(1)),
    )
    .await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(escape(), b"\x1b[27u")],
    )
    .await;
    assert_eq!(
        lease
            .written
            .iter()
            .map(|(epoch, _, _)| *epoch)
            .collect::<Vec<_>>(),
        vec![1, 1, 1],
        "one epoch throughout: the lease never moved"
    );
}

/// KR-REQ-08.61: the moment the view's screen says the program reads keys in a form the view does
/// not produce, control ends at once and says why: nothing more is written, the epoch goes back
/// once, and a later screen changes nothing. A take is refused while the program reads it, and
/// succeeds once it reads a form the view produces again.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_asking_for_what_the_view_cannot_send_ends_control_at_once() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(1), &mut lease).await;
    let at = reporting(Mouse::Sgr).keys(Keys::kitty(1));
    lease.negotiate(Negotiated::Kitty(5));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, Keys::kitty(5)),
    )
    .await;
    let ended = page_view
        .newest(3, |state| control(state).1 == "watching")
        .await;
    assert_eq!(control(&ended), (1, "watching".to_owned()));
    assert_eq!(
        ended["control"]["ended"],
        "Control ended: the program now reads keys in a form this view cannot send."
    );
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 1);
    lease.answer(&mut link, &release).await;
    assert_eq!(
        code(
            &page_view
                .input(&view, key(1, "Escape", &[], "press"))
                .expect_err("control ended")
        ),
        "LEASE_LOST"
    );
    lease.negotiate(Negotiated::Kitty(9));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 41, 42, Keys::kitty(9)),
    )
    .await;
    assert!(
        link.quiet_for(QUIET).await,
        "a later screen releases nothing more and writes nothing"
    );
    assert!(lease.written.is_empty());

    page_view.take(&view, 2);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    let refused = page_view
        .newest(3, |state| {
            control(state) == (2, "watching".to_owned()) && !state["control"]["ended"].is_null()
        })
        .await;
    assert_eq!(
        refused["control"]["ended"],
        "This view cannot take control: the program reads keys in a form the view does not send."
    );
    lease.negotiate(Negotiated::Kitty(1));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 42, 43, Keys::kitty(1)),
    )
    .await;
    page_view.take(&view, 3);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    page_view
        .newest(3, |state| control(state) == (3, "controlling".to_owned()))
        .await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(key(3, "Escape", &[], "press"), b"\x1b[27u")],
    )
    .await;
}

/// KR-REQ-08.61: a screen saying the program reads keys in a form the view does not produce is never
/// published with the view in control: control ends before the page is told of the screen, which
/// comes with the words, in one state.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsupported_screen_is_never_published_with_the_view_in_control() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (_view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(1), &mut lease).await;
    let at = reporting(Mouse::Sgr).keys(Keys::kitty(1));
    let seen = page_view.states(3).len();
    lease.negotiate(Negotiated::Kitty(5));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, Keys::kitty(5)),
    )
    .await;
    page_view
        .newest(3, |state| control(state) == (1, "watching".to_owned()))
        .await;
    let after = page_view.states(3).split_off(seen);
    assert!(
        after
            .iter()
            .all(|state| state["control"]["state"] != "controlling"),
        "{after:#?}"
    );
    assert_eq!(
        after.first().map(|state| state["control"]["ended"].clone()),
        Some(json!(
            "Control ended: the program now reads keys in a form this view cannot send."
        )),
        "the screen and the end of control go in one state"
    );
}

/// KR-REQ-08.61: a take the session grants just before the program changes to a form the view does
/// not produce, whose answer reaches the view after the screen that says so, ends as the answer
/// arrives: the page is never told the view controls the program, the granted epoch goes back once,
/// and nothing is written under it, a wheel turn included.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_granted_just_before_the_program_changed_to_what_the_view_cannot_send_ends_at_once()
{
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let at = reporting(Mouse::Sgr).keys(Keys::kitty(1));
    lease.negotiate(Negotiated::Kitty(1));
    let (view, mut link) = panned(&page_view, &mut worker, 3, &at).await;
    page_view.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, Keys::kitty(5)),
    )
    .await;
    // The session granted the take under Kitty 1, and ends the lease on its side as the program
    // changes.
    lease.answer(&mut link, &acquire).await;
    lease.negotiate(Negotiated::Kitty(5));
    let ended = page_view
        .newest(3, |state| control(state) == (1, "watching".to_owned()))
        .await;
    assert_eq!(
        ended["control"]["ended"],
        "Control ended: the program now reads keys in a form this view cannot send."
    );
    assert!(
        page_view
            .states(3)
            .iter()
            .all(|state| state["control"]["state"] != "controlling"),
        "the page is never told the view controls the program"
    );
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 1);
    lease.answer(&mut link, &release).await;
    assert_eq!(
        code(
            &page_view
                .input(&view, key(1, "Escape", &[], "press"))
                .expect_err("control ended")
        ),
        "LEASE_LOST"
    );
    assert_eq!(
        code(
            &page_view
                .wheel(&view, 1, 0, 0, 1)
                .expect_err("control ended")
        ),
        "LEASE_LOST"
    );
    assert!(
        link.quiet_for(QUIET).await,
        "nothing more is asked or written"
    );
    assert!(lease.written.is_empty());
}

/// KR-REQ-08.61: a newer take served by the lease the view still holds keeps what was pressed under
/// it, so a key held across the take is released to the program rather than left down.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_held_across_a_newer_take_is_released_to_the_program() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::kitty(3), &mut lease).await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(
            based(key(1, "i", &["control"], "press"), "i"),
            b"\x1b[105;5u",
        )],
    )
    .await;
    page_view.take(&view, 2);
    page_view
        .newest(3, |state| control(state) == (2, "controlling".to_owned()))
        .await;
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(based(key(2, "i", &[], "release"), "i"), b"\x1b[105;1:3u")],
    )
    .await;
    assert!(
        link.quiet_for(QUIET).await,
        "the lease it holds serves the newer take: nothing is asked"
    );
}

/// KR-REQ-08.59: the alternate buffer keeps its own Kitty flags, so a full-screen program's
/// negotiation is read while its buffer shows, and the shell's once it is gone.
#[tokio::test(flavor = "multi_thread")]
async fn the_alternate_buffers_negotiation_is_its_own() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let keys = Keys {
        alternate: Some(1),
        ..Keys::ordinary()
    };
    let mut at = reporting(Mouse::Sgr).keys(keys);
    at.buffer = kr_protocol::projection::ProjectedBuffer::Alternate;
    lease.negotiate(keys.negotiated(true));
    let (view, mut link) = controlling(&page_view, &mut worker, 3, &at, &mut lease).await;
    let escape = || key(1, "Escape", &[], "press");
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(escape(), b"\x1b[27u")],
    )
    .await;
    let mut primary = at;
    primary.buffer = kr_protocol::projection::ProjectedBuffer::Primary;
    primary.generation = 2;
    lease.negotiate(keys.negotiated(false));
    let seen = page_view.states(3).len();
    frame(&mut link, &primary).await;
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let states = page_view.states(3);
            let after = states.get(seen..).unwrap_or_default();
            if after.iter().any(|state| state["state"] == "waiting")
                && after
                    .last()
                    .is_some_and(|state| state["state"] == "showing")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the primary buffer's screen is shown within the watchdog");
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(escape(), b"\x1b")],
    )
    .await;
}

/// KR-REQ-08.59, KR-REQ-08.61: a key, text or a paste made while the view holds no screen of the
/// session, before the first and between a reset and the snapshot that follows it, is refused with
/// words and control kept: the program's keyboard is not known then. Nothing takes a number.
#[tokio::test(flavor = "multi_thread")]
async fn keys_text_and_paste_wait_for_the_sessions_screen() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let at = reporting(Mouse::Sgr);
    let view = page_view.open(worker.session_id, at.window_columns, at.window_rows, 3);
    let mut link = worker.link().await;
    link.attach().await;
    page_view
        .newest(3, |state| state["state"] == "waiting")
        .await;
    page_view.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    let mut lease = WorkerLease::default();
    lease.answer(&mut link, &acquire).await;
    page_view
        .newest(3, |state| control(state) == (1, "controlling".to_owned()))
        .await;
    let refused_while_waiting = |page: &Page| {
        for (what, answer) in [
            ("That key", page.input(&view, key(1, "a", &[], "press"))),
            ("That text", page.text(&view, 1, "a")),
            ("That paste", page.paste(&view, 1, "a")),
        ] {
            let refusal = answer.expect_err(what);
            assert_eq!(code(&refusal), "INPUT_INCOMPATIBLE", "{what}");
            // The words say why, and there is nothing to update: an update is not what the code
            // maps to for a host's refusal, and not what this refusal asks.
            assert_eq!(refusal["user_action"], "nothing", "{what}");
            assert_eq!(
                refusal["message"],
                format!(
                    "{what} did not reach the program: the view is waiting for the session's \
                     screen."
                )
            );
        }
    };
    refused_while_waiting(&page_view);
    frame(&mut link, &at).await;
    page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    page_view.text(&view, 1, "x").expect("taken");
    let (sequence, _) = next_write(&mut link, &mut lease).await;
    assert_eq!(sequence, 0, "nothing refused took a number");

    link.push(
        PROJECTION_RESET_EVENT,
        &reset(2, 50, ProjectionResetReason::BufferSwitch, 0),
    )
    .await;
    page_view
        .newest(3, |state| state["state"] == "waiting")
        .await;
    refused_while_waiting(&page_view);
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (1, "controlling".to_owned()),
        "control is kept"
    );
    let mut switched = at;
    switched.generation = 2;
    switched.cursor = 50;
    frame(&mut link, &switched).await;
    page_view
        .newest(3, |state| state["state"] == "showing")
        .await;
    page_view.text(&view, 1, "y").expect("taken");
    let (sequence, bytes) = next_write(&mut link, &mut lease).await;
    assert_eq!((sequence, bytes.as_slice()), (1, &b"y"[..]));
}

/// KR-REQ-08.59: a key the program's encoding cannot express is refused with the encoder's words,
/// and nothing is written: Shift with Control on Tab in the ordinary encoding, a shifted chord whose
/// unshifted character the platform did not report under the Kitty protocol, and a key with no
/// spelling. Control is kept, and the next key takes the next number.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_the_encoding_cannot_express_is_refused_and_control_kept() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::ordinary(), &mut lease).await;
    for (input, words) in [
        (
            key(1, "Tab", &["shift", "control"], "press"),
            "That key did not reach the program: the negotiated encoding cannot express Shift \
             together with another modifier on Tab, and this encoder does not invent one.",
        ),
        (
            key(1, "PrintScreen", &[], "press"),
            "That key did not reach the program: this encoder has no spelling for that key.",
        ),
        (
            key(1, "BrightnessUp", &[], "press"),
            "That key did not reach the program: this encoder has no spelling for that key.",
        ),
    ] {
        let refusal = page_view.input(&view, input.clone()).expect_err("refused");
        assert_eq!(code(&refusal), "INPUT_INCOMPATIBLE", "{input}");
        assert_eq!(refusal["message"], words, "{input}");
    }
    assert!(link.quiet_for(QUIET).await, "nothing written");
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (1, "controlling".to_owned())
    );
    writes(
        &page_view,
        &view,
        &mut link,
        &mut lease,
        vec![(key(1, "Tab", &["shift"], "press"), b"\x1b[Z")],
    )
    .await;

    let at = reporting(Mouse::Sgr);
    lease.negotiate(Negotiated::Kitty(1));
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, Keys::kitty(1)),
    )
    .await;
    let refusal = page_view
        .input(&view, key(1, "A", &["control", "shift"], "press"))
        .expect_err("no unshifted character");
    assert_eq!(code(&refusal), "INPUT_INCOMPATIBLE");
    assert_eq!(
        refusal["message"],
        "That key did not reach the program: the negotiated encoding cannot express the unshifted \
         key a shifted character was produced from, and this encoder does not invent one."
    );
    let (sequence, _) = {
        page_view.text(&view, 1, "k").expect("taken");
        next_write(&mut link, &mut lease).await
    };
    assert_eq!(sequence, 1);
}

/// KR-REQ-08.59: text is its UTF-8, and a paste is bracketed exactly when the program asked for it,
/// with any delimiter inside it taken out; the longest paste fits one input frame once framed.
#[tokio::test(flavor = "multi_thread")]
async fn text_is_its_utf8_and_a_paste_is_bracketed_when_the_program_asks() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page_view = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling_keys(&page_view, &mut worker, 3, Keys::ordinary(), &mut lease).await;
    page_view.text(&view, 1, "日本語").expect("taken");
    assert_eq!(
        next_write(&mut link, &mut lease).await.1,
        "日本語".as_bytes()
    );
    page_view.paste(&view, 1, "one\ntwo").expect("taken");
    assert_eq!(next_write(&mut link, &mut lease).await.1, b"one\ntwo");

    let at = reporting(Mouse::Sgr);
    let bracketed = Keys {
        bracketed_paste: true,
        ..Keys::ordinary()
    };
    applied(
        &page_view,
        &mut link,
        3,
        &keys_delta(&at, 40, 41, bracketed),
    )
    .await;
    page_view.paste(&view, 1, "one\ntwo").expect("taken");
    assert_eq!(
        next_write(&mut link, &mut lease).await.1,
        b"\x1b[200~one\ntwo\x1b[201~"
    );
    page_view
        .paste(&view, 1, "rm -rf /\u{1b}[201~\ninnocent")
        .expect("taken");
    assert_eq!(
        next_write(&mut link, &mut lease).await.1,
        b"\x1b[200~rm -rf /\ninnocent\x1b[201~",
        "a paste cannot end itself"
    );
    // A paste of more than one frame carries: the lane cuts it, in frames of at most the level's
    // input bytes, and never inside a mark. Its size is chosen so that the closing mark stands
    // across the place where the frame ends, three bytes of it before that place, so that a cut made
    // there would fall inside the mark.
    let start = b"\x1b[200~".as_slice();
    let end = b"\x1b[201~".as_slice();
    let frame_bytes = kr_protocol::input::max_input_bytes(64 * 1024);
    let longest = "x".repeat(frame_bytes - start.len() - 3);
    page_view.paste(&view, 1, &longest).expect("taken");
    let mut expected = start.to_vec();
    expected.extend_from_slice(longest.as_bytes());
    expected.extend_from_slice(end);
    assert!(
        expected.len() - end.len() < frame_bytes && frame_bytes < expected.len(),
        "the closing mark stands across the cut at the frame's size"
    );
    let mut writes: Vec<Vec<u8>> = Vec::new();
    let mut joined = Vec::new();
    while joined.len() < expected.len() {
        let bytes = next_write(&mut link, &mut lease).await.1;
        joined.extend_from_slice(&bytes);
        writes.push(bytes);
    }
    assert_eq!(
        joined, expected,
        "the writes of a paste, joined in their order, are the paste whole with its marks"
    );
    assert!(
        writes.iter().all(|bytes| bytes.len() <= frame_bytes),
        "every write of the paste is at most the lane's frame bytes"
    );
    let mut at = 0;
    for bytes in &writes[..writes.len() - 1] {
        at += bytes.len();
        for mark in [start, end] {
            for begin in at.saturating_sub(mark.len() - 1)..at {
                assert!(
                    !expected[begin..].starts_with(mark),
                    "a cut of the paste never falls inside one of its marks"
                );
            }
        }
    }
    assert!(
        writes.last().is_some_and(|last| last.ends_with(end)),
        "the closing mark travels whole, at the end of the last write"
    );
}

/// The launch surface a worker answers when the editor is verified and this view holds the input.
fn a_surface_held_here(
    session_id: kr_protocol::ids::SessionId,
) -> kr_protocol::root::ShellLaunchSurfaceResult {
    use kr_protocol::root::{
        CwdRevision, EditorBufferRevision, LaunchCommand, LaunchEditor, LaunchInput, LaunchOffer,
        LaunchShell, PromptGeneration, ShellLaunchSurfaceResult,
    };
    ShellLaunchSurfaceResult {
        session_id,
        editor: LaunchEditor::Verified {
            prompt_generation: PromptGeneration::new(12),
            buffer_revision: EditorBufferRevision::new(3),
            cwd_revision: CwdRevision::new(5),
        },
        input: LaunchInput::HeldHere,
        shell: kr_protocol::scalars::Nullable::some(LaunchShell::Zsh),
        offers: vec![LaunchOffer {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code")
                .expect("a plugin identifier"),
            label: "Claude Code".to_owned(),
            command: LaunchCommand::Arguments(vec!["claude".to_owned()]),
        }],
    }
}

/// KR-REQ-13.11: a view reads the launch surface on its own link, the link that holds the session's
/// input once the person takes control, so the answer can say the input is held here. The page is
/// given what the worker answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_view_reads_the_launch_surface_on_its_own_link() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    let reading = page.invoke_later("terminal_view_launch_surface", json!({ "view": view }));
    let asked = link.expect(Method::ShellLaunchSurface).await;
    assert_eq!(asked.kind, CallKind::Request);
    let params: kr_protocol::root::ShellLaunchSurfaceParams = asked.params();
    assert_eq!(params.session_id, worker.session_id);
    let surface = a_surface_held_here(worker.session_id);
    link.answer(&asked, &surface).await;
    let told = reading.await.expect("joins").expect("the surface is read");
    assert_eq!(told["state"], "served", "{told}");
    assert_eq!(
        told["surface"],
        serde_json::to_value(&surface).expect("serialises"),
        "the page is given what the worker answered"
    );
}

/// KR-REQ-13.11: a worker that stated that it serves the launch surface and refuses the read has
/// refused it for the grant: the page is given that refusal as it is, and the view asks the session
/// nothing else first. (A paired host's daemon says nothing of its worker, and the view tells an
/// unlisted method from a lost right there by what the same right reads.)
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_serves_the_launch_surface_and_refuses_it_is_not_taken_for_one_that_does_not()
{
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;

    let reading = page.invoke_later("terminal_view_launch_surface", json!({ "view": view }));
    let first = link.expect(Method::ShellLaunchSurface).await;
    link.refuse_with(&first, ErrorCode::PermissionDenied, "the right is gone")
        .await;
    // Answered by the refusal alone: a view that asked the session anything else first would wait
    // for an answer this test does not give.
    let refused = tokio::time::timeout(WATCHDOG, reading)
        .await
        .expect("the page was answered without the view asking anything else")
        .expect("joins")
        .expect_err("the refusal is the grant's");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");

    // The next read is the next call on the link: nothing was asked in between.
    let reading = page.invoke_later("terminal_view_launch_surface", json!({ "view": view }));
    let again = link.expect(Method::ShellLaunchSurface).await;
    link.answer(&again, &a_surface_held_here(worker.session_id))
        .await;
    let told = reading.await.expect("joins").expect("served");
    assert_eq!(told["state"], "served", "{told}");
}

/// KR-REQ-13.11: a worker that lists the read and is of a release that does not serve it refuses it
/// as an unsupported capability, and a worker that does not state the capability is not asked at
/// all. Either way the page is told the host does not serve it.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_does_not_serve_the_launch_surface_is_not_asked_or_is_told_so() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    let reading = page.invoke_later("terminal_view_launch_surface", json!({ "view": view }));
    let asked = link.expect(Method::ShellLaunchSurface).await;
    link.refuse_with(
        &asked,
        ErrorCode::UnsupportedCapability,
        "an earlier release",
    )
    .await;
    let told = reading.await.expect("joins").expect("an answer");
    assert_eq!(told, json!({ "state": "not_served" }));

    let mut silent = ScriptedWorker::start_not_stating_the_launch_surface();
    let page = Page::new(silent.paths());
    let (view, mut link) = panned(&page, &mut silent, 3, &reporting(Mouse::Sgr)).await;
    let told = page
        .invoke_later("terminal_view_launch_surface", json!({ "view": view }))
        .await
        .expect("joins")
        .expect("an answer");
    assert_eq!(told, json!({ "state": "not_served" }));
    // The next call on the link is the one the person's take makes: the read was not asked.
    page.take(&view, 1);
    link.expect(Method::InputAcquire).await;
}

/// KR-REQ-13.11: a launch is pressed on the view's own link, for the view's own session, quoting the
/// prompt generation and the buffer revision of the read the button was drawn from; the page is
/// given what the session answered. A prompt that moved is refused by the session as `DRAFT_CONFLICT`,
/// and the page is given that code.
#[tokio::test(flavor = "multi_thread")]
async fn a_launch_is_pressed_on_the_views_link_and_a_moved_prompt_is_refused() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    let press = json!({
        "command": { "arguments": ["claude"] },
        "expected_prompt_generation": "12",
        "expected_buffer_revision": "3",
    });

    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": press }),
    );
    let launch = link.expect(Method::ShellLaunch).await;
    assert_eq!(launch.kind, CallKind::Mutation);
    let asked: kr_protocol::root::ShellLaunchParams = launch.params();
    assert_eq!(
        asked.session_id, worker.session_id,
        "the view's own session"
    );
    assert_eq!(
        asked.command,
        kr_protocol::root::LaunchCommand::Arguments(vec!["claude".to_owned()])
    );
    assert_eq!(asked.expected_prompt_generation.0.get(), 12);
    assert_eq!(asked.expected_buffer_revision.0.get(), 3);
    let installed = kr_protocol::root::ShellLaunchResult {
        fence_id: kr_protocol::root::FenceId::new(kr_ipc::new_uuid()),
        prompt_generation: asked.expected_prompt_generation,
        buffer_revision: kr_protocol::root::EditorBufferRevision::new(4),
    };
    link.answer(&launch, &installed).await;
    let told = pressing
        .await
        .expect("joins")
        .expect("the launch is installed");
    assert_eq!(
        told,
        serde_json::to_value(&installed).expect("serialises"),
        "the page is given what the session answered"
    );

    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": press }),
    );
    let launch = link.expect(Method::ShellLaunch).await;
    link.refuse_with(
        &launch,
        ErrorCode::DraftConflict,
        "the prompt moved on before the launch was installed",
    )
    .await;
    let refused = pressing
        .await
        .expect("joins")
        .expect_err("the prompt moved");
    assert_eq!(refused["code"], "DRAFT_CONFLICT", "{refused}");
}

/// KR-REQ-13.11: the page names the command to install and the prompt it quotes, and nothing else:
/// a press that names a session of its own, or anything the application does not read, is refused
/// before the view is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_press_that_names_more_than_the_command_and_its_quote_is_refused_unread() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    let refused = page
        .invoke_later(
            "terminal_view_launch",
            json!({ "view": view, "press": {
                "session_id": kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string(),
                "command": { "arguments": ["claude"] },
                "expected_prompt_generation": "12",
                "expected_buffer_revision": "3",
            }}),
        )
        .await
        .expect("joins")
        .expect_err("refused");
    assert_eq!(refused["code"], "INVALID_ARGUMENT", "{refused}");
    // The next call on the link is the person's own input: no launch went out before it.
    page.paste(&view, 1, "ok").expect("taken");
    next_write(&mut link, &mut lease).await;
}

/// KR-REQ-13.11: a launch the session has not answered when the view ends may have been installed,
/// so the page is told the outcome is unknown and never that nothing was typed. A launch that never
/// reached the session, because the view had ended before it, is still told as a lost lease.
#[tokio::test(flavor = "multi_thread")]
async fn a_launch_still_waiting_when_its_view_ends_is_an_unknown_outcome() {
    let press = json!({
        "command": { "arguments": ["claude"] },
        "expected_prompt_generation": "12",
        "expected_buffer_revision": "3",
    });
    for ending in ["lost", "closed"] {
        let mut worker = ScriptedWorker::start(Challenge::Answered);
        let page = Page::new(worker.paths());
        let mut lease = WorkerLease::default();
        let (view, mut link) =
            controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
        let pressing = page.invoke_later(
            "terminal_view_launch",
            json!({ "view": view, "press": press }),
        );
        link.expect(Method::ShellLaunch).await;
        if ending == "lost" {
            drop(link);
        } else {
            page.close(&view);
        }
        let told = pressing
            .await
            .expect("joins")
            .expect_err("the view ended before the session answered");
        assert_eq!(code(&told), "OUTCOME_UNKNOWN", "{ending}: {told}");
        page.held_becomes(0).await;

        let late = page
            .invoke_later(
                "terminal_view_launch",
                json!({ "view": view, "press": press }),
            )
            .await
            .expect("joins")
            .expect_err("the view has ended");
        assert_eq!(code(&late), "LEASE_LOST", "{ending}: {late}");
    }
}

// ---- The session's input lane and the order of its notifications ------------------------------

/// A launch that the page presses, which the tests below send as one command.
fn the_press() -> Value {
    json!({
        "command": { "arguments": ["claude"] },
        "expected_prompt_generation": "12",
        "expected_buffer_revision": "3",
    })
}

/// The lane writes one key at a time on this link and waits for the worker's answer to each, so a
/// release made while a key waits for its answer stands behind that key. Nothing of the release is
/// on the wire, the page is told at once that control ended, and the page's close ends the wait
/// and the connection with it: the worker's own clean-up at the connection's end gives the lease
/// back.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_behind_an_unanswered_key_is_not_on_the_wire_and_the_close_ends_the_wait() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let _key = link.expect(Method::InputWrite).await;
    page.release(&view, 2);
    let told = page
        .newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    assert_eq!(told["state"], "showing", "the page is told at once");
    assert!(
        link.quiet_for(QUIET).await,
        "the release stands behind the key: nothing of it is on the wire"
    );
    page.close(&view);
    assert_eq!(page.held(), 0, "the close ended the view");
    let sent = link.closed().await;
    assert!(
        sent.is_empty(),
        "the close ended the connection with neither the release nor the detach written: {sent:?}"
    );
}

/// The mirror of the last: a detach at the person's close stands behind a key that the worker has
/// not answered, and the close ends the wait and the connection without writing it.
#[tokio::test(flavor = "multi_thread")]
async fn a_detach_behind_an_unanswered_key_is_not_on_the_wire_and_the_close_ends_the_connection() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let _key = link.expect(Method::InputWrite).await;
    page.close(&view);
    assert_eq!(page.held(), 0, "the close ended the view");
    let sent = link.closed().await;
    assert!(
        sent.is_empty(),
        "the close ended the connection and the detach behind the key was not written: {sent:?}"
    );
}

/// With every key answered the detach is written whole, and before the connection closes: it is
/// the one call on the wire after the launch that followed the key, which the worker has read
/// when the lane has taken the key's answer, and it asks for no barrier on a link whose typing is
/// requests.
#[tokio::test(flavor = "multi_thread")]
async fn the_detach_is_written_whole_before_the_connection_closes() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    next_write(&mut link, &mut lease).await;
    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    // The launch is written once the lane has the key's answer: no key waits now.
    link.expect(Method::ShellLaunch).await;
    page.close(&view);
    let sent = link.closed().await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].method, Method::SessionDetach.to_string());
    let detach: kr_protocol::attachment::SessionDetachParams = sent[0].params();
    assert!(detach.after_input.is_none());
    let _ = pressing.await;
}

/// A launch stands behind the key before it: it is not on the wire until the worker has answered
/// the key, and goes at once after.
#[tokio::test(flavor = "multi_thread")]
async fn a_launch_goes_after_the_key_before_it_and_not_before_the_worker_answers_it() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let key = link.expect(Method::InputWrite).await;
    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    assert!(
        link.quiet_for(QUIET).await,
        "the launch stands behind the key: nothing of it is on the wire"
    );
    lease.answer(&mut link, &key).await;
    link.expect(Method::ShellLaunch).await;
    page.close(&view);
    let told = pressing
        .await
        .expect("joins")
        .expect_err("the view ended before the session answered");
    assert_eq!(code(&told), "OUTCOME_UNKNOWN");
}

/// A launch behind a key that the worker does not answer is never on the wire: the close ends the
/// wait and the connection, and the page is told that the launch's outcome is unknown, as it is
/// for any launch the session had not answered when the view ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_launch_behind_an_unanswered_key_is_told_unknown_when_the_close_ends_the_wait() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let _key = link.expect(Method::InputWrite).await;
    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    assert!(
        link.quiet_for(QUIET).await,
        "the launch stands behind the key: nothing of it is on the wire"
    );
    page.close(&view);
    let told = pressing
        .await
        .expect("joins")
        .expect_err("the view ended before the launch was written");
    assert_eq!(code(&told), "OUTCOME_UNKNOWN");
    let sent = link.closed().await;
    assert!(sent.is_empty(), "{sent:?}");
}

/// A burst of keys is taken whole: each one is told taken at once, and the lane writes them one
/// after the other, in the order made, under the numbers 0, 1, 2 and on, each when the worker has
/// answered the one before.
#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_keys_is_written_in_order_one_at_a_time() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    for key in 0..200 {
        page.text(&view, 1, &format!("k{key};"))
            .expect("the key is taken");
    }
    for key in 0..200_u64 {
        let (sequence, bytes) = next_write(&mut link, &mut lease).await;
        assert_eq!(sequence, key, "the key's number");
        assert_eq!(bytes, format!("k{key};").into_bytes(), "the key's bytes");
    }
}

/// A key that the session refuses as the lease having moved on ends the view's control with the
/// session's words, and the page is told so.
#[tokio::test(flavor = "multi_thread")]
async fn a_lease_refusal_of_a_key_ends_control_with_the_sessions_words() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let key = link.expect(Method::InputWrite).await;
    link.refuse_with(&key, ErrorCode::LeaseLost, "the lease has moved on")
        .await;
    let ended = page
        .newest_within(3, |state| control(state) == (1, "watching".to_owned()))
        .await
        .expect("the refusal ended control within the bound");
    let words = ended["control"]["ended"]
        .as_str()
        .expect("words of the end");
    assert!(words.starts_with("Control ended"), "{words}");
}

/// A connection that goes while the attach waits ends the open with how the link ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_lost_during_the_attach_says_how_the_link_ended() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 10, 2, 3);
    let mut link = worker.link().await;
    link.expect(Method::SessionAttach).await;
    drop(link);
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "The connection to this session ended: the peer closed the connection"
    );
}

/// What the page's commands to a view that has ended are answered with, as on any lost link.
fn refused_after_the_end(page: &Page, view: &str) {
    for (what, answer) in [
        ("text", page.text(view, 1, "q")),
        ("a key", page.input(view, key(1, "q", &[], "press"))),
    ] {
        let refusal = answer.expect_err(what);
        assert_eq!(code(&refusal), "LEASE_LOST", "{what}");
        assert_eq!(
            refusal["message"], "This view has ended, and took nothing.",
            "{what}"
        );
    }
}

/// A host that sends a client a frame that a client may not receive is not one this application
/// reads: the client library ends the session on it, by its one rule for every connection, and the
/// view reads through that library alone. While the view opens, the page is told why, once; the
/// connection is closed, and a command that follows is refused as on any lost link.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_a_client_may_not_receive_during_the_attach_ends_the_open_with_its_cause() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let view = page.open(worker.session_id, 10, 2, 3);
    let mut link = worker.link().await;
    link.expect(Method::SessionAttach).await;
    link.send_request().await;
    let ended = page.state(3, 0).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(
        ended["reason"],
        "The connection to this session ended: the host sent a frame this application does not read"
    );
    page.held_becomes(0).await;
    assert_eq!(
        page.states(3).len(),
        1,
        "the page is told once, and nothing follows: {:?}",
        page.states(3)
    );
    assert!(
        link.closed().await.is_empty(),
        "the view closed its connection and wrote nothing more"
    );
    refused_after_the_end(&page, &view);
}

/// The same frame while the view shows: the view ends as lost, once, and the page is told what it
/// is told of every lost link, which carries no cause; the connection is closed, and a command that
/// follows is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_a_client_may_not_receive_while_the_view_shows_ends_it_as_lost() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    link.send_request().await;
    let ended = page.state(3, 2).await;
    assert_eq!(ended["state"], "ended");
    assert_eq!(ended["reason"], "The connection to this session ended.");
    page.held_becomes(0).await;
    assert_eq!(
        page.states(3).len(),
        3,
        "the page is told once, and nothing follows: {:?}",
        page.states(3)
    );
    assert!(
        link.closed().await.is_empty(),
        "the view closed its connection and wrote nothing more"
    );
    refused_after_the_end(&page, &view);
}

/// A delivery that restarts is told from the one it replaces by its first notification at 0:
/// everything of the old stream that still arrives, before the subscription's answer and after it,
/// is dropped, and the page never shows it.
#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_delivery_drops_the_old_streams_frames_until_its_first_at_zero() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (_view, mut link) = showing(&page, &mut worker, 3).await;
    let shown = page.states(3).len();
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    screen(&mut link, 4, 70, vec![row(0, "stale before")], 0).await;
    link.push("session.resync", &resync_marker(70)).await;
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    screen(&mut link, 5, 80, vec![row(0, "stale after")], 0).await;
    link.push("session.resync", &resync_marker(80)).await;
    assert!(
        link.quiet_for(QUIET).await,
        "an old stream's marker, before and after the answer, starts no second recovery"
    );
    link.restart_stream();
    screen(&mut link, 6, 100, vec![row(0, "new")], 0).await;
    page.newest(3, |state| {
        state["state"] == "showing" && text_of(state) == ["new"]
    })
    .await;
    for state in &page.states(3)[shown..] {
        if state["state"] == "showing" {
            assert_ne!(
                text_of(state)[0],
                "stale before",
                "an old frame before the answer"
            );
            assert_ne!(
                text_of(state)[0],
                "stale after",
                "an old frame after the answer"
            );
        }
    }
}

/// A view that is slower than the host loses no notification: the page holds the view inside its
/// first state while the host writes 262 notifications, more than the 256 that the session's
/// channel holds, so the session's reader waits for room. The host writes from a task of its own,
/// which the case joins, under a bound, once the page lets the view go. While the view is held the
/// case waits only until the host has written what the view, the channel and the reader hold
/// between them (one, 256 and one), which needs no room in the socket: nothing here depends on how
/// much a socket holds, and a host that cannot write the rest yet waits for the view. Every screen
/// the host sent is then shown, in order, and when the host's connection goes the view ends with
/// the words it always had.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_view_loses_no_notification_and_ends_with_its_words() {
    const SCREENS: u64 = 262;
    // What the view, the session's channel and the session's reader hold between them.
    const HELD: u64 = 1 + 256 + 1;
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (_view, link) = showing(&page, &mut worker, 3).await;
    let shown = page.states(3).len();
    let held = Held::new(&page.gate);
    let (progress, mut written) = tokio::sync::watch::channel(0_u64);
    let host = tokio::spawn(async move {
        let mut link = link;
        for number in 0..SCREENS {
            link.push(
                PROJECTION_DELTA_EVENT,
                &delta(
                    1,
                    40 + number,
                    41 + number,
                    10,
                    2,
                    0,
                    vec![row(1, &format!("screen {number}"))],
                ),
            )
            .await;
            progress.send_replace(number + 1);
        }
        drop(link);
    });
    let reached = tokio::time::timeout(STATE_BOUND, written.wait_for(|count| *count >= HELD))
        .await
        .is_ok_and(|count| count.is_ok());
    assert!(
        reached,
        "the host did not write what the view, the channel and the reader hold within the bound"
    );
    page.state(3, shown).await;
    assert_eq!(
        page.states(3).len(),
        shown + 1,
        "the page held the view inside the first state while the host wrote"
    );
    drop(held);
    let joined = tokio::time::timeout(STATE_BOUND, host).await;
    assert!(
        joined.is_ok_and(|host| host.is_ok()),
        "the host did not finish writing within the bound once the view was let on"
    );
    let ended = page.newest(3, |state| state["state"] == "ended").await;
    assert_eq!(ended["reason"], "The connection to this session ended.");
    let expected: Vec<String> = (0..SCREENS)
        .map(|number| format!("screen {number}"))
        .collect();
    assert_eq!(
        flood_texts(&page.states(3), shown),
        expected,
        "every screen is shown, in order"
    );
}

/// A delivery that restarts may begin before the subscription's answer: the first notification of
/// the new stream, at 0, comes after the old stream's last ones and before the answer. The view
/// shows the new screen, and the answer that follows changes nothing: the next update applies to the
/// new screen and nothing is asked again.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_stream_that_begins_before_the_subscriptions_answer_is_shown() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (_view, mut link) = showing(&page, &mut worker, 3).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    screen(&mut link, 4, 70, vec![row(0, "stale")], 0).await;
    link.restart_stream();
    screen(&mut link, 5, 80, vec![row(0, "fresh")], 0).await;
    let fresh = page
        .newest_within(3, |state| {
            state["state"] == "showing" && text_of(state) == ["fresh"]
        })
        .await;
    assert!(
        fresh.is_some(),
        "the new stream's first screen was shown before the subscription was answered: {:?}",
        page.states(3)
    );
    link.answer(&subscribe, &scripted_worker::subscribed())
        .await;
    link.push(
        PROJECTION_DELTA_EVENT,
        &delta(5, 80, 90, 10, 1, 0, vec![row(0, "next")]),
    )
    .await;
    let next = page
        .newest_within(3, |state| {
            state["state"] == "showing" && text_of(state) == ["next"]
        })
        .await;
    assert!(
        next.is_some(),
        "the update after the answer applied to the new screen: {:?}",
        page.states(3)
    );
    assert!(
        link.call_now().is_none(),
        "the answer started no second recovery"
    );
    let shown: Vec<Vec<String>> = page
        .states(3)
        .iter()
        .filter(|state| state["state"] == "showing")
        .map(text_of)
        .collect();
    assert_eq!(
        shown,
        vec![
            vec!["first".to_owned(), "second".to_owned()],
            vec!["fresh".to_owned()],
            vec!["next".to_owned()]
        ],
        "nothing of the old stream was shown"
    );
}

/// A word heard while a size report waits for its answer lets the size go again when the session
/// refuses it for now, whichever of the refusal and the word the loop takes first: the host sent the
/// repaint before the refusal here, and the size goes again at once, with no further word.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_for_now_after_a_word_heard_in_flight_lets_the_size_go_again() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    page.resize(&view, 12, 3);
    let first = link.expect(Method::AttachmentViewport).await;
    screen(&mut link, 2, 60, vec![row(0, "repaint")], 0).await;
    page.newest(3, |state| {
        state["state"] == "showing" && text_of(state) == ["repaint"]
    })
    .await;
    link.refuse_with(&first, ErrorCode::ResourceUnavailable, "not now")
        .await;
    let again = tokio::time::timeout(Duration::from_secs(5), link.call()).await;
    assert!(
        again.is_ok_and(|call| call.method == Method::AttachmentViewport.to_string()),
        "the size goes again after a repaint was heard while it was in flight"
    );
}

/// A call that the loop started is never dropped by the loop going on: a report that waits for its
/// answer while notifications and commands pass is still answered when the answer comes.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_waiting_for_its_answer_survives_everything_the_loop_does_meanwhile() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    page.resize(&view, 12, 3);
    let asked = link.expect(Method::AttachmentViewport).await;
    for number in 0..20_u64 {
        screen(&mut link, number + 2, 60 + number, vec![row(0, "busy")], 0).await;
        page.resize(&view, 12 + number % 2, 3);
    }
    page.newest(3, |state| {
        state["state"] == "showing" && text_of(state) == ["busy"]
    })
    .await;
    link.answer(&asked, &viewport_answer(1)).await;
    // The answer is applied to the attachment the page is shown, with the next screen.
    screen(&mut link, 40, 300, vec![row(0, "after")], 1).await;
    let after = page
        .newest(3, |state| {
            state["state"] == "showing" && text_of(state) == ["after"]
        })
        .await;
    assert_eq!(
        after["attachment"]["presentation_reason"], "size_mismatch",
        "the answer of a call that waited through all that is applied"
    );
}

/// The screens of the states a view published from index `from` on, one text for each screen: the
/// second row's text, with a state that only changes control (it shows the screen before it again)
/// counted once.
fn flood_texts(states: &[Value], from: usize) -> Vec<String> {
    let mut texts: Vec<String> = states[from..]
        .iter()
        .filter(|state| state["state"] == "showing")
        .map(|state| text_of(state)[1].clone())
        .collect();
    texts.dedup();
    texts
}

/// A flood of screens that the page takes slowly, with two calls the host has not answered and a
/// command of the page behind them. The view keeps the host's order between a screen and an answer
/// (every screen the host sent before an answer is shown before the answer's effect), the page's
/// command leaves in the turn that takes it while the page still holds the view and the view's queue
/// holds what the channel held, and that queue never holds more than the session's channel and what
/// was ready in one look.
///
/// The page is held by the gate of its publication: the view's own task waits inside a state until
/// the case lets it pass. While it is held the host writes only what the view, the session's
/// channel and the session's reader hold between them: 258 notifications (one, 256 and one), the
/// answer to the take's acquire after the first 150 screens, and the answer to a launch surface
/// read after ten notices that draw nothing and 87 screens more, then ten notices and one screen.
/// The answers take no place in the channel, so both are read while the channel is full and are
/// ready in the first look, with all of the channel. Nothing the host writes needs room in the
/// socket, so nothing here depends on how much a socket holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_flood_the_page_takes_slowly_keeps_the_hosts_order_and_holds_back_no_command() {
    const BEFORE_ACQUIRE: u64 = 150;
    const BETWEEN_NOTICES: u64 = 10;
    const BEFORE_SURFACE: u64 = 87;
    const AFTER_NOTICES: u64 = 10;
    const FLOOD: u64 = BEFORE_ACQUIRE + BEFORE_SURFACE;
    const CHANNEL: usize = 256;
    // The view holds one, the channel 256 and the session's reader one.
    const _: () = assert!(FLOOD + BETWEEN_NOTICES + AFTER_NOTICES + 1 == 1 + CHANNEL as u64 + 1);
    const CALLS_IN_FLIGHT: usize = 3;
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::default();
    let (view, mut link) = showing(&page, &mut worker, 3).await;
    let views = page.app.state::<companion_tauri::terminal::TerminalViews>();
    // Two calls that the host has not answered when the flood begins.
    page.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    page.newest(3, |state| control(state) == (1, "taking".to_owned()))
        .await;
    let reading = page.invoke_later("terminal_view_launch_surface", json!({ "view": view }));
    let surface = link.expect(Method::ShellLaunchSurface).await;
    let first = page.states(3).len();
    let held = Held::new(&page.gate);
    let flood = |number: u64| {
        delta(
            1,
            40 + number,
            41 + number,
            10,
            2,
            0,
            vec![row(1, &format!("flood {number}"))],
        )
    };
    for number in 0..BEFORE_ACQUIRE {
        link.push(PROJECTION_DELTA_EVENT, &flood(number)).await;
    }
    lease.answer(&mut link, &acquire).await;
    let notice = json!({"requested_cursor": "10", "oldest_retained_cursor": "20"});
    for _ in 0..BETWEEN_NOTICES {
        link.push("session.gap", &notice).await;
    }
    for number in BEFORE_ACQUIRE..FLOOD {
        link.push(PROJECTION_DELTA_EVENT, &flood(number)).await;
    }
    link.answer(&surface, &a_surface_held_here(worker.session_id))
        .await;
    for _ in 0..AFTER_NOTICES {
        link.push("session.gap", &notice).await;
    }
    link.push(
        PROJECTION_DELTA_EVENT,
        &delta(1, 40 + FLOOD, 41 + FLOOD, 10, 2, 0, vec![row(1, "after")]),
    )
    .await;
    // The view is inside the first state of the flood, and holds nothing else.
    page.state(3, first).await;
    // The page takes states one at a time until a look has moved what the channel held into the
    // view's queue.
    let mut recorded = first + 1;
    for _ in 0..60 {
        if views.queue_peak(&view).expect("the view is open") >= CHANNEL - CHANNEL / 8 {
            break;
        }
        held.let_pass(1);
        page.state(3, recorded).await;
        recorded += 1;
    }
    // A command of the page, while the view is held in the middle of that queue: a size report,
    // which nothing in flight stops. One state passes, and the command leaves in the turn that
    // takes it, with the rest of the queue still waiting.
    page.resize(&view, 12, 3);
    held.let_pass(1);
    page.state(3, recorded).await;
    let report = link.call_within(STATE_BOUND).await.expect(
        "the size report was not on the wire within the bound while the page still holds the view",
    );
    assert_eq!(report.method, Method::AttachmentViewport.to_string());
    assert_eq!(
        report
            .params::<kr_protocol::attachment::AttachmentViewportParams>()
            .dimensions,
        Dimensions::new(12, 3),
        "the report is the command's"
    );
    assert!(
        link.quiet_for(QUIET).await,
        "the command made one request, and nothing else was owed"
    );
    drop(held);
    page.newest(3, |state| {
        state["state"] == "showing" && text_of(state)[1] == "after"
    })
    .await;
    let states = page.states(3);
    let expected: Vec<String> = (0..FLOOD)
        .map(|number| format!("flood {number}"))
        .chain(["after".to_owned()])
        .collect();
    assert_eq!(
        flood_texts(&states, first),
        expected,
        "every screen is shown, in the order the host sent it"
    );
    let controlling = states
        .iter()
        .position(|state| control(state) == (1, "controlling".to_owned()))
        .expect("the acquire's answer is served");
    assert!(
        flood_texts(&states[..controlling], first)
            .contains(&format!("flood {}", BEFORE_ACQUIRE - 1)),
        "every screen the host sent before the answer is shown before the answer's effect"
    );
    let peak = views.queue_peak(&view).expect("the view is open");
    assert!(
        peak > CHANNEL / 2,
        "a look moved what the channel held into the queue: {peak}"
    );
    assert!(
        peak <= CHANNEL + CALLS_IN_FLIGHT,
        "the queue never held more than the channel's size and what was ready in one look: {peak}"
    );
    let told = reading.await.expect("joins").expect("the surface is read");
    assert_eq!(told["state"], "served", "{told}");
}

/// More than sixty-four notifications, the session's close and then a definite refusal of the subscription
/// that was waiting: the host sent the close first, so the view ends with the close's words, not
/// with the refusal's, although the refusal's call is complete when the view looks at its calls.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_that_follows_the_sessions_close_does_not_end_the_view_first() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (_view, mut link) = showing(&page, &mut worker, 3).await;
    link.push("session.resync", &resync_marker(60)).await;
    let subscribe = link.expect(Method::EventsSubscribe).await;
    let first = page.states(3).len();
    let held = Held::new(&page.gate);
    link.restart_stream();
    // Twenty-two screens of three notifications each: more than the sixty-four in a row that the
    // view once took before it looked at its calls.
    for number in 0..22_u64 {
        screen(
            &mut link,
            number + 2,
            60 + number,
            vec![row(0, &format!("screen {number}"))],
            0,
        )
        .await;
    }
    link.push("session.closed", &json!({"reason": "exited"}))
        .await;
    link.refuse(&subscribe, "the subscription is refused").await;
    // The view is inside the first state it published after the marker.
    page.state(3, first).await;
    drop(held);
    let ended = page.newest(3, |state| state["state"] == "ended").await;
    assert_eq!(
        ended["reason"], "This session has closed.",
        "the close came first on the wire"
    );
}

/// The most a view's close may take when a key stands unanswered at the worker. The close does not
/// wait for a frame that will not come, so it ends at once; this is what a loaded machine is given.
const CLOSE_BOUND: Duration = Duration::from_secs(10);

/// Asks `view` to close as the page does, without waiting for it, and says whether the view ended
/// within [`CLOSE_BOUND`].
async fn ended_within_the_close_bound(page: &Page, view: &str) -> bool {
    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .closer(view)();
    tokio::time::timeout(CLOSE_BOUND, async {
        while page.held() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// The methods of the calls a view wrote, as `Link::closed` read them.
fn methods(sent: &[scripted_worker::Call]) -> Vec<&str> {
    sent.iter().map(|call| call.method.as_str()).collect()
}

/// Two keys of one epoch, the first waiting for its answer; a release and a new take; the worker
/// answers the first key and the acquire and never the second. The lane's writer waits for that
/// answer for ever, and the release stands behind it. The person's close ends the view at once: the
/// lane has a key of an older epoch in flight, so the view queues no detach, which could not be
/// written, and the connection's end is what ends the attachment.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_after_a_new_take_does_not_wait_for_a_key_the_worker_never_answers() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the first key is taken");
    page.text(&view, 1, "b").expect("the second key is taken");
    let first = link.expect(Method::InputWrite).await;
    page.release(&view, 2);
    page.take(&view, 3);
    let acquire = link.expect(Method::InputAcquire).await;
    // The answer to the first key lets the lane write the second, which the worker never answers.
    lease.answer(&mut link, &first).await;
    let second = link.expect(Method::InputWrite).await;
    assert_eq!(
        second.params::<InputWriteParams>().sequence.get(),
        1,
        "the second key of the epoch"
    );
    lease.answer(&mut link, &acquire).await;
    page.newest(3, |state| control(state) == (3, "controlling".to_owned()))
        .await;
    assert!(
        ended_within_the_close_bound(&page, &view).await,
        "the close did not end the view within its bound: it waits for the second key's answer"
    );
    let sent = link.closed().await;
    assert!(
        sent.is_empty(),
        "neither the release nor the detach behind the second key was written: {:?}",
        methods(&sent)
    );
}

/// A key that the worker answered, whose acceptance the lane has not handed on because the view
/// is held inside a state it published, does not keep the close from writing the detach whole: the
/// lane has no key left, whatever the view has read of its words. The release that stands behind
/// the key is written when the lane has the key's answer, which shows that the lane has the
/// acceptance.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_answered_before_the_view_read_its_acceptance_does_not_stop_the_detach() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the key is taken");
    let key = link.expect(Method::InputWrite).await;
    // The view took the release and queued it behind the key before it takes anything else.
    page.release(&view, 2);
    page.newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    link.push("session.resync", &resync_marker(60)).await;
    let _subscribe = link.expect(Method::EventsSubscribe).await;
    let first = page.states(3).len();
    let held = Held::new(&page.gate);
    link.restart_stream();
    screen(&mut link, 2, 60, vec![row(0, "one"), row(1, "two")], 0).await;
    // The view is inside the first state it published after the marker, and takes nothing.
    page.state(3, first).await;
    lease.answer(&mut link, &key).await;
    // The release goes once the lane has the key's answer: the lane holds the acceptance, and the
    // view, being held, has not read it.
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .closer(&view)();
    drop(held);
    page.held_becomes(0).await;
    let sent = link.closed().await;
    assert_eq!(
        methods(&sent)
            .iter()
            .filter(|method| **method == "session.detach")
            .count(),
        1,
        "the detach was written whole: {:?}",
        methods(&sent)
    );
}

/// A key that the worker answered, whose acceptance the view has read from the lane and set aside
/// behind an update that it serves first, does not keep a close that is served meanwhile from
/// writing the detach whole. The view is held inside the state of a first update; a second update
/// reaches its session's channel, and the key's answer reaches the lane, whose release behind the
/// key goes once it has the answer. When the view is let on, it takes the second update and the
/// acceptance together, serves the update, and is held inside its state while the close waits: the
/// acceptance is in the view's queue, not the lane's, when the close is served.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_whose_acceptance_waits_in_the_views_queue_does_not_stop_the_detach() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) = controlling(
        &page,
        &mut worker,
        3,
        &Frame::live((10, 2), (10, 2), 0),
        &mut lease,
    )
    .await;
    page.text(&view, 1, "a").expect("the key is taken");
    let key = link.expect(Method::InputWrite).await;
    page.release(&view, 2);
    page.newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    let first = page.states(3).len();
    let held = Held::new(&page.gate);
    link.push(
        PROJECTION_DELTA_EVENT,
        &delta(1, 40, 52, 10, 2, 0, vec![row(1, "one")]),
    )
    .await;
    // The view is inside the state of the first update, and takes nothing.
    page.state(3, first).await;
    link.push(
        PROJECTION_DELTA_EVENT,
        &delta(1, 52, 64, 10, 2, 0, vec![row(1, "two")]),
    )
    .await;
    lease.answer(&mut link, &key).await;
    // The release goes once the lane has the key's answer. The second update came before that
    // answer on the connection, so the session's channel holds it by now.
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    held.let_pass(1);
    // The view took the second update ahead of the acceptance, and is inside the update's state.
    page.state(3, first + 1).await;
    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .closer(&view)();
    drop(held);
    page.held_becomes(0).await;
    let sent = link.closed().await;
    assert_eq!(
        methods(&sent)
            .iter()
            .filter(|method| **method == "session.detach")
            .count(),
        1,
        "the detach was written whole: {:?}",
        methods(&sent)
    );
}

/// Two keys typed one after the other, the first waiting for its answer; a release and a new take;
/// the worker answers the acquire, and then refuses the first key, late, under the older epoch,
/// which the lane reports by no event. The second key never left the lane's queue: the new epoch
/// dropped it. The person closes before a key of the new epoch is accepted: the lane has no key
/// left, so the close waits for the detach and the worker reads it whole.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_after_a_new_take_waits_for_the_detach_when_every_key_has_its_answer() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.text(&view, 1, "a").expect("the first key is taken");
    page.text(&view, 1, "b").expect("the second key is taken");
    let first = link.expect(Method::InputWrite).await;
    page.release(&view, 2);
    page.take(&view, 3);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    page.newest(3, |state| control(state) == (3, "controlling".to_owned()))
        .await;
    link.refuse_with(&first, ErrorCode::LeaseLost, "the lease has moved on")
        .await;
    // The release of the older epoch goes once the lane has the first key's answer.
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    lease.answer(&mut link, &release).await;
    assert!(
        ended_within_the_close_bound(&page, &view).await,
        "the close did not end the view within its bound"
    );
    let sent = link.closed().await;
    assert_eq!(
        methods(&sent)
            .iter()
            .filter(|method| **method == "session.detach")
            .count(),
        1,
        "the detach was written whole: {:?}",
        methods(&sent)
    );
}

/// How a scripted worker answers a launch.
enum Launched {
    Installed,
    Refused(ErrorCode),
}

/// Presses a launch on `view` and answers it as `launched` says; returns what the page was told.
/// Fails when the page was told before the launch reached the wire.
async fn launch_answered(
    page: &Page,
    view: &str,
    link: &mut Link,
    launched: &Launched,
    round: usize,
) -> Result<Value, Value> {
    let mut pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    let launch = tokio::select! {
        launch = link.expect(Method::ShellLaunch) => launch,
        told = &mut pressing => {
            panic!("launch {round} was answered to the page before it reached the wire: {told:?}")
        }
    };
    match launched {
        Launched::Installed => {
            let asked: kr_protocol::root::ShellLaunchParams = launch.params();
            let installed = kr_protocol::root::ShellLaunchResult {
                fence_id: kr_protocol::root::FenceId::new(kr_ipc::new_uuid()),
                prompt_generation: asked.expected_prompt_generation,
                buffer_revision: kr_protocol::root::EditorBufferRevision::new(4),
            };
            link.answer(&launch, &installed).await;
        }
        Launched::Refused(refusal) => link.refuse_with(&launch, *refusal, "scripted").await,
    }
    pressing.await.expect("joins")
}

/// Launches whose results are definite, more of them than the session keeps unresolved actions
/// for, are settled by the view as they are answered: the session's book does not grow with the
/// view's life, and a release and a detach after them still go.
#[tokio::test(flavor = "multi_thread")]
async fn definite_results_of_launches_do_not_fill_the_sessions_unresolved_actions() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    for round in 0..kr_client::session::MAX_UNRESOLVED_ACTIONS + 8 {
        if round % 2 == 0 {
            let told = launch_answered(&page, &view, &mut link, &Launched::Installed, round).await;
            assert!(told.is_ok(), "launch {round} was installed: {told:?}");
        } else {
            let told = launch_answered(
                &page,
                &view,
                &mut link,
                &Launched::Refused(ErrorCode::DraftConflict),
                round,
            )
            .await
            .expect_err("the host refused the launch");
            assert_eq!(code(&told), "DRAFT_CONFLICT", "launch {round}");
        }
    }
    page.release(&view, 2);
    let release = link.expect(Method::InputRelease).await;
    lease.answer(&mut link, &release).await;
    page.newest(3, |state| control(state) == (2, "watching".to_owned()))
        .await;
    assert!(
        ended_within_the_close_bound(&page, &view).await,
        "the view ended within the close bound"
    );
    let sent = link.closed().await;
    assert_eq!(
        methods(&sent),
        vec!["session.detach"],
        "the detach still went after the launches"
    );
}

/// A result that is not definite is left as the session's rule has it: a launch answered as of
/// unknown outcome, or refused for now, stays an unresolved action, so that the session can ask
/// after it. At the bound the next launch is refused by the session before any byte goes.
#[tokio::test(flavor = "multi_thread")]
async fn launches_whose_result_is_not_definite_stay_unresolved_at_the_session() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let mut lease = WorkerLease::at(4);
    let (view, mut link) =
        controlling(&page, &mut worker, 3, &reporting(Mouse::Sgr), &mut lease).await;
    for round in 0..kr_client::session::MAX_UNRESOLVED_ACTIONS {
        let (refusal, said) = if round % 4 == 3 {
            (ErrorCode::RendezvousUnavailable, "RENDEZVOUS_UNAVAILABLE")
        } else {
            (ErrorCode::OutcomeUnknown, "OUTCOME_UNKNOWN")
        };
        let told = launch_answered(&page, &view, &mut link, &Launched::Refused(refusal), round)
            .await
            .expect_err("the host did not decide");
        assert_eq!(code(&told), said, "launch {round}");
    }
    let mut pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    let told = tokio::select! {
        launch = link.expect(Method::ShellLaunch) => {
            panic!("the launch reached the wire with the session at its bound: {:?}", launch.method)
        }
        told = &mut pressing => told.expect("joins").expect_err("the session refuses it"),
    };
    assert_eq!(code(&told), "RESOURCE_UNAVAILABLE");
}

// ---- The network carrier: a paired view's typing on a stream of its own -----------------------

/// The window that the scripted host says on the input stream: `frames` frames, and room for any
/// of them.
fn lane_window(frames: u32) -> kr_protocol::input::InputWindow {
    kr_protocol::input::InputWindow {
        frames,
        bytes: kr_protocol::scalars::U64::new(512 * 1024),
    }
}

impl Page {
    /// The application whose next view opens on the connection of `host`, a paired host's: the view
    /// opens the session on it as it does on a connection its device dialled.
    fn over(host: &mut ScriptedHost) -> Self {
        let page = Self::new(host.paths());
        page.app
            .state::<companion_tauri::terminal::TerminalViews>()
            .over(host.transport());
        page
    }
}

/// A view of a paired host's session, attached and showing `at`, whose host takes the input stream
/// and has seen it open.
async fn paired(page: &Page, host: &mut ScriptedHost, channel: u32, at: &Frame) -> (String, Link) {
    let view = page.open(host.session_id, at.window_columns, at.window_rows, channel);
    let mut link = host.link().await;
    link.attach().await;
    host.takes(&mut link, Takes::Input).await;
    frame(&mut link, at).await;
    page.newest(channel, |state| state["state"] == "showing")
        .await;
    host.script
        .until("the input stream's header", |seen| seen.headers.len() == 1)
        .await;
    (view, link)
}

/// A view as [`paired`] has it, which controls the program under the page's take 1.
async fn paired_controlling(
    page: &Page,
    host: &mut ScriptedHost,
    channel: u32,
    at: &Frame,
    lease: &mut WorkerLease,
) -> (String, Link) {
    let (view, mut link) = paired(page, host, channel, at).await;
    page.take(&view, 1);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &acquire).await;
    page.newest(channel, |state| {
        control(state) == (1, "controlling".to_owned())
    })
    .await;
    (view, link)
}

/// The frames that the host has read, as (epoch, sequence, text).
fn read_by(host: &ScriptedHost) -> Vec<(u64, u64, String)> {
    host.script
        .frames()
        .into_iter()
        .map(|seen| {
            (
                seen.epoch,
                seen.sequence,
                String::from_utf8(seen.bytes).expect("typing the cases wrote"),
            )
        })
        .collect()
}

/// The lane opens on a paired link once the attach is answered, with one stream under the
/// attachment's header; the typing goes on that stream in order, under the epoch the acquire gave and
/// numbers from 0, and none of it is a call on the control stream.
#[tokio::test(flavor = "multi_thread")]
async fn a_paired_views_lane_opens_after_the_attach_and_its_keys_go_on_the_stream_in_order() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    let kinds = host.script.seen(|seen| {
        seen.headers
            .iter()
            .map(|header| header.kind)
            .collect::<Vec<_>>()
    });
    assert_eq!(kinds, vec![kr_protocol::frame::StreamKind::TerminalInput]);
    for key in ["a", "b", "c"] {
        page.text(&view, 1, key).expect("the key is taken");
    }
    host.script
        .until("three frames", |seen| seen.frames.len() == 3)
        .await;
    assert_eq!(
        read_by(&host),
        vec![
            (1, 0, "a".to_owned()),
            (1, 1, "b".to_owned()),
            (1, 2, "c".to_owned())
        ]
    );
    assert!(
        link.quiet_for(QUIET).await,
        "none of the typing is a call on the control stream"
    );
}

/// How long a case waits for a call or a state of a lane that must come at once once the barrier's
/// wait (the lane bounds that by two seconds) is over.
const AFTER_BARRIER: Duration = Duration::from_secs(10);

/// Three keys, `a`, `b` and `c`, taken by the view under the page's take 1 and read by the host, and
/// none of them accepted: the lane's barrier for an ending that follows cannot be reached.
async fn three_keys_the_host_has_read(page: &Page, view: &str, host: &ScriptedHost) {
    for key in ["a", "b", "c"] {
        page.text(view, 1, key).expect("the key is taken");
    }
    host.script
        .until("three frames", |seen| seen.frames.len() == 3)
        .await;
}

/// The release's position, as the host reads it: the epoch and the count of frames it names.
fn position(release: &scripted_worker::Call) -> Option<(u64, u64)> {
    release
        .params::<InputReleaseParams>()
        .after_input
        .map(|barrier| (barrier.epoch.get(), barrier.count.get()))
}

/// KR-REQ-07 (the input stream), release: a release whose barrier the host did not reach (the lane
/// waits two seconds for the host to accept the typing before it) goes at once, and names the typing
/// that the host did accept, not what the view admitted: the first of three frames.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreached_release_goes_at_once_naming_the_typing_the_host_accepted() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    host.script.accept(1, 0);
    page.release(&view, 2);
    let release = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release went within the bound after the barrier's wait");
    assert_eq!(release.method, Method::InputRelease.to_string());
    assert_eq!(
        position(&release),
        Some((1, 1)),
        "the release names the one frame the host accepted, not the three admitted"
    );
}

/// A release that the host refuses because it had not taken the typing before it goes once more,
/// with no position, and the page is told nothing of a refusal.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_refused_for_the_typing_before_it_goes_once_more_with_no_position() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    page.release(&view, 2);
    let first = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release went");
    assert_eq!(position(&first), Some((1, 0)), "nothing was accepted");
    link.refuse_with(
        &first,
        ErrorCode::DraftConflict,
        "the typing before this request has not all arrived",
    )
    .await;
    let again = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release was sent once more within the bound");
    assert_eq!(again.method, Method::InputRelease.to_string());
    assert_eq!(position(&again), None, "the second send names no position");
    lease.answer(&mut link, &again).await;
    assert!(link.call_within(QUIET).await.is_none(), "no third send");
    let state = newest_now(&page, 3);
    assert_eq!(control(&state), (2, "watching".to_owned()));
    assert!(
        state["control"]["ended"].is_null(),
        "the page is told of no refusal: {state}"
    );
}

/// A second refusal of the release is shown once, in the shown rule's words for the session's own
/// message, and claims nothing of whether control ended; nothing is sent a third time.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_refusal_of_a_release_is_shown_once_and_claims_no_end_of_control() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    page.release(&view, 2);
    let first = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release went");
    link.refuse_with(&first, ErrorCode::DraftConflict, "not all arrived")
        .await;
    let again = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release was sent once more within the bound");
    link.refuse_with(&again, ErrorCode::PermissionDenied, "no way")
        .await;
    let words = "The session did not accept this view's release of control: no way";
    let told = page
        .newest_within(3, |state| state["control"]["ended"] == words)
        .await
        .expect("the second refusal was shown within the bound");
    assert_eq!(control(&told), (2, "watching".to_owned()));
    assert!(link.call_within(QUIET).await.is_none(), "no third send");
    let shown = page
        .states(3)
        .iter()
        .filter(|state| state["control"]["ended"] == words)
        .count();
    assert_eq!(shown, 1, "shown once");
}

/// A first refusal that is not the failed precondition and not a lost lease is shown once as well,
/// and the release is not sent again.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_refused_for_another_reason_is_shown_once_and_not_sent_again() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.release(&view, 2);
    let first = link.expect(Method::InputRelease).await;
    link.refuse_with(&first, ErrorCode::PermissionDenied, "not yours")
        .await;
    let words = "The session did not accept this view's release of control: not yours";
    page.newest_within(3, |state| state["control"]["ended"] == words)
        .await
        .expect("the refusal was shown within the bound");
    assert!(
        link.call_within(QUIET).await.is_none(),
        "the release is not sent again"
    );
}

/// A lost lease is a release that is done: nothing is sent again, and nothing is shown.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_of_a_lease_already_lost_is_done_and_shows_nothing() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    page.release(&view, 2);
    let first = link.expect(Method::InputRelease).await;
    link.refuse_with(
        &first,
        ErrorCode::LeaseLost,
        "this attachment does not hold it",
    )
    .await;
    assert!(
        link.call_within(QUIET).await.is_none(),
        "the release is not sent again"
    );
    assert!(newest_now(&page, 3)["control"]["ended"].is_null());
}

/// The host refuses the third frame and says it took two before it: an ending that stood behind the
/// typing names those two, the count that a refusal of the same epoch states.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_that_states_what_was_accepted_moves_the_count_an_ending_names() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    page.release(&view, 2);
    host.script
        .refuse(1, 2, Some(1), ErrorCode::PermissionDenied);
    let release = link
        .call_within(AFTER_BARRIER)
        .await
        .expect("the release went within the bound");
    assert_eq!(position(&release), Some((1, 2)));
}

/// The close's detach is written whole, once, naming what the host accepted, and that counts what the
/// host accepts while the close waits for the rest.
#[tokio::test(flavor = "multi_thread")]
async fn the_close_names_what_the_host_accepted_including_what_it_accepted_while_it_waited() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    host.script.accept(1, 0);
    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .closer(&view)();
    host.script.accept(1, 1);
    assert!(
        ended_within_the_close_bound(&page, &view).await,
        "the close ended the view within the bound"
    );
    // The view writes the detach and closes the connection at once, so the host may not read what
    // the connection took whole: the case reads it where the connection took it.
    let detaches: Vec<SessionDetachParams> = host
        .written()
        .into_iter()
        .filter_map(|frame| match frame {
            kr_protocol::envelope::ControlFrame::Mutation(mutation)
                if mutation.method.to_string() == Method::SessionDetach.to_string() =>
            {
                mutation.params.to_typed().ok()
            }
            _ => None,
        })
        .collect();
    assert_eq!(detaches.len(), 1, "the detach is written once");
    let barrier = detaches[0]
        .after_input
        .clone()
        .expect("the detach names a position");
    assert_eq!((barrier.epoch.get(), barrier.count.get()), (1, 2));
    let _ = link.closed().await;
}

/// A launch whose barrier the host did not reach is never sent: the page is told at once, in the
/// ruled words, nothing of it is on the wire, and the typing held behind it goes out in order.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreached_launch_is_not_sent_and_the_typing_behind_it_goes_in_order() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    three_keys_the_host_has_read(&page, &view, &host).await;
    let mut pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    assert!(
        link.quiet_for(QUIET).await,
        "the launch stands behind the typing: nothing of it is on the wire"
    );
    // Typed after the press has taken its barrier, so the lane holds it behind the launch.
    page.text(&view, 1, "z").expect("the key is taken");
    let told = tokio::time::timeout(AFTER_BARRIER, &mut pressing)
        .await
        .expect("the page was told within the bound")
        .expect("joins")
        .expect_err("the launch was not started");
    assert_eq!(code(&told), "TERMINAL_UNAVAILABLE");
    assert_eq!(
        told["message"],
        "The launch was not started: the session had not accepted all the typing before it."
    );
    host.script
        .until_soon("the typing held behind the launch", |seen| {
            seen.frames.len() == 4
        })
        .await;
    assert_eq!(read_by(&host).last(), Some(&(1, 3, "z".to_owned())));
    assert!(
        link.call_within(QUIET).await.is_none(),
        "no launch is on the wire"
    );
}

/// A launch whose barrier the host reached, with typing behind it that the lane holds: the press has
/// taken its barrier once its call is on the control stream, so the key typed then is held behind it.
async fn launched_with_typing_behind_it(
    page: &Page,
    view: &str,
    host: &ScriptedHost,
    link: &mut Link,
) -> (
    tokio::task::JoinHandle<Result<Value, Value>>,
    scripted_worker::Call,
) {
    three_keys_the_host_has_read(page, view, host).await;
    host.script.accept(1, 2);
    let pressing = page.invoke_later(
        "terminal_view_launch",
        json!({ "view": view, "press": the_press() }),
    );
    let launch = link.expect(Method::ShellLaunch).await;
    page.text(view, 1, "z").expect("the key is taken");
    (pressing, launch)
}

/// Whether the host reads a fourth frame within the quiet that a view that sends nothing is watched
/// for: false is what a held key does.
async fn fourth_frame_within_the_quiet(host: &ScriptedHost) -> bool {
    tokio::time::timeout(
        QUIET,
        host.script
            .until("a fourth frame", |seen| seen.frames.len() >= 4),
    )
    .await
    .is_ok()
}

/// A launch whose outcome the host does not know keeps the typing behind it held: the launch may
/// still be before its reservation. The page is told the outcome is unknown, and the marker, when it
/// comes, releases the key in order.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_launch_outcome_keeps_the_typing_behind_it_held_until_the_marker() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    let (pressing, launch) = launched_with_typing_behind_it(&page, &view, &host, &mut link).await;
    link.refuse_with(&launch, ErrorCode::OutcomeUnknown, "the host does not know")
        .await;
    let told = tokio::time::timeout(AFTER_BARRIER, pressing)
        .await
        .expect("the page was told within the bound")
        .expect("joins")
        .expect_err("the outcome is unknown");
    assert_eq!(code(&told), "OUTCOME_UNKNOWN");
    assert!(
        !fourth_frame_within_the_quiet(&host).await,
        "the key behind an unknown launch is still held"
    );
    host.script.marker(1);
    host.script
        .until_soon("the key behind the launch", |seen| seen.frames.len() == 4)
        .await;
    assert_eq!(read_by(&host).last(), Some(&(1, 3, "z".to_owned())));
}

/// A launch that the host answers definitely, here by a refusal that is not the library's unknown,
/// releases the typing behind it in order, with no marker.
#[tokio::test(flavor = "multi_thread")]
async fn a_definite_launch_answer_releases_the_typing_behind_it_in_order() {
    let mut host = ScriptedHost::start(lane_window(8)).await;
    let page = Page::over(&mut host);
    let mut lease = WorkerLease::default();
    let (view, mut link) =
        paired_controlling(&page, &mut host, 3, &reporting(Mouse::Sgr), &mut lease).await;
    let (pressing, launch) = launched_with_typing_behind_it(&page, &view, &host, &mut link).await;
    link.refuse_with(
        &launch,
        ErrorCode::DraftConflict,
        "the editor has typing before the launch",
    )
    .await;
    let told = tokio::time::timeout(AFTER_BARRIER, pressing)
        .await
        .expect("the page was told within the bound")
        .expect("joins")
        .expect_err("the launch was refused");
    assert_eq!(code(&told), "DRAFT_CONFLICT");
    host.script
        .until_soon("the key behind the launch", |seen| seen.frames.len() == 4)
        .await;
    assert_eq!(read_by(&host).last(), Some(&(1, 3, "z".to_owned())));
}
