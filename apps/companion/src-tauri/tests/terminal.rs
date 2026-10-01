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
use scripted_worker::{
    CallKind, Challenge, Frame, Keys, Link, Mouse, Negotiated, ScriptedWorker, Stated, WATCHDOG,
    WorkerLease, delta, frame, frame_delta, keys_delta, mouse_delta, page as rows_page, reset, row,
    screen, snapshot,
};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
#[cfg(not(windows))]
const BUNDLE: &str = "tauri://localhost";

/// How long a view that should send nothing is watched.
const QUIET: Duration = Duration::from_millis(300);

/// The page: an application with the view's commands, and every state each channel was sent.
struct Page {
    app: tauri::App<MockRuntime>,
    windows: BTreeMap<String, tauri::WebviewWindow<MockRuntime>>,
    published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>>,
}

impl Page {
    /// The application, with its view registry reading descriptors from `worker`'s host tree.
    fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        Self::with_pages(paths, &["main"])
    }

    fn with_pages(paths: kr_ipc::paths::EnvironmentPaths, labels: &[&str]) -> Self {
        let published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>> = Arc::default();
        let heard = Arc::clone(&published);
        let builder = tauri::test::mock_builder()
            .channel_interceptor(move |_webview, callback, _index, body| {
                if let tauri::ipc::InvokeResponseBody::Json(json) = body {
                    let state: Value = serde_json::from_str(json).expect("a state the page reads");
                    heard
                        .lock()
                        .expect("the record")
                        .entry(callback.0)
                        .or_default()
                        .push(state);
                }
                true
            })
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::terminal_view_open,
                companion_tauri::commands::terminal_view_resize,
                companion_tauri::commands::terminal_view_move,
                companion_tauri::commands::terminal_view_input,
                companion_tauri::commands::terminal_view_close,
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
    hostile.runs[0].cells =
        kr_protocol::scalars::U64::new(kr_term::unicode::cells_for(text) as u64);
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
    kr_protocol::attachment::AttachmentViewportResult {
        geometry: kr_protocol::attachment::GeometryState {
            owner: kr_protocol::scalars::Nullable::null(),
            epoch: kr_protocol::ids::GeometryEpoch::new(1),
            dimensions: Dimensions::new(80, 24),
        },
        presentation: kr_protocol::attachment::TerminalPresentationMode::Viewport,
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
        asked.bytes.as_slice(),
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
        asked.bytes.as_slice(),
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
        assert_eq!(
            asked.bytes.as_slice(),
            format!("\x1b[<{button};1;1M").as_bytes()
        );
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
        asked.bytes.as_slice(),
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
        asked.bytes.as_slice(),
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
        write.params::<InputWriteParams>().bytes.as_slice(),
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

/// A release and a take made one after the other each go in order under their own epochs; a late
/// answer for the old epoch changes nothing, and an input made under the old take is refused once
/// the new one controls the program.
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
    let release = link.expect(Method::InputRelease).await;
    assert_eq!(release.params::<InputReleaseParams>().epoch.get(), 5);
    let acquire = link.expect(Method::InputAcquire).await;
    lease.answer(&mut link, &release).await;
    lease.answer(&mut link, &acquire).await;
    page_view
        .newest(3, |state| control(state) == (3, "controlling".to_owned()))
        .await;
    link.refuse_with(&old_write, ErrorCode::LeaseLost, "the lease has moved on")
        .await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        control(&newest_now(&page_view, 3)),
        (3, "controlling".to_owned()),
        "an old epoch's answer changes nothing"
    );
    assert_eq!(
        code(
            &page_view
                .text(&view, 1, "late")
                .expect_err("an input of the old take")
        ),
        "LEASE_LOST"
    );
    page_view.text(&view, 3, "b").expect("the text is taken");
    let write = link.expect(Method::InputWrite).await;
    let asked: InputWriteParams = write.params();
    assert_eq!((asked.epoch.get(), asked.sequence.get()), (7, 0));
    lease.answer(&mut link, &write).await;
    assert_eq!(lease.written, vec![(7, 0, b"b".to_vec())]);
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
        write.params::<InputWriteParams>().bytes.as_slice(),
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
    (asked.sequence.get(), asked.bytes.as_slice().to_vec())
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
    let longest = "x".repeat(64 * 1024 - 12);
    page_view.paste(&view, 1, &longest).expect("taken");
    assert_eq!(next_write(&mut link, &mut lease).await.1.len(), 64 * 1024);
}
