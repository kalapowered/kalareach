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
use kr_protocol::method::Method;
use kr_protocol::projection::{
    PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, ProjectionResetReason,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::session::Dimensions;
use scripted_worker::{
    Challenge, Link, ScriptedWorker, WATCHDOG, delta, page as rows_page, reset, row, screen,
    snapshot,
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

/// KR-REQ-08.02: the view attaches on the worker's own endpoint, after the worker has proved who it
/// is, in terminal mode with no geometry claim and no terminal profile, observing only, at the size
/// the page measured; it subscribes from the attach's own cursor; and its first state carries the
/// attachment's summary, a viewport for want of a profile.
#[tokio::test(flavor = "multi_thread")]
async fn a_view_attaches_on_the_workers_endpoint_with_no_claim_and_no_profile() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let _view = page.open(worker.session_id, 30, 5, 7);
    let mut link = worker.link().await;
    let (attachment_id, asked) = link.attach().await;
    assert_eq!(asked.session_id, worker.session_id);
    assert_eq!(asked.mode, AttachMode::Terminal);
    assert!(!asked.claim_geometry, "a view makes no geometry claim");
    assert_eq!(asked.dimensions.0, Some(Dimensions::new(30, 5)));
    assert_eq!(asked.terminal_profile_id.0, None, "and declares no profile");
    assert_eq!(
        asked.requested.iter().copied().collect::<Vec<_>>(),
        vec![AttachmentCapability::ObserveTerminal]
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
        "no_terminal_profile"
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
    link.answer(
        &attach,
        &kr_protocol::attachment::SessionAttachResult {
            attachment: scripted_worker::summary(attachment_id, Dimensions::new(30, 5)),
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
                Dimensions::new(30, 5),
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
    assert_eq!(shown["screen"]["window"], json!({"rows": 2, "columns": 10}));
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
/// window at the live screen's first line and column.
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
                Dimensions::new(10, 2),
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
                        Dimensions::new(10, 2),
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
