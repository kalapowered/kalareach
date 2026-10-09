//! The page of the question suites: an application with the question commands, reaching the workers
//! of one host tree, and a place of its own for the answers it keeps.

#![allow(dead_code, reason = "each suite uses the part of the page it needs")]

use serde_json::Value;
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// How long a command may take before the test calls it hung.
pub const WATCHDOG: std::time::Duration = std::time::Duration::from_secs(20);

/// Where the bundle's pages are served from.
pub const BUNDLE: &str = "tauri://localhost";

/// The page: an application with the question commands, reaching the workers of one host tree, and
/// a place of its own for the answers it keeps.
pub struct Page {
    pub app: tauri::App<MockRuntime>,
    pub window: tauri::WebviewWindow<MockRuntime>,
    pub kept: tempfile::TempDir,
}

impl Page {
    pub fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        let state = companion_tauri::AppState::new();
        let kept = tempfile::tempdir().expect("a place for the kept answers");
        state.questions().keep_at(kept.path().to_path_buf());
        Self::over(state, paths, kept)
    }

    pub fn over(
        state: companion_tauri::AppState,
        paths: kr_ipc::paths::EnvironmentPaths,
        kept: tempfile::TempDir,
    ) -> Self {
        let app = tauri::test::mock_builder()
            .manage(state)
            .manage(companion_tauri::agent::WorkerLinks::at(paths))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::question_read,
                companion_tauri::commands::question_answer,
                companion_tauri::commands::question_kept,
                companion_tauri::commands::question_settle,
                companion_tauri::commands::question_send_kept,
                companion_tauri::commands::question_dismiss_kept,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self { app, window, kept }
    }

    /// Calls `command` as the page does, on a thread of its own, since its answer waits for the
    /// worker this test is scripting.
    pub fn call(
        &self,
        command: &'static str,
        body: Value,
    ) -> tokio::task::JoinHandle<Result<Value, Value>> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = self.window.clone();
        tokio::task::spawn_blocking(move || {
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
            .map(|answer| answer.deserialize().expect("an answer the page reads"))
        })
    }

    pub fn links(&self) -> usize {
        self.app
            .state::<companion_tauri::agent::WorkerLinks>()
            .held()
    }
}

/// What a call answered, once it has.
pub async fn answered(call: tokio::task::JoinHandle<Result<Value, Value>>) -> Result<Value, Value> {
    tokio::time::timeout(WATCHDOG, call)
        .await
        .expect("the command answered within the watchdog")
        .expect("the command's thread finished")
}

pub fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or("not a refusal")
}
