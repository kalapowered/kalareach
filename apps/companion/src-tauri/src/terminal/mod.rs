//! The raw terminal view: its own link to its session, and the screen it draws.
//!
//! A raw terminal view is a projected attachment of the session it shows. The control daemon on this
//! machine carries none of an attachment's methods, so each view opens a link of its own to the
//! session's worker, the way `kr attach` does: it reads the worker's descriptor from the host's
//! runtime directory, has the worker prove it holds the descriptor's key, and only then attaches.
//!
//! The screen is held here, by the client library's projection, and the page is sent the part of it
//! the view shows, as cells, on the view's own channel. The page never receives a protocol event and
//! never writes a host byte into its renderer, so nothing a session printed can make the page's
//! terminal answer a query.
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`self`] | The views each page holds open, and the rule that ends them when the page loads again |
//! | [`screen`] | The shape the page draws: a view's state, its screen, lines and pieces |
//! | `view` | One view's task: the link, the attachment, the projection and the size reports |

pub mod screen;
mod view;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::SessionId;
use kr_protocol::session::Dimensions;

pub use screen::TerminalViewState;

/// Where the host's session descriptors are, found when a view opens.
///
/// A function rather than a path, because the host on this machine can be started after the
/// application: each open looks again.
pub type Locate = Arc<dyn Fn() -> Result<EnvironmentPaths, String> + Send + Sync>;

/// Where one view's states go: the page's channel for it.
pub type Publish = Arc<dyn Fn(TerminalViewState) + Send + Sync>;

/// One open view, as the registry holds it.
struct Held {
    /// The label of the web view whose page opened it.
    page: String,
    /// How the page's commands reach the view's task.
    commands: tokio::sync::mpsc::UnboundedSender<view::Command>,
    /// The view's task, once it has been started.
    task: Option<tauri::async_runtime::JoinHandle<()>>,
}

/// The raw terminal views this application holds open.
pub struct TerminalViews {
    locate: Locate,
    held: Arc<Mutex<BTreeMap<u64, Held>>>,
    next: AtomicU64,
}

impl TerminalViews {
    /// The views of the host on this machine, whose descriptors are found the way the local
    /// connection finds its control daemon.
    #[must_use]
    pub fn local() -> Self {
        Self::with(Arc::new(|| {
            let paths = kr_ipc::paths::HostPaths::discover()
                .map_err(|error| format!("There is no host on this computer: {error}"))?;
            let environment_id = paths
                .open_environment_id()
                .map_err(|error| format!("There is no host on this computer: {error}"))?;
            Ok(paths.environment(environment_id))
        }))
    }

    /// The views of the host whose environment `paths` names.
    #[must_use]
    pub fn at(paths: EnvironmentPaths) -> Self {
        Self::with(Arc::new(move || Ok(paths.clone())))
    }

    fn with(locate: Locate) -> Self {
        Self {
            locate,
            held: Arc::default(),
            next: AtomicU64::new(1),
        }
    }

    /// Opens a view of `session_id` for the page `page`, `dimensions` in size, whose states go to
    /// `publish`, and returns its handle at once: everything after this arrives on `publish`.
    pub fn open(
        &self,
        page: &str,
        session_id: SessionId,
        dimensions: Dimensions,
        publish: Publish,
    ) -> String {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        // Held before the task starts, so a close that arrives at once finds it.
        self.lock().insert(
            id,
            Held {
                page: page.to_owned(),
                commands,
                task: None,
            },
        );
        let held = Arc::clone(&self.held);
        let locate = Arc::clone(&self.locate);
        let task = tauri::async_runtime::spawn(async move {
            view::run(&locate, session_id, dimensions, receiver, &publish).await;
            // A view that has ended is not held: its page is told, and nothing more reaches it.
            held.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
        });
        if let Some(entry) = self.lock().get_mut(&id) {
            entry.task = Some(task);
        }
        id.to_string()
    }

    /// Tells a view the page's grid is now `dimensions`. A view that has ended takes nothing.
    pub fn resize(&self, view: &str, dimensions: Dimensions) {
        let Ok(id) = view.parse::<u64>() else {
            return;
        };
        if let Some(entry) = self.lock().get(&id) {
            let _ = entry.commands.send(view::Command::Resize(dimensions));
        }
    }

    /// Closes a view and returns once its task has ended: it detaches, closes its link and publishes
    /// nothing more. Closing a view that has already ended, or was never open, does nothing.
    pub async fn close(&self, view: &str) {
        let Ok(id) = view.parse::<u64>() else {
            return;
        };
        let Some(entry) = self.lock().remove(&id) else {
            return;
        };
        let _ = entry.commands.send(view::Command::Close);
        if let Some(task) = entry.task {
            let _ = task.await;
        }
    }

    /// What a page loading tells the views: when the page `page` starts loading again, every view it
    /// opened is closed, without waiting, since nothing it publishes could reach the new page. A load
    /// that has finished, and another page's load, close nothing.
    pub fn page_load(&self, page: &str, event: tauri::webview::PageLoadEvent) {
        if event != tauri::webview::PageLoadEvent::Started {
            return;
        }
        let mut held = self.lock();
        let leaving: Vec<u64> = held
            .iter()
            .filter(|(_, entry)| entry.page == page)
            .map(|(id, _)| *id)
            .collect();
        for id in leaving {
            if let Some(entry) = held.remove(&id) {
                let _ = entry.commands.send(view::Command::Close);
            }
        }
    }

    /// How many views are open.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Puts the views and the rule that ends them into an application.
///
/// The application's own start and the tests' use this one function, so the rule a test sees
/// working is the one the application runs.
pub fn install<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    views: TerminalViews,
) -> tauri::Builder<R> {
    use tauri::Manager as _;

    builder.manage(views).on_page_load(|webview, payload| {
        if let Some(views) = webview.try_state::<TerminalViews>() {
            views.page_load(webview.label(), payload.event());
        }
    })
}
