//! A launch pressed through a raw terminal view, on a real worker.
//!
//! The session is a managed one, hosted by this test with the product's own worker and a real
//! bridge endpoint. The reader on the other end of the bridge is the contract's reference bridge,
//! so the test decides when the reader enters a prompt, when it proves its queues and what it
//! answers to an install, and everything else is the product: the view's link, the attachment, the
//! input lease the view takes, the worker's acceptance of a launch from the connection that holds
//! it, and the refusals it makes before the reader is asked.

#![cfg(unix)]

use kr_protocol::root::{EditorBufferRevision, PromptGeneration};
use serde_json::{Value, json};
use tauri::Manager as _;

mod common;

use common::{BUFFER, Hosted, PROMPT, Page, code, hosted};

/// The channel the first view publishes on, and the second's.
const FIRST: u32 = 3;
const SECOND: u32 = 4;

impl Page {
    /// The launch surface `view` reads on its own link.
    async fn surface(&self, view: &str) -> Value {
        self.call("terminal_view_launch_surface", json!({ "view": view }))
            .await
            .expect("the launch surface is read")
    }

    /// A launch of `claude` pressed on `view`, quoting the prompt and the buffer given.
    fn press(
        &self,
        view: &str,
        prompt: u64,
        buffer: u64,
    ) -> impl std::future::Future<Output = Result<Value, Value>> {
        self.call(
            "terminal_view_launch",
            json!({ "view": view, "press": {
                "command": { "arguments": ["claude"] },
                "expected_prompt_generation": prompt.to_string(),
                "expected_buffer_revision": buffer.to_string(),
            }}),
        )
    }
}

/// A managed session at an empty prompt, a view of it that has taken control, and the reader's
/// proof of the fence that control asks for.
async fn controlled() -> (Hosted, Page, String) {
    let mut hosted = hosted("exec cat").await;
    hosted.enters_the_prompt().await;
    let page = Page::new(hosted.temp.environment());
    let view = page.showing(hosted.session_id, FIRST).await;
    // The reader is answered while the take is waited for, since which of them comes first is the
    // worker's.
    tokio::join!(page.takes_control(&view, FIRST), hosted.proves_a_fence());
    (hosted, page, view)
}

/// KR-REQ-13.11: a press through a view is accepted by a real worker from the connection whose
/// attachment holds the input, and only from it. The view reads the surface as held here at the
/// prompt the reader reported; a press that quotes a prompt that has moved is refused by the worker
/// as `DRAFT_CONFLICT` before the reader is asked; a view that does not hold the input is refused
/// as `LEASE_LOST`; and the press that quotes what was read is installed by the reader, which the
/// page is told with the revision the reader reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_press_through_the_view_is_accepted_only_from_the_view_that_holds_the_input() {
    let (mut hosted, page, view) = controlled().await;

    let surface = page.surface(&view).await;
    assert_eq!(surface["state"], "served", "{surface}");
    assert_eq!(surface["surface"]["input"], "held_here", "{surface}");
    let editor = &surface["surface"]["editor"];
    assert_eq!(editor["state"], "verified", "{surface}");
    assert_eq!(editor["prompt_generation"], PROMPT.to_string(), "{surface}");
    assert_eq!(editor["buffer_revision"], BUFFER.to_string(), "{surface}");

    // A prompt that moved: the worker refuses the quote before anything reaches the reader.
    let stale = page
        .press(&view, PROMPT + 1, BUFFER)
        .await
        .expect_err("the prompt moved");
    assert_eq!(code(&stale), "DRAFT_CONFLICT", "{stale}");

    // A view that holds nothing: the worker refuses a press from a connection whose attachment is
    // not the one that holds the input.
    let watching = page.showing(hosted.session_id, SECOND).await;
    let refused = page
        .press(&watching, PROMPT, BUFFER)
        .await
        .expect_err("this view holds nothing");
    assert_eq!(code(&refused), "LEASE_LOST", "{refused}");

    // The quote the view read: the reader is asked for exactly it, and installs it.
    let pressing = page.press(&view, PROMPT, BUFFER);
    let asked = hosted.install_asked().await;
    assert_eq!(
        asked.command,
        kr_protocol::root::LaunchCommand::Arguments(vec!["claude".to_owned()])
    );
    assert_eq!(
        asked.expected_prompt_generation,
        PromptGeneration::new(PROMPT)
    );
    assert_eq!(
        asked.expected_buffer_revision,
        EditorBufferRevision::new(BUFFER)
    );
    hosted.installs(&asked).await;
    let installed = pressing.await.expect("the launch is installed");
    assert_eq!(
        installed["prompt_generation"],
        PROMPT.to_string(),
        "{installed}"
    );
    assert_eq!(
        installed["buffer_revision"],
        (BUFFER + 1).to_string(),
        "{installed}"
    );
    hosted.close().await;
}

/// KR-REQ-13.11: a view that is lost after its press was written, before the session answered, is
/// told the outcome is unknown and never that nothing was typed: the reader had been asked, and may
/// have installed the command. The press had reached a real worker, which has asked the reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_lost_after_its_press_was_sent_is_told_the_outcome_is_unknown() {
    let (mut hosted, page, view) = controlled().await;
    let pressing = page.press(&view, PROMPT, BUFFER);
    let asked = hosted.install_asked().await;
    assert_eq!(
        asked.expected_buffer_revision,
        EditorBufferRevision::new(BUFFER)
    );

    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .lose_connection(&view);
    let told = pressing
        .await
        .expect_err("the view was lost before the session answered");
    assert_eq!(code(&told), "OUTCOME_UNKNOWN", "{told}");
    hosted.close().await;
}
