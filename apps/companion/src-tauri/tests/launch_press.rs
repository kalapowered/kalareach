//! A launch pressed through a raw terminal view, on a real worker.
//!
//! The session is a managed one, hosted by this test with the product's own worker and a real
//! bridge endpoint. The reader on the other end of the bridge is the contract's reference bridge,
//! so the test decides when the reader enters a prompt, when it proves its queues and what it
//! answers to an install, and everything else is the product: the view's link, the attachment, the
//! input lease the view takes, the worker's acceptance of a launch from the connection that holds
//! it, and the refusals it makes before the reader is asked.

#![cfg(unix)]

use kr_protocol::root::{
    EditorBufferRevision, EditorKeymap, EditorLeaveReason, EditorState, LaunchCommand,
    PendingReaderInput, PromptGeneration, ReaderContext, ReaderRevision, RootEditorEnterParams,
    RootEditorLeaveParams,
};
use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::requests::WorkerRequest;
use kr_shell_integration::host::scripted::ToBridge;
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
        self.press_vector(view, vec!["claude".to_owned()], prompt, buffer)
    }

    /// A launch of `vector` pressed on `view`, quoting the prompt and the buffer given.
    fn press_vector(
        &self,
        view: &str,
        vector: Vec<String>,
        prompt: u64,
        buffer: u64,
    ) -> impl std::future::Future<Output = Result<Value, Value>> {
        self.call(
            "terminal_view_launch",
            json!({ "view": view, "press": {
                "command": { "arguments": vector },
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

/// A saved command's vector as a person saved it: a program, a word with a space, an empty word, a
/// Windows path and words a shell reads as more than themselves.
fn saved_vector() -> Vec<String> {
    [
        "claude",
        "--resume",
        "two words",
        "",
        "C:\\tools\\agent.exe",
        "it's \"q\" $HOME ~ * ; |",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// The largest vector the rules allow: a program of 512 bytes and sixteen arguments, which with a
/// label of 48 characters make 3,072 bytes in all, every argument holding what a shell reads as
/// more than itself.
fn the_largest_vector() -> Vec<String> {
    let mut vector = vec!["p".repeat(512)];
    for index in 0..16 {
        let mut word = format!("it's \"q\" $HOME ~ * ; | \\ {index:02} ");
        let missing = 157 - word.len();
        word.push_str(&"x".repeat(missing));
        vector.push(word);
    }
    let bytes: usize = vector.iter().map(String::len).sum();
    assert_eq!(bytes + 48, 3072, "the largest command the rules allow");
    vector
}

/// KR-REQ-13.11: a press of a saved command is installed exactly as the vector was saved. The
/// reader is asked for the program and each argument as they were written, an empty word, a word
/// with a space, a Windows path and a word full of shell characters included, and the largest
/// vector the rules allow goes through the same way, unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_command_press_is_installed_exactly_as_the_vector_is_saved() {
    for vector in [saved_vector(), the_largest_vector()] {
        let (mut hosted, page, view) = controlled().await;
        let pressing = page.press_vector(&view, vector.clone(), PROMPT, BUFFER);
        let asked = hosted.install_asked().await;
        assert_eq!(
            asked.command,
            LaunchCommand::Arguments(vector.clone()),
            "the reader was asked for a vector other than the one pressed"
        );
        hosted.installs(&asked).await;
        let installed = pressing.await.expect("the launch is installed");
        assert_eq!(
            installed["buffer_revision"],
            (BUFFER + 1).to_string(),
            "{installed}"
        );
        hosted.close().await;
    }
}

/// How a state the table names is made at the reader, and the press it refuses.
async fn refused_in(
    state: &str,
    hosted: &mut Hosted,
    page: &Page,
    view: &str,
    vector: &[String],
) -> Value {
    match state {
        "a prompt that moved" => page
            .press_vector(view, vector.to_vec(), PROMPT + 1, BUFFER)
            .await
            .expect_err("the prompt moved"),
        "a view that holds nothing" => {
            let watching = page.showing(hosted.session_id, SECOND).await;
            page.press_vector(&watching, vector.to_vec(), PROMPT, BUFFER)
                .await
                .expect_err("this view holds nothing")
        }
        "the editor left" => {
            let leaving = RootEditorLeaveParams {
                session_id: hosted.session_id,
                prompt_generation: PromptGeneration::new(PROMPT),
                reader_revision: ReaderRevision::new(hosted.reader.numbers.reader_revision),
                reason: EditorLeaveReason::ReaderTakeover,
            };
            hosted
                .reader
                .bridge
                .send_event(BridgeEvent::EditorLeave(leaving))
                .await
                .expect("the reader leaves");
            hosted.settled().await;
            page.press_vector(view, vector.to_vec(), PROMPT, BUFFER)
                .await
                .expect_err("the editor left")
        }
        "a non-empty buffer" => {
            let numbers = hosted.reader.numbers;
            let entering = RootEditorEnterParams {
                session_id: hosted.session_id,
                root_process: hosted.reader.root_process.clone(),
                prompt_generation: PromptGeneration::new(PROMPT),
                reader_revision: ReaderRevision::new(numbers.reader_revision),
                reader_context: ReaderContext::Primary,
                editor: EditorState {
                    buffer_empty: false,
                    buffer_revision: EditorBufferRevision::new(BUFFER + 1),
                    keymap: EditorKeymap::Emacs,
                    pending: PendingReaderInput::NONE,
                },
                cwd_revision: kr_protocol::root::CwdRevision::new(numbers.cwd_revision),
            };
            hosted
                .reader
                .bridge
                .send_event(BridgeEvent::EditorEnter(entering))
                .await
                .expect("the reader enters again");
            hosted.settled().await;
            page.press_vector(view, vector.to_vec(), PROMPT, BUFFER)
                .await
                .expect_err("the buffer holds text")
        }
        other => panic!("{other} is not a state of the table"),
    }
}

/// KR-REQ-13.11: a press of a saved command is refused exactly as a press of an installed agent's
/// is. One table over the states the worker refuses a press in, a prompt that moved, a view that
/// holds nothing, the editor left and a buffer that holds text, is run once with an installed
/// agent's vector and once with a saved command's: the codes are equal, each is the one the state
/// has, and the reader is asked for nothing either time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_command_press_is_refused_exactly_as_a_profile_press_is() {
    let profile = vec!["claude".to_owned()];
    let table = [
        ("a prompt that moved", "DRAFT_CONFLICT"),
        ("a view that holds nothing", "LEASE_LOST"),
        ("the editor left", "EDITOR_BUSY"),
        ("a non-empty buffer", "EDITOR_BUSY"),
    ];
    for (state, wanted) in table {
        let mut codes = Vec::new();
        for vector in [&profile, &saved_vector()] {
            let (mut hosted, page, view) = controlled().await;
            let refused = refused_in(state, &mut hosted, &page, &view, vector).await;
            codes.push(code(&refused).to_owned());
            let seen = tokio::time::timeout(common::SOON, hosted.reader.settled_seeing())
                .await
                .expect("the worker handled the events")
                .expect("settles");
            assert!(
                !seen.iter().any(|frame| matches!(
                    frame,
                    ToBridge::Request { request, .. } if matches!(**request, WorkerRequest::Launch(_))
                )),
                "{state}: the reader was asked to install a refused press: {seen:?}"
            );
            hosted.close().await;
        }
        assert_eq!(
            codes[0], codes[1],
            "{state}: the two presses were refused differently"
        );
        assert_eq!(codes[0], wanted, "{state}");
    }
}
