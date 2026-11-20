//! The messages sent over a channel that confirms nothing, and the records of sends under way, kept
//! by the application on this device and read back by the page, through the commands the page calls.
//!
//! The store is the application's real one, in a directory of the test's own. A restart is a new
//! application state over the same directory; a second window is a second state over it too. A
//! fault is made as the drafts' own cases make it: a directory flush that fails after the rename it
//! follows, and a stop or a wait at a named point of a step.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::channel_messages::{Limits, Point, kept_in, testing};
use kr_ipc::testing::PrivateTempDir;
use serde_json::{Value, json};
use tauri::test::MockRuntime;

const BUNDLE: &str = "tauri://localhost";
const SESSION: &str = "8a7b6c50-22bb-4c3d-8e4f-000000000101";
const OTHER_SESSION: &str = "8a7b6c50-22bb-4c3d-8e4f-000000000102";
const INSTANCE: &str = "9a7b6c50-22bb-4c3d-8e4f-000000000201";
/// Long enough for a step to be seen waiting, short enough for a failing case to end.
const WAIT: Duration = Duration::from_secs(10);
const SHORT: Duration = Duration::from_millis(600);

/// One window of the application: its state over a data directory, and the page that calls it.
struct Window {
    _app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
}

impl Window {
    fn over(data: &Path) -> Self {
        let state = companion_tauri::AppState::new();
        state.keep_under(data);
        let app = tauri::test::mock_builder()
            .manage(state)
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::device_drafts,
                companion_tauri::commands::device_draft_save,
                companion_tauri::commands::device_draft_discard,
                companion_tauri::commands::device_draft_mark_removal,
                companion_tauri::commands::device_channel_messages,
                companion_tauri::commands::device_channel_message_keep,
                companion_tauri::commands::device_channel_message_remove,
                companion_tauri::commands::device_channel_hold_create,
                companion_tauri::commands::device_channel_hold_update,
                companion_tauri::commands::device_channel_hold_clear,
                companion_tauri::commands::device_drafts_ledger_set_aside,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self { _app: app, window }
    }

    fn call(&self, command: &'static str, params: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, method)| *name == command && method.is_none()),
            "{command} is a command of the application's own"
        );
        tauri::test::get_ipc_response(
            &self.window,
            tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: BUNDLE.parse().expect("the bundle's address"),
                body: tauri::ipc::InvokeBody::Json(json!({ "params": params })),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .map(|answer| answer.deserialize().expect("an answer the page reads"))
    }

    fn drafts(&self) -> Result<Value, Value> {
        self.call("device_drafts", json!(null))
    }

    fn list(&self) -> Value {
        self.call("device_channel_messages", json!({ "withText": true }))
            .expect("the messages are read")
    }

    fn keep(&self, params: Value) -> Result<Value, Value> {
        self.call("device_channel_message_keep", params)
    }

    /// A draft stored for the session, as a composer's text is.
    fn draft(&self, text: &str) -> (String, String) {
        let saved = self
            .call(
                "device_draft_save",
                json!({
                    "id": null, "expectedRevision": null, "sessionId": SESSION,
                    "applicationInstanceId": INSTANCE, "agentBindingRevision": "1",
                    "state": "open", "text": text, "attachments": []
                }),
            )
            .expect("the draft is saved");
        (
            saved["draft"]["id"].as_str().expect("an id").to_owned(),
            saved["draft"]["revision"]
                .as_str()
                .expect("a revision")
                .to_owned(),
        )
    }

    fn create_hold(&self, id: &str, refs: &[(String, String)]) -> Result<Value, Value> {
        self.call("device_channel_hold_create", hold(id, refs))
    }
}

fn action(n: u8) -> String {
    format!("6a7b6c50-22bb-4c3d-8e4f-0000000004{n:02}")
}

fn refs_json(refs: &[(String, String)]) -> Value {
    Value::Array(
        refs.iter()
            .map(|(id, revision)| json!({ "id": id, "expectedRevision": revision }))
            .collect(),
    )
}

/// The parameters of a keep of message `n` to `session`.
fn message_to(n: u8, session: &str, text: &str, refs: &[(String, String)]) -> Value {
    json!({
        "actionId": action(n), "holdId": null, "localId": format!("s-{n}"), "sessionId": session,
        "applicationInstanceId": INSTANCE, "agentBindingRevision": "1", "environmentId": null,
        "hostName": "studio", "text": text, "sentAtMs": format!("{}", 1000 + u64::from(n)),
        "drafts": refs_json(refs)
    })
}

fn message(n: u8, text: &str, refs: &[(String, String)]) -> Value {
    message_to(n, SESSION, text, refs)
}

fn hold(id: &str, refs: &[(String, String)]) -> Value {
    json!({
        "holdId": id, "localId": format!("local-{id}"), "sessionId": SESSION,
        "applicationInstanceId": INSTANCE, "agentBindingRevision": "1", "environmentId": null,
        "hostName": "studio", "sentAtMs": "900", "drafts": refs_json(refs)
    })
}

fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or("not a refusal")
}

fn dir(data: &Path) -> PathBuf {
    kept_in(data)
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn ledger_bytes(data: &Path) -> Option<Vec<u8>> {
    std::fs::read(data.join("drafts-removals")).ok()
}

fn ledger_refs(data: &Path) -> Vec<(String, String)> {
    let Some(bytes) = ledger_bytes(data) else {
        return Vec::new();
    };
    let parsed: Vec<Value> = serde_json::from_slice(&bytes).expect("a readable ledger");
    let mut refs: Vec<(String, String)> = parsed
        .iter()
        .map(|line| {
            (
                line["id"].as_str().expect("an id").to_owned(),
                line["expectedRevision"]
                    .as_str()
                    .expect("a revision")
                    .to_owned(),
            )
        })
        .collect();
    refs.sort();
    refs
}

fn pending(read: &Value) -> Vec<(String, String)> {
    let mut refs: Vec<(String, String)> = read["pendingRemovals"]
        .as_array()
        .expect("a list of removals")
        .iter()
        .map(|line| {
            (
                line["id"].as_str().expect("an id").to_owned(),
                line["expectedRevision"]
                    .as_str()
                    .expect("a revision")
                    .to_owned(),
            )
        })
        .collect();
    refs.sort();
    refs
}

fn sorted(mut refs: Vec<(String, String)>) -> Vec<(String, String)> {
    refs.sort();
    refs
}

fn messages(list: &Value) -> &Vec<Value> {
    list["messages"].as_array().expect("a list of messages")
}

fn data() -> PrivateTempDir {
    PrivateTempDir::create()
}

/// Runs `step` on a window of its own over `data` on a thread, and answers what it returned.
fn on_thread<T: Send + 'static>(
    data: &Path,
    step: impl FnOnce(Window) -> T + Send + 'static,
) -> mpsc::Receiver<T> {
    let (sender, receiver) = mpsc::channel();
    let data = data.to_path_buf();
    std::thread::spawn(move || {
        let _ = sender.send(step(Window::over(&data)));
    });
    receiver
}

/// A hook that tells a test it was reached and then waits for the test to let it go.
fn a_wait() -> (
    impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (reached, was_reached) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let reached = Mutex::new(reached);
    let released = Mutex::new(released);
    let first = std::sync::atomic::AtomicBool::new(true);
    let hook = move || {
        if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = reached.lock().expect("a lock").send(());
            let _ = released.lock().expect("a lock").recv_timeout(WAIT);
        }
        Ok(())
    };
    (hook, was_reached, release)
}

fn io_fault(what: &'static str) -> std::io::Error {
    std::io::Error::other(what)
}

/// KR-REQ-12.26: a message is kept whole, listed with its session and time, and removed by the
/// person: one at a time, or every one of a session. No other call changes it.
#[test]
fn a_message_is_kept_whole_listed_and_removed_only_by_a_person() {
    let data = data();
    let window = Window::over(data.path());
    let text = "line one\n\u{1F600} é \u{0}\tand a tab";
    window
        .keep(message(1, text, &[]))
        .expect("the first is kept");
    window
        .keep(message_to(2, OTHER_SESSION, "elsewhere", &[]))
        .expect("the second is kept");
    window
        .keep(message(3, "third", &[]))
        .expect("the third is kept");
    let list = window.list();
    let kept = messages(&list);
    assert_eq!(kept.len(), 3, "{list}");
    assert_eq!(kept[0]["text"], text, "the whole text, byte for byte");
    assert_eq!(kept[0]["actionId"], action(1));
    assert_eq!(kept[0]["hostName"], "studio");
    assert!(
        kept[0].get("drafts").is_none(),
        "the references that removed a draft are never sent to the page"
    );
    assert_eq!(list["used"]["entries"], 3);
    assert_eq!(list["limits"]["entries"], 10_000);
    let removed = window
        .call(
            "device_channel_message_remove",
            json!({ "actionId": action(1) }),
        )
        .expect("one is removed");
    assert_eq!(removed["removed"], 1);
    assert_eq!(messages(&window.list()).len(), 2);
    let removed = window
        .call(
            "device_channel_message_remove",
            json!({ "sessionId": SESSION }),
        )
        .expect("a session's are removed");
    assert_eq!(removed["removed"], 1);
    let list = window.list();
    assert_eq!(messages(&list).len(), 1);
    assert_eq!(messages(&list)[0]["sessionId"], OTHER_SESSION);
    let again = window
        .call(
            "device_channel_message_remove",
            json!({ "actionId": action(1) }),
        )
        .expect("a removal of what is gone is made");
    assert_eq!(again["removed"], 0);
}

/// KR-REQ-12.26: what a read without text leaves out is the text alone, and nothing else changes.
#[test]
fn a_read_without_text_carries_no_text_member() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "secret words", &[])).expect("kept");
    let without = window
        .call("device_channel_messages", json!({ "withText": false }))
        .expect("a read");
    assert!(messages(&without)[0].get("text").is_none(), "{without}");
    assert_eq!(messages(&without)[0]["actionId"], action(1));
    assert_eq!(messages(&without)[0]["localId"], "s-1");
    let with = window.list();
    assert_eq!(messages(&with)[0]["text"], "secret words");
}

/// KR-REQ-12.26: a message is still there when the application starts again.
#[test]
fn a_new_application_state_over_the_directory_lists_what_was_kept() {
    let data = data();
    let first = Window::over(data.path());
    first.keep(message(1, "still here", &[])).expect("kept");
    drop(first);
    let second = Window::over(data.path());
    assert_eq!(messages(&second.list())[0]["text"], "still here");
}

/// KR-REQ-12.26: a keep under an identity that holds a file of another layout, or a message that
/// differs, is refused and the bytes stay as they were; such files are counted and never listed.
#[test]
fn a_file_of_another_layout_is_counted_and_left_and_never_replaced() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "first", &[])).expect("kept");
    let folder = dir(data.path());
    let other = folder.join(format!("{}.message", action(2)));
    let newer = br#"{"version":2,"action_id":"x","text":"from a later release"}"#.to_vec();
    std::fs::write(&other, &newer).expect("a later release's file");
    let extra = folder.join(format!("{}.message", action(3)));
    let with_extra = br#"{"version":1,"unknown_member":true}"#.to_vec();
    std::fs::write(&extra, &with_extra).expect("a file with a member more");
    let misnamed = folder.join("not-a-message.message");
    std::fs::write(&misnamed, b"{}").expect("a misnamed file");
    let list = window.list();
    assert_eq!(messages(&list).len(), 1, "{list}");
    assert_eq!(list["unreadableMessages"]["layout"], 3, "{list}");
    assert_eq!(list["unreadableMessages"]["now"], 0);
    for (n, bytes) in [(2, &newer), (3, &with_extra)] {
        let refused = window.keep(message(n, "mine", &[]));
        {
            let refusal = (refused).clone().expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
        }
        let path = folder.join(format!("{}.message", action(n)));
        assert_eq!(&std::fs::read(path).expect("still there"), bytes);
    }
    // Removals leave what they cannot read exactly as it is.
    window
        .call(
            "device_channel_message_remove",
            json!({ "sessionId": SESSION }),
        )
        .expect("the readable one goes");
    window
        .call(
            "device_channel_message_remove",
            json!({ "actionId": action(2) }),
        )
        .expect("an unreadable one is not removed");
    assert_eq!(std::fs::read(&other).expect("left"), newer);
    assert_eq!(std::fs::read(&extra).expect("left"), with_extra);
    assert_eq!(std::fs::read(&misnamed).expect("left"), b"{}");
}

/// KR-REQ-12.26: a keep under an identity that holds a different message is refused, and a repeat
/// of the same one is a resume.
#[test]
fn a_keep_under_a_used_identity_is_a_resume_only_when_it_is_the_same_message() {
    let data = data();
    let window = Window::over(data.path());
    let first = window.keep(message(1, "same", &[])).expect("kept");
    assert_eq!(first["resumed"], false);
    let again = window.keep(message(1, "same", &[])).expect("a resume");
    assert_eq!(again["resumed"], true);
    {
        let refusal = (window.keep(message(1, "different", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert_eq!(messages(&window.list())[0]["text"], "same");
}

/// KR-REQ-12.26: a file that cannot be read now is counted apart from a file of another layout and
/// refuses nothing; the drafts then answer with their sources unknown, and a file of another layout
/// does not do that.
#[test]
fn a_file_that_cannot_be_read_now_is_counted_apart_and_makes_the_sources_unknown() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "kept", &[])).expect("kept");
    let folder = dir(data.path());
    std::fs::write(folder.join(format!("{}.message", action(2))), b"{}").expect("another layout");
    let read = window.drafts().expect("the drafts are read");
    assert_eq!(read["sources"], "known", "{read}");
    std::fs::create_dir(folder.join(format!("{}.message", action(3)))).expect("a directory");
    let list = window.list();
    assert_eq!(list["unreadableMessages"]["layout"], 1, "{list}");
    assert_eq!(list["unreadableMessages"]["now"], 1, "{list}");
    assert_eq!(messages(&list).len(), 1);
    let read = window.drafts().expect("the drafts are read");
    assert_eq!(read["sources"], "unknown", "{read}");
    assert_eq!(read["ledger"], "ok");
}

/// KR-REQ-12.26: a fault at the entry's flush leaves the entry and no ledger line, and a repeat of
/// the keep flushes it and only then names the draft.
#[test]
fn an_entry_whose_flush_failed_is_finished_by_the_next_keep_and_names_the_draft_only_then() {
    let data = data();
    let window = Window::over(data.path());
    window
        .keep(message(9, "first", &[]))
        .expect("the directory exists");
    let (id, revision) = window.draft("the text");
    let refs = vec![(id, revision)];
    let guard = kr_flush::testing::refuse_flushes_of(dir(data.path()));
    let failed = window.keep(message(1, "the text", &refs));
    {
        let refusal = (failed).clone().expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    drop(guard);
    assert!(
        names(&dir(data.path())).contains(&format!("{}.message", action(1))),
        "the entry stays"
    );
    assert!(ledger_refs(data.path()).is_empty(), "no line is written");
    let done = window
        .keep(message(1, "the text", &refs))
        .expect("a resume");
    assert_eq!(done["resumed"], true);
    assert_eq!(ledger_refs(data.path()), sorted(refs));
}

/// KR-REQ-12.26: a folder whose own name cannot be made durable keeps no entry, and fails again
/// until the flush works.
#[test]
fn a_directory_whose_name_cannot_be_flushed_keeps_no_entry_and_fails_again() {
    let temporary = data();
    // The walk that proves each name on a path durable flushes the directories as they resolve, so
    // the refusal names the directory as it resolves.
    let root = temporary.path().canonicalize().expect("a resolved path");
    let window = Window::over(&root);
    let guard = kr_flush::testing::refuse_flushes_of(&root);
    {
        let refusal = (window.keep(message(1, "text", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    {
        let refusal = (window.keep(message(1, "text", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    assert!(
        !names(&dir(&root)).contains(&format!("{}.message", action(1))),
        "nothing is kept while the folder's name is not durable"
    );
    drop(guard);
    window.keep(message(1, "text", &[])).expect("kept at last");
    assert_eq!(messages(&window.list()).len(), 1);
}

/// KR-REQ-12.26: a resume whose ledger lines are present still flushes the data directory, and fails
/// while it cannot.
#[test]
fn a_resume_whose_lines_are_present_still_proves_the_ledger_durable() {
    let data = data();
    let window = Window::over(data.path());
    let (id, revision) = window.draft("text");
    let refs = vec![(id, revision)];
    window.keep(message(1, "text", &refs)).expect("kept");
    // Entry flushed again first, then the ledger step.
    let stop = kr_flush::testing::refuse_flushes_of(dir(data.path()));
    {
        let refusal = (window.keep(message(1, "text", &refs)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    drop(stop);
    let first = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&first);
    let root = data.path().to_path_buf();
    let _at = testing::at(dir(data.path()), Point::AfterEntry, move || {
        *slot.lock().expect("a lock") = Some(kr_flush::testing::refuse_flushes_of(root.clone()));
        Ok(())
    });
    // The keep is a resume, so the hook at the entry still runs, and the ledger flush then fails.
    {
        let refusal = (window.keep(message(1, "text", &refs)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    first.lock().expect("a lock").take();
    assert_eq!(ledger_refs(data.path()), sorted(refs));
}

/// KR-REQ-12.26: two references and a ledger that fails before its rename leave none or both, and
/// an entry no line names is undone; a fault after the rename keeps the entry.
#[test]
fn a_ledger_that_fails_leaves_none_or_both_lines_and_undoes_only_an_unnamed_entry() {
    let data = data();
    let window = Window::over(data.path());
    let a = window.draft("a");
    let b = window.draft("b");
    let refs = vec![a, b];
    {
        let _at = testing::at(data.path(), Point::LedgerBeforeRename, || {
            Err(io_fault("the ledger is refused"))
        });
        {
            let refusal = (window.keep(message(1, "ab", &refs)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    assert!(ledger_refs(data.path()).is_empty(), "no line, not one");
    assert!(
        !names(&dir(data.path())).contains(&format!("{}.message", action(1))),
        "an entry that no line names is undone"
    );
    let kept = window.keep(message(1, "ab", &refs));
    assert!(kept.is_ok(), "kept now: {kept:?}");
    assert_eq!(ledger_refs(data.path()), sorted(refs.clone()));
    // A hook that lets the first publication through and refuses a second: the two references of one
    // keep are one publication, so both lines come and the keep succeeds; a writer that publishes a
    // line for each reference is refused at its second and leaves one.
    let c = window.draft("c");
    let d = window.draft("d");
    let more = vec![c, d];
    let publications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&publications);
    let _second = testing::at(data.path(), Point::LedgerBeforeRename, move || {
        if counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(io_fault("a second publication is refused"))
        }
    });
    let kept = window.keep(message(2, "cd", &more));
    assert!(kept.is_ok(), "one batch is one publication: {kept:?}");
    assert_eq!(
        publications.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the keep published once"
    );
    let all: Vec<(String, String)> = refs.iter().chain(more.iter()).cloned().collect();
    assert_eq!(
        ledger_refs(data.path()),
        sorted(all),
        "both lines of the keep stand with the earlier two"
    );
}

/// KR-REQ-12.26: a ledger renamed whose flush then failed keeps the entry, and the removal is made
/// at the next start.
#[test]
fn a_ledger_renamed_and_not_flushed_keeps_the_entry_and_the_next_start_removes() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    let slot = Arc::new(Mutex::new(None));
    let hold_slot = Arc::clone(&slot);
    let root = data.path().to_path_buf();
    let at = testing::at(dir(data.path()), Point::AfterEntry, move || {
        *hold_slot.lock().expect("a lock") =
            Some(kr_flush::testing::refuse_flushes_of(root.clone()));
        Ok(())
    });
    // The first keep makes the directory; its entry is then durable, and the ledger flush is refused.
    {
        let refusal = (window.keep(message(1, "text", &refs)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    slot.lock().expect("a lock").take();
    drop(at);
    assert!(
        names(&dir(data.path())).contains(&format!("{}.message", action(1))),
        "the entry stays after the ledger was renamed"
    );
    assert_eq!(
        ledger_refs(data.path()),
        sorted(refs.clone()),
        "the ledger is in place"
    );
    drop(window);
    let restarted = Window::over(data.path());
    let read = restarted.drafts().expect("the drafts are read");
    assert_eq!(pending(&read), sorted(refs));
}

/// KR-REQ-12.26: a stop between the entry and the ledger leaves a message that a repeat finishes.
#[test]
fn a_stop_between_the_entry_and_the_ledger_is_finished_by_a_repeat_of_the_keep() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (window.keep(message(1, "text", &refs)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    assert!(ledger_refs(data.path()).is_empty());
    let done = window.keep(message(1, "text", &refs)).expect("a resume");
    assert_eq!(done["resumed"], true);
    assert_eq!(ledger_refs(data.path()), sorted(refs));
}

/// KR-REQ-12.26: the bounds refuse and evict nothing; a repeat of an identity is no new entry; an
/// oversized or empty text is an invalid argument and never a quota.
#[test]
fn the_bounds_refuse_and_evict_nothing_and_a_bad_text_is_not_a_quota() {
    let data = data();
    let window = Window::over(data.path());
    window
        .keep(message(9, "x", &[]))
        .expect("the directory exists");
    window
        .call(
            "device_channel_message_remove",
            json!({ "actionId": action(9) }),
        )
        .expect("removed");
    let _limits = testing::lower_limits(
        dir(data.path()),
        Limits {
            entries: 2,
            bytes: 100_000,
            holds: 1_000,
        },
    );
    window.keep(message(1, "one", &[])).expect("one");
    window.keep(message(2, "two", &[])).expect("two");
    {
        let refusal = (window.keep(message(3, "three", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "QUOTA_EXCEEDED", "{refusal}");
    }
    assert_eq!(messages(&window.list()).len(), 2, "nothing was evicted");
    window
        .keep(message(1, "one", &[]))
        .expect("a repeat is no new entry");
    let _bytes = testing::lower_limits(
        dir(data.path()),
        Limits {
            entries: 100,
            bytes: 1_000,
            holds: 1_000,
        },
    );
    {
        let refusal = (window.keep(message(4, &"y".repeat(2_000), &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "QUOTA_EXCEEDED", "{refusal}");
    }
    let list = window.list();
    assert_eq!(list["limits"]["bytes"], 1_000);
    assert_eq!(messages(&list).len(), 2);
    {
        let refusal = (window.keep(message(5, "", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    {
        let refusal = (window.keep(message(5, &"z".repeat(64 * 1024 + 1), &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
}

/// KR-REQ-12.26: two windows that each keep one message into a store with one place left never pass
/// the bound: the second waits for the first, at the entry bound and at the byte bound.
#[test]
fn two_keeps_over_one_folder_with_one_place_left_never_pass_the_bound() {
    for bound in ["entries", "bytes"] {
        let data = data();
        let first = Window::over(data.path());
        first
            .keep(message(9, "seed", &[]))
            .expect("the directory exists");
        first
            .call(
                "device_channel_message_remove",
                json!({ "actionId": action(9) }),
            )
            .expect("removed");
        let limits = if bound == "entries" {
            Limits {
                entries: 1,
                bytes: 1_000_000,
                holds: 1_000,
            }
        } else {
            Limits {
                entries: 100,
                bytes: 450,
                holds: 1_000,
            }
        };
        let _limits = testing::lower_limits(dir(data.path()), limits);
        let (hook, reached, release) = a_wait();
        let _at = testing::at(dir(data.path()), Point::AfterCountRead, hook);
        let one = on_thread(data.path(), |window| window.keep(message(1, "one", &[])));
        reached.recv_timeout(WAIT).expect("the first has counted");
        let two = on_thread(data.path(), |window| window.keep(message(2, "two", &[])));
        assert!(
            two.recv_timeout(SHORT).is_err(),
            "the second waits while the first holds the lock ({bound})"
        );
        release.send(()).expect("let the first go");
        one.recv_timeout(WAIT)
            .expect("the first ends")
            .expect("the first is kept");
        let second = two.recv_timeout(WAIT).expect("the second ends");
        {
            let refusal = (second).clone().expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "QUOTA_EXCEEDED", "{refusal}");
        }
        assert_eq!(
            messages(&first.list()).len(),
            1,
            "never past the bound ({bound})"
        );
    }
}

/// KR-REQ-12.26: a repair that has named what the entries owe holds the lock, so a keep waits for it
/// and no entry is removed under it.
#[test]
fn a_repair_and_a_keep_never_run_together() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (window.keep(message(1, "text", &refs)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    let (hook, reached, release) = a_wait();
    let _at = testing::at(dir(data.path()), Point::RepairNamed, hook);
    let repair = on_thread(data.path(), |window| window.drafts());
    reached.recv_timeout(WAIT).expect("the repair has named");
    let keep = on_thread(data.path(), |window| window.keep(message(2, "other", &[])));
    assert!(
        keep.recv_timeout(SHORT).is_err(),
        "a keep waits for the repair"
    );
    release.send(()).expect("let it go");
    let read = repair
        .recv_timeout(WAIT)
        .expect("the repair ends")
        .expect("the drafts are read");
    assert_eq!(pending(&read), sorted(refs));
    keep.recv_timeout(WAIT)
        .expect("the keep ends")
        .expect("kept");
    assert_eq!(messages(&window.list()).len(), 2, "the entry stayed");
}

/// KR-REQ-12.26: a staged file a crash left is there right after a listing and gone after the next
/// keep.
#[test]
fn a_staged_file_a_crash_left_is_swept_by_the_next_keep_and_not_by_a_listing() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "one", &[])).expect("kept");
    let staged = dir(data.path()).join(format!("{}.message.staged-1-1", action(7)));
    std::fs::write(&staged, b"half").expect("a staged file");
    let list = window.list();
    assert_eq!(messages(&list).len(), 1, "a staged file is never listed");
    assert!(staged.exists(), "a listing sweeps nothing");
    window.keep(message(2, "two", &[])).expect("kept");
    assert!(!staged.exists(), "the next keep sweeps it");
}

/// KR-REQ-12.26: a directory that cannot be read as one refuses the drafts and lists none; a missing
/// directory answers as it did before.
#[test]
fn a_message_directory_that_cannot_be_read_refuses_the_drafts() {
    let data = data();
    let window = Window::over(data.path());
    window.draft("a draft");
    let read = window.drafts().expect("a missing directory answers");
    assert_eq!(read["drafts"].as_array().expect("drafts").len(), 1);
    assert_eq!(read["sources"], "known");
    std::fs::write(dir(data.path()), b"not a directory").expect("a file at the folder's name");
    {
        let refusal = (window.drafts()).clone().expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    {
        let refusal = (window.call("device_channel_messages", json!({ "withText": false })))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
}

/// KR-REQ-12.26: the repair makes both directories durable before it writes a line, and a refused
/// flush of either makes both reads refuse.
#[test]
fn a_repair_that_cannot_flush_either_directory_refuses_both_reads() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "text", &[])).expect("kept");
    for refused in [dir(data.path()), data.path().to_path_buf()] {
        let guard = kr_flush::testing::refuse_flushes_of(refused);
        {
            let refusal = (window.drafts()).clone().expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
        }
        {
            let refusal = (window.call("device_channel_messages", json!({ "withText": false })))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
        }
        drop(guard);
        window.drafts().expect("answers once the flush works");
    }
}

/// KR-REQ-12.26: no draft reader lists a message, and none of its files is under the drafts.
#[test]
fn no_draft_reader_lists_a_message_and_no_file_of_it_is_a_draft() {
    let data = data();
    let window = Window::over(data.path());
    window
        .keep(message(1, "only a message", &[]))
        .expect("kept");
    let read = window.drafts().expect("read");
    assert!(
        read["drafts"].as_array().expect("drafts").is_empty(),
        "{read}"
    );
    let drafts_dir = data.path().join("drafts");
    assert!(
        names(&drafts_dir)
            .iter()
            .all(|name| !name.contains("message")),
        "{:?}",
        names(&drafts_dir)
    );
    assert!(names(&dir(data.path())).contains(&format!("{}.message", action(1))));
}

/// KR-REQ-12.26: the absent branch of a draft's removal flushes its directory, so a removal that is
/// already made is proved durable before the caller relies on it.
#[test]
fn a_discard_of_a_draft_already_gone_proves_the_removal_durable() {
    let data = data();
    let window = Window::over(data.path());
    let (id, revision) = window.draft("text");
    let params = json!({ "id": id, "expectedRevision": revision });
    window
        .call("device_draft_discard", params.clone())
        .expect("removed");
    let guard = kr_flush::testing::refuse_flushes_of(data.path().join("drafts"));
    {
        let refusal = (window.call("device_draft_discard", params.clone()))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    drop(guard);
    window
        .call("device_draft_discard", params)
        .expect("an absent draft is removed once the flush works");
}

/// KR-REQ-12.26: a repair names a draft only at the revision an entry names: one saved again after
/// the entry is left alone.
#[test]
fn the_repair_names_nothing_for_a_draft_saved_again_after_the_entry() {
    let data = data();
    let window = Window::over(data.path());
    let (id, revision) = window.draft("text");
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (window.keep(message(1, "text", &[(id.clone(), revision.clone())])))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    window
        .call(
            "device_draft_save",
            json!({
                "id": id, "expectedRevision": revision, "sessionId": SESSION,
                "applicationInstanceId": INSTANCE, "agentBindingRevision": "1",
                "state": "open", "text": "edited since", "attachments": []
            }),
        )
        .expect("saved again");
    let read = window.drafts().expect("read");
    assert!(pending(&read).is_empty(), "{read}");
    assert!(ledger_refs(data.path()).is_empty());
}

/// KR-REQ-12.26: a repair removes a record of a send that an entry names, only after the ledger line
/// is durable; a ledger that fails leaves it.
#[test]
fn a_repair_removes_a_record_an_entry_names_only_after_the_ledger_is_published() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    window.create_hold("hold-a", &refs).expect("a record");
    window.create_hold("hold-unrelated", &[]).expect("another");
    let mut params = message(1, "text", &refs);
    params["holdId"] = json!("hold-a");
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (window.keep(params))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    {
        let _at = testing::at(data.path(), Point::LedgerBeforeRename, || {
            Err(io_fault("the ledger is refused"))
        });
        let read = window.drafts().expect("the drafts are read");
        assert_eq!(pending(&read), sorted(refs.clone()), "still owed: {read}");
    }
    assert!(
        names(&dir(data.path())).contains(&"hold-a.held".to_owned()),
        "the record stays while the ledger is not published"
    );
    window.drafts().expect("read again");
    let held = names(&dir(data.path()));
    assert!(!held.contains(&"hold-a.held".to_owned()), "{held:?}");
    assert!(
        held.contains(&"hold-unrelated.held".to_owned()),
        "a record no entry names stays"
    );
}

/// KR-REQ-12.26: the repair stays owed after a fault: a second read in the same process, and one
/// from a second window, still return the removal.
#[test]
fn a_removal_a_failed_repair_owed_is_returned_by_every_later_read() {
    let data = data();
    let first = Window::over(data.path());
    let refs = vec![first.draft("text")];
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (first.keep(message(1, "text", &refs)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    {
        let _at = testing::at(data.path(), Point::LedgerBeforeRename, || {
            Err(io_fault("the ledger is refused"))
        });
        assert_eq!(
            pending(&first.drafts().expect("read")),
            sorted(refs.clone())
        );
        let second = Window::over(data.path());
        assert_eq!(
            pending(&second.drafts().expect("read")),
            sorted(refs.clone())
        );
    }
    assert_eq!(pending(&first.drafts().expect("read")), sorted(refs));
}

/// KR-REQ-12.26: after a native restart that follows a durable entry and no ledger line, the repair
/// returns the exact references and publishes the ledger.
#[test]
fn a_restart_between_the_entry_and_the_ledger_is_repaired_by_the_first_read() {
    let data = data();
    let first = Window::over(data.path());
    let refs = vec![first.draft("text")];
    {
        let _at = testing::at(dir(data.path()), Point::AfterEntry, || {
            Err(io_fault("the process stopped"))
        });
        {
            let refusal = (first.keep(message(1, "text", &refs)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    drop(first);
    let restarted = Window::over(data.path());
    let read = restarted.drafts().expect("read");
    assert_eq!(pending(&read), sorted(refs.clone()));
    assert_eq!(ledger_refs(data.path()), sorted(refs));
}

/// KR-REQ-12.26: a keep whose own removal of its record fails still succeeds.
#[test]
fn a_keep_whose_removal_of_its_record_fails_still_succeeds() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    window.create_hold("hold-a", &refs).expect("a record");
    let mut params = message(1, "text", &refs);
    params["holdId"] = json!("hold-a");
    let _at = testing::at(dir(data.path()), Point::HoldRemoval, || {
        Err(io_fault("the removal is refused"))
    });
    window.keep(params).expect("the keep succeeds");
    assert!(names(&dir(data.path())).contains(&"hold-a.held".to_owned()));
}

/// KR-REQ-12.26: a keep removes the record of the send it ends.
#[test]
fn a_keep_removes_the_record_of_the_send_it_ends() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    window.create_hold("hold-a", &refs).expect("a record");
    assert!(names(&dir(data.path())).contains(&"hold-a.held".to_owned()));
    let mut params = message(1, "text", &refs);
    params["holdId"] = json!("hold-a");
    window.keep(params).expect("kept");
    assert!(!names(&dir(data.path())).contains(&"hold-a.held".to_owned()));
}

/// KR-REQ-12.26: a record of a send is made once, takes the action the host named, never changes
/// what it holds, and is removed by its identity, also when it is not there.
#[test]
fn a_record_of_a_send_is_made_once_updated_with_its_action_and_cleared() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    window.create_hold("hold-a", &refs).expect("made");
    {
        let refusal = (window.create_hold("hold-a", &refs))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    let list = window.list();
    assert_eq!(list["holds"][0]["holdId"], "hold-a", "{list}");
    assert_eq!(list["holds"][0]["actionId"], Value::Null);
    assert_eq!(list["holds"][0]["drafts"][0]["id"], refs[0].0);
    assert_eq!(list["holds"][0]["localId"], "local-hold-a");
    let update = |hold: &str, n: u8| {
        window.call(
            "device_channel_hold_update",
            json!({ "holdId": hold, "actionId": action(n) }),
        )
    };
    {
        let refusal = (update("hold-absent", 1))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    update("hold-a", 1).expect("null to a value");
    update("hold-a", 1).expect("the same value again");
    {
        let refusal = (update("hold-a", 2))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    let list = window.list();
    assert_eq!(list["holds"][0]["actionId"], action(1));
    assert_eq!(
        list["holds"][0]["drafts"][0]["id"], refs[0].0,
        "press references unchanged"
    );
    let clear = || window.call("device_channel_hold_clear", json!({ "holdId": "hold-a" }));
    clear().expect("cleared");
    clear().expect("cleared again: an absent record is already removed");
    assert!(window.list()["holds"].as_array().expect("holds").is_empty());
}

/// KR-REQ-12.26: an update whose flush fails after its rename leaves the supplied identity in the
/// file, and a retry cannot recreate a record that was removed.
#[test]
fn an_update_whose_flush_failed_after_its_rename_may_have_left_the_identity() {
    let data = data();
    let window = Window::over(data.path());
    window.create_hold("hold-a", &[]).expect("made");
    {
        let _guard = kr_flush::testing::refuse_flushes_of(dir(data.path()));
        {
            let refusal = (window.call(
                "device_channel_hold_update",
                json!({ "holdId": "hold-a", "actionId": action(1) }),
            ))
            .clone()
            .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    let list = window.list();
    assert_eq!(
        list["holds"][0]["actionId"],
        action(1),
        "the file the rename made is read: {list}"
    );
    window
        .call("device_channel_hold_clear", json!({ "holdId": "hold-a" }))
        .expect("cleared");
    {
        let refusal = (window.call(
            "device_channel_hold_update",
            json!({ "holdId": "hold-a", "actionId": action(1) }),
        ))
        .clone()
        .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert!(window.list()["holds"].as_array().expect("holds").is_empty());
}

/// KR-REQ-12.26: only readable records count towards the bound; a replacement is always allowed.
#[test]
fn only_readable_records_count_towards_the_bound() {
    let data = data();
    let window = Window::over(data.path());
    window
        .create_hold("hold-0", &[])
        .expect("the directory exists");
    window
        .call("device_channel_hold_clear", json!({ "holdId": "hold-0" }))
        .expect("cleared");
    let _limits = testing::lower_limits(
        dir(data.path()),
        Limits {
            entries: 100,
            bytes: 1_000_000,
            holds: 3,
        },
    );
    window.create_hold("hold-1", &[]).expect("one");
    window.create_hold("hold-2", &[]).expect("two");
    std::fs::write(dir(data.path()).join("hold-bad.held"), b"not json").expect("an unreadable one");
    window
        .create_hold("hold-3", &[])
        .expect("999 of 1,000 readable and one unreadable: made");
    {
        let refusal = (window.create_hold("hold-4", &[]))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "QUOTA_EXCEEDED", "{refusal}");
    }
    window
        .call(
            "device_channel_hold_update",
            json!({ "holdId": "hold-3", "actionId": action(1) }),
        )
        .expect("a replacement is always allowed");
}

/// KR-REQ-12.26: a record of another layout is counted and left; a damaged one is listed by its
/// name and the person removes it; one of a later version is never removed.
#[test]
fn a_damaged_record_is_listed_by_its_name_and_a_later_one_is_left_alone() {
    let data = data();
    let window = Window::over(data.path());
    window.create_hold("hold-ok", &[]).expect("made");
    let folder = dir(data.path());
    std::fs::write(folder.join("hold-bad.held"), b"not json at all").expect("damaged");
    std::fs::write(
        folder.join("hold-member.held"),
        br#"{"version":1,"kind":"held"}"#,
    )
    .expect("version 1 with members missing");
    let later = br#"{"version":2,"kind":"held","new_member":1}"#.to_vec();
    std::fs::write(folder.join("hold-later.held"), &later).expect("a later release's");
    let list = window.list();
    assert_eq!(list["holds"].as_array().expect("holds").len(), 1, "{list}");
    let mut damaged: Vec<&str> = list["damagedHolds"]
        .as_array()
        .expect("names")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    damaged.sort_unstable();
    assert_eq!(damaged, ["hold-bad", "hold-member"], "{list}");
    assert_eq!(list["unreadableHolds"]["layout"], 1, "{list}");
    window
        .call("device_channel_hold_clear", json!({ "holdId": "hold-bad" }))
        .expect("a damaged record is removed by name");
    {
        let refusal = (window.call(
            "device_channel_hold_clear",
            json!({ "holdId": "hold-later" }),
        ))
        .clone()
        .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert_eq!(
        std::fs::read(folder.join("hold-later.held")).expect("left"),
        later
    );
}

/// KR-REQ-12.26: removals and a clear whose folder cannot be flushed fail, and a clear of an absent
/// record fails until a flush succeeds.
#[test]
fn a_removal_or_clear_whose_flush_is_refused_fails_even_for_an_absent_record() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "one", &[])).expect("kept");
    window.create_hold("hold-a", &[]).expect("made");
    {
        let _guard = kr_flush::testing::refuse_flushes_of(dir(data.path()));
        {
            let refusal = (window.call(
                "device_channel_message_remove",
                json!({ "actionId": action(1) }),
            ))
            .clone()
            .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
        {
            let refusal = (window.call("device_channel_hold_clear", json!({ "holdId": "hold-a" })))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
        {
            let refusal = (window.call("device_channel_hold_clear", json!({ "holdId": "hold-a" })))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
        {
            let refusal = (window.call(
                "device_channel_hold_clear",
                json!({ "holdId": "hold-gone" }),
            ))
            .clone()
            .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
    }
    window
        .call(
            "device_channel_hold_clear",
            json!({ "holdId": "hold-gone" }),
        )
        .expect("an absent record is cleared once the flush works");
}

/// KR-REQ-12.26: a store and its files are for the owner alone, and a directory made wider is
/// narrowed.
#[cfg(unix)]
#[test]
fn the_store_is_private_to_its_owner_and_a_wider_directory_is_narrowed() {
    use std::os::unix::fs::PermissionsExt as _;

    let data = data();
    let folder = dir(data.path());
    std::fs::create_dir(&folder).expect("a folder");
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).expect("wide");
    let window = Window::over(data.path());
    window.keep(message(1, "one", &[])).expect("kept");
    window.create_hold("hold-a", &[]).expect("made");
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&folder), 0o700);
    assert_eq!(mode(&folder.join(format!("{}.message", action(1)))), 0o600);
    assert_eq!(mode(&folder.join("hold-a.held")), 0o600);
}

/// KR-REQ-12.26: a ledger that cannot be parsed is read as damaged, never as empty: the drafts
/// answer with their sources unknown, a keep fails and keeps its entry, and the bytes are unchanged.
#[test]
fn a_ledger_that_cannot_be_parsed_is_damaged_and_is_never_written_over() {
    let data = data();
    let window = Window::over(data.path());
    let refs = vec![window.draft("text")];
    std::fs::write(data.path().join("drafts-removals"), b"{ not a list").expect("damaged");
    let read = window.drafts().expect("read");
    assert_eq!(read["ledger"], "damaged", "{read}");
    assert_eq!(read["sources"], "unknown");
    {
        let refusal = (window.keep(message(1, "text", &refs)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    assert!(
        names(&dir(data.path())).contains(&format!("{}.message", action(1))),
        "the entry stays: a damaged ledger may name its references"
    );
    assert_eq!(ledger_bytes(data.path()).expect("bytes"), b"{ not a list");
    let mark = window.call(
        "device_draft_mark_removal",
        json!({ "id": refs[0].0, "expectedRevision": refs[0].1 }),
    );
    assert!(
        mark.is_err(),
        "a removal never replaces a ledger that cannot be read"
    );
    assert_eq!(ledger_bytes(data.path()).expect("bytes"), b"{ not a list");
}

/// KR-REQ-12.26: a ledger that cannot be read at all is `unreadable`, offers no set-aside and the
/// command refuses and leaves it as it was.
#[test]
fn a_ledger_that_cannot_be_read_is_unreadable_and_cannot_be_set_aside() {
    let data = data();
    let window = Window::over(data.path());
    std::fs::create_dir(data.path().join("drafts-removals")).expect("a directory at the name");
    let read = window.drafts().expect("read");
    assert_eq!(read["ledger"], "unreadable", "{read}");
    assert_eq!(read["sources"], "unknown");
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert!(data.path().join("drafts-removals").is_dir());
}

/// KR-REQ-12.26: setting a damaged ledger aside copies its bytes to a file of its own, replaces the
/// ledger with the removals the entries name, and a keep then succeeds. A readable ledger is
/// refused and left.
#[test]
fn a_damaged_ledger_is_set_aside_as_a_copy_and_replaced_by_the_rebuilt_list() {
    let data = data();
    let window = Window::over(data.path());
    let kept = window.draft("kept text");
    let stays = window.draft("a draft nobody sent");
    window
        .keep(message(1, "kept text", std::slice::from_ref(&kept)))
        .expect("kept");
    let damaged = b"[ truncated".to_vec();
    let _clock = testing::clock(data.path(), 1_700_000_000_123);
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    std::fs::write(data.path().join("drafts-removals"), &damaged).expect("damaged");
    let done = window
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("set aside");
    assert_eq!(done["moved"], true);
    assert_eq!(done["confirmed"], true);
    let copy = data.path().join("drafts-removals.set-aside-1700000000123");
    assert_eq!(
        std::fs::read(&copy).expect("the copy"),
        damaged,
        "the bytes are kept"
    );
    assert_eq!(
        ledger_refs(data.path()),
        vec![kept.clone()],
        "the rebuilt list"
    );
    let read = window.drafts().expect("read");
    assert_eq!(read["ledger"], "ok");
    assert_eq!(read["sources"], "known");
    assert!(
        read["drafts"]
            .as_array()
            .expect("drafts")
            .iter()
            .any(|draft| draft["id"] == stays.0),
        "a draft no entry names stays a draft"
    );
    window
        .keep(message(2, "next", &[]))
        .expect("a keep succeeds now");
    // A ledger that parses is never moved.
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert!(copy.exists());
}

/// KR-REQ-12.26: a name already in use is never replaced, and nothing changes when the copy fails.
#[test]
fn a_set_aside_never_replaces_a_name_that_is_used() {
    let data = data();
    let window = Window::over(data.path());
    let damaged = b"[ truncated".to_vec();
    std::fs::write(data.path().join("drafts-removals"), &damaged).expect("damaged");
    let used = data.path().join("drafts-removals.set-aside-5");
    std::fs::write(&used, b"an earlier set-aside").expect("a used name");
    let _clock = testing::clock(data.path(), 5);
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    assert_eq!(std::fs::read(&used).expect("kept"), b"an earlier set-aside");
    assert_eq!(
        ledger_bytes(data.path()).expect("bytes"),
        damaged,
        "nothing changed"
    );
}

/// KR-REQ-12.26: a flush refused before the ledger was replaced moves nothing; one refused after it
/// is `moved` and not `confirmed`: the drafts refuse until it succeeds, no draft is adopted
/// meanwhile, and a retry shows no control.
#[test]
fn a_set_aside_whose_flush_failed_is_owed_and_completed_before_any_adoption() {
    let data = data();
    let window = Window::over(data.path());
    window.draft("a draft");
    let damaged = b"[ truncated".to_vec();
    std::fs::write(data.path().join("drafts-removals"), &damaged).expect("damaged");
    let _clock = testing::clock(data.path(), 7);
    {
        let _early = kr_flush::testing::refuse_flushes_of(data.path());
        {
            let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
                .clone()
                .expect_err("the call is refused");
            assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
        }
        assert_eq!(
            ledger_bytes(data.path()).expect("bytes"),
            damaged,
            "nothing moved"
        );
    }
    let _copy = data.path().join("drafts-removals.set-aside-7");
    std::fs::remove_file(&_copy).expect("the stray copy of the first attempt");
    let slot = Arc::new(Mutex::new(None));
    let hold_slot = Arc::clone(&slot);
    let root = data.path().to_path_buf();
    let _at = testing::at(data.path(), Point::SetAsideCopied, move || {
        *hold_slot.lock().expect("a lock") =
            Some(kr_flush::testing::refuse_flushes_of(root.clone()));
        Ok(())
    });
    let done = window
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("the move is made");
    assert_eq!(done["moved"], true);
    assert_eq!(done["confirmed"], false);
    {
        let refusal = (window.drafts()).clone().expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    slot.lock().expect("a lock").take();
    let read = window.drafts().expect("answers once the flush is made");
    assert_eq!(read["ledger"], "ok", "a retry shows no control");
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
}

/// KR-REQ-12.26: the owed flush of a set-aside is kept with no message directory too, and every
/// reader of the ledger sees the damaged list or the rebuilt one, never an absent name.
#[test]
fn a_second_window_after_a_set_aside_reads_the_rebuilt_ledger_and_adopts_no_source() {
    let data = data();
    let first = Window::over(data.path());
    let second = Window::over(data.path());
    let kept = first.draft("kept text");
    first
        .keep(message(1, "kept text", std::slice::from_ref(&kept)))
        .expect("kept");
    second
        .drafts()
        .expect("the second window's repair completed");
    std::fs::write(data.path().join("drafts-removals"), b"[ truncated").expect("damaged");
    first
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("set aside by the first");
    assert!(
        data.path().join("drafts-removals").exists(),
        "the name is never absent"
    );
    let read = second.drafts().expect("read by the second");
    assert_eq!(pending(&read), vec![kept], "{read}");
    assert_eq!(read["ledger"], "ok");
}

/// KR-REQ-12.26: a set-aside waits for the file lock of the ledger and moves nothing under a lock
/// that is held; it holds the order of the locks.
#[test]
fn a_set_aside_waits_for_the_ledgers_file_lock() {
    let data = data();
    let window = Window::over(data.path());
    std::fs::write(data.path().join("drafts-removals"), b"[ truncated").expect("damaged");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data.path().join("drafts-removals.lock"))
        .expect("the lock file");
    kr_flush::lock::exclusive(&lock).expect("held by another process's handle");
    let set_aside = on_thread(data.path(), |window| {
        window.call("device_drafts_ledger_set_aside", json!(null))
    });
    assert!(
        set_aside.recv_timeout(SHORT).is_err(),
        "a set-aside moves nothing while the lock is held"
    );
    assert_eq!(ledger_bytes(data.path()).expect("bytes"), b"[ truncated");
    drop(lock);
    set_aside
        .recv_timeout(WAIT)
        .expect("it ends once the lock is let go")
        .expect("set aside");
    drop(window);
}

/// KR-REQ-12.26: with no message directory, a refused flush after a set-aside still keeps the flush
/// owed, so the drafts refuse until it is made.
#[test]
fn a_set_aside_with_no_message_directory_keeps_its_flush_owed() {
    let data = data();
    let window = Window::over(data.path());
    std::fs::write(data.path().join("drafts-removals"), b"[ truncated").expect("damaged");
    let _clock = testing::clock(data.path(), 11);
    let slot = Arc::new(Mutex::new(None));
    let hold_slot = Arc::clone(&slot);
    let root = data.path().to_path_buf();
    let _at = testing::at(data.path(), Point::SetAsideCopied, move || {
        *hold_slot.lock().expect("a lock") =
            Some(kr_flush::testing::refuse_flushes_of(root.clone()));
        Ok(())
    });
    window
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("moved");
    assert!(!dir(data.path()).exists(), "no message directory exists");
    {
        let refusal = (window.drafts()).clone().expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    slot.lock().expect("a lock").take();
    window.drafts().expect("answers once the flush is made");
}

/// KR-REQ-12.26: the source of a kept message whose entry the person removed comes back as a draft
/// after a set-aside, and nothing sends it.
#[test]
fn a_set_aside_loses_the_removal_of_a_message_the_person_removed() {
    let data = data();
    let window = Window::over(data.path());
    let kept = window.draft("kept text");
    window
        .keep(message(1, "kept text", std::slice::from_ref(&kept)))
        .expect("kept");
    window
        .call(
            "device_channel_message_remove",
            json!({ "actionId": action(1) }),
        )
        .expect("the person removes the entry");
    std::fs::write(data.path().join("drafts-removals"), b"[ truncated").expect("damaged");
    let done = window
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("set aside");
    assert_eq!(done["moved"], true, "{done}");
    let read = window.drafts().expect("read");
    assert!(pending(&read).is_empty(), "the removal is lost: {read}");
    assert!(
        read["drafts"]
            .as_array()
            .expect("drafts")
            .iter()
            .any(|draft| draft["id"] == kept.0),
        "the source is a draft again"
    );
}

/// KR-REQ-12.26: a set-aside names the sources of the entries it lists only once those entries' names
/// are proved durable, and refuses, moving nothing, while that proof fails.
#[test]
fn a_set_aside_refuses_while_an_entrys_name_is_not_proved_durable() {
    let data = data();
    let window = Window::over(data.path());
    window
        .keep(message(9, "first", &[]))
        .expect("the directory exists");
    let (id, revision) = window.draft("the text");
    let refs = vec![(id, revision)];
    // The entry is renamed in and its folder's flush is refused: an entry with no line.
    let guard = kr_flush::testing::refuse_flushes_of(dir(data.path()));
    {
        let refusal = (window.keep(message(1, "the text", &refs)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    assert!(
        names(&dir(data.path())).contains(&format!("{}.message", action(1))),
        "the entry is visible and not proved durable"
    );
    let ledger = data.path().join("drafts-removals");
    std::fs::write(&ledger, b"not a list").expect("a damaged list");
    {
        let refusal = (window.call("device_drafts_ledger_set_aside", json!(null)))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    assert_eq!(
        std::fs::read(&ledger).ok(),
        Some(b"not a list".to_vec()),
        "the original list is in place"
    );
    assert!(
        !names(data.path())
            .iter()
            .any(|name| name.starts_with("drafts-removals.set-aside-")),
        "nothing was copied"
    );
    drop(guard);
    let done = window
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("the list is set aside once the proof can be made");
    assert_eq!(done["moved"], true, "{done}");
    assert_eq!(ledger_refs(data.path()), sorted(refs));
}

/// KR-REQ-12.26: another state over the data directory, which owes nothing itself, proves a
/// set-aside durable before it reads, whether or not there is a folder of messages.
#[test]
fn another_state_proves_a_set_aside_durable_before_it_reads_with_no_message_folder() {
    let data = data();
    let first = Window::over(data.path());
    std::fs::write(data.path().join("drafts-removals"), b"not a list").expect("a damaged list");
    let slot = Arc::new(Mutex::new(None));
    let hold_slot = Arc::clone(&slot);
    let root = data.path().to_path_buf();
    let at = testing::at(data.path(), Point::SetAsideCopied, move || {
        *hold_slot.lock().expect("a lock") =
            Some(kr_flush::testing::refuse_flushes_of(root.clone()));
        Ok(())
    });
    let done = first
        .call("device_drafts_ledger_set_aside", json!(null))
        .expect("the list is moved");
    drop(at);
    assert_eq!(done["moved"], true, "{done}");
    assert_eq!(done["confirmed"], false, "{done}");
    let second = Window::over(data.path());
    {
        let refusal = (second.drafts()).clone().expect_err("the read is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    slot.lock().expect("a lock").take();
    assert!(
        second.drafts().is_ok(),
        "the read answers once the flush can be made"
    );
    assert!(!dir(data.path()).exists(), "there is no folder of messages");
}

/// A change to the members of a stored file, as a case under test makes it.
type Edit = dyn Fn(&mut serde_json::Map<String, Value>);

/// KR-REQ-12.26: a file is of this layout only with every member, nullable ones included, a numeric
/// time and no member more.
#[test]
fn a_message_or_record_file_is_of_this_layout_only_with_every_member_and_no_other() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "valid", &[])).expect("kept");
    let path = dir(data.path()).join(format!("{}.message", action(1)));
    let valid: Value = serde_json::from_slice(&std::fs::read(&path).expect("the entry"))
        .expect("the entry's json");
    assert!(valid["sent_at_ms"].is_u64(), "a JSON number: {valid}");
    let variant = |n: u8, edit: &Edit| {
        let mut file = valid.clone();
        let members = file.as_object_mut().expect("an object");
        members.insert("action_id".to_owned(), json!(action(n)));
        edit(members);
        std::fs::write(
            dir(data.path()).join(format!("{}.message", action(n))),
            serde_json::to_vec(&file).expect("bytes"),
        )
        .expect("a file");
    };
    // The control changes nothing but the identity, and is read.
    variant(2, &|_| {});
    assert_eq!(messages(&window.list()).len(), 2, "a valid variant is read");
    let breaks: [(u8, &Edit); 4] = [
        (3, &|members| {
            members.remove("environment_id");
        }),
        (4, &|members| {
            members.remove("hold_id");
        }),
        (5, &|members| {
            members.insert("extra".to_owned(), json!(1));
        }),
        (6, &|members| {
            members.insert("sent_at_ms".to_owned(), json!("5"));
        }),
    ];
    for (n, edit) in breaks {
        variant(n, edit);
        let list = window.list();
        assert_eq!(messages(&list).len(), 2, "variant {n} is not read: {list}");
        assert_eq!(
            list["unreadableMessages"]["layout"], 1,
            "variant {n} is of another layout: {list}"
        );
        std::fs::remove_file(dir(data.path()).join(format!("{}.message", action(n))))
            .expect("the variant goes");
    }
    // A record of a send with a member less is damaged: listed by its name for the person to remove.
    window.create_hold("a-hold", &[]).expect("a hold");
    let held = dir(data.path()).join("a-hold.held");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&held).expect("the record")).expect("json");
    assert!(record["sent_at_ms"].is_u64(), "a JSON number: {record}");
    record
        .as_object_mut()
        .expect("an object")
        .remove("action_id");
    std::fs::write(&held, serde_json::to_vec(&record).expect("bytes")).expect("a file");
    assert_eq!(window.list()["damagedHolds"], json!(["a-hold"]));
}

/// KR-REQ-12.26: a keep with no references takes the ledger step: a damaged list fails it, and a
/// flush that is refused fails it until a repeat completes.
#[test]
fn a_keep_with_no_references_takes_the_ledger_step_too() {
    let data = data();
    let window = Window::over(data.path());
    window
        .keep(message(9, "first", &[]))
        .expect("the directory exists");
    let ledger = data.path().join("drafts-removals");
    std::fs::write(&ledger, b"not a list").expect("a damaged list");
    {
        let refusal = (window.keep(message(1, "no draft", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    assert_eq!(
        std::fs::read(&ledger).ok(),
        Some(b"not a list".to_vec()),
        "a damaged list is never written over"
    );
    std::fs::remove_file(&ledger).expect("the damaged list goes");
    window.drafts().expect("the list now reads as empty");
    let guard = kr_flush::testing::refuse_flushes_of(data.path().to_path_buf());
    {
        let refusal = (window.keep(message(2, "no draft either", &[])))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "RESOURCE_UNAVAILABLE", "{refusal}");
    }
    drop(guard);
    // The keep reported the failure, so the page sends nothing; the same keep, repeated, completes.
    let done = window
        .keep(message(2, "no draft either", &[]))
        .expect("the repeated keep completes");
    assert_eq!(done["resumed"], true, "{done}");
}

/// KR-REQ-12.26: a keep removes the record of its send only when it reads as this layout, and a
/// removal that cannot read a record removes nothing.
#[test]
fn a_record_of_a_later_layout_or_that_cannot_be_read_is_never_removed_by_cleanup() {
    let data = data();
    let window = Window::over(data.path());
    window.create_hold("later", &[]).expect("a hold");
    let later = dir(data.path()).join("later.held");
    std::fs::write(&later, br#"{"version":2,"kind":"held","hold_id":"later"}"#)
        .expect("a later layout");
    let mut request = message(1, "text", &[]);
    request["holdId"] = json!("later");
    window.keep(request).expect("the keep succeeds");
    assert!(later.exists(), "a record of a later layout is left");
    {
        let refusal = (window.call("device_channel_hold_clear", json!({ "holdId": "later" })))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "INVALID_ARGUMENT", "{refusal}");
    }
    assert!(later.exists(), "a clear leaves it as well");
    // A record that cannot be read now: a folder of that name.
    std::fs::create_dir(dir(data.path()).join("unread.held")).expect("a folder");
    {
        let refusal = (window.call("device_channel_hold_clear", json!({ "holdId": "unread" })))
            .clone()
            .expect_err("the call is refused");
        assert_eq!(code_of(&refusal), "STORAGE_UNAVAILABLE", "{refusal}");
    }
    assert!(
        dir(data.path()).join("unread.held").is_dir(),
        "nothing was removed"
    );
    // A damaged record goes by the person's own clear, and not by a keep.
    let damaged = dir(data.path()).join("damaged.held");
    std::fs::write(&damaged, b"not json").expect("a damaged record");
    let mut next = message(2, "text", &[]);
    next["holdId"] = json!("damaged");
    window.keep(next).expect("the keep succeeds");
    assert!(damaged.exists(), "a keep leaves a damaged record");
    window
        .call("device_channel_hold_clear", json!({ "holdId": "damaged" }))
        .expect("the person's clear");
    assert!(!damaged.exists(), "a clear removes it");
}

/// KR-REQ-12.26: a repair and a record's update sweep the staged files an unfinished write left,
/// and a listing leaves them alone.
#[test]
fn a_repair_and_an_update_sweep_staged_files_and_a_listing_does_not() {
    let data = data();
    let window = Window::over(data.path());
    window.create_hold("held-one", &[]).expect("a hold");
    let staged_message = dir(data.path()).join(format!("{}.message.staged-1-1", action(7)));
    let staged_hold = dir(data.path()).join("x.held.staged-1-1");
    std::fs::write(&staged_message, b"half").expect("a staged file");
    std::fs::write(&staged_hold, b"half").expect("a staged file");
    window.list();
    assert!(
        staged_message.exists() && staged_hold.exists(),
        "a listing changes nothing"
    );
    window.drafts().expect("a repair");
    assert!(
        !staged_message.exists() && !staged_hold.exists(),
        "a repair sweeps them"
    );
    std::fs::write(&staged_hold, b"half").expect("a staged file");
    window
        .call(
            "device_channel_hold_update",
            json!({ "holdId": "held-one", "actionId": action(1) }),
        )
        .expect("an update");
    assert!(!staged_hold.exists(), "an update sweeps them");
}

/// KR-REQ-12.26: after the first keep made the folder durable, a later keep flushes no name of the
/// path again, so a case that refuses one flush refuses only that one.
#[test]
fn a_later_keep_flushes_nothing_more_of_the_path() {
    let data = data();
    let window = Window::over(data.path());
    window.keep(message(1, "first", &[])).expect("kept");
    let parent = data.path().parent().expect("a parent").to_path_buf();
    let guard = kr_flush::testing::refuse_flushes_of(parent);
    let second = window.keep(message(2, "second", &[]));
    drop(guard);
    assert!(
        second.is_ok(),
        "a refused flush of the path's parent does not reach a later keep: {second:?}"
    );
}
