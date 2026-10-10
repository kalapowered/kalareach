//! The drafts a person has written and not sent, kept by the application on this device and read
//! back by the page, through the commands the page calls.
//!
//! The store is the client library's real one, in a directory of the test's own. A restart is a new
//! application state over the same directory; a second window is a second state over it too.

use serde_json::{Value, json};
use tauri::test::MockRuntime;

const BUNDLE: &str = "tauri://localhost";

const SESSION: &str = "8a7b6c50-22bb-4c3d-8e4f-000000000101";
const OTHER_SESSION: &str = "8a7b6c50-22bb-4c3d-8e4f-000000000102";
const INSTANCE: &str = "9a7b6c50-22bb-4c3d-8e4f-000000000201";
const NEXT_INSTANCE: &str = "9a7b6c50-22bb-4c3d-8e4f-000000000202";

/// One window of the application: its state over a data directory, and the page that calls it.
struct Window {
    _app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
}

impl Window {
    /// An application started over `data`, which is where everything it keeps lives.
    fn over(data: &std::path::Path) -> Self {
        let state = companion_tauri::AppState::new();
        state.keep_under(data);
        let app = tauri::test::mock_builder()
            .manage(state)
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::device_drafts,
                companion_tauri::commands::device_draft_save,
                companion_tauri::commands::device_draft_retarget,
                companion_tauri::commands::device_draft_discard,
                companion_tauri::commands::question_kept,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self { _app: app, window }
    }

    /// Calls `command` as the page does.
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

    fn read(&self) -> Value {
        self.call("device_drafts", json!(null))
            .expect("the drafts are read")
    }

    /// A save of a new draft for the session, with `text`.
    fn write(&self, text: &str) -> Value {
        self.call("device_draft_save", save(None, None, SESSION, None, text))
            .expect("the draft is saved")
    }
}

/// The parameters of a save.
fn save(
    id: Option<&str>,
    revision: Option<&str>,
    session: &str,
    instance: Option<&str>,
    text: &str,
) -> Value {
    json!({
        "id": id,
        "expectedRevision": revision,
        "sessionId": session,
        "applicationInstanceId": instance,
        "agentBindingRevision": instance.map(|_| "1"),
        "state": "open",
        "text": text,
        "attachments": []
    })
}

/// A completed upload with no preview, whose file name is `name`.
fn a_handle(index: u8, name: &str) -> kr_protocol::transfer::AttachmentHandle {
    use kr_protocol::ids::{EnvironmentId, TransferId};
    use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

    kr_protocol::transfer::AttachmentHandle {
        environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
        transfer_id: TransferId::new(Uuid::from_bytes([index + 10; 16])),
        session_id: Nullable::null(),
        byte_len: U64::new(4096),
        content_digest: Digest256::from_bytes([3; 32]),
        declared_media_type: "image/png".to_owned(),
        original_file_name: name.to_owned(),
        preview: Nullable::null(),
        presented_as_image: true,
        published_at_ms: TimestampMs::new(10),
        expires_at_ms: TimestampMs::new(20),
        submitted: false,
    }
}

fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or("not a refusal")
}

fn drafts_of(read: &Value) -> &Vec<Value> {
    read["drafts"].as_array().expect("a list of drafts")
}

/// A draft the application kept is there after the application starts again, with its text, its
/// session and the version the next save names, and a second start reads the same owner.
#[test]
fn a_draft_is_still_there_when_the_application_starts_again() {
    let data = tempfile::tempdir().expect("a data directory");
    let first = Window::over(data.path());
    let saved = first.write("half a thought");
    assert_eq!(saved["outcome"], "stored");
    assert_eq!(saved["draft"]["revision"], "1");
    drop(first);

    let second = Window::over(data.path());
    let read = second.read();
    let drafts = drafts_of(&read);
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0]["text"], "half a thought");
    assert_eq!(drafts[0]["sessionId"], SESSION);
    assert_eq!(drafts[0]["state"], "open");
    assert_eq!(drafts[0]["id"], saved["draft"]["id"]);
    // The owner is the same on a second start, so the draft is still this device's to change.
    let again = second
        .call(
            "device_draft_save",
            save(
                drafts[0]["id"].as_str(),
                drafts[0]["revision"].as_str(),
                SESSION,
                None,
                "half a thought, finished",
            ),
        )
        .expect("the owner of the draft can change it");
    assert_eq!(again["draft"]["revision"], "2");
}

/// A save that names a version that is no longer the stored one means another window wrote in
/// between. The stored draft stays as that window left it, and what this window has is kept beside
/// it as a copy, so neither text is lost and neither replaces the other.
#[test]
fn a_save_of_an_older_version_is_kept_beside_the_draft_and_replaces_nothing() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("the first window began this");
    let id = made["draft"]["id"].as_str().expect("an id");

    // The second window opens it and writes first.
    let theirs = two
        .call(
            "device_draft_save",
            save(
                Some(id),
                Some("1"),
                SESSION,
                None,
                "the second window's version",
            ),
        )
        .expect("saved");
    assert_eq!(theirs["outcome"], "stored");
    assert_eq!(theirs["draft"]["revision"], "2");

    // The first still holds version one.
    let mine = one
        .call(
            "device_draft_save",
            save(
                Some(id),
                Some("1"),
                SESSION,
                None,
                "the first window's version",
            ),
        )
        .expect("kept");
    assert_eq!(mine["outcome"], "copied");
    assert_eq!(mine["of"], id);
    assert_ne!(mine["draft"]["id"], json!(id), "a draft of its own");
    assert_eq!(mine["draft"]["copyOf"], json!(id));

    let read = one.read();
    let drafts = drafts_of(&read);
    assert_eq!(drafts.len(), 2);
    let original = drafts
        .iter()
        .find(|draft| draft["id"] == json!(id))
        .expect("the original");
    assert_eq!(original["text"], "the second window's version");
    assert_eq!(original["revision"], "2");
    let copy = drafts
        .iter()
        .find(|draft| draft["id"] != json!(id))
        .expect("the copy");
    assert_eq!(copy["text"], "the first window's version");

    // The first window carries on with its copy: its next save names the copy's version.
    let on = one
        .call(
            "device_draft_save",
            save(
                mine["draft"]["id"].as_str(),
                Some("1"),
                SESSION,
                None,
                "the first window's version, further on",
            ),
        )
        .expect("saved on the copy");
    assert_eq!(on["outcome"], "stored");
    assert_eq!(
        drafts_of(&one.read()).len(),
        2,
        "one copy, however long it carries on"
    );
}

/// A window that is behind the stored draft keeps its text even when what it would save also breaks
/// a rule: it is kept beside the stored draft, not refused. A person's text is never the price of
/// another window having moved the draft on.
#[test]
fn a_save_from_behind_is_kept_even_when_it_also_breaks_a_rule() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("begun in the first window");
    let id = made["draft"]["id"].as_str().expect("an id");
    // The second window learns which conversation the draft is for.
    two.call(
        "device_draft_save",
        save(
            Some(id),
            Some("1"),
            SESSION,
            Some(INSTANCE),
            "begun in the first window",
        ),
    )
    .expect("saved");

    // The first window still holds version one, and its page believes the agent has moved on.
    let behind = one
        .call(
            "device_draft_save",
            save(
                Some(id),
                Some("1"),
                SESSION,
                Some(NEXT_INSTANCE),
                "a thought the first window had",
            ),
        )
        .expect("kept, not refused");
    assert_eq!(behind["outcome"], "copied");
    assert_eq!(behind["draft"]["text"], "a thought the first window had");
    // It is kept apart as a draft that needs a choice, not as one that is open: the stored draft
    // holds text for one conversation and this text was written for another.
    assert_eq!(behind["draft"]["state"], "conflicted");
}

/// A copy does not take a draft back to open: when another window marked the draft while this one
/// held an older version, what this window wrote is kept with the stricter mark.
#[test]
fn a_copy_keeps_the_mark_another_window_gave_the_draft() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("begun in the first window");
    let id = made["draft"]["id"].as_str().expect("an id");
    let mut orphaned = save(
        Some(id),
        Some("1"),
        SESSION,
        None,
        "begun in the first window",
    );
    orphaned["state"] = json!("orphaned");
    two.call("device_draft_save", orphaned).expect("marked");

    let behind = one
        .call(
            "device_draft_save",
            save(
                Some(id),
                Some("1"),
                SESSION,
                None,
                "and the first window went on",
            ),
        )
        .expect("kept, not refused");
    assert_eq!(behind["outcome"], "copied");
    assert_eq!(
        behind["draft"]["state"], "orphaned",
        "an open copy of an orphaned draft would reach a composer without a choice"
    );
}

/// Another window removed the draft this window still holds, because it sent it or because the
/// person discarded it there. What this window has is kept as a draft again, with an identity of its
/// own, and the page takes that identity; its next save does not fail on the one that is gone.
#[test]
fn a_save_of_a_draft_another_window_removed_makes_it_again() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("written in the first window");
    let id = made["draft"]["id"].as_str().expect("an id").to_owned();
    two.call(
        "device_draft_discard",
        json!({ "id": id, "expectedRevision": "1" }),
    )
    .expect("discarded in the second window");

    let again = one
        .call(
            "device_draft_save",
            save(
                Some(&id),
                Some("1"),
                SESSION,
                None,
                "written in the first window, and more",
            ),
        )
        .expect("kept again, not refused");
    assert_eq!(again["outcome"], "stored");
    assert_ne!(again["draft"]["id"], json!(id), "a draft of its own");
    assert_eq!(again["draft"]["revision"], "1");
    assert_eq!(again["draft"]["copyOf"], Value::Null);
    let read = one.read();
    let drafts = drafts_of(&read);
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0]["text"], "written in the first window, and more");
}

/// A first save with files is all stored or none of it: a record that holds the text and lacks the
/// files would be answered as the whole draft, and the page would not write the files again.
#[test]
fn a_first_save_with_files_stores_all_of_it_or_none() {
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());
    // The text alone fits a draft; the text with these files does not.
    let text = "a".repeat(60 * 1024);
    let mut request = save(None, None, SESSION, None, &text);
    request["attachments"] = json!(
        (0..3)
            .map(
                |index| serde_json::to_value(a_handle(index, &"n".repeat(4 * 1024)))
                    .expect("a handle")
            )
            .collect::<Vec<_>>()
    );
    let refused = window
        .call("device_draft_save", request)
        .expect_err("the draft with its files does not fit");
    assert_eq!(code_of(&refused), "QUOTA_EXCEEDED");
    assert!(
        drafts_of(&window.read()).is_empty(),
        "no record holds only the text"
    );
    // The text on its own is kept.
    let alone = window
        .call("device_draft_save", save(None, None, SESSION, None, &text))
        .expect("the text alone fits");
    assert_eq!(alone["outcome"], "stored");
}

/// The limit is on the bytes a draft is stored as, not on characters: text of two-byte letters
/// reaches it at half the length.
#[test]
fn the_limit_on_a_draft_counts_the_bytes_it_is_stored_as() {
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());
    let letters = "e".repeat(60 * 1024);
    window
        .call(
            "device_draft_save",
            save(None, None, SESSION, None, &letters),
        )
        .expect("sixty thousand one-byte letters fit");
    let accented = "é".repeat(40 * 1024);
    let refused = window
        .call(
            "device_draft_save",
            save(None, None, OTHER_SESSION, None, &accented),
        )
        .expect_err("forty thousand two-byte letters do not");
    assert_eq!(code_of(&refused), "QUOTA_EXCEEDED");
}

/// The rules the page cannot be left to keep: a draft keeps its session, never goes back to open by
/// a save, and does not move to another conversation while it holds text for one.
#[test]
fn a_save_keeps_the_session_the_mark_and_the_conversation_a_draft_was_written_for() {
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());

    // A draft that began with no conversation takes the first one it learns, once.
    let made = window.write("written before the agent was read");
    let id = made["draft"]["id"].as_str().expect("an id").to_owned();
    let learned = window
        .call(
            "device_draft_save",
            save(
                Some(&id),
                Some("1"),
                SESSION,
                Some(INSTANCE),
                "written before the agent was read",
            ),
        )
        .expect("the first conversation is learned");
    assert_eq!(learned["draft"]["applicationInstanceId"], INSTANCE);

    // Then it keeps it: the agent starting again is a conflict the person settles, not a move.
    let moved = window
        .call(
            "device_draft_save",
            save(
                Some(&id),
                Some("2"),
                SESSION,
                Some(NEXT_INSTANCE),
                "written before the agent was read",
            ),
        )
        .expect_err("a draft with text does not follow the agent");
    assert_eq!(code_of(&moved), "DRAFT_CONFLICT");

    // Another session is the person's choice, by retargeting.
    let elsewhere = window
        .call(
            "device_draft_save",
            save(
                Some(&id),
                Some("2"),
                OTHER_SESSION,
                Some(INSTANCE),
                "written before the agent was read",
            ),
        )
        .expect_err("a save does not change the session");
    assert_eq!(code_of(&elsewhere), "INVALID_ARGUMENT");

    // The mark goes forward, and a save never takes it back.
    let mut marked = save(
        Some(&id),
        Some("2"),
        SESSION,
        Some(INSTANCE),
        "written before the agent was read",
    );
    marked["state"] = json!("conflicted");
    let marked = window.call("device_draft_save", marked).expect("marked");
    assert_eq!(marked["draft"]["state"], "conflicted");
    let still = window
        .call(
            "device_draft_save",
            save(
                Some(&id),
                Some("3"),
                SESSION,
                Some(INSTANCE),
                "and a little more",
            ),
        )
        .expect("saved");
    assert_eq!(
        still["draft"]["state"], "conflicted",
        "a window that thinks the draft is open does not reopen it"
    );
    assert_eq!(still["draft"]["text"], "and a little more");
}

/// Retargeting names the version the person was shown, is the one way back to open, and makes a
/// copy an ordinary draft of the session it was sent to.
#[test]
fn retargeting_is_the_way_back_to_open_and_names_the_version_it_was_shown() {
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());
    let made = window.write("for the old conversation");
    let id = made["draft"]["id"].as_str().expect("an id").to_owned();
    let mut orphaned = save(
        Some(&id),
        Some("1"),
        SESSION,
        None,
        "for the old conversation",
    );
    orphaned["state"] = json!("orphaned");
    window.call("device_draft_save", orphaned).expect("marked");

    let stale = window
        .call(
            "device_draft_retarget",
            json!({ "id": id, "expectedRevision": "1", "sessionId": OTHER_SESSION,
                    "applicationInstanceId": null, "agentBindingRevision": null }),
        )
        .expect_err("the person was shown an older version");
    assert_eq!(code_of(&stale), "DRAFT_CONFLICT");

    let moved = window
        .call(
            "device_draft_retarget",
            json!({ "id": id, "expectedRevision": "2", "sessionId": OTHER_SESSION,
                    "applicationInstanceId": null, "agentBindingRevision": null }),
        )
        .expect("retargeted");
    assert_eq!(moved["sessionId"], OTHER_SESSION);
    assert_eq!(moved["state"], "open");
    assert_eq!(moved["text"], "for the old conversation");
}

/// A copy kept beside another window's draft becomes an ordinary draft of the session it is sent to,
/// by the person's choice, and is not a copy any more.
#[test]
fn sending_a_copy_to_a_session_makes_it_a_draft_of_that_session() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("begun");
    let id = made["draft"]["id"].as_str().expect("an id").to_owned();
    two.call(
        "device_draft_save",
        save(Some(&id), Some("1"), SESSION, None, "theirs"),
    )
    .expect("saved");
    let copy = one
        .call(
            "device_draft_save",
            save(Some(&id), Some("1"), SESSION, None, "mine"),
        )
        .expect("kept");
    assert_eq!(copy["outcome"], "copied");
    let copy_id = copy["draft"]["id"].as_str().expect("an id").to_owned();

    let sent = one
        .call(
            "device_draft_retarget",
            json!({ "id": copy_id, "expectedRevision": "1", "sessionId": OTHER_SESSION,
                    "applicationInstanceId": null, "agentBindingRevision": null }),
        )
        .expect("retargeted");
    assert_eq!(sent["sessionId"], OTHER_SESSION);
    assert_eq!(
        sent["copyOf"],
        Value::Null,
        "a draft the person sent is not a copy"
    );
}

/// A discard removes the version the person was shown and no later one.
#[test]
fn a_discard_removes_the_version_that_was_shown_and_no_later_one() {
    let data = tempfile::tempdir().expect("a data directory");
    let one = Window::over(data.path());
    let two = Window::over(data.path());
    let made = one.write("shown to the person");
    let id = made["draft"]["id"].as_str().expect("an id").to_owned();
    two.call(
        "device_draft_save",
        save(Some(&id), Some("1"), SESSION, None, "a later version"),
    )
    .expect("saved");

    let refused = one
        .call(
            "device_draft_discard",
            json!({ "id": id, "expectedRevision": "1" }),
        )
        .expect_err("the draft moved on");
    assert_eq!(code_of(&refused), "DRAFT_CONFLICT");
    assert_eq!(drafts_of(&one.read()).len(), 1);

    let removed = one
        .call(
            "device_draft_discard",
            json!({ "id": id, "expectedRevision": "2" }),
        )
        .expect("discarded");
    assert_eq!(removed["removed"], true);
    assert!(drafts_of(&one.read()).is_empty());
    let again = one
        .call(
            "device_draft_discard",
            json!({ "id": id, "expectedRevision": "2" }),
        )
        .expect("a draft already gone");
    assert_eq!(again["removed"], false);
}

/// The file that says who owns the drafts is never replaced by a new one: every draft already stored
/// would then belong to someone else. A file that cannot be read opens no store.
#[test]
fn an_owner_that_cannot_be_read_opens_no_store_and_is_never_written_over() {
    let data = tempfile::tempdir().expect("a data directory");
    let first = Window::over(data.path());
    first.write("kept");
    drop(first);

    let owner = data.path().join("drafts-owner");
    std::fs::write(&owner, b"not an identifier").expect("a damaged owner file");
    let second = Window::over(data.path());
    let refused = second
        .call("device_drafts", json!(null))
        .expect_err("the store is not opened");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    let refused = second
        .call("device_draft_save", save(None, None, SESSION, None, "more"))
        .expect_err("nothing is saved either");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    assert_eq!(
        std::fs::read(&owner).expect("the file"),
        b"not an identifier"
    );
}

/// A stored record is bounded and a preview can fill it, so a draft keeps its files without them.
#[test]
fn a_file_is_kept_on_a_draft_without_its_preview() {
    use kr_protocol::ids::{EnvironmentId, TransferId};
    use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, U64, Uuid};
    use kr_protocol::transfer::{AttachmentHandle, AttachmentPreview, PreviewFormat};

    let handle = AttachmentHandle {
        environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
        transfer_id: TransferId::new(Uuid::from_bytes([2; 16])),
        session_id: Nullable::null(),
        byte_len: U64::new(4096),
        content_digest: Digest256::from_bytes([3; 32]),
        declared_media_type: "image/png".to_owned(),
        original_file_name: "diagram.png".to_owned(),
        preview: Nullable::some(AttachmentPreview {
            source_format: PreviewFormat::Png,
            source_width: U64::new(64),
            source_height: U64::new(64),
            width: U64::new(32),
            height: U64::new(32),
            thumbnail: Bytes::from(vec![7; 40 * 1024]),
        }),
        presented_as_image: true,
        published_at_ms: TimestampMs::new(10),
        expires_at_ms: TimestampMs::new(20),
        submitted: false,
    };
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());
    let mut request = save(None, None, SESSION, None, "look at this");
    request["attachments"] = json!([serde_json::to_value(&handle).expect("a handle")]);
    let saved = window
        .call("device_draft_save", request)
        .expect("saved with a file");
    let kept = &saved["draft"]["attachments"][0];
    assert_eq!(kept["transfer_id"], json!(handle.transfer_id));
    assert_eq!(kept["original_file_name"], "diagram.png");
    assert_eq!(kept["preview"], Value::Null, "the preview is not kept");

    let read = window.read();
    assert_eq!(
        drafts_of(&read)[0]["attachments"][0]["preview"],
        Value::Null
    );
}

/// The application wires both of its stores under its data directory with one call, which is the
/// call it makes at start: without it the kept answers and the drafts have no place.
#[test]
fn the_application_gives_its_answers_and_its_drafts_a_place_under_its_data_directory() {
    let data = tempfile::tempdir().expect("a data directory");
    let window = Window::over(data.path());
    let answers = window.call("question_kept", json!(null));
    assert_eq!(
        answers.expect("the kept answers are read"),
        json!({ "answers": [], "unreadable": 0 })
    );
    assert_eq!(window.read()["drafts"], json!([]));
    assert!(data.path().join("drafts").is_dir());
}
