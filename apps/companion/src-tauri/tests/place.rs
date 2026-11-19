//! A terminal view's kept place, restored by a real worker.
//!
//! The session is hosted by this test with the product's own worker, and the shell it runs prints
//! the rows a case keeps a place in and then waits on a line from the person. A view opens at a
//! place the page kept, and what is read is the screen the view publishes: the row it starts at, its
//! text, and what native code says of it.

#![cfg(unix)]

mod common;

use common::{Hosted, Page, hosted};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::ids::AttachmentId;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::Dimensions;
use serde_json::Value;

/// The channels the views publish on.
const TYPIST: u32 = 3;
const FIRST: u32 = 4;
const SECOND: u32 = 5;
const THIRD: u32 = 6;

/// The shell's script: a hundred rows, then three phases each started by a line the person types.
/// The second adds rows, the third erases the scrollback and adds others.
const PHASES: &str = "rows() { i=1; while [ \"$i\" -le \"$2\" ]; do printf '%s %03d\\n' \"$1\" \"$i\"; \
     i=$((i+1)); done; }; rows row 100; read a; rows more 60; read b; printf '\\033[3J'; \
     rows last 30; exec cat";

/// A published screen that shows `text` on some line.
fn shows(state: &Value, text: &str) -> bool {
    state["state"] == "showing" && Page::lines(state).iter().any(|line| line.contains(text))
}

/// A session at an empty prompt whose shell runs `script`, and a view of it that has taken control,
/// with the reader's proof of the fence that control asks for.
async fn typist(script: &str) -> (Hosted, Page, String) {
    let mut hosted = hosted(script).await;
    hosted.enters_the_prompt().await;
    let page = Page::new(hosted.temp.environment());
    let view = page
        .open_at(hosted.session_id, TYPIST, 80, 24, &Value::Null)
        .await
        .expect("the view opens");
    page.newest(TYPIST, |state| state["state"] == "showing")
        .await;
    tokio::join!(page.takes_control(&view, TYPIST), hosted.proves_a_fence());
    (hosted, page, view)
}

/// KR-REQ-13.03: a real worker gives back the row a view was left at, with its text and no note,
/// after more rows were written; and once the scrollback is erased it says that the place is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_worker_gives_back_a_kept_row_and_says_when_it_is_gone() {
    let (hosted, page, typing) = typist(PHASES).await;
    page.newest(TYPIST, |state| shows(state, "row 100")).await;

    // A view that reads the history ten rows up, and the place it leaves.
    let reading = page
        .open_at(hosted.session_id, FIRST, 80, 24, &Value::Null)
        .await
        .expect("the view opens");
    page.newest(FIRST, |state| shows(state, "row 100")).await;
    page.pan(&reading, 1, 0, -10).await;
    let left = page
        .newest(FIRST, |state| {
            state["state"] == "showing" && state["settled"] == 1
        })
        .await;
    let kept = left["anchor"].clone();
    assert_ne!(kept, Value::Null, "the view is in the history");
    let first = Page::lines(&left)[0].clone();
    assert!(first.starts_with("row "), "a numbered row: {first:?}");
    page.close(&reading).await;

    // More rows are written; the row is still in the history, where it was.
    page.enter(&typing).await;
    page.newest(TYPIST, |state| shows(state, "more 060")).await;
    let returned = page
        .open_at(hosted.session_id, SECOND, 80, 24, &kept)
        .await
        .expect("the view opens");
    let back = page
        .newest(SECOND, |state| state["state"] == "showing")
        .await;
    assert_eq!(back["note"], Value::Null, "{back}");
    assert_eq!(Page::lines(&back)[0], first, "the same first row");
    assert_eq!(back["anchor"]["row"], kept["row"]);
    page.close(&returned).await;

    // The scrollback is erased: the row is gone.
    page.enter(&typing).await;
    page.newest(TYPIST, |state| shows(state, "last 030")).await;
    let _gone = page
        .open_at(hosted.session_id, THIRD, 80, 24, &kept)
        .await
        .expect("the view opens");
    let after = page
        .newest(THIRD, |state| state["state"] == "showing")
        .await;
    assert_eq!(after["note"], "gone", "{after}");
    assert_ne!(Page::lines(&after)[0], first, "not the row it was");
    hosted.close().await;
}

/// The shell's script for the reflow: sixty lines of more than eighty columns, each wrapping at
/// eighty, whose continuation rows carry the line's own number.
const WIDE: &str = "pad=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; \
     i=1; while [ \"$i\" -le 60 ]; do printf 'row %03d %s tail %03d\\n' \"$i\" \"$pad\" \"$i\"; \
     i=$((i+1)); done; exec cat";

/// KR-REQ-13.03: after the session was reflowed to another width and back, a real worker never
/// shows other text for a kept place without saying so: the note is none only when the first row's
/// text is the text the anchor was made from, and `different` otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_worker_never_shows_other_text_after_a_width_change_without_saying_so() {
    let mut hosted = hosted(WIDE).await;
    hosted.enters_the_prompt().await;
    let page = Page::new(hosted.temp.environment());

    // A view that leaves its window on a continuation row of a wrapped line.
    let reading = page
        .open_at(hosted.session_id, FIRST, 80, 24, &Value::Null)
        .await
        .expect("the view opens");
    page.newest(FIRST, |state| shows(state, "tail 060")).await;
    page.pan(&reading, 1, 0, -10).await;
    let mut left = page
        .newest(FIRST, |state| {
            state["state"] == "showing" && state["settled"] == 1
        })
        .await;
    if Page::lines(&left)[0].starts_with("row ") {
        page.pan(&reading, 2, 0, -1).await;
        left = page
            .newest(FIRST, |state| {
                state["state"] == "showing" && state["settled"] == 2
            })
            .await;
    }
    let kept = left["anchor"].clone();
    assert_ne!(kept, Value::Null, "the view is in the history");
    let first = Page::lines(&left)[0].clone();
    assert!(!first.is_empty(), "a first row with text");
    page.close(&reading).await;

    // A second attachment owns the size, and takes it to 120 columns and back.
    let owner = AttachmentId::new(kr_ipc::new_uuid());
    {
        let mut granted = CanonicalSet::new();
        granted.insert(AttachmentCapability::Geometry);
        let params = SessionAttachParams {
            session_id: hosted.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: true,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: granted.clone(),
        };
        let mut session = hosted.runtime.session();
        let attached = session
            .attach(&params, granted, owner)
            .expect("the owner attaches");
        let mut epoch = attached.geometry.epoch.get();
        for size in [Dimensions::new(120, 24), Dimensions::new(80, 24)] {
            epoch = session
                .resize(owner, size, epoch)
                .expect("the owner resizes")
                .epoch
                .get();
        }
    }

    let _returned = page
        .open_at(hosted.session_id, SECOND, 80, 24, &kept)
        .await
        .expect("the view opens");
    let shown = page
        .newest(SECOND, |state| state["state"] == "showing")
        .await;
    let same = Page::lines(&shown)[0] == first;
    match shown["note"].as_str() {
        None => assert!(
            same,
            "other text is shown with no note: {first:?} then {shown}"
        ),
        Some(note) => assert_eq!(note, "different", "{shown}"),
    }
    hosted.close().await;
}
