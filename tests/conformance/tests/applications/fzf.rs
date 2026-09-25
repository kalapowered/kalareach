//! fzf: a list with CJK in it, a typed query, a pasted query, a click, and what it chose.

use std::path::Path;

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Session, application};
use crate::queries;

/// fzf choosing from four items, writing its choice to `chosen`.
fn launch(chosen: &Path) -> Launch {
    let fzf = application("fzf");
    let script = format!(
        "printf '%s\\n' alpha beta '中文テキスト' gamma | '{}' --no-sort > '{}'",
        fzf.executable.display(),
        chosen.display()
    );
    Launch::new(Path::new("/bin/sh"))
        .variable("FZF_DEFAULT_OPTS", "")
        .arguments(["-c".to_owned(), script])
        .after("printf 'kr-after-fzf\\n'; read -r _")
}

async fn chosen(session: &Session, path: &Path) -> String {
    session
        .wait_for("the shell after fzf", |screen| screen.shows("kr-after-fzf"))
        .await;
    std::fs::read_to_string(path).expect("fzf's choice")
}

async fn no_query_reached_the_terminal(session: &Session) {
    let reached = queries::find(&session.received().await);
    assert!(
        reached.is_empty(),
        "a query reached the attached terminal: {}",
        reached
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// KR-ACC-004, KR-REQ-27.04: fzf lists its items, CJK among them, on the alternate screen; a typed
/// query narrows the list, the choice it prints is the item left, and the shell's screen comes
/// back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_typed_query_narrows_the_list_and_chooses_the_item_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("chosen");
    let mut session = Session::start(launch(&path)).await;
    let screen = session
        .wait_for("fzf's list", |screen| {
            screen.shows("4/4") && screen.shows("中文テキスト")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    session.type_bytes(b"bet");
    session
        .wait_for("the narrowed list", |screen| screen.shows("1/4"))
        .await;
    session.type_bytes(b"\r");
    assert_eq!(chosen(&session, &path).await, "beta\n");
    let screen = session.snapshot().await;
    assert_eq!(screen.buffer, ProjectedBuffer::Primary, "{screen}");
    assert!(
        !screen.shows("中文テキスト"),
        "fzf's list stayed on the primary screen:\n{screen}"
    );
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: fzf turns bracketed paste on, and a pasted CJK query narrows the list
/// to the CJK item, which is the choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_pasted_cjk_query_chooses_the_cjk_item() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("chosen");
    let mut session = Session::start(launch(&path)).await;
    let screen = session
        .wait_for("fzf's list", |screen| screen.shows("4/4"))
        .await;
    assert!(
        screen.mode(2004),
        "fzf turned bracketed paste on: {}",
        screen.modes
    );
    session.paste("テキ");
    session
        .wait_for("the narrowed list", |screen| screen.shows("1/4"))
        .await;
    session.type_bytes(b"\r");
    assert_eq!(chosen(&session, &path).await, "中文テキスト\n");
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: fzf turns mouse reporting on, and a click on an item moves its
/// pointer there, so the item clicked, not the first, is the choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_click_on_an_item_makes_it_the_choice() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("chosen");
    let mut session = Session::start(launch(&path)).await;
    let screen = session
        .wait_for("fzf's list", |screen| {
            screen.shows("4/4") && screen.shows("gamma")
        })
        .await;
    assert!(
        screen.mode(1000) || screen.mode(1002),
        "fzf turned mouse reporting on: {}",
        screen.modes
    );
    let row = screen.row_of("gamma").expect("the item");
    let column = screen.line(row).find("gamma").expect("the item's text");
    session.click(
        &screen,
        u16::try_from(column + 1).expect("a column"),
        u16::try_from(row + 1).expect("a row"),
    );
    // The pointer starts on the first item, alpha; fzf marks it with colour alone, so the choice
    // it prints is what says where the click put it.
    session.type_bytes(b"\r");
    assert_eq!(chosen(&session, &path).await, "gamma\n");
    no_query_reached_the_terminal(&session).await;
}
