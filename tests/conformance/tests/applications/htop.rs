//! htop: its screen, a click on its function bar, and the way out.

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Session, application};
use crate::queries;

fn launch() -> Launch {
    let htop = application("htop");
    // A long delay between refreshes, so what a case reads is not being redrawn under it.
    Launch::new(&htop.executable)
        .arguments(["--delay=50", "--no-color"])
        .after("printf 'kr-after-htop\\n'; read -r _")
}

fn no_query_reached_the_terminal(session: &Session) {
    let reached = queries::find(&session.received());
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

/// KR-ACC-004, KR-REQ-27.04: htop draws its meters, its process table and its function bar on the
/// alternate screen, and its quit key puts back the shell's screen with nothing of htop's on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn htop_draws_its_screen_on_the_alternate_screen_and_leaves_it() {
    let mut session = Session::start(launch()).await;
    let screen = session
        .wait_for("htop's screen", |screen| {
            screen.shows("F10Quit") && screen.shows("PID")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    let bar = screen.row_of("F10Quit").expect("the function bar");
    assert_eq!(
        bar,
        screen.rows.len() - 1,
        "the function bar is the last row:\n{screen}"
    );
    assert!(screen.line(bar).starts_with("F1Help"), "{screen}");
    session.type_bytes(b"q");
    let screen = session
        .wait_for("the shell after htop", |screen| {
            screen.shows("kr-after-htop")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Primary, "{screen}");
    assert!(
        !screen.shows("F10Quit"),
        "htop's screen stayed on the primary screen:\n{screen}"
    );
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: htop turns mouse reporting on, and a click on the Quit label of its
/// function bar ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_click_on_htops_quit_label_ends_it() {
    let mut session = Session::start(launch()).await;
    let screen = session
        .wait_for("htop's screen", |screen| screen.shows("F10Quit"))
        .await;
    assert!(
        screen.mode(1000) || screen.mode(1002),
        "htop turned mouse reporting on: {}",
        screen.modes
    );
    let row = screen.row_of("F10Quit").expect("the function bar");
    let column = screen.line(row).find("F10Quit").expect("the label") + 3;
    session.click(
        &screen,
        u16::try_from(column + 1).expect("a column"),
        u16::try_from(row + 1).expect("a row"),
    );
    let screen = session
        .wait_for("the shell after htop", |screen| {
            screen.shows("kr-after-htop")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Primary, "{screen}");
    no_query_reached_the_terminal(&session);
}
