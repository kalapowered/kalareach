//! lazygit: its panels over a repository of the case's own, a click on a panel, and the way out.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Session, application};
use crate::queries;

/// A repository with one commit, and lazygit's configuration: no update check, no start-up popup.
fn prepare(directory: &Path) -> (PathBuf, PathBuf) {
    let repository = directory.join("kr-repository");
    std::fs::create_dir(&repository).expect("a repository directory");
    let git = |arguments: &[&str]| {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(&repository)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("git runs");
        assert!(status.success(), "git {arguments:?}");
    };
    git(&["init", "-q", "-b", "main"]);
    std::fs::write(repository.join("notes.txt"), "a line\n").expect("a file");
    git(&["add", "notes.txt"]);
    git(&[
        "-c",
        "user.name=KalaReach",
        "-c",
        "user.email=conformance@example.invalid",
        "commit",
        "-q",
        "-m",
        "kr-first",
    ]);
    let configuration = directory.join("lazygit");
    std::fs::create_dir(&configuration).expect("a configuration directory");
    std::fs::write(
        configuration.join("config.yml"),
        "update:\n  method: never\ndisableStartupPopups: true\ngui:\n  showRandomTip: false\n",
    )
    .expect("writes the configuration");
    (repository, configuration)
}

fn launch(repository: &Path, configuration: &Path) -> Launch {
    let lazygit = application("lazygit");
    Launch::new(&lazygit.executable)
        .variable("GIT_CONFIG_GLOBAL", "/dev/null")
        .variable("GIT_CONFIG_NOSYSTEM", "1")
        .arguments([
            "--use-config-dir".to_owned(),
            configuration.to_string_lossy().into_owned(),
        ])
        .arguments(["-p".to_owned(), repository.to_string_lossy().into_owned()])
        .after("printf 'kr-after-lazygit\\n'; read -r _")
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

/// KR-ACC-004, KR-REQ-27.04: lazygit draws its panels over the repository on the alternate screen,
/// and its quit key puts back the shell's screen with nothing of lazygit's on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn lazygit_draws_its_panels_on_the_alternate_screen_and_leaves_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let (repository, configuration) = prepare(directory.path());
    let mut session = Session::start(launch(&repository, &configuration)).await;
    let screen = session
        .wait_for("lazygit's panels", |screen| {
            screen.shows("kr-repository") && screen.shows("kr-first")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    for panel in ["Status", "Files", "Commits", "Stash"] {
        assert!(screen.shows(panel), "the {panel} panel:\n{screen}");
    }
    session.type_bytes(b"q");
    let screen = session
        .wait_for("the shell after lazygit", |screen| {
            screen.shows("kr-after-lazygit")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Primary, "{screen}");
    assert!(
        !screen.shows("kr-first"),
        "lazygit's screen stayed on the primary screen:\n{screen}"
    );
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: lazygit turns mouse reporting on, and a click on the commit in its
/// Commits panel shows that commit, its author included, in its main view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_click_on_a_commit_shows_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let (repository, configuration) = prepare(directory.path());
    let mut session = Session::start(launch(&repository, &configuration)).await;
    let screen = session
        .wait_for("lazygit's panels", |screen| screen.shows("kr-first"))
        .await;
    assert!(
        !screen.shows("conformance@example.invalid"),
        "the commit is shown before the click:\n{screen}"
    );
    assert!(
        screen.mode(1000) || screen.mode(1002) || screen.mode(1003),
        "lazygit turned mouse reporting on: {}",
        screen.modes
    );
    let row = screen.row_of("kr-first").expect("the commit");
    let line = screen.line(row);
    let column = line.find("kr-first").expect("the commit's subject");
    let column = line[..column].chars().count() + 2;
    session.click(
        &screen,
        u16::try_from(column + 1).expect("a column"),
        u16::try_from(row + 1).expect("a row"),
    );
    let screen = session
        .wait_for("the commit in the main view", |screen| {
            screen.shows("conformance@example.invalid")
        })
        .await;
    assert!(screen.shows("conformance@example.invalid"), "{screen}");
    no_query_reached_the_terminal(&session);
}
