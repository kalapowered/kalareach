//! The probe's own behaviour, against terminals that are scripted rather than physical.
//!
//! A physical terminal is what the probe is for, and its results are the records under
//! `fixtures/terminal/physical`. What these tests check is the harness: that a terminal that is the
//! canonical grid agrees on every step, that one that differs in one rule is found on exactly the
//! steps of that rule, and that one that says nothing is not counted as one that disagrees.

use std::collections::BTreeSet;
use std::io;

use kr_term::budget::GridSize;
use kr_term::lane::LaneGate;
use kr_term::{Engine, EngineConfig};
use kr_term_probe::corpus::{self, Step};
use kr_term_probe::replies::{self, Position};
use kr_term_probe::report::{Report, Summary};
use kr_term_probe::run::{self, Terminal};

/// A terminal that is one long-lived canonical grid, which answers as a session's broker does.
struct Simulated {
    engine: Engine,
    now_ms: u64,
    /// Rewrites what the terminal is sent before it sees it, to give it a fault.
    fault: fn(&[u8]) -> Vec<u8>,
}

impl Simulated {
    fn new(cols: u32, rows: u32, fault: fn(&[u8]) -> Vec<u8>) -> Self {
        Self {
            engine: Engine::new(EngineConfig {
                size: GridSize::new(cols, rows),
                ..EngineConfig::DEFAULT
            })
            .expect("an engine"),
            now_ms: 0,
            fault,
        }
    }
}

impl Terminal for Simulated {
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        // A real terminal's answers are not rate limited by the clock the engine's broker keeps, so
        // time moves on for every write.
        self.now_ms += 1000;
        self.engine.feed(&(self.fault)(bytes), self.now_ms);
        self.engine.quiesce(self.now_ms);
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let replies = self
            .engine
            .lane_mut()
            .drain(LaneGate::default(), 1 << 20, self.now_ms);
        let bytes: Vec<u8> = replies
            .iter()
            .flat_map(|reply| reply.bytes().to_vec())
            .collect();
        Ok(replies::primary_attributes(&bytes).map(|_| bytes))
    }
}

/// A terminal that never answers anything.
struct Silent;

impl Terminal for Silent {
    fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn faithful(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// A terminal that draws every wide character in one cell.
fn narrow(bytes: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|scalar| match scalar {
            '\u{3042}' | '\u{3044}' | '\u{ff21}' | '\u{ff22}' | '\u{1f600}' => 'x',
            other => other,
        })
        .collect::<String>()
        .into_bytes()
}

fn ids(outcomes: &[run::Outcome], keep: impl Fn(&run::Outcome) -> bool) -> BTreeSet<String> {
    outcomes
        .iter()
        .filter(|outcome| keep(outcome))
        .map(|outcome| outcome.id.clone())
        .collect()
}

#[test]
fn the_corpus_names_every_step_once_and_fits_every_window() {
    for (cols, rows) in [(40, 12), (80, 24), (120, 40), (200, 60)] {
        let steps = corpus::steps(cols, rows);
        assert!(steps.len() > 100, "a corpus of real size: {}", steps.len());
        let names: BTreeSet<&str> = steps.iter().map(|step| step.id.as_str()).collect();
        assert_eq!(names.len(), steps.len(), "every step has its own name");
        for step in &steps {
            assert!(!step.bytes.is_empty(), "{} writes something", step.id);
            assert!(
                step.id.starts_with(step.group),
                "{} is in its group",
                step.id
            );
        }
    }
    // The steps that depend on the window follow it.
    let small = corpus::steps(40, 12);
    let large = corpus::steps(80, 24);
    let fill = |steps: &[Step]| {
        steps
            .iter()
            .find(|step| step.id == "autowrap.fill-a-row-leaves-the-wrap-pending")
            .map(|step| step.bytes.len())
    };
    assert_eq!(fill(&small), Some(40));
    assert_eq!(fill(&large), Some(80));
}

/// Control: a terminal that is the canonical grid agrees on every step, so a difference found on a
/// physical terminal is the terminal's and not the harness's.
#[test]
fn a_terminal_that_is_the_canonical_grid_agrees_on_every_step() {
    let (cols, rows) = (80, 24);
    let mut terminal = Simulated::new(cols, rows, faithful);
    let identity = run::identify(&mut terminal).expect("identifies");
    assert!(
        identity.primary_attributes.is_some(),
        "it answers the barrier"
    );
    let steps = corpus::steps(cols, rows);
    let measured = run::measure_all(&mut terminal, &steps, cols, rows).expect("measures");
    assert_eq!(measured.stopped, None);
    let outcomes = measured.outcomes;
    let differing = ids(&outcomes, |outcome| !outcome.agrees);
    assert!(
        differing.is_empty(),
        "the canonical grid disagrees with itself on {differing:?}"
    );
    let summary = Summary::of(&outcomes);
    assert_eq!(
        (summary.agree, summary.differ, summary.unanswered),
        (steps.len(), 0, 0)
    );
}

/// A terminal with one fault disagrees on the steps that fault reaches. The steps named as
/// unaffected are ones no wide character is in, so a difference there would be the harness's.
#[test]
fn a_terminal_that_draws_wide_characters_narrow_is_found_on_the_wide_steps() {
    let (cols, rows) = (80, 24);
    let mut terminal = Simulated::new(cols, rows, narrow);
    let steps = corpus::steps(cols, rows);
    let outcomes = run::measure_all(&mut terminal, &steps, cols, rows)
        .expect("measures")
        .outcomes;
    let differing = ids(&outcomes, |outcome| !outcome.agrees);
    for expected in [
        "wide.two-cjk-characters",
        "wide.mixed-with-ascii",
        "wide.fullwidth-latin",
        "emoji.one-emoji",
    ] {
        assert!(
            differing.contains(expected),
            "{expected} is found: {differing:?}"
        );
    }
    for unaffected in [
        "addressing.absolute",
        "autowrap.fill-a-row-leaves-the-wrap-pending",
        "tabs.default-stop",
        "margins.reverse-index-at-the-top-margin",
        "alternate-screen.enter-and-leave-restores-the-cursor",
    ] {
        assert!(
            !differing.contains(unaffected),
            "{unaffected} is not: {differing:?}"
        );
    }
}

/// A terminal that says nothing stops the run at its first step: the reply that ends each read
/// never came, so there is no telling whether it is still on its way.
#[test]
fn a_terminal_that_says_nothing_stops_the_run_at_the_first_step() {
    let steps = corpus::steps(80, 24);
    let measured = run::measure_all(&mut Silent, &steps, 80, 24).expect("measures");
    assert_eq!(
        measured.outcomes.len(),
        1,
        "the run stopped at the first step"
    );
    assert!(measured.stopped.is_some());
    let summary = Summary::of(&measured.outcomes);
    assert_eq!(
        (summary.agree, summary.differ, summary.unanswered),
        (0, 0, 1)
    );
    assert!(
        measured
            .outcomes
            .iter()
            .all(|outcome| outcome.terminal.is_none() && !outcome.barrier)
    );
    assert_eq!(
        run::identify(&mut Silent).expect("identifies"),
        run::Identity::default()
    );
}

/// A terminal whose reply to the barrier comes one step late. The run must not take that late
/// reply for the next step's answer, so it stops at the step whose barrier is missing and the
/// records show no step answered with another step's position.
struct Late {
    inner: Simulated,
    /// The read (from zero) at which the barrier is held back and delivered with the next one.
    hold_at: usize,
    reads: usize,
    held: Vec<u8>,
}

impl Terminal for Late {
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.send(bytes)
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let bytes = self.inner.receive()?;
        self.reads += 1;
        if self.reads == self.hold_at + 1 {
            // This read times out; its bytes arrive with the next read.
            self.held = bytes.unwrap_or_default();
            return Ok(None);
        }
        Ok(bytes.map(|bytes| [std::mem::take(&mut self.held), bytes].concat()))
    }
}

#[test]
fn a_late_reply_is_not_taken_for_the_next_steps_answer() {
    let (cols, rows) = (80, 24);
    let steps = corpus::steps(cols, rows);
    let mut late = Late {
        inner: Simulated::new(cols, rows, faithful),
        hold_at: 5,
        reads: 0,
        held: Vec::new(),
    };
    let measured = run::measure_all(&mut late, &steps, cols, rows).expect("measures");
    assert_eq!(
        measured.outcomes.len(),
        6,
        "stopped at the step that missed its reply"
    );
    assert!(
        measured
            .stopped
            .as_deref()
            .is_some_and(|why| why.contains(&steps[5].id))
    );
    assert!(measured.outcomes[5].terminal.is_none());
    assert!(
        measured.outcomes[..5].iter().all(|outcome| outcome.agrees),
        "the steps before it are the ones that were answered in time"
    );
}

/// A terminal that sends the barrier and no cursor report is recorded as silent on that step, and
/// the run goes on, because the barrier says nothing is still on its way.
struct NoCursorReport(Simulated);

impl Terminal for NoCursorReport {
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        // The cursor position report is never asked, so the terminal never answers it.
        let mut kept = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at..].starts_with(b"\x1b[6n") {
                at += 4;
            } else {
                kept.push(bytes[at]);
                at += 1;
            }
        }
        self.0.send(&kept)
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.0.receive()
    }
}

#[test]
fn a_barrier_with_no_cursor_report_is_an_unanswered_step_and_the_run_goes_on() {
    let (cols, rows) = (80, 24);
    let steps = corpus::steps(cols, rows);
    let mut terminal = NoCursorReport(Simulated::new(cols, rows, faithful));
    let measured = run::measure_all(&mut terminal, &steps, cols, rows).expect("measures");
    assert_eq!(measured.stopped, None);
    assert_eq!(measured.outcomes.len(), steps.len());
    let summary = Summary::of(&measured.outcomes);
    assert_eq!(
        (summary.agree, summary.differ, summary.unanswered),
        (0, 0, steps.len())
    );
    assert!(measured.outcomes.iter().all(|outcome| outcome.barrier));
}

/// The record carries the launcher's facts, the terminal's own answers and one outcome per step.
#[test]
fn the_record_carries_what_was_measured() {
    let (cols, rows) = (80, 24);
    let mut terminal = Simulated::new(cols, rows, faithful);
    let identity = run::identify(&mut terminal).expect("identifies");
    let steps = corpus::steps(cols, rows);
    let measured = run::measure_all(&mut terminal, &steps, cols, rows).expect("measures");
    let report = Report::new(
        serde_json::json!({ "application": "a scripted terminal" }),
        identity,
        (cols, rows),
        measured,
    );
    let text = serde_json::to_string(&report).expect("serialises");
    let value: serde_json::Value = serde_json::from_str(&text).expect("reads back");
    assert_eq!(value["probe"], "kr-term-probe/1");
    assert_eq!(value["launcher"]["application"], "a scripted terminal");
    assert_eq!(value["window"], serde_json::json!([80, 24]));
    assert_eq!(value["steps"].as_array().map(Vec::len), Some(steps.len()));
    assert_eq!(value["summary"]["agree"], steps.len());
    assert_eq!(
        value["canonical_library"],
        kr_term::unicode::LIBRARY.revision
    );
}

#[test]
fn replies_are_found_among_bytes_nobody_asked_for() {
    let noisy = b"\x1b[I\x1b[12;40R\x1b[?62;22c";
    assert_eq!(
        replies::cursor_position(noisy),
        Some(Position { row: 12, col: 40 })
    );
    assert_eq!(replies::primary_attributes(noisy), Some(vec![62, 22]));
    assert_eq!(replies::cursor_position(b"\x1b[?62;22c"), None);
    assert_eq!(replies::window_size(b"\x1b[8;24;80t"), Some((24, 80)));
    assert_eq!(replies::window_size(b"\x1b[4;480;800t"), None);
    assert_eq!(
        replies::secondary_attributes(b"\x1b[>1;95;0c\x1b[?1;2c"),
        Some(vec![1, 95, 0])
    );
    assert_eq!(replies::mode_status(b"\x1b[?2027;2$y", 2027), Some(2));
    assert_eq!(replies::mode_status(b"\x1b[?2027;2$y", 7), None);
    assert_eq!(
        replies::version_text(b"\x1bP>|iTerm2 3.6.11\x1b\\\x1b[?1;2c").as_deref(),
        Some("iTerm2 3.6.11")
    );
    assert_eq!(replies::version_text(b"\x1b[?1;2c"), None);
}

/// A record is kept in a repository, so what identifies the account is taken out of the launcher's
/// facts before it is written: the programs the window descends from keep their names and lose
/// their directories, and the home directory, where one is written, becomes `~`.
#[test]
fn a_record_keeps_no_home_directory_and_no_user_name() {
    let launcher = serde_json::json!({
        "ancestors": [
            "/bin/bash",
            "-zsh",
            "/usr/bin/login",
            "/Users/jo/Library/Application Support/iTerm2/iTermServer-3.6.11",
            "C:\\Users\\jo\\AppData\\Local\\Terminal\\wt.exe"
        ],
        "bundle": "/Applications/iTerm.app",
        "environment": {
            "TERMINFO_DIRS": "/Users/jo/.terminfo:/Applications/iTerm.app/Contents/Resources/terminfo",
            "TERM": "xterm-256color"
        },
        "build": "3.7.1"
    });
    let kept = kr_term_probe::report::keep_private(launcher, Some("/Users/jo"));
    assert_eq!(
        kept["ancestors"],
        serde_json::json!(["bash", "-zsh", "login", "iTermServer-3.6.11", "wt.exe"])
    );
    assert_eq!(
        kept["environment"]["TERMINFO_DIRS"],
        "~/.terminfo:/Applications/iTerm.app/Contents/Resources/terminfo"
    );
    assert_eq!(
        kept["bundle"], "/Applications/iTerm.app",
        "an application's directory stays"
    );
    assert_eq!(kept["build"], "3.7.1");
    assert!(!kept.to_string().contains("jo"), "{kept}");

    // A launcher with nothing to take out is written as it is, and a missing home takes out nothing
    // beyond the programs' directories.
    let plain = serde_json::json!({ "application": "a scripted terminal" });
    assert_eq!(
        kr_term_probe::report::keep_private(plain.clone(), None),
        plain
    );
    assert_eq!(
        kr_term_probe::report::keep_private(serde_json::Value::Null, Some("/Users/jo")),
        serde_json::Value::Null
    );
}

/// The home directory is written as `~` only where it is a whole path or begins one, and the
/// session variables keep nothing but whether they were set.
#[test]
fn only_a_whole_home_path_becomes_a_tilde_and_session_variables_keep_no_value() {
    let launcher = serde_json::json!({
        "environment": {
            "STY": "1234.pts-0.host",
            "TMUX": "/private/tmp/tmux-501/default,4321,0",
            "TMUX_PANE": "%3",
            "TERM": "xterm-256color",
            "TERMINFO": null
        },
        "paths": [
            "/Users/jo",
            "/Users/jo/.terminfo",
            "/Users/joanne/.terminfo",
            "/opt:/Users/jo/bin:/usr/bin",
            "a/Users/jo/b",
            "/Users/jo/a /Users/jo"
        ]
    });
    let kept = kr_term_probe::report::keep_private(launcher, Some("/Users/jo"));
    assert_eq!(
        kept["paths"],
        serde_json::json!([
            "~",
            "~/.terminfo",
            "/Users/joanne/.terminfo",
            "/opt:~/bin:/usr/bin",
            "a/Users/jo/b",
            "~/a ~"
        ])
    );
    assert_eq!(kept["environment"]["STY"], "set");
    assert_eq!(kept["environment"]["TMUX"], "set");
    assert_eq!(kept["environment"]["TMUX_PANE"], "set");
    assert_eq!(kept["environment"]["TERM"], "xterm-256color");
    assert!(
        kept["environment"]["TERMINFO"].is_null(),
        "an unset variable stays unset"
    );
}
