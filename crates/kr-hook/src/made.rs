//! A clock and a wait that a case moves, for the cases that hold how long a run waits at the most.
//!
//! Time passes on a [`Made`] clock only when a case moves it or when a wait of its own runs out, so
//! what a run waited is read off the clock by a condition and never measured. A wait that runs out
//! moves the clock to the moment it was asked to wait until; one that is given a message waits for
//! the message and moves nothing. The one real wait here is the receive in `Wait::Message`, which
//! ends when the message comes, or at a guard when none does.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::Done;

/// How long a wait that is given a message waits for it, which only ends a case whose message never
/// comes. The wait never takes this long when the run is right.
const MESSAGE_GUARD: Duration = Duration::from_secs(30);

/// What one wait of a run is, in the order the run makes them.
#[derive(Clone, Copy)]
pub(crate) enum Wait {
    /// The thread waited for sends: the wait takes its message, and no time passes.
    Message,
    /// The thread waited for never sends: the clock moves to the moment waited until, and the wait
    /// times out. A wait beyond the ones a case lists runs out.
    RunsOut,
}

/// A clock that stands where it is until it is moved.
pub(crate) struct Made {
    start: Instant,
    passed: Cell<Duration>,
    waits: RefCell<VecDeque<Wait>>,
    asked: RefCell<Vec<Duration>>,
}

impl Made {
    /// A clock at its start, whose waits are the given ones, in the order a run makes them.
    pub(crate) fn new(waits: impl IntoIterator<Item = Wait>) -> Self {
        Self {
            start: Instant::now(),
            passed: Cell::new(Duration::ZERO),
            waits: RefCell::new(waits.into_iter().collect()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// Where the clock began, which is when a case starts its run.
    pub(crate) fn start(&self) -> Instant {
        self.start
    }

    /// The clock's reading.
    pub(crate) fn now(&self) -> Instant {
        self.start + self.passed.get()
    }

    /// How far the clock has moved from its start.
    pub(crate) fn passed(&self) -> Duration {
        self.passed.get()
    }

    /// Moves the clock on: time that something other than a wait takes.
    pub(crate) fn pass(&self, time: Duration) {
        self.passed.set(self.passed.get() + time);
    }

    /// Every moment a run asked a wait to wait until, as how long after the start, in the order it
    /// asked.
    pub(crate) fn asked(&self) -> Vec<Duration> {
        self.asked.borrow().clone()
    }

    /// The wait a run is given: the next one of the clock's list, asked to wait until `by`.
    pub(crate) fn wait(
        &self,
        channel: &Receiver<Done>,
        by: Instant,
    ) -> Result<Done, RecvTimeoutError> {
        let until = by.saturating_duration_since(self.start);
        self.asked.borrow_mut().push(until);
        match self.waits.borrow_mut().pop_front().unwrap_or(Wait::RunsOut) {
            Wait::Message => channel.recv_timeout(MESSAGE_GUARD),
            Wait::RunsOut => {
                self.passed.set(self.passed.get().max(until));
                Err(RecvTimeoutError::Timeout)
            }
        }
    }
}

/// What a clock that a case moves cannot see: a wait that does not go through the wait a run is
/// given. These cases hold, by a scan of the words that block and of two names, that the code a
/// hook run executes waits only through that wait; that the wiring that gives a run the system's
/// clock, the system's wait and the claim is held by its text; and that the claim's clock and pause
/// are held by their text. The scan checks words, and its case names its limits.
#[cfg(test)]
mod waits_only_through_the_seam {
    /// What blocks a thread for a time or until another thread acts, as it is written.
    const BLOCKING: [&str; 11] = [
        "recv_timeout",
        "recv_deadline",
        "sleep",
        "park_timeout",
        "wait_timeout",
        "thread::park",
        ".join()",
        ".recv()",
        ".wait(",
        "wait_while",
        "block_on",
    ];

    /// The name of the system's wait, which a run is given and which only the entries that give it
    /// may name.
    const SYSTEM_WAIT: &str = "wait_by";

    /// The name of the claim's entry, which a run is given and which only the entries that give it
    /// may name: a second call of it is a second wait of up to the claim's time.
    const CLAIM_ENTRY: &str = "claim_answer";

    /// The functions of a file that may hold what the scan looks for.
    #[derive(Clone, Copy, Default)]
    struct Allowed<'a> {
        /// A blocking word.
        blocking: &'a [&'a str],
        /// The name of the system's wait.
        system_wait: &'a [&'a str],
        /// The name of the claim's entry.
        claim: &'a [&'a str],
    }

    /// `line` without a `//` comment at its end. A `//` inside a string literal is not a comment
    /// (a character literal or a raw string that holds a quote is not told apart).
    fn without_comment(line: &str) -> &str {
        let bytes = line.as_bytes();
        let mut in_string = false;
        let mut at = 0;
        while at < bytes.len() {
            match bytes[at] {
                b'\\' if in_string => at += 1,
                b'"' => in_string = !in_string,
                b'/' if !in_string && bytes.get(at + 1) == Some(&b'/') => return &line[..at],
                _ => {}
            }
            at += 1;
        }
        line
    }

    /// Every line of `source`, up to its test module, as the function it is in (empty outside one)
    /// and its code, which is the line without its comment.
    fn code_lines(source: &str) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        // The function a line is in, and the line that closes it.
        let mut within: Option<(String, String)> = None;
        let mut previous = "";
        for line in source.lines() {
            if line.trim_end() == "mod tests {" && previous.trim() == "#[cfg(test)]" {
                break;
            }
            previous = line;
            let mut opened_here = false;
            if within.is_none() {
                let indent = &line[..line.len() - line.trim_start().len()];
                let item = line.trim_start();
                let item = item.strip_prefix("pub(crate) ").unwrap_or(item);
                let item = item.strip_prefix("pub ").unwrap_or(item);
                if let Some(rest) = item.strip_prefix("fn ") {
                    let name = rest.split(['(', '<']).next().unwrap_or(rest);
                    within = Some((name.to_owned(), format!("{indent}}}")));
                    opened_here = true;
                }
            }
            let name = within.as_ref().map_or("", |(name, _)| name.as_str());
            lines.push((name.to_owned(), without_comment(line).to_owned()));
            // A function that opens and closes on its own line is through at once.
            let one_line = opened_here && line.trim_end().ends_with('}');
            if one_line
                || within
                    .as_ref()
                    .is_some_and(|(_, closing)| line.trim_end() == closing)
            {
                within = None;
            }
        }
        lines
    }

    /// The lines of `source`, up to its test module, that hold a blocking word outside a comment,
    /// or name the system's wait or the claim's entry, as the function they are in and the line.
    /// Each is left out in the functions that `allowed` names for it.
    fn blocking_waits(source: &str, allowed: Allowed) -> Vec<String> {
        code_lines(source)
            .into_iter()
            .filter(|(name, code)| {
                let name = name.as_str();
                let blocks = !allowed.blocking.contains(&name)
                    && BLOCKING.iter().any(|word| code.contains(word));
                let system = !allowed.system_wait.contains(&name) && code.contains(SYSTEM_WAIT);
                let claim = !allowed.claim.contains(&name) && code.contains(CLAIM_ENTRY);
                blocks || system || claim
            })
            .map(|(name, code)| format!("in `{name}`: {}", code.trim()))
            .collect()
    }

    /// `text` without white space, and without a comma before a closing parenthesis, so that the
    /// way a formatter breaks a line does not matter.
    fn squashed(text: &str) -> String {
        text.split_whitespace()
            .collect::<String>()
            .replace(",)", ")")
    }

    /// The code of the function `name` in `source` between its signature and its closing line,
    /// squashed.
    fn body_of(source: &str, name: &str) -> String {
        let code: Vec<String> = code_lines(source)
            .into_iter()
            .filter(|(within, _)| within == name)
            .map(|(_, code)| code.trim().to_owned())
            .collect();
        // The signature ends at the first line that opens the body; the last line closes it.
        let opens = code
            .iter()
            .position(|line| line.ends_with('{'))
            .map_or(0, |at| at + 1);
        let closes = code.len().saturating_sub(1);
        squashed(&code[opens.min(closes)..closes].concat())
    }

    /// Whether the code of the function `name` in `source` holds `call`, as it is written.
    fn holds(source: &str, name: &str, call: &str) -> bool {
        body_of(source, name).contains(&squashed(call))
    }

    /// A hook run waits only through the wait it is given, which is what a clock that a case
    /// moves holds: there is no other wait in what the run executes that the scan can see, so no
    /// case passes with such a wait it cannot see.
    /// - `observe` is the run's work, which the run abandons at its deadline.
    /// - `wait_by` is the system's wait that `run` passes, and `start` and `finish` are the report
    ///   writer's own thread and its closing wait, which the channel server runs and a hook run
    ///   never does.
    /// - The system's wait is named only in its definition, in `run` and in `report_by`; the claim's
    ///   entry only in `run`, in the wrapper that `hook.rs` gives it and in its definition in
    ///   `helper.rs`. A second call of either elsewhere is found.
    /// - What gives a run the system's clock, the system's wait and the claim is held by its text:
    ///   `run`'s call of `run_with`, `report_by`'s call of `report_with`, the wrapper's one
    ///   statement, `wait_by`'s one line, and `claim_answer`'s one statement in `helper.rs`, which
    ///   passes the system's clock and the pause of a millisecond to `claim`, whose waits are then
    ///   given by its caller.
    ///
    /// The scan finds words and has limits:
    /// - A word in a string literal is found; a character literal or a raw string that holds a
    ///   quote, a string that spans lines, and a `/* */` comment are not told apart.
    /// - A primitive that is not in the list is not found: a `select!`, blocking input or output, a
    ///   spin on the clock, a path call such as `Receiver::recv(&rx)`, a lock that another thread
    ///   holds (`std::io::stderr().lock()` after the diagnostic, while the stalled writer holds
    ///   it).
    /// - A call of a function that waits inside it is not followed: `report_by` reaches `wait_by`,
    ///   and `kr_ipc::install::this_process()` can wait.
    /// - A name holds what a function contains, not where it runs: `observe` is safe only while
    ///   the work that `run` gives `run_with` is its one caller, and `start` and `finish` allow
    ///   every function of that name in `lib.rs`.
    #[test]
    fn a_hook_run_waits_only_through_the_wait_it_is_given() {
        let (hook, lib, helper) = (
            include_str!("hook.rs"),
            include_str!("lib.rs"),
            include_str!("helper.rs"),
        );
        for (file, source, allowed) in [
            (
                "hook.rs",
                hook,
                Allowed {
                    blocking: &["observe"],
                    system_wait: &["run"],
                    claim: &["run", "claim_answer"],
                },
            ),
            (
                "lib.rs",
                lib,
                Allowed {
                    blocking: &["wait_by", "start", "finish"],
                    system_wait: &["wait_by", "report_by"],
                    claim: &[],
                },
            ),
            (
                "helper.rs",
                helper,
                Allowed {
                    blocking: &["claim_answer"],
                    system_wait: &[],
                    claim: &["claim_answer"],
                },
            ),
        ] {
            let found = blocking_waits(source, allowed);
            assert!(
                found.is_empty(),
                "{file} waits other than through the wait a run is given: {found:#?}"
            );
        }
        assert!(
            holds(
                hook,
                "run",
                "run_with(started, move |started| observe(application, started), claim_answer, \
                 answer, |bytes| { use std::io::Write as _; \
                 let _ = std::io::stderr().lock().write_all(bytes); }, \
                 std::time::Instant::now, crate::wait_by,);"
            ),
            "what gives a run its work, its claim, its answer, its clock and its wait is not what it was"
        );
        assert_eq!(
            body_of(hook, "claim_answer"),
            squashed("#[cfg(unix)] crate::helper::claim_answer();"),
            "the claim's wrapper is not what it was"
        );
        assert_eq!(
            body_of(lib, "report_by"),
            squashed(
                "report_with(line, by, |bytes| { use std::io::Write as _; \
                 let _ = std::io::stderr().lock().write_all(bytes); }, wait_by,);"
            ),
            "what gives a report the system's wait is not what it was"
        );
        assert_eq!(
            body_of(lib, "wait_by"),
            squashed(
                "channel.recv_timeout(by.saturating_duration_since(std::time::Instant::now()))"
            ),
            "the system's wait is not what it was"
        );
        assert_eq!(
            body_of(helper, "claim_answer"),
            squashed(
                "claim(&ANSWERED, CLAIM_WAIT, Instant::now, || { \
                 std::thread::sleep(Duration::from_millis(1)); });"
            ),
            "the claim's clock and pause are not what they were"
        );
    }

    /// The scan finds each word it looks for, in any function that is not allowed, and passes a
    /// comment, an allowed function by its name, and a test module; it finds the system's wait and
    /// the claim's entry outside the functions that may name them, and it holds a function's text.
    #[test]
    fn the_scan_finds_every_blocking_wait_and_passes_a_comment() {
        let none = Allowed::default();
        // Joining a path takes an argument and waits for nothing; joining a thread does not.
        let path = "fn hand_over() {\n    let at = dir.join(\"bin\");\n}\n";
        assert!(blocking_waits(path, none).is_empty(), "a path is joined");
        // A `//` inside a string is not a comment, so the word after it is found.
        let string = "fn run_with() {\n    let at = \"a//b\"; outcome.recv_timeout(d);\n}\n";
        assert_eq!(blocking_waits(string, none).len(), 1, "after a string");
        for word in BLOCKING {
            let wait = format!("fn run_with() {{\n    let _ = outcome {word} 5;\n}}\n");
            assert_eq!(blocking_waits(&wait, none).len(), 1, "`{word}` is found");
            let nested =
                format!("impl Run {{\n    fn finish(&self) {{\n        {word}\n    }}\n}}\n");
            assert_eq!(
                blocking_waits(&nested, none).len(),
                1,
                "`{word}` in a method is found"
            );
            let finish = Allowed {
                blocking: &["finish"],
                ..none
            };
            assert_eq!(
                blocking_waits(&nested, finish),
                Vec::<String>::new(),
                "`{word}` in an allowed function passes"
            );
            let other =
                format!("fn run_with() {{\n    {word}\n}}\nfn wait_by() {{\n    {word}\n}}\n");
            let wait_by = Allowed {
                blocking: &["wait_by"],
                system_wait: &["wait_by"],
                ..none
            };
            assert_eq!(
                blocking_waits(&other, wait_by),
                ["in `run_with`: ".to_owned() + word],
                "only the function that is not allowed is found"
            );
            for comment in [
                format!("    // {word}"),
                format!("    /// {word}"),
                format!("    x(); // {word}"),
            ] {
                let source = format!("fn run_with() {{\n{comment}\n}}\n");
                assert!(
                    blocking_waits(&source, none).is_empty(),
                    "`{comment}` is a comment"
                );
            }
            let after_a_short_one = format!("fn quick() {{}}\nfn wait_by() {{\n    {word}\n}}\n");
            assert!(
                blocking_waits(&after_a_short_one, wait_by).is_empty(),
                "a function on one line does not hold the next one's name"
            );
            let tests = format!("fn run_with() {{}}\n#[cfg(test)]\nmod tests {{\n    {word}\n}}\n");
            assert!(
                blocking_waits(&tests, none).is_empty(),
                "`{word}` in the test module passes"
            );
            let item = format!("static WAIT: u64 = {word};\n");
            assert_eq!(
                blocking_waits(&item, none).len(),
                1,
                "`{word}` outside a function is found"
            );
        }
        // The system's wait and the claim's entry are named only where they are allowed.
        let call =
            "fn write_by() {\n    let _ = wait_by(&done, by);\n}\nfn run() {\n    wait_by,\n}\n";
        let entries = Allowed {
            system_wait: &["run"],
            claim: &["run"],
            ..none
        };
        assert_eq!(
            blocking_waits(call, entries),
            ["in `write_by`: let _ = wait_by(&done, by);"],
            "a call of the system's wait outside the entries is found"
        );
        let twice = "fn run_with() {\n    claim();\n    claim_answer();\n}\nfn run() {\n    claim_answer,\n}\n";
        assert_eq!(
            blocking_waits(twice, entries),
            ["in `run_with`: claim_answer();"],
            "a second call of the claim's entry is found"
        );
        assert!(
            blocking_waits("fn run() {\n    // wait_by claim_answer\n}\n", none).is_empty(),
            "a comment names them"
        );
        // A function's text is held however a formatter breaks its lines, and a change shows.
        let wait = "pub(crate) fn wait_by(\n    c: &C,\n) -> R {\n    c.recv_timeout(by)\n}\n";
        assert_eq!(body_of(wait, "wait_by"), "c.recv_timeout(by)");
        let longer = wait.replace("(by)", "(by + extra)");
        assert_ne!(body_of(&longer, "wait_by"), "c.recv_timeout(by)");
        let broken = "fn claim_answer() {\n    claim(\n        a,\n        || {\n            go();\n        },\n    );\n}\n";
        assert_eq!(body_of(broken, "claim_answer"), "claim(a,||{go();});");
        // What gives a run its wait is held: the wait itself, and a clock with time added, are not
        // the text that is held.
        let wiring = "fn run() {\n    run_with(\n        started,\n        std::time::Instant::now,\n        crate::wait_by,\n    );\n}\n";
        let held = "run_with(started, std::time::Instant::now, crate::wait_by,);";
        assert!(holds(wiring, "run", held), "the text that is held");
        let later_wait = wiring.replace(
            "crate::wait_by,",
            "|c, by| crate::wait_by(c, by + std::time::Duration::from_millis(50)),",
        );
        assert!(!holds(&later_wait, "run", held), "a wait with time added");
        let later_clock = wiring.replace(
            "std::time::Instant::now,",
            "|| std::time::Instant::now() + std::time::Duration::from_millis(300),",
        );
        assert!(!holds(&later_clock, "run", held), "a clock with time added");
    }
}
