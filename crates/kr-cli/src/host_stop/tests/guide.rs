//! The guide's passage on how `kr host stop` ends, held one claim at a time.
//!
//! Each kept text below is the exact text of a claim of the passage that stands between the two
//! marker comments of `docs/cli/README.md`. A claim is held by a property over the rows that the
//! product prints into the end table (each with doctored rows that break it), by a property over
//! the words of a row, or by a named case where no row holds it. One case shows that each kept text
//! stands in the passage exactly once and that the kept texts cover every character of it that is
//! not a space, so that a changed sentence fails that case until a person reads its property
//! again. Whether a property says what its sentence says is a question for a reader: nothing
//! here proves it.

use super::*;

/// The guide, read when the tests are built.
const GUIDE: &str = include_str!("../../../../../docs/cli/README.md");
/// The source of the lib cases and of this file, where a named case of the lib stands.
const LIB_CASES: &str = include_str!("../../../src/host_stop.rs");
/// The source of the startup suite, where a named startup case stands.
const STARTUP_CASES: &str = include_str!("../../../tests/startup.rs");
/// The comment that opens the passage in the guide.
const PASSAGE_START: &str = "<!-- the end of a stop: start -->";
/// The comment that closes the passage in the guide.
const PASSAGE_END: &str = "<!-- the end of a stop: end -->";

/// The kind of section that a line of the table stands in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Round,
    After,
    Wait,
    Before,
    First,
    Closed,
    Start,
    Holder,
    Source,
    Decided,
    Waited,
    Split,
    Other,
}

/// One line of the generated end table, with the section that it stands in.
#[derive(Clone, Debug)]
struct Row {
    kind: Kind,
    line: String,
}

impl Row {
    fn new(kind: Kind, line: &str) -> Self {
        Self {
            kind,
            line: line.to_owned(),
        }
    }

    /// The value of the reading or member that the line names, or the empty text.
    fn field(&self, key: &str) -> &str {
        self.line
            .split_whitespace()
            .find_map(|word| word.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
    }

    fn is(&self, key: &str, value: &str) -> bool {
        self.field(key) == value
    }

    /// The look of the line without the process that a look of another generation names.
    fn look(&self) -> &str {
        self.field("look").split('(').next().unwrap_or("")
    }

    /// The word after the arrow.
    fn result(&self) -> &str {
        self.line
            .split_once(" -> ")
            .and_then(|(_, right)| right.split_whitespace().next())
            .unwrap_or("")
    }

    fn exit(&self) -> i32 {
        self.field("exit").parse().unwrap_or(-1)
    }

    /// A round at the bound that the wait can make.
    fn at_the_bound(&self) -> bool {
        self.kind == Kind::Round && self.is("bound", "yes") && self.is("reachable", "yes")
    }

    /// No usable reading of the process: none was possible, or the system did not say.
    fn no_process(&self) -> bool {
        matches!(self.field("process"), "no_identity" | "unreadable")
    }
}

fn kind_of_section(head: &str) -> Kind {
    const SECTIONS: [(&str, Kind); 11] = [
        ("rounds", Kind::Round),
        ("after a request", Kind::After),
        (
            "a request that could not be made: what the wait",
            Kind::Wait,
        ),
        (
            "a request that could not be made: what is said",
            Kind::Before,
        ),
        (
            "a request that could not be made: the first look",
            Kind::First,
        ),
        ("the start of the command", Kind::Start),
        ("the process that the lock file names", Kind::Holder),
        (
            "a request that could not be made: where a failure goes",
            Kind::Source,
        ),
        (
            "a request that could not be made: what a failure",
            Kind::Decided,
        ),
        (
            "the process that the end of a stop is waited for by",
            Kind::Waited,
        ),
        ("the stop: where a refusal goes", Kind::Split),
    ];
    SECTIONS
        .iter()
        .find(|(prefix, _)| head.starts_with(prefix))
        .map_or(Kind::Other, |(_, kind)| *kind)
}

/// The lines of the table that the product prints, each with its section.
fn rows_of_the_table() -> Vec<Row> {
    let mut kind = Kind::Other;
    let mut rows = Vec::new();
    for line in the_table().lines() {
        if let Some(head) = line.strip_prefix("## ") {
            kind = kind_of_section(head);
        } else if line.starts_with("closed=yes") {
            rows.push(Row::new(Kind::Closed, line));
        } else if !line.starts_with('#') && line.contains(" -> ") {
            rows.push(Row::new(kind, line));
        }
    }
    rows
}

/// A claim that rows of the table hold: the rows it speaks of, the rows that contradict it, and
/// changes to one row that make it contradict the claim.
struct Claim {
    /// The claim as the guide has it, character for character.
    text: &'static str,
    /// The place of the text in the passage: the number of its sentence, and 1 or 2 for the first or
    /// the second part of a sentence that is kept in two parts (0 for a whole sentence).
    place: (u8, u8),
    /// What the claim speaks of, in words.
    speaks_of: &'static str,
    about: fn(&Row) -> bool,
    breaks: fn(&Row) -> bool,
    /// Each pair changes the first row that the claim speaks of and that holds the old text.
    doctored: &'static [(&'static str, &'static str)],
}

/// A claim about the words that a row says: the readings, the request, the kind of sentence and
/// the words.
struct WordsClaim {
    text: &'static str,
    /// The place of the text in the passage: the number of its sentence, and 1 or 2 for the first or
    /// the second part of a sentence that is kept in two parts (0 for a whole sentence).
    place: (u8, u8),
    speaks_of: &'static str,
    about: fn(&Round, &AfterRequest, &Request) -> bool,
    breaks: fn(&Round, &AfterRequest, &Request, &str) -> bool,
    /// Each pair changes the words of the first row that the claim speaks of and that holds the old
    /// text; an empty old text adds the new text at the end of the words.
    doctored: &'static [(&'static str, &'static str)],
}

/// Where a named case stands.
#[derive(Clone, Copy)]
enum Where {
    Lib,
    Startup,
}

/// A text that no row holds: a named case holds it, or it defines or names what other texts claim.
struct Held {
    text: &'static str,
    /// The place of the text in the passage: the number of its sentence, and 1 or 2 for the first or
    /// the second part of a sentence that is kept in two parts (0 for a whole sentence).
    place: (u8, u8),
    /// Why no row holds the text.
    why: &'static str,
    /// The cases that hold it.
    holders: &'static [(Where, &'static str)],
}

fn claims() -> Vec<Claim> {
    vec![
        Claim {
            text: r#"The command ends with one of these results, which `--json` keeps apart as `stop`: `ended` (the daemon was seen to end), `told` (the daemon took the stop and was not seen to end after 30 seconds, exit 1), `maybe_asked` (the request may have left, neither its answer nor the daemon's end was seen, and the daemon was not seen to end after 30 seconds, exit 1), `refused` (the request left and the daemon refused it) and `not_asked` (no request left)."#,
            place: (1, 0),
            speaks_of: "every row of an end after a request and before one: the `stop` member against the exit",
            about: |r| matches!(r.kind, Kind::After | Kind::Before),
            breaks: |r| {
                !matches!(
                    r.field("stop"),
                    "ended" | "told" | "maybe_asked" | "refused" | "not_asked"
                ) || (r.is("stop", "told") && r.exit() != 1)
                    || (r.is("stop", "maybe_asked") && r.exit() != 1)
            },
            doctored: &[
                (
                    "request=told -> not_ended exit=1",
                    "request=told -> not_ended exit=2",
                ),
                (
                    "request=maybe_asked -> not_ended exit=1",
                    "request=maybe_asked -> not_ended exit=2",
                ),
                ("stop=not_asked", "stop=unasked"),
            ],
        },
        Claim {
            text: r#"The command reads where the failure comes from."#,
            place: (5, 0),
            speaks_of: "the walk of the source of a failure: where each source goes",
            about: |r| r.kind == Kind::Source,
            breaks: |r| {
                let route = match r.field("source") {
                    "reply" => "reply:",
                    "closure" => "the_end:",
                    "own_fault" => "own_fault:",
                    _ => "",
                };
                r.result() != route
            },
            doctored: &[
                ("source=reply -> reply:", "source=reply -> the_end:"),
                ("source=closure -> the_end:", "source=closure -> own_fault:"),
                (
                    "source=own_fault -> own_fault:",
                    "source=own_fault -> reply:",
                ),
            ],
        },
        Claim {
            text: r#"A failure of the connection that a daemon wrote (a refusal of the connection in its own words, a version it does not take, a message of another kind) shows that a daemon answers: the result is `not_asked` and the exit is 3, with no look and no wait."#,
            place: (6, 0),
            speaks_of: "the end that a daemon's reply makes, before the request and in the walk of the source",
            about: |r| {
                (r.kind == Kind::Before && r.result() == "unmade:answered")
                    || (r.kind == Kind::Source && r.is("source", "reply"))
            },
            breaks: |r| {
                if r.kind == Kind::Source {
                    r.result() != "reply:"
                } else {
                    !(r.is("stop", "not_asked") && r.exit() == 3)
                }
            },
            doctored: &[
                ("-> unmade:answered exit=3", "-> unmade:answered exit=2"),
                (
                    "code=HOST_NOT_CONFIGURED stop=not_asked",
                    "code=HOST_NOT_CONFIGURED stop=ended",
                ),
                ("source=reply -> reply:", "source=reply -> the_end:"),
            ],
        },
        Claim {
            text: r#"A failure that is this side's own (the check of the peer's credentials or of the endpoint's access list, a fault of this side's files or socket, a request that is not in the level) says its own words with exit 3 and no look, since no daemon's end causes it."#,
            place: (8, 0),
            speaks_of: "the end that this side's own fault makes, before the request and in the walk of the source",
            about: |r| {
                (r.kind == Kind::Before && r.result() == "unmade:own_fault")
                    || (r.kind == Kind::Source && r.is("source", "own_fault"))
            },
            breaks: |r| {
                if r.kind == Kind::Source {
                    r.result() != "own_fault:"
                } else {
                    r.exit() != 3
                }
            },
            doctored: &[
                ("-> unmade:own_fault exit=3", "-> unmade:own_fault exit=1"),
                (
                    "source=own_fault -> own_fault:",
                    "source=own_fault -> reply:",
                ),
            ],
        },
        Claim {
            text: r#"A failure that a daemon's end can cause (a closed connection, a stream cut short, a frame that cannot be read, nothing listening) is decided by the daemon's end: the command takes at most 30 seconds, counted after it has read the process that holds the environment, to find out what became of the daemon."#,
            place: (9, 0),
            speaks_of: "the walk of the source of a failure: a closure goes to the daemon's end",
            about: |r| r.kind == Kind::Source && r.is("source", "closure"),
            breaks: |r| r.result() != "the_end:",
            doctored: &[("source=closure -> the_end:", "source=closure -> reply:")],
        },
        Claim {
            text: r#"Where the daemon closed the connection or cut the stream, the command does not first look at the endpoint; it waits for the daemon's end for the 30 seconds."#,
            place: (10, 0),
            speaks_of: "the first-look line for a closed connection",
            about: |r| r.kind == Kind::Closed,
            breaks: |r| !r.line.contains("no look is made"),
            doctored: &[("no look is made", "a look is made")],
        },
        Claim {
            text: r#"Where a daemon answers that look, the command waits no longer: it sent nothing, so the daemon that answers stays, the result is `not_asked` and the exit is 3."#,
            place: (12, 0),
            speaks_of: "the first-look rows with a look that answers, and the before row that an answer makes",
            about: |r| {
                (r.kind == Kind::First && matches!(r.look(), "same" | "unproved"))
                    || (r.kind == Kind::Before && r.is("before", "answers"))
            },
            breaks: |r| {
                if r.kind == Kind::First {
                    r.result() != "answers"
                } else {
                    !(r.is("stop", "not_asked") && r.exit() == 3)
                }
            },
            doctored: &[
                ("look=same -> answers", "look=same -> the wait decides"),
                ("-> unmade:answered exit=3", "-> unmade:answered exit=0"),
            ],
        },
        Claim {
            text: r#"An answer counts when its generation matches the daemon that the command asked, and when it proves no generation."#,
            place: (13, 0),
            speaks_of: "the first-look rows of a look of the generation asked, of no proved generation and of another generation",
            about: |r| r.kind == Kind::First && matches!(r.look(), "same" | "unproved" | "another"),
            breaks: |r| (r.look() != "another") != (r.result() == "answers"),
            doctored: &[
                ("look=same -> answers", "look=same -> the wait decides"),
                (
                    "look=another -> the wait decides",
                    "look=another -> answers",
                ),
            ],
        },
        Claim {
            text: r#"After a failure at the greeting or at the read of `host.info` the command knows no generation to match, so every answer to the look counts there, whatever its kind."#,
            place: (14, 0),
            speaks_of: "the first-look rows of a look that proves no generation",
            about: |r| r.kind == Kind::First && r.look() == "unproved",
            breaks: |r| r.result() != "answers",
            doctored: &[(
                "look=unproved -> answers",
                "look=unproved -> the wait decides",
            )],
        },
        Claim {
            text: r#"An answer of another generation, which the command can tell only where it knows the generation that it asked, does not count, and the wait goes on."#,
            place: (15, 0),
            speaks_of: "the first-look rows of a look of another generation",
            about: |r| r.kind == Kind::First && r.look() == "another",
            breaks: |r| r.result() == "answers",
            doctored: &[(
                "look=another -> the wait decides",
                "look=another -> answers",
            )],
        },
        Claim {
            text: r#"Where no answer counts, it waits for the end for the rest of the 30 seconds, and a daemon that answers the last look of that wait, at its bound, stays too: the result is `not_asked` and the exit is 3."#,
            place: (16, 0),
            speaks_of: "the rows of what the wait decides where it decides an answer, and the before row that an answer makes",
            about: |r| {
                (r.kind == Kind::Wait && r.result() == "answers")
                    || (r.kind == Kind::Before && r.is("before", "answers"))
            },
            breaks: |r| {
                if r.kind == Kind::Wait {
                    !matches!(r.look(), "same" | "unproved")
                } else {
                    !(r.is("stop", "not_asked") && r.exit() == 3)
                }
            },
            doctored: &[
                ("look=same -> answers", "look=nobody -> answers"),
                ("-> unmade:answered exit=3", "-> unmade:answered exit=0"),
            ],
        },
        Claim {
            text: r#"Where the daemon has ended, the result is `ended`, the exit is 0 and `unsettled` is null; the text says that the daemon ended, why the request could not be made and that the command sent nothing."#,
            place: (17, 0),
            speaks_of: "the before rows of kind ended",
            about: |r| r.kind == Kind::Before && r.result() == "ended",
            breaks: |r| !(r.is("stop", "ended") && r.exit() == 0),
            doctored: &[
                ("-> ended exit=0", "-> ended exit=3"),
                (
                    "-> ended exit=0 code=- stop=ended",
                    "-> ended exit=0 code=- stop=told",
                ),
            ],
        },
        Claim {
            text: r#"Where another daemon now holds the environment, the result is `ended`, the exit is 0 and the text is the one that every end with a successor gets."#,
            place: (18, 0),
            speaks_of: "the wait rows of kind ended_by_a_successor, and the before row of kind ended",
            about: |r| {
                (r.kind == Kind::Wait && r.result() == "ended_by_a_successor")
                    || (r.kind == Kind::Before && r.result() == "ended")
            },
            breaks: |r| {
                if r.kind == Kind::Wait {
                    !((r.is("lock", "held") && r.is("process", "ended") && r.is("holder", "other"))
                        || r.look() == "another")
                } else {
                    !(r.is("stop", "ended") && r.exit() == 0)
                }
            },
            doctored: &[
                (
                    "look=another(5000) -> ended_by_a_successor",
                    "look=nobody -> ended_by_a_successor",
                ),
                ("-> ended exit=0", "-> ended exit=3"),
            ],
        },
        Claim {
            text: r#"Where the end is not shown by the deadline and the last look did not show a daemon answering, the exit is 1 and the text says that no stop was requested: where the lock is held, that a control daemon holds the environment and does not answer, so that it may be starting or stopping; where the lock is free, that the daemon listening for the environment accepted the connection and did not answer within 30 seconds."#,
            place: (19, 0),
            speaks_of: "the before rows of kind silent and holds_and_is_silent",
            about: |r| {
                r.kind == Kind::Before && matches!(r.result(), "silent" | "holds_and_is_silent")
            },
            breaks: |r| r.exit() != 1 || !r.is("stop", "not_asked"),
            doctored: &[
                ("-> silent exit=1", "-> silent exit=2"),
                ("stop=not_asked", "stop=told"),
            ],
        },
        Claim {
            text: r#"Where the failure was a connect that found nothing listening, no connection was accepted: with the lock free the exit is 3 and the text is that of a request that could not be made, which says that nothing was sent and nothing was stopped, and a lock that is held keeps the sentence that a control daemon holds the environment and does not answer."#,
            place: (20, 0),
            speaks_of: "the before rows of a connect that found nothing listening, with the lock read again as free or held",
            about: |r| {
                r.kind == Kind::Before
                    && r.is("before", "silent_nothing_accepted")
                    && matches!(r.field("lock_again"), "free" | "held")
            },
            breaks: |r| {
                if r.is("lock_again", "held") {
                    r.result() != "holds_and_is_silent"
                } else {
                    r.exit() != 3 || r.result() != "unmade:nothing_listening"
                }
            },
            doctored: &[
                (
                    "lock_again=free -> unmade:nothing_listening exit=3",
                    "lock_again=free -> unmade:nothing_listening exit=1",
                ),
                (
                    "lock_again=held -> holds_and_is_silent",
                    "lock_again=held -> silent",
                ),
            ],
        },
        Claim {
            text: r#""Ended" means, where the command read the process that held the environment before it asked and the daemon's answer, if it arrived, named the same process, that this process has gone and that the lock is free or another control daemon holds it."#,
            place: (22, 0),
            speaks_of: "the after rows of a process that was read as running or as ended and that end with exit 0",
            about: |r| {
                r.kind == Kind::After
                    && matches!(r.field("process"), "running" | "ended")
                    && r.exit() == 0
            },
            breaks: |r| {
                !r.is("process", "ended") || (r.result() != "successor" && !r.is("lock", "free"))
            },
            doctored: &[
                ("lock=free process=ended", "lock=held process=ended"),
                ("-> successor exit=0", "-> stopped exit=0"),
                (
                    "lock=held process=ended holder=other",
                    "lock=held process=running holder=other",
                ),
            ],
        },
        Claim {
            text: r#"Where it did not (always on Windows; where the lock file cannot be read; where it names no process whose start the command can read; or where the daemon's answer names another process than the lock file does),"#,
            place: (23, 1),
            speaks_of: "the walk of the process that a stop is waited for by: no process where the lock file names none or the answer names another",
            about: |r| r.kind == Kind::Waited,
            breaks: |r| {
                (r.is("named", "none")
                    || (r.field("answer") != "none" && r.field("answer") != r.field("named")))
                    && r.field("waits_for") != "-"
            },
            doctored: &[
                (
                    "named=none answer=none -> waits_for=-",
                    "named=none answer=none -> waits_for=4000",
                ),
                (
                    "named=4000 answer=4001 -> waits_for=-",
                    "named=4000 answer=4001 -> waits_for=4000",
                ),
            ],
        },
        Claim {
            text: r#"it means that the lock is free and nothing answers at the daemon's endpoint, or that a daemon of another generation answers, which is the successor below."#,
            place: (23, 2),
            speaks_of: "the after rows with no process identity that end with exit 0",
            about: |r| r.kind == Kind::After && r.is("process", "no_identity") && r.exit() == 0,
            breaks: |r| {
                if r.result() == "successor" {
                    r.look() != "another"
                } else {
                    !(r.is("lock", "free") && r.look() == "nobody")
                }
            },
            doctored: &[
                (
                    "lock=free process=no_identity holder=not_read look=nobody request=told -> stopped",
                    "lock=held process=no_identity holder=not_read look=nobody request=told -> stopped",
                ),
                ("look=another(5000) request=told", "look=same request=told"),
            ],
        },
        Claim {
            text: r#"and the command cannot name or wait for that process."#,
            place: (24, 2),
            speaks_of: "the walk of the process that a stop is waited for by, where the lock file names none",
            about: |r| r.kind == Kind::Waited && r.is("named", "none"),
            breaks: |r| r.field("waits_for") != "-",
            doctored: &[(
                "named=none answer=4000 -> waits_for=-",
                "named=none answer=4000 -> waits_for=4000",
            )],
        },
        Claim {
            text: r#"and it counts for neither a sign of life nor an end."#,
            place: (26, 2),
            speaks_of: "the rounds at the bound with a process that cannot be read",
            about: |r| r.at_the_bound() && r.is("process", "unreadable"),
            breaks: |r| {
                r.result() == "not_ended:running"
                    || (r.result() == "gone" && !(r.is("lock", "free") && r.look() == "nobody"))
            },
            doctored: &[
                ("-> not_ended:answers", "-> not_ended:running"),
                ("-> not_ended:answers", "-> gone"),
            ],
        },
        Claim {
            text: r#"With the lock free, the endpoint decides as it does where no process could be read: nobody listening is the end, a daemon of another generation is a successor, and anything else shows no end."#,
            place: (27, 0),
            speaks_of: "the rounds at the bound with a free lock and a process that cannot be read",
            about: |r| r.at_the_bound() && r.is("lock", "free") && r.is("process", "unreadable"),
            breaks: |r| match r.look() {
                "nobody" => r.result() != "gone",
                "another" => !r.result().starts_with("successor"),
                _ => !r.result().starts_with("not_ended"),
            },
            doctored: &[
                ("-> gone", "-> not_ended:not_shown answered=no"),
                ("-> successor(5000)", "-> not_ended:not_shown answered=no"),
                ("-> not_ended:answers", "-> gone"),
            ],
        },
        Claim {
            text: r#"With the lock held, the command reads neither the lock file's process nor the endpoint: it shows no successor and no daemon that answers, and at the bound it says that the environment was still held and that it could not show what holds it (exit 1)."#,
            place: (28, 0),
            speaks_of: "the rounds at the bound with a held lock and a process that cannot be read, and the after rows of the same readings",
            about: |r| {
                (r.at_the_bound() || r.kind == Kind::After)
                    && r.is("lock", "held")
                    && r.is("process", "unreadable")
            },
            breaks: |r| {
                if r.kind == Kind::Round {
                    !(r.is("holder", "not_read")
                        && r.is("look", "not_made")
                        && r.is("answered", "no")
                        && r.result() == "not_ended:held_not_shown")
                } else {
                    !(r.result() == "held_not_shown" && r.exit() == 1)
                }
            },
            doctored: &[
                ("-> not_ended:held_not_shown", "-> not_ended:held"),
                ("-> held_not_shown exit=1", "-> held_not_shown exit=2"),
            ],
        },
        Claim {
            text: r#"A lock that another command's look holds for a moment is waited through."#,
            place: (29, 0),
            speaks_of: "the rounds before the bound that the wait can make",
            about: |r| r.kind == Kind::Round && r.is("bound", "no") && r.is("reachable", "yes"),
            breaks: |r| r.result().starts_with("not_ended"),
            doctored: &[("-> gone", "-> not_ended:held")],
        },
        Claim {
            text: r#"Where the old process was read, a lock file that names a live process named `kr-controller` other than the old one shows that something started the daemon again, and so does a daemon of another generation that answers once the old process has gone or was not read."#,
            place: (30, 0),
            speaks_of: "the reachable rounds at the bound that show another daemon: a named other process with the process gone, a look of another generation where the lock and the process leave room",
            about: |r| {
                r.at_the_bound()
                    && ((r.is("lock", "held")
                        && r.is("process", "ended")
                        && r.is("holder", "other"))
                        || (r.look() == "another"
                            && ((r.is("lock", "free") && r.no_process())
                                || (r.is("lock", "held")
                                    && matches!(r.field("process"), "ended" | "no_identity")))))
            },
            breaks: |r| !r.result().starts_with("successor"),
            doctored: &[("-> successor(5000)", "-> gone")],
        },
        Claim {
            text: r#"The command says so and exits 0."#,
            place: (31, 0),
            speaks_of: "the after rows of kind successor",
            about: |r| r.kind == Kind::After && r.result() == "successor",
            breaks: |r| r.exit() != 0,
            doctored: &[("-> successor exit=0", "-> successor exit=1")],
        },
        Claim {
            text: r#"Where the old process has gone and something that is not shown to be a daemon still holds the environment after 30 seconds, the command says that and exits 1, whatever the last look answered without a proved generation;"#,
            place: (32, 1),
            speaks_of: "the after rows with the process gone, the lock held, no named other process and a look that is no proved answer or another generation",
            about: |r| {
                r.kind == Kind::After
                    && r.is("lock", "held")
                    && r.is("process", "ended")
                    && !r.is("holder", "other")
                    && matches!(r.look(), "nobody" | "unproved" | "unclear" | "not_made")
            },
            breaks: |r| r.result() != "still_held" || r.exit() != 1,
            doctored: &[
                ("-> still_held exit=1", "-> still_held exit=3"),
                ("-> still_held", "-> stopped"),
            ],
        },
        Claim {
            text: r#"where the lock cannot be looked at and no process is shown to run, it says that instead, with the reason: a start lock of the store that stayed held, or the failure of the look in its own words."#,
            place: (32, 2),
            speaks_of: "the after rows with a lock that cannot be read and no process shown to run",
            about: |r| {
                r.kind == Kind::After
                    && r.is("lock", "unreadable")
                    && matches!(r.field("process"), "ended" | "no_identity" | "unreadable")
            },
            breaks: |r| r.result() != "unlooked",
            doctored: &[("-> unlooked", "-> not_shown")],
        },
        Claim {
            text: r#"Where the lock is free, no process could be read and the last look showed nothing, or an answer with no proved generation, the text says that the command could not confirm the end."#,
            place: (33, 0),
            speaks_of: "the after rows with a free lock, no readable process and a look that gave nothing or no proved generation",
            about: |r| {
                r.kind == Kind::After
                    && r.is("lock", "free")
                    && r.no_process()
                    && matches!(r.look(), "unproved" | "unclear")
            },
            breaks: |r| r.result() != "not_shown",
            doctored: &[("-> not_shown", "-> stopped")],
        },
        Claim {
            text: r#"Where the lock is held, no process could be read, no look showed a daemon of another generation and no look showed the daemon asked answering, the text says that the environment was still held and that the command could not show what holds it, and that it could not confirm the end (exit 1); the reading is the environment's own lock, and what holds it can be the daemon that was told, a daemon that is starting, or another command's look."#,
            place: (34, 0),
            speaks_of: "the after rows with a held lock, no readable process and no look of another generation or of the daemon asked",
            about: |r| {
                r.kind == Kind::After
                    && r.is("lock", "held")
                    && r.no_process()
                    && !matches!(r.look(), "another" | "same")
            },
            breaks: |r| r.result() != "held_not_shown" || r.exit() != 1,
            doctored: &[
                ("-> held_not_shown exit=1", "-> held_not_shown exit=2"),
                ("-> held_not_shown", "-> still_held"),
            ],
        },
        Claim {
            text: r#"The text says that the daemon has not ended only where the last round of the wait proved that the daemon asked is alive: a look that showed a daemon of its generation answering, or a process that runs."#,
            place: (35, 0),
            speaks_of: "the after rows of kind not_ended",
            about: |r| r.kind == Kind::After && r.result() == "not_ended",
            breaks: |r| !(r.look() == "same" || r.is("process", "running")),
            doctored: &[(
                "look=same request=told -> not_ended",
                "look=nobody request=told -> not_ended",
            )],
        },
        Claim {
            text: r#"It shows that something answers at the endpoint and nothing of which daemon it is."#,
            place: (37, 0),
            speaks_of: "the rounds at the bound with an answer of no proved generation that end without an end",
            about: |r| {
                r.at_the_bound() && r.look() == "unproved" && r.result().starts_with("not_ended")
            },
            breaks: |r| !r.is("answered", "yes"),
            doctored: &[("answered=yes", "answered=no")],
        },
        Claim {
            text: r#"A look that gets nothing within its bound is no answer and shows nothing."#,
            place: (38, 0),
            speaks_of: "the rounds at the bound and the first-look rows with a look that got nothing",
            about: |r| (r.at_the_bound() || r.kind == Kind::First) && r.look() == "unclear",
            breaks: |r| r.is("answered", "yes") || r.result() == "answers",
            doctored: &[
                ("answered=no", "answered=yes"),
                (
                    "look=unclear -> the wait decides",
                    "look=unclear -> answers",
                ),
            ],
        },
        Claim {
            text: r#"The exit is 0 for both."#,
            place: (42, 0),
            speaks_of: "the after rows of kind stopped",
            about: |r| r.kind == Kind::After && r.result() == "stopped",
            breaks: |r| r.exit() != 0,
            doctored: &[("-> stopped exit=0", "-> stopped exit=1")],
        },
    ]
}

/// The pids that a text names as a process: a number after `process ` or after the command that
/// ends a process.
fn named_processes(text: &str) -> Vec<u64> {
    let mut found = Vec::new();
    for marker in ["process ", handover::STOP_COMMAND] {
        for (at, _) in text.match_indices(marker) {
            let digits: String = text[at + marker.len()..]
                .trim_start()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(pid) = digits.parse() {
                found.push(pid);
            }
        }
    }
    found
}

/// The process that the successor's words name, where they name one.
fn successor_named(sentence: &AfterRequest) -> Option<u64> {
    match sentence {
        AfterRequest::Successor(pid) => *pid,
        _ => None,
    }
}

fn words_claims() -> Vec<WordsClaim> {
    vec![
        WordsClaim {
            text: r#"The text then names no process of the daemon that was asked, except where it says how to end the lock's holder (below),"#,
            place: (24, 1),
            speaks_of: "the words of every round with no process identity, for each request",
            about: |round, _, _| round.process == Process::NoIdentity,
            breaks: |_, sentence, _, text| {
                named_processes(text)
                    .iter()
                    .any(|pid| Some(*pid) != successor_named(sentence))
            },
            doctored: &[("", "The control daemon (process 4000) ended.")],
        },
        WordsClaim {
            text: r#"Where a daemon of another generation answers, the text names the process that the lock file names, where that is a live process named `kr-controller`."#,
            place: (25, 0),
            speaks_of: "the words of a successor that a look of another generation showed where the lock file names no other holder",
            about: |round, sentence, _| {
                matches!(sentence, AfterRequest::Successor(_))
                    && matches!(round.look, Some(Endpoint::Another))
                    && !(lock_held(round)
                        && round.process == Process::Ended
                        && matches!(round.holder, Holder::Other(_)))
            },
            breaks: |round, _, _, text| {
                (round.successor == Some(5000)) != text.contains("process 5000")
            },
            doctored: &[
                ("process 5000", "another control daemon"),
                ("another control daemon", "process 5000"),
            ],
        },
        WordsClaim {
            text: r#"Where it read the process and the system does not say whether it runs, the process is still named in the words that name one,"#,
            place: (26, 1),
            speaks_of: "the words that name a process, where the process cannot be read",
            about: |round, sentence, _| {
                round.process == Process::Unreadable
                    && matches!(sentence, AfterRequest::Stopped | AfterRequest::Successor(_))
            },
            breaks: |_, _, _, text| !text.contains("process 4000"),
            doctored: &[("process 4000", "process 4999")],
        },
        WordsClaim {
            text: r#"Where the daemon is seen to end after a stop that it answered, the text says that the command stopped it."#,
            place: (40, 0),
            speaks_of: "the words of a daemon that was seen to end after a request that was told",
            about: |_, sentence, request| {
                matches!(sentence, AfterRequest::Stopped) && matches!(request, Request::Told)
            },
            breaks: |_, _, _, text| !text.contains("Stopped the control daemon"),
            doctored: &[(
                "Stopped the control daemon",
                "Waited for the control daemon",
            )],
        },
        WordsClaim {
            text: r#"Where the request's outcome is not known (`maybe_asked`), it says that the daemon did not show whether it took the stop, with the reason, and that it has ended."#,
            place: (41, 0),
            speaks_of: "the words of a daemon that was seen to end after a request whose outcome was not shown",
            about: |_, sentence, request| {
                matches!(sentence, AfterRequest::Stopped)
                    && matches!(request, Request::MaybeAsked(_))
            },
            breaks: |_, _, _, text| {
                !(text.contains("did not show whether it took the stop")
                    && text.contains("and it has ended"))
            },
            doctored: &[("and it has ended", "and it has not ended")],
        },
    ]
}

fn held() -> Vec<Held> {
    vec![
        Held {
            text: r#"A request that could not be made left nothing: it could not be composed, or the level's check refused the frame at the write, before any byte went."#,
            place: (2, 0),
            why: "it says what a request that left nothing is. The case holds the level's refusal at the write; no case holds that a request that cannot be composed (what the daemon pushed cannot be absorbed, or a parameter that the level cannot encode) is not told",
            holders: &[(
                Where::Lib,
                "a_write_that_the_level_refused_left_nothing_and_any_other_failure_is_unknown",
            )],
        },
        Held {
            text: r#"A write that fails after that may have sent a part of the frame, and the result is then `maybe_asked`."#,
            place: (3, 0),
            why: "the class of a failed write is a case, not a row",
            holders: &[(
                Where::Lib,
                "a_write_that_the_level_refused_left_nothing_and_any_other_failure_is_unknown",
            )],
        },
        Held {
            text: r#"A frame that this side cannot encode fails before any byte is written, but the command does not tell that failure from a write that failed, so its result is `maybe_asked` too."#,
            place: (4, 0),
            why: "the class of a frame that cannot be encoded is a case, not a row",
            holders: &[(
                Where::Lib,
                "a_write_that_the_level_refused_left_nothing_and_any_other_failure_is_unknown",
            )],
        },
        Held {
            text: r#"The command's own read of the daemon's state, once the connection is made, ends before any stop is asked: a refusal of that read exits 8 and a result that does not decode exits 1, and both are `not_asked`."#,
            place: (7, 0),
            why: "the stop's own first read of the daemon is a startup case, not a row",
            holders: &[(
                Where::Startup,
                "a_refused_read_of_the_daemon_exits_8_and_one_that_does_not_decode_exits_1_with_no_stop_asked",
            )],
        },
        Held {
            text: r#"After any other failure of that kind it first looks once at the endpoint, for as long as the 30 seconds leave and no longer than a second."#,
            place: (11, 0),
            why: "the table lists a look for each value and holds no field for its bound: one case shows the first look taking what the deadline leaves, the other that a look is bound by one second where more is left",
            holders: &[
                (
                    Where::Lib,
                    "the_first_look_takes_what_is_left_of_the_deadline",
                ),
                (
                    Where::Lib,
                    "a_look_takes_no_longer_than_one_second_however_much_of_the_deadline_is_left",
                ),
            ],
        },
        Held {
            text: r#"A second `kr host stop` meets the first of these when the first one's stop has taken effect."#,
            place: (21, 0),
            why: "it describes two commands, not a result of one",
            holders: &[(
                Where::Startup,
                "two_kr_host_stops_at_once_each_say_what_is_true_and_one_daemon_ends",
            )],
        },
        Held {
            text: r#"A look whose link fails is read the same way, also where the greeting was acknowledged before the link failed: it gives no reply that the command could weigh."#,
            place: (39, 0),
            why: "it says how a look whose link fails is read: the look table prints it (`gave=link_failed` is unclear, no answer), and no row of the end table holds a link",
            holders: &[
                (Where::Lib, "the_table_of_the_look_is_the_file"),
                (
                    Where::Lib,
                    "the_exchange_of_a_look_gives_a_value_for_each_way_it_ends",
                ),
            ],
        },
        Held {
            text: r#"An answer with no proved generation is any answer that came within the look's bound and proves no generation of the daemon asked: a reply that the command cannot use (a refusal of the connection or of the read of `host.info`, a version that does not fit, a message of another kind, a result that does not decode), or an answer where the generation asked is not known."#,
            place: (36, 0),
            why: "it defines a term: which exchanges give a look of no proved generation is the look table's, and the properties hold that no such look reads as proved",
            holders: &[
                (Where::Lib, "the_table_of_the_look_is_the_file"),
                (
                    Where::Lib,
                    "the_look_label_holds_its_principle_in_every_row",
                ),
            ],
        },
    ]
}

/// Every kept text of the passage with its place.
fn kept_with_places() -> Vec<((u8, u8), &'static str)> {
    claims()
        .iter()
        .map(|claim| (claim.place, claim.text))
        .chain(words_claims().iter().map(|claim| (claim.place, claim.text)))
        .chain(held().iter().map(|held| (held.place, held.text)))
        .collect()
}

/// Every kept text of the passage.
fn kept_texts() -> Vec<&'static str> {
    kept_with_places()
        .into_iter()
        .map(|(_, text)| text)
        .collect()
}

/// The passage of the guide between the two marker comments.
fn the_passage() -> &'static str {
    assert_eq!(GUIDE.matches(PASSAGE_START).count(), 1);
    assert_eq!(GUIDE.matches(PASSAGE_END).count(), 1);
    let start = GUIDE.find(PASSAGE_START).expect("the opening marker") + PASSAGE_START.len();
    let end = GUIDE.find(PASSAGE_END).expect("the closing marker");
    assert!(start < end, "the markers stand in the wrong order");
    &GUIDE[start..end]
}

/// Every claim that rows hold is true of every row that it speaks of, and speaks of some row.
#[test]
fn the_claims_of_the_guide_hold_over_every_row_of_the_table() {
    let rows = rows_of_the_table();
    for claim in claims() {
        let spoken: Vec<&Row> = rows.iter().filter(|row| (claim.about)(row)).collect();
        assert!(
            !spoken.is_empty(),
            "no row is spoken of by ({}): {}",
            claim.speaks_of,
            claim.text
        );
        let contradicting: Vec<&str> = spoken
            .iter()
            .filter(|row| (claim.breaks)(row))
            .map(|row| row.line.as_str())
            .collect();
        assert!(
            contradicting.is_empty(),
            "rows that contradict ({}): {}\n{contradicting:#?}",
            claim.speaks_of,
            claim.text
        );
    }
}

/// Each claim contradicts a real row that one change turns against it.
#[test]
fn each_claim_of_the_guide_fails_for_a_row_that_breaks_it() {
    let rows = rows_of_the_table();
    for claim in claims() {
        assert!(
            !claim.doctored.is_empty(),
            "no doctored row for: {}",
            claim.text
        );
        for (old, new) in claim.doctored {
            let row = rows
                .iter()
                .find(|row| (claim.about)(row) && row.line.contains(old))
                .unwrap_or_else(|| {
                    panic!(
                        "no row that the claim speaks of holds `{old}`: {}",
                        claim.text
                    )
                });
            let doctored = Row::new(row.kind, &row.line.replacen(old, new, 1));
            assert!(
                (claim.about)(&doctored),
                "the doctored row is no longer spoken of: {}\n{}",
                claim.text,
                doctored.line
            );
            assert!(
                (claim.breaks)(&doctored),
                "the doctored row does not break the claim: {}\n{}",
                claim.text,
                doctored.line
            );
        }
    }
}

/// Every claim about words is true of the words of every row that it speaks of, and speaks of some row.
#[test]
fn the_claims_of_the_guide_about_words_hold_over_every_row() {
    let rows = composed_rows(&every_round(), false);
    for claim in words_claims() {
        let spoken: Vec<&Composed> = rows
            .iter()
            .filter(|row| (claim.about)(&row.round, &row.said.sentence, &row.request))
            .collect();
        assert!(
            !spoken.is_empty(),
            "no row is spoken of by ({}): {}",
            claim.speaks_of,
            claim.text
        );
        let contradicting: Vec<String> = spoken
            .iter()
            .filter(|row| (claim.breaks)(&row.round, &row.said.sentence, &row.request, &row.text))
            .map(|row| {
                format!(
                    "{} request={} says: {}",
                    readings(&row.round),
                    row.request.label(),
                    row.text
                )
            })
            .collect();
        assert!(
            contradicting.is_empty(),
            "rows that contradict ({}): {}\n{contradicting:#?}",
            claim.speaks_of,
            claim.text
        );
    }
}

/// Each claim about words contradicts the words of a real row that one change turns against it.
#[test]
fn each_claim_of_the_guide_about_words_fails_for_words_that_break_it() {
    let rows = composed_rows(&every_round(), false);
    for claim in words_claims() {
        assert!(
            !claim.doctored.is_empty(),
            "no doctored words for: {}",
            claim.text
        );
        for (old, new) in claim.doctored {
            let row = rows
                .iter()
                .find(|row| {
                    (claim.about)(&row.round, &row.said.sentence, &row.request)
                        && row.text.contains(old)
                })
                .unwrap_or_else(|| {
                    panic!(
                        "no row that the claim speaks of says `{old}`: {}",
                        claim.text
                    )
                });
            let text = if old.is_empty() {
                format!("{} {new}", row.text)
            } else {
                row.text.replacen(old, new, 1)
            };
            assert!(
                (claim.breaks)(&row.round, &row.said.sentence, &row.request, &text),
                "the doctored words do not break the claim: {}\n{text}",
                claim.text
            );
        }
    }
}

/// The words of a round with no process identity are of three kinds, and no other: they name the
/// successor's process, they say how to end the lock's holder, or they name no process. A
/// successor's process is named only where a look showed it (the lock file is empty in these
/// rows, so the words of the holder name no number).
#[test]
fn the_words_of_a_round_with_no_process_identity_name_the_successor_say_how_to_end_the_holder_or_name_none()
 {
    let rows = composed_rows(&the_rounds_that_happen(), false);
    let (mut successor, mut how_to_end, mut none) = (0, 0, 0);
    for row in rows
        .iter()
        .filter(|row| row.round.process == Process::NoIdentity)
    {
        let names = named_processes(&row.text);
        if !names.is_empty() {
            assert_eq!(names, vec![5000], "{}", row.text);
            assert!(matches!(
                row.said.sentence,
                AfterRequest::Successor(Some(5000))
            ));
            successor += 1;
        } else if row.text.contains("If it stays") {
            assert!(matches!(
                row.said.sentence,
                AfterRequest::NotEnded | AfterRequest::StillHeld
            ));
            how_to_end += 1;
        } else {
            none += 1;
        }
    }
    assert_eq!((successor, how_to_end, none), (6, 6, 26));
}

/// Each named case of a text that no row holds stands in the source of its file.
#[test]
fn each_text_that_a_case_holds_names_a_case_that_exists() {
    for held in held() {
        assert!(!held.holders.is_empty(), "no case holds: {}", held.text);
        for (place, name) in held.holders {
            let source = match place {
                Where::Lib => LIB_CASES,
                Where::Startup => STARTUP_CASES,
            };
            assert!(
                source.contains(&format!("fn {name}(")),
                "no case named {name} holds ({}): {}",
                held.why,
                held.text
            );
        }
    }
}

/// Each kept text stands once in the passage between the markers, and the kept texts cover every
/// character of the passage that is not a space.
#[test]
fn the_kept_texts_stand_in_the_passage_once_and_cover_it() {
    let passage = the_passage();
    let kept = kept_texts();
    let distinct: std::collections::HashSet<&str> = kept.iter().copied().collect();
    assert_eq!(distinct.len(), kept.len(), "a kept text is kept twice");
    let mut covered = vec![false; passage.len()];
    for text in &kept {
        let found: Vec<usize> = passage.match_indices(text).map(|(at, _)| at).collect();
        assert_eq!(
            found.len(),
            1,
            "a kept text stands {} times in the passage: {text}",
            found.len()
        );
        covered[found[0]..found[0] + text.len()].fill(true);
    }
    let missing: String = passage
        .char_indices()
        .filter(|(at, character)| !character.is_whitespace() && !covered[*at])
        .map(|(_, character)| character)
        .collect();
    assert!(
        missing.is_empty(),
        "characters of the passage that no kept text holds: {missing}"
    );
}

/// The kept texts stand in the passage in the order of their sentences, with no sentence left out
/// of the numbering, and the two parts of a sentence that is kept in two stand side by side. A
/// sentence that moves, or a part that is separated from its other part, fails here: several
/// sentences change what they say when they move.
#[test]
fn the_kept_texts_stand_in_the_order_of_the_passage_and_a_split_sentence_stays_whole() {
    let passage = the_passage();
    let mut kept = kept_with_places();
    kept.sort_by_key(|(place, _)| *place);
    let mut sentences: Vec<u8> = kept.iter().map(|((sentence, _), _)| *sentence).collect();
    sentences.dedup();
    assert_eq!(sentences.first(), Some(&1));
    assert!(
        sentences.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "the sentences are not numbered one after the other: {sentences:?}"
    );
    let mut end = 0;
    let mut before: Option<(u8, u8)> = None;
    for (place, text) in &kept {
        let at = passage
            .find(text)
            .unwrap_or_else(|| panic!("a kept text does not stand in the passage: {text}"));
        assert!(
            at >= end,
            "the text of sentence {} does not follow the text before it: {text}",
            place.0
        );
        if before.is_some_and(|before| before.0 == place.0) {
            assert!(
                passage[end..at].trim().is_empty(),
                "the two parts of sentence {} do not stand side by side: {text}",
                place.0
            );
        }
        end = at + text.len();
        before = Some(*place);
    }
}
