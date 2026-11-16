//! The guide's passage on a PowerShell question that fails, held against the rows of the generated
//! table.
//!
//! Each claim of the passage has the exact text that makes it, a property over the table's rows, and a
//! doctored row that breaks the property. One case reads the passage between its marker comments and
//! shows that every kept text stands in it exactly once, and that the kept texts and a short list of
//! texts that claim nothing about a row cover every character of the passage that is not a space. A
//! sentence that is changed, or added, fails the case until a person reads its property again.
//!
//! What the case does not show is whether a property says what its sentence says: that stays a
//! question for the person who reads the sentence and the property side by side.

/// The table, as the repository holds it.
const TABLE: &str = include_str!("../../../tests/shell_question_table.txt");

/// The guide.
const GUIDE: &str = include_str!("../../../../../docs/shell-integration/host.md");

/// The marker comments around the two parts of the passage: the sentences on a question that fails
/// in the paragraph on placing the entry, and the sentences in the paragraph on the profile paths.
const MARKERS: [(&str, &str); 2] = [
    (
        "<!-- kr-question-install:begin -->",
        "<!-- kr-question-install:end -->",
    ),
    (
        "<!-- kr-question-profiles:begin -->",
        "<!-- kr-question-profiles:end -->",
    ),
];

/// The profile that the table says the placement and the check of.
const PROFILE: &str = "/home/person/profile.ps1";

/// What the table says is left of the profile where a question fails: the profile asked about, or
/// nothing written for PowerShell where no profile is known yet.
const LEFT_PROFILE: &str = "the profile as it was";
const LEFT_NOTHING: &str = "nothing written for PowerShell";

/// One row of the table: what the install says, and what it leaves.
#[derive(Clone)]
struct Row {
    question: String,
    way: String,
    text: String,
    left: String,
}

/// What the table holds, as the properties read it.
#[derive(Clone)]
struct Facts {
    rows: Vec<Row>,
    header: String,
}

/// Reads the table.
fn facts() -> Facts {
    let mut rows: Vec<Row> = Vec::new();
    let mut header = String::new();
    let mut section = "";
    for line in TABLE.lines() {
        if let Some(name) = line.strip_prefix("## ") {
            section = if name == "what the install says" {
                "says"
            } else if name == "what the install leaves" {
                "leaves"
            } else {
                ""
            };
            continue;
        }
        if line.starts_with('#') {
            header.push_str(line);
            header.push(' ');
            continue;
        }
        let Some(rest) = line.strip_prefix("question=") else {
            continue;
        };
        let (question, rest) = rest.split_once(" way=").expect("a way");
        let (way, said) = rest.split_once(" -> ").unwrap_or((rest, ""));
        match section {
            "says" => rows.push(Row {
                question: question.to_owned(),
                way: way.to_owned(),
                text: said.to_owned(),
                left: String::new(),
            }),
            "leaves" => {
                let row = rows
                    .iter_mut()
                    .find(|row| row.question == question && row.way == way)
                    .expect("a row that says what is left");
                row.left = said.to_owned();
            }
            _ => {}
        }
    }
    Facts { rows, header }
}

impl Facts {
    fn row(&self, question: &str, way: &str) -> &Row {
        self.rows
            .iter()
            .find(|row| row.question == question && row.way == way)
            .unwrap_or_else(|| panic!("the table has no row for {question} {way}"))
    }

    fn row_mut(&mut self, question: &str, way: &str) -> &mut Row {
        self.rows
            .iter_mut()
            .find(|row| row.question == question && row.way == way)
            .unwrap_or_else(|| panic!("the table has no row for {question} {way}"))
    }

    /// The rows of these questions in these ways.
    fn of<'a>(&'a self, questions: &'a [&str], ways: &'a [&str]) -> impl Iterator<Item = &'a Row> {
        self.rows.iter().filter(move |row| {
            questions.contains(&row.question.as_str()) && ways.contains(&row.way.as_str())
        })
    }
}

const EVERY: [&str; 3] = ["profiles", "placement", "check"];
const LATER: [&str; 2] = ["placement", "check"];
const UNANSWERED: [&str; 4] = ["timed_out", "not_started", "failed", "signalled"];
const NOT_UNDERSTOOD: [&str; 3] = ["too_long", "not_text", "wrong_form"];
const OWN: [&str; 3] = ["not_prepared", "wait_failed", "unread"];
const NOT_USED: [&str; 10] = [
    "too_long",
    "not_text",
    "wrong_form",
    "timed_out",
    "not_started",
    "failed",
    "signalled",
    "not_prepared",
    "wait_failed",
    "unread",
];

/// Whether a text is this host's own failure: a full path, then the system's error, and no word of
/// PowerShell's.
fn is_own_failure(text: &str) -> bool {
    text.split_once(": ").is_some_and(|(path, error)| {
        path.starts_with('/')
            && error.contains("(os error ")
            && error.ends_with(')')
            && !text.contains("PowerShell")
    })
}

/// What kind of end a row's text says.
fn kind(row: &Row) -> &'static str {
    if is_own_failure(&row.text) {
        "own failure"
    } else if row.text.contains("was not understood") {
        "not understood"
    } else if row
        .text
        .contains("did not answer in time, could not start or ended with an error")
    {
        "unanswered"
    } else if row.text.starts_with("(nothing is said") {
        "used"
    } else {
        "other"
    }
}

/// What a row leaves where the question failed: nothing written for PowerShell at the question that
/// has no profile yet, the profile as it was at the others.
fn left_of(question: &str) -> &'static str {
    if question == "profiles" {
        LEFT_NOTHING
    } else {
        LEFT_PROFILE
    }
}

/// One claim of the passage.
struct Claim {
    /// What the claim says, in a few words.
    name: &'static str,
    /// The exact texts of the passage that make the claim; each stands in the passage once.
    texts: &'static [&'static str],
    /// The property over the table that the claim says.
    holds: fn(&Facts) -> bool,
    /// A doctored row (or header) that breaks the property.
    doctor: fn(&mut Facts),
}

/// The claims of the passage, in the order of the passage.
fn claims() -> Vec<Claim> {
    vec![
        Claim {
            name: "where PowerShell does not start or does not answer, the install leaves the profile and says so",
            texts: &[
                "If PowerShell does not start, or does not answer",
                " install leaves the profile that it asked about as it was and says so.",
            ],
            holds: |facts| {
                facts.of(&LATER, &["timed_out", "not_started"]).all(|row| {
                    row.left == LEFT_PROFILE
                        && row.text.starts_with(&format!("{PROFILE}: "))
                        && row.text.ends_with("so nothing was written")
                        && row.text.contains(if row.way == "timed_out" {
                            "did not answer in time"
                        } else {
                            "could not start"
                        })
                })
            },
            doctor: |facts| facts.row_mut("placement", "timed_out").left = "written".to_owned(),
        },
        Claim {
            name: "the same holds where PowerShell ends with an error or says something that is not understood",
            texts: &[
                "The same holds where PowerShell ends with an error or says something that is not understood.",
            ],
            holds: |facts| {
                facts
                    .of(&LATER, &["failed", "signalled"])
                    .all(|row| row.left == LEFT_PROFILE && row.text.contains("ended with an error"))
                    && facts.of(&LATER, &NOT_UNDERSTOOD).all(|row| {
                        row.left == LEFT_PROFILE && row.text.contains("was not understood")
                    })
            },
            doctor: |facts| {
                let row = facts.row_mut("check", "failed");
                row.text = row.text.replace("ended with an error", "stopped");
            },
        },
        Claim {
            name: "where this host itself fails, the profile is left and the path and the system's error are shown",
            texts: &[
                "Where this host itself fails (it cannot prepare the folder and the files that a question uses, cannot wait for PowerShell or cannot read the answer), the install also leaves the profile as it was, and it shows the path that failed and the system's error.",
            ],
            holds: |facts| {
                facts
                    .of(&EVERY, &OWN)
                    .all(|row| is_own_failure(&row.text) && row.left == left_of(&row.question))
                    && facts
                        .rows
                        .iter()
                        .filter(|row| is_own_failure(&row.text))
                        .all(|row| OWN.contains(&row.way.as_str()))
            },
            doctor: |facts| {
                facts.row_mut("placement", "wait_failed").text =
                    "PowerShell did not wait".to_owned();
            },
        },
        Claim {
            name: "the profile question fails in one of three ways and writes nothing for PowerShell",
            texts: &[
                "Where PowerShell is found and the question fails, `kr shell install` writes nothing for PowerShell and says so, in one of three ways:",
            ],
            holds: |facts| {
                let rows: Vec<&Row> = facts.of(&["profiles"], &NOT_USED).collect();
                let mut kinds: Vec<&str> = rows.iter().map(|row| kind(row)).collect();
                kinds.sort_unstable();
                kinds.dedup();
                rows.iter().all(|row| row.left == LEFT_NOTHING)
                    && kinds == ["not understood", "own failure", "unanswered"]
            },
            doctor: |facts| facts.row_mut("profiles", "signalled").left = "written".to_owned(),
        },
        Claim {
            name: "it did not say where its profiles are: no answer in time, no start or an end with an error",
            texts: &[
                "that it did not say where its profiles are, because it did not answer",
                " not start or ended with an error;",
            ],
            holds: |facts| {
                facts.of(&["profiles"], &UNANSWERED).all(|row| {
                    row.text.contains("did not say where its profiles are")
                        && row.text.contains(
                            "it did not answer in time, could not start or ended with an error",
                        )
                        && row.text.ends_with("so nothing was written for PowerShell")
                })
            },
            doctor: |facts| {
                let other = facts.row("profiles", "too_long").text.clone();
                facts.row_mut("profiles", "failed").text = other;
            },
        },
        Claim {
            name: "its answer was not understood: too long, or not two full paths in the form asked for",
            texts: &[
                "that its answer was not understood, because it was too long, or it was not two full paths in the form that this host asked for;",
            ],
            holds: |facts| {
                facts.of(&["profiles"], &NOT_UNDERSTOOD).all(|row| {
                    row.text.contains("was not understood")
                        && row.text.contains(
                            "it was too long, or it was not two full paths in the form that this host asked for",
                        )
                        && row.text.ends_with("so nothing was written for PowerShell")
                })
            },
            doctor: |facts| {
                facts.row_mut("profiles", "not_text").text = "PowerShell said nothing".to_owned();
            },
        },
        Claim {
            name: "this host's own failure at the profile question: the path that failed and the system's error",
            texts: &[
                "or, where this host itself could not prepare the folder and the files that the question uses, could not wait for PowerShell or could not read the file that holds the answer, the path that failed and the system's error.",
            ],
            holds: |facts| {
                facts
                    .of(&["profiles"], &OWN)
                    .all(|row| is_own_failure(&row.text))
            },
            doctor: |facts| {
                facts.row_mut("profiles", "unread").text = "entity not found".to_owned()
            },
        },
        Claim {
            name: "that last way is a failure of this host and not of PowerShell",
            texts: &["The last is a failure of this host and not of PowerShell."],
            holds: |facts| {
                facts
                    .of(&EVERY, &OWN)
                    .all(|row| !row.text.contains("PowerShell"))
            },
            doctor: |facts| {
                let row = facts.row_mut("profiles", "not_prepared");
                row.text = format!("PowerShell {}", row.text);
            },
        },
        Claim {
            name: "the placement and the check end the same three ways as the profile question",
            texts: &[
                "The two questions that the install asks about a profile, where the entry goes in it and the check of the profile with the entry in it, end the same three ways:",
            ],
            holds: |facts| {
                facts.of(&LATER, &NOT_USED).all(|row| {
                    kind(row) == kind(facts.row("profiles", &row.way)) && kind(row) != "other"
                })
            },
            doctor: |facts| {
                let other = facts.row("check", "too_long").text.clone();
                facts.row_mut("check", "signalled").text = other;
            },
        },
        Claim {
            name: "the install names the profile and says that PowerShell did not answer, or that its answer was not understood",
            texts: &[
                "the install names the profile and says that PowerShell did not answer in time, could not start or ended with an error, or that its answer was not understood,",
            ],
            holds: |facts| {
                facts.of(&LATER, &UNANSWERED).all(|row| {
                    row.text.starts_with(&format!("{PROFILE}: "))
                        && row.text.contains(
                            "it did not answer in time, could not start or ended with an error",
                        )
                }) && facts.of(&LATER, &NOT_UNDERSTOOD).all(|row| {
                    row.text.starts_with(&format!("{PROFILE}: "))
                        && row.text.contains("was not understood")
                })
            },
            doctor: |facts| {
                let row = facts.row_mut("placement", "wrong_form");
                row.text = row.text.replacen(&format!("{PROFILE}: "), "", 1);
            },
        },
        Claim {
            name: "where this host failed, the path that failed and the system's error, and no profile",
            texts: &[
                "and where this host failed it names the path that failed and the system's error, and no profile.",
            ],
            holds: |facts| {
                facts
                    .of(&LATER, &OWN)
                    .all(|row| is_own_failure(&row.text) && !row.text.contains(PROFILE))
            },
            doctor: |facts| {
                let row = facts.row_mut("check", "unread");
                row.text = format!("{PROFILE}: {}", row.text);
            },
        },
        Claim {
            name: "an answer in which PowerShell refuses the profile by name is an answer that was used",
            texts: &[
                "An answer in which PowerShell refuses the profile by name is an answer that was used, and is not one of the three ways.",
            ],
            holds: |facts| {
                facts
                    .header
                    .contains("answers that a script gives as refusals of the profile")
                    && facts.header.contains("are answers that are used")
            },
            doctor: |facts| {
                facts.header = facts
                    .header
                    .replace("are answers that are used", "are answers");
            },
        },
    ]
}

/// Texts of the passage that make no claim about a row, each with the reason.
const NO_CLAIM: &[(&str, &str)] = &[
    (
        " within a minute, the",
        "the limit is the install's time for each question; no row carries a limit, and the cases of the limits hold it: an_install_waits_longer_for_the_profile_question_than_a_report_does and the_placement_and_the_check_wait_longer_than_a_report_does",
    ),
    (
        " within a minute, could",
        "the same limit, said of the profile question: held by an_install_waits_longer_for_the_profile_question_than_a_report_does",
    ),
    (
        "A profile that the same run wrote before that keeps its entry.",
        "what an earlier shell keeps is not a row of this table; the case a_powershell_that_cannot_be_asked_ends_the_install_after_the_shells_before_it holds it",
    ),
];

/// Returns the passage: the text between each pair of markers, one after the other.
fn passage() -> String {
    let mut passage = String::new();
    for (begin, end) in MARKERS {
        assert_eq!(GUIDE.matches(begin).count(), 1, "{begin} stands once");
        assert_eq!(GUIDE.matches(end).count(), 1, "{end} stands once");
        let from = GUIDE.find(begin).expect("a begin marker") + begin.len();
        let to = GUIDE.find(end).expect("an end marker");
        assert!(from < to, "{begin} comes before {end}");
        passage.push_str(&GUIDE[from..to]);
        passage.push(' ');
    }
    passage
}

/// The passage is held by the table's rows: each kept text stands in it once, the kept texts and the
/// texts that claim nothing cover every character that is not a space, and each property holds of
/// the table and breaks on its doctored row.
#[test]
fn the_guides_passage_on_a_failed_question_is_held_by_the_tables_rows() {
    let mut rest = passage();
    let claims = claims();
    let mut kept: Vec<&str> = Vec::new();
    for claim in &claims {
        assert!(
            !claim.texts.is_empty(),
            "{}: a claim keeps its text",
            claim.name
        );
        kept.extend(claim.texts);
    }
    for (text, reason) in NO_CLAIM {
        assert!(
            !reason.is_empty(),
            "{text:?}: a text that claims nothing says why"
        );
        kept.push(text);
    }
    for text in kept {
        assert_eq!(
            rest.matches(text).count(),
            1,
            "this text stands once in the passage: {text:?}"
        );
        rest = rest.replacen(text, " ", 1);
    }
    assert_eq!(
        rest.split_whitespace().collect::<Vec<_>>(),
        Vec::<&str>::new(),
        "text of the passage that no claim keeps and no reason excuses"
    );

    let table = facts();
    for claim in &claims {
        assert!(
            (claim.holds)(&table),
            "the table's rows do not hold the claim: {}",
            claim.name
        );
        let mut doctored = table.clone();
        (claim.doctor)(&mut doctored);
        assert!(
            !(claim.holds)(&doctored),
            "the doctored row does not break the property of the claim: {}",
            claim.name
        );
    }
}
