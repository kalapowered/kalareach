//! The guide's passage on a PowerShell question that fails, held against the rows of the generated
//! table.
//!
//! Each claim of the passage has the exact texts that make it, a property over the table's rows that
//! reads the whole claim of its sentences, and doctored rows that break each promise of the property.
//! One case reads the passage between its marker comments and shows that every kept text stands in it
//! exactly once, that the kept texts and a short list of texts that claim nothing about a row cover
//! every character of the passage that is not a space, that each text that claims nothing names cases
//! that exist, and that each property holds of the table and breaks on its doctored rows. A second
//! case shows that the kept texts stand in the order of the claims, which matters because two
//! sentences take their meaning from the sentence before them. A sentence that is changed, added or
//! moved fails a case until a person reads its property again.
//!
//! What the cases do not show is whether a property says what its sentence says: that stays a
//! question for the person who reads the sentence and the property side by side. The second cell of
//! the three `timed_out` rows is the rule alone (the table's header says so).

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

/// The program that this host could not wait for, and the call's folder, as the table says them.
const PROGRAM: &str = "/tmp/walk/pwsh";
const CALL_FOLDER: &str = "/tmp/kr-shell-ask-ID";

/// Whether a row of this host's own failure names the program that this host could not wait for, or
/// the call's folder or a file in it that this host could not use, with the system's error after it.
fn names_what_this_host_could_not_use(row: &Row) -> bool {
    let path = row.text.split_once(": ").map_or("", |(path, _)| path);
    if row.way == "wait_failed" {
        path == PROGRAM
    } else {
        path.starts_with(CALL_FOLDER)
    }
}

/// Whether a row says that nothing was written.
fn says_nothing_was_written(row: &Row) -> bool {
    row.text.contains("nothing was written")
}

/// Whether a row says, behind the profile that it concerns where there is one, that PowerShell did
/// not answer, could not start or ended with an error (`phrase`) and that nothing was written.
fn says_so(row: &Row, phrase: &str) -> bool {
    row.text.contains(phrase) && row.text.ends_with("so nothing was written")
}

/// One claim of the passage.
struct Claim {
    /// What the claim says, in a few words.
    name: &'static str,
    /// The exact texts of the passage that make the claim, in the order of the passage; each stands
    /// in the passage once.
    texts: &'static [&'static str],
    /// The property over the table that the claim says.
    holds: fn(&Facts) -> bool,
    /// Doctored rows (or header) that each break the property: one for each promise that it checks.
    doctors: &'static [fn(&mut Facts)],
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
                        && says_so(
                            row,
                            if row.way == "timed_out" {
                                "did not answer in time"
                            } else {
                                "could not start"
                            },
                        )
                })
            },
            doctors: &[
                |facts| facts.row_mut("placement", "timed_out").left = "written".to_owned(),
                |facts| {
                    let row = facts.row_mut("check", "not_started");
                    row.text = row.text.replace(", so nothing was written", "");
                },
            ],
        },
        Claim {
            name: "the same holds where PowerShell ends with an error or says something that is not understood",
            texts: &[
                "The same holds where PowerShell ends with an error or says something that is not understood.",
            ],
            holds: |facts| {
                facts.of(&LATER, &["failed", "signalled"]).all(|row| {
                    row.left == LEFT_PROFILE
                        && row.text.starts_with(&format!("{PROFILE}: "))
                        && says_so(row, "ended with an error")
                }) && facts.of(&LATER, &NOT_UNDERSTOOD).all(|row| {
                    row.left == LEFT_PROFILE
                        && row.text.starts_with(&format!("{PROFILE}: "))
                        && says_so(row, "was not understood")
                })
            },
            doctors: &[
                |facts| {
                    let row = facts.row_mut("check", "failed");
                    row.text = row.text.replace("ended with an error", "stopped");
                },
                |facts| {
                    let row = facts.row_mut("check", "failed");
                    row.text = row.text.replace(", so nothing was written", "");
                },
                |facts| {
                    let row = facts.row_mut("placement", "wrong_form");
                    row.text = row.text.replace(", so nothing was written", "");
                },
                |facts| facts.row_mut("placement", "signalled").left = "written".to_owned(),
            ],
        },
        Claim {
            name: "where this host itself fails, the profile is left, and the install shows the path of what this host could not use and the system's error, and no more",
            texts: &[
                "Where this host itself fails (it cannot prepare the folder and the files that a question uses, cannot wait for PowerShell or cannot read the answer), the install also leaves the profile as it was, and it shows the path of the program or the file that this host could not use and the system's error, and no more.",
            ],
            holds: |facts| {
                facts.of(&LATER, &OWN).all(|row| {
                    is_own_failure(&row.text)
                        && names_what_this_host_could_not_use(row)
                        && !says_nothing_was_written(row)
                        && !row.text.contains(PROFILE)
                        && row.left == LEFT_PROFILE
                })
            },
            doctors: &[
                |facts| {
                    facts.row_mut("placement", "wait_failed").text =
                        "PowerShell did not wait".to_owned();
                },
                |facts| facts.row_mut("check", "unread").left = "written".to_owned(),
                |facts| {
                    let row = facts.row_mut("check", "not_prepared");
                    row.text = row.text.replace("/tmp/kr-shell-ask-ID", "/tmp/walk/other");
                },
                |facts| {
                    let row = facts.row_mut("placement", "unread");
                    row.text = row.text.replace(": ", ": nothing was written: ");
                },
            ],
        },
        Claim {
            name: "the profile question fails in one of three ways and writes nothing for PowerShell",
            texts: &[
                "Where PowerShell is found and the question fails, `kr shell install` writes nothing for PowerShell. The question fails in one of three ways.",
            ],
            holds: |facts| {
                let rows: Vec<&Row> = facts.of(&["profiles"], &NOT_USED).collect();
                let mut kinds: Vec<&str> = rows.iter().map(|row| kind(row)).collect();
                kinds.sort_unstable();
                kinds.dedup();
                rows.iter().all(|row| row.left == LEFT_NOTHING)
                    && kinds == ["not understood", "own failure", "unanswered"]
            },
            doctors: &[
                |facts| facts.row_mut("profiles", "signalled").left = "written".to_owned(),
                |facts| {
                    let other = facts.row("profiles", "too_long").text.clone();
                    facts.row_mut("profiles", "not_prepared").text = other;
                },
            ],
        },
        Claim {
            name: "in two of them the install says so: PowerShell did not say where its profiles are, because no answer in time, no start or an end with an error",
            texts: &[
                "In two of them the install says so: that PowerShell did not say where its profiles are, because it did not answer",
                " not start or ended with an error;",
            ],
            holds: |facts| {
                facts.of(&["profiles"], &UNANSWERED).all(|row| {
                    row.text.contains("did not say where its profiles are")
                        && says_so(
                            row,
                            "it did not answer in time, could not start or ended with an error",
                        )
                        && row.text.ends_with("so nothing was written for PowerShell")
                })
            },
            doctors: &[
                |facts| {
                    let other = facts.row("profiles", "too_long").text.clone();
                    facts.row_mut("profiles", "failed").text = other;
                },
                |facts| {
                    let row = facts.row_mut("profiles", "signalled");
                    row.text = row
                        .text
                        .replace(", so nothing was written for PowerShell", "");
                },
            ],
        },
        Claim {
            name: "or that its answer was not understood: too long, or not two full paths in the form asked for",
            texts: &[
                "or that PowerShell's answer was not understood, because it was too long, or it was not two full paths in the form that this host asked for.",
            ],
            holds: |facts| {
                facts.of(&["profiles"], &NOT_UNDERSTOOD).all(|row| {
                    says_so(
                        row,
                        "it was too long, or it was not two full paths in the form that this host asked for",
                    ) && row.text.contains("was not understood")
                        && row.text.ends_with("so nothing was written for PowerShell")
                })
            },
            doctors: &[
                |facts| {
                    facts.row_mut("profiles", "not_text").text =
                        "PowerShell said nothing".to_owned();
                },
                |facts| {
                    let row = facts.row_mut("profiles", "wrong_form");
                    row.text = row
                        .text
                        .replace(", so nothing was written for PowerShell", "");
                },
            ],
        },
        Claim {
            name: "in the third, this host's own failure at the profile question does not say so: the path of what this host could not use and the system's error, and no more",
            texts: &[
                "In the third, where this host itself could not prepare the folder and the files that the question uses, could not wait for PowerShell or could not read the file that holds the answer, it does not say so: it shows the path of the program or the file that this host could not use and the system's error, and no more.",
            ],
            holds: |facts| {
                facts.of(&["profiles"], &OWN).all(|row| {
                    is_own_failure(&row.text)
                        && names_what_this_host_could_not_use(row)
                        && !says_nothing_was_written(row)
                        && row.left == LEFT_NOTHING
                })
            },
            doctors: &[
                |facts| {
                    facts.row_mut("profiles", "unread").text = "entity not found".to_owned();
                },
                |facts| {
                    let row = facts.row_mut("profiles", "not_prepared");
                    row.text = row.text.replace(": ", ": nothing was written: ");
                },
                |facts| {
                    let row = facts.row_mut("profiles", "wait_failed");
                    row.text = row.text.replace(PROGRAM, CALL_FOLDER);
                },
            ],
        },
        Claim {
            name: "that last way is a failure of this host and not of PowerShell",
            texts: &["The last is a failure of this host and not of PowerShell."],
            holds: |facts| {
                facts
                    .of(&EVERY, &OWN)
                    .all(|row| !row.text.contains("PowerShell"))
            },
            doctors: &[|facts| {
                let row = facts.row_mut("profiles", "not_prepared");
                row.text = format!("PowerShell {}", row.text);
            }],
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
            doctors: &[|facts| {
                let other = facts.row("check", "too_long").text.clone();
                facts.row_mut("check", "signalled").text = other;
            }],
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
            doctors: &[|facts| {
                let row = facts.row_mut("placement", "wrong_form");
                row.text = row.text.replacen(&format!("{PROFILE}: "), "", 1);
            }],
        },
        Claim {
            name: "where this host failed, the path of what it could not use and the system's error, and no profile",
            texts: &[
                "and where this host failed it shows the path of the program or the file that this host could not use and the system's error, and no profile.",
            ],
            holds: |facts| {
                facts.of(&LATER, &OWN).all(|row| {
                    is_own_failure(&row.text)
                        && names_what_this_host_could_not_use(row)
                        && !row.text.contains(PROFILE)
                })
            },
            doctors: &[
                |facts| {
                    let row = facts.row_mut("check", "unread");
                    row.text = format!("{PROFILE}: {}", row.text);
                },
                |facts| {
                    let row = facts.row_mut("placement", "wait_failed");
                    row.text = row.text.replace(PROGRAM, CALL_FOLDER);
                },
            ],
        },
    ]
}

/// A text of the passage that makes no claim about a row, with the text that it stands directly after
/// and the cases that hold what it says. Each case is named, and the cases that cover it are read: a
/// name that no source holds fails.
struct NoClaim {
    text: &'static str,
    after: &'static str,
    holders: &'static [&'static str],
    reason: &'static str,
}

const NO_CLAIM: &[NoClaim] = &[
    NoClaim {
        text: " within a minute, the",
        after: "If PowerShell does not start, or does not answer",
        holders: &[
            "the_install_gives_each_question_a_minute",
            "an_install_waits_longer_for_the_profile_question_than_a_report_does",
            "the_placement_and_the_check_wait_longer_than_a_report_does",
        ],
        reason: "the limit is the install's time for each of its three questions, one minute: the first case reads the figure, the other two show that the questions wait longer than the five seconds of a report; no case waits the whole minute, so the time-out rows' second cell is the rule that the table's header names",
    },
    NoClaim {
        text: "A profile that the same run wrote before the question that failed keeps its entry.",
        after: "The same holds where PowerShell ends with an error or says something that is not understood.",
        holders: &[
            "a_profile_that_the_same_run_wrote_before_a_failed_question_keeps_its_entry",
            "a_powershell_that_cannot_be_asked_ends_the_install_after_the_shells_before_it",
        ],
        reason: "an earlier PowerShell profile keeps its entry and its text, and the later one is not written, at each way that a script can make at the later check (the first case); the file of a shell that was written before PowerShell keeps its entry when PowerShell's profile question fails (the second)",
    },
    NoClaim {
        text: " within a minute, could",
        after: "In two of them the install says so: that PowerShell did not say where its profiles are, because it did not answer",
        holders: &[
            "the_install_gives_each_question_a_minute",
            "an_install_waits_longer_for_the_profile_question_than_a_report_does",
        ],
        reason: "the same limit, said of the profile question",
    },
    NoClaim {
        text: "An answer in which PowerShell refuses the profile by name is an answer that was used, and is not one of the three ways.",
        after: "and where this host failed it shows the path of the program or the file that this host could not use and the system's error, and no profile.",
        holders: &[
            "an_answer_that_refuses_the_profile_by_name_is_used_and_is_none_of_the_tables_rows",
        ],
        reason: "a script's answer `kr-refused <code>` is read and understood, and the install says the refusal's own sentence behind the profile, which is no row of the table, with the home as it was",
    },
];

/// The sources whose cases the texts that claim nothing name.
const HOLDERS: [&str; 3] = [
    include_str!("question_table.rs"),
    include_str!("../../shell.rs"),
    include_str!("../../../../kr-shell-integration/src/host/startup.rs"),
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
/// texts that claim nothing cover every character that is not a space, the cases that the texts which
/// claim nothing name exist, and each property holds of the table and breaks on each doctored row.
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
        assert!(
            !claim.doctors.is_empty(),
            "{}: a claim has a doctored row for each promise",
            claim.name
        );
        kept.extend(claim.texts);
    }
    for entry in NO_CLAIM {
        assert!(
            !entry.reason.is_empty() && !entry.holders.is_empty(),
            "{:?}: a text that claims nothing says why and names its cases",
            entry.text
        );
        for holder in entry.holders {
            assert!(
                HOLDERS
                    .iter()
                    .any(|source| source.contains(&format!("fn {holder}("))),
                "{:?}: no case is called {holder}",
                entry.text
            );
        }
        kept.push(entry.text);
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
        for (index, doctor) in claim.doctors.iter().enumerate() {
            let mut doctored = table.clone();
            doctor(&mut doctored);
            assert!(
                !(claim.holds)(&doctored),
                "the doctored row {index} does not break the property of the claim: {}",
                claim.name
            );
        }
    }
}

/// Says whether the kept texts stand in `passage` in the order of the claims, and each text that
/// claims nothing stands directly after the text that it names.
fn in_order(passage: &str) -> Result<(), String> {
    let claims = claims();
    let mut placed: Vec<(usize, &str)> = Vec::new();
    for text in claims.iter().flat_map(|claim| claim.texts.iter().copied()) {
        let at = passage
            .find(text)
            .ok_or_else(|| format!("this text is not in the passage: {text:?}"))?;
        if let Some((last, before)) = placed.last() {
            if at < *last {
                return Err(format!("{text:?} stands before {before:?}"));
            }
        }
        placed.push((at, text));
    }
    for entry in NO_CLAIM {
        let at = passage
            .find(entry.text)
            .ok_or_else(|| format!("this text is not in the passage: {:?}", entry.text))?;
        placed.push((at, entry.text));
    }
    placed.sort_by_key(|(at, _)| *at);
    for entry in NO_CLAIM {
        let index = placed
            .iter()
            .position(|(_, text)| *text == entry.text)
            .expect("placed");
        let before = index.checked_sub(1).map(|index| placed[index].1);
        if before != Some(entry.after) {
            return Err(format!(
                "{:?} does not stand directly after {:?}",
                entry.text, entry.after
            ));
        }
    }
    Ok(())
}

/// The kept texts stand in the order of the claims, and a text that claims nothing stands where its
/// claim puts it: "The same holds" and "The last" take their meaning from the sentence before them.
/// A passage with two sentences exchanged fails.
#[test]
fn the_kept_texts_stand_in_the_order_of_the_passage() {
    let real = passage();
    assert_eq!(in_order(&real), Ok(()));
    let claims = claims();
    let swap = |first: &str, second: &str| {
        real.replacen(first, "@@first@@", 1)
            .replacen(second, first, 1)
            .replacen("@@first@@", second, 1)
    };
    // A claim's sentence moved after the sentence that follows it.
    let (same, last) = (claims[1].texts[0], claims[7].texts[0]);
    let third = claims[2].texts[0];
    assert!(in_order(&swap(same, third)).is_err());
    assert!(in_order(&swap(last, claims[8].texts[0])).is_err());
    // A text that claims nothing moved away from the sentence that it follows.
    let kept = NO_CLAIM[1].text;
    assert!(in_order(&swap(kept, third)).is_err());
}
