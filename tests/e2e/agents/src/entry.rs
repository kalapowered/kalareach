//! What a build list entry gives, what it lacks, and what a real start of it refuses.
//!
//! A part reads fields of its entry. A field the entry lists in `missing` is missing, and a case
//! that reads it stops: it is never read as empty. [`check`] names, for each part, the fields the
//! entry lacks and says whose gap each is, and lists what a real start of the entry refuses: an
//! entry with no isolation contract, an entry with an account and no `turn_line`, and a build the
//! entry does not digest.

use std::fmt;

use crate::build::{Build, Launch};

/// The package whose isolation the driver keeps in its own arm.
const CODEX_PACKAGE: &str = "kalareach/codex";

/// Whose gap a missing field is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// The entry lacks a value that the agent's own program or screens could give.
    EntryField,
    /// The product cannot give the part what it needs yet: a script or wheel pin, no newer build,
    /// no account.
    ProductGap,
    /// The entry's value cannot be read until the driver learns to read it.
    HarnessGap,
}

/// A field a part reads that the entry lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The part that reads the field.
    pub part: &'static str,
    /// The field's dotted path in the entry.
    pub field: String,
    /// Whose gap it is.
    pub class: Class,
    /// Why the field is missing, as the entry says it or as the check states it.
    pub reason: String,
}

/// What a real start of an entry refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The entry lacks members of the isolation contract.
    NoIsolation(Vec<&'static str>),
    /// An entry with an account gives no `turn_line`.
    NoTurnLine,
    /// A build the entry names has no digest.
    NotDigested(&'static str),
    /// A field the entry lists as missing is not one a part reads, or is given as well.
    Contradiction(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIsolation(members) => write!(
                out,
                "the entry gives no isolation contract: it lacks {}, so a real start of it is refused",
                members.join(", ")
            ),
            Self::NoTurnLine => write!(
                out,
                "the entry has an account and no turn_line, so no real case can count the agent's \
                 turns and a real start of it is refused"
            ),
            Self::NotDigested(program) => write!(
                out,
                "the entry gives no digest for {program}, so a real start of it is refused"
            ),
            Self::Contradiction(text) => write!(out, "{text}"),
        }
    }
}

/// What [`check`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The fields the parts read that the entry lacks.
    pub gaps: Vec<Gap>,
    /// What a real start of the entry refuses.
    pub refusals: Vec<Refusal>,
    /// The runtimes the harness compares with its own placed copy, which the entry does not digest.
    pub placed: Vec<String>,
}

/// The gaps that the driver, not the entry, must close: a field of a package that the entry lists
/// as missing until the driver can read it, with what the driver lacks.
pub const HARNESS_GAPS: [(&str, &str, &str); 2] = [
    (
        "kalareach/gemini-cli",
        "account.turn_line",
        "the record reader does not tell a typed prompt from the other user messages that start with text: the lines that rewrite the whole message list, function responses and synthetic messages",
    ),
    (
        "kalareach/kimi-code-cli",
        "account.image_line",
        "the record holds an image of ordinary size as a reference to a blob store that the driver does not read",
    ),
];

/// The fields each part reads, by the part's name. `account.turn_line` is also read by every real
/// case of an entry with an account.
const NEEDS: [(&str, &[&str]); 5] = [
    ("1", &["account.image_line"]),
    ("4", &["account.turn_line"]),
    (
        "7",
        &[
            "account.draft",
            "account.resume_refused",
            "account.commands.fork",
            "account.commands.new",
            "account.commands.quit",
        ],
    ),
    ("7f", &["account.fork"]),
    ("14.03a", &["composer"]),
];

/// Whether the entry gives a value for `field`, a dotted path of [`NEEDS`]. An empty list is a
/// value: the entry says each rests on a positive finding.
fn given(build: &Build, field: &str) -> bool {
    let account = build.account.as_ref();
    match field {
        "account.image_line" => account.is_some_and(|account| account.image_line.is_some()),
        "account.turn_line" => account.is_some_and(|account| account.turn_line.is_some()),
        "account.draft" | "account.resume_refused" | "account.fork" => account.is_some(),
        "account.commands.fork" | "account.commands.new" | "account.commands.quit" => account
            .zip(field.rsplit('.').next())
            .is_some_and(|(account, command)| account.commands.contains_key(command)),
        // An entry with an account reaches its composer by the account's own steps.
        "composer" => build.composer.is_some() || account.is_some(),
        _ => false,
    }
}

/// Whether `text` is a SHA-256 digest in hexadecimal.
fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Checks `build` as the entry of the parts and of a real start.
#[must_use]
pub fn check(build: &Build) -> Report {
    let mut report = Report::default();
    for (part, fields) in NEEDS {
        for &field in fields {
            if build.account.is_none() && field.starts_with("account.") {
                if !report.gaps.iter().any(|gap| gap.part == part) {
                    report.gaps.push(Gap {
                        part,
                        field: "account".to_owned(),
                        class: Class::ProductGap,
                        reason: build.no_account.clone().unwrap_or_default(),
                    });
                }
                continue;
            }
            let listed = build.missing.get(field);
            if listed.is_none() && given(build, field) {
                continue;
            }
            let harness = HARNESS_GAPS
                .iter()
                .find(|(package, named, _)| *package == build.package && *named == field);
            report.gaps.push(Gap {
                part,
                field: field.to_owned(),
                class: if harness.is_some() {
                    Class::HarnessGap
                } else {
                    Class::EntryField
                },
                reason: listed.cloned().unwrap_or_else(|| {
                    "the entry gives no value and does not list it as missing".to_owned()
                }),
            });
        }
    }
    let read: Vec<&str> = NEEDS
        .iter()
        .flat_map(|(_, fields)| fields.iter().copied())
        .collect();
    for field in build.missing.keys() {
        if !read.contains(&field.as_str()) {
            report.refusals.push(Refusal::Contradiction(format!(
                "the entry lists {field} as missing, and no part reads it"
            )));
        } else if (matches!(field.as_str(), "account.turn_line" | "account.image_line")
            && given(build, field))
            || (field == "composer" && build.composer.is_some())
        {
            report.refusals.push(Refusal::Contradiction(format!(
                "the entry lists {field} as missing and gives it"
            )));
        }
    }
    if matches!(build.launch, Launch::Script | Launch::Wheel) {
        report.gaps.push(Gap {
            part: "naming",
            field: "launch".to_owned(),
            class: Class::ProductGap,
            reason: "the pipeline never names a script or a wheel pin".to_owned(),
        });
    }
    if build.newer.is_none() {
        report.gaps.push(Gap {
            part: "6a",
            field: "newer".to_owned(),
            class: Class::ProductGap,
            reason: build.no_newer.clone().unwrap_or_default(),
        });
    }
    report.placed = build
        .runtime
        .iter()
        .map(|runtime| runtime.display().to_string())
        .collect();
    if build.package != CODEX_PACKAGE {
        let isolation = build.isolation.as_ref();
        let own = |from_account: Option<usize>, from_isolation: Option<usize>| {
            from_account.or(from_isolation).unwrap_or(0) > 0
        };
        let mut lacking = Vec::new();
        if isolation.is_none_or(|isolation| isolation.person_trees.is_empty()) {
            lacking.push("person_trees");
        }
        if !own(
            build
                .account
                .as_ref()
                .map(|account| account.installs_off.len()),
            isolation.map(|isolation| isolation.installs_off.len()),
        ) {
            lacking.push("installs_off");
        }
        if !own(
            build.account.as_ref().map(|account| account.absent.len()),
            isolation.map(|isolation| isolation.absent.len()),
        ) {
            lacking.push("absent");
        }
        if !lacking.is_empty() {
            report.refusals.push(Refusal::NoIsolation(lacking));
        }
    }
    if build
        .account
        .as_ref()
        .is_some_and(|account| account.turn_line.is_none())
    {
        report.refusals.push(Refusal::NoTurnLine);
    }
    if !is_digest(&build.sha256) {
        report
            .refusals
            .push(Refusal::NotDigested("the pinned build"));
    }
    if build
        .newer
        .as_ref()
        .is_some_and(|newer| !is_digest(&newer.sha256) || newer.pinned.is_empty())
    {
        report
            .refusals
            .push(Refusal::NotDigested("the newer build"));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed::build_of;

    const PACKAGES: [&str; 8] = [
        "kalareach/claude-code",
        "kalareach/codex",
        "kalareach/gemini-cli",
        "kalareach/kimi-cli",
        "kalareach/kimi-code-cli",
        "kalareach/opencode",
        "kalareach/opencode-attach",
        "kalareach/qoder-cli",
    ];

    fn found(package: &str) -> Vec<(&'static str, String, Class)> {
        let mut found: Vec<_> = check(&build_of(package))
            .gaps
            .into_iter()
            .map(|gap| (gap.part, gap.field, gap.class))
            .collect();
        found.sort();
        found
    }

    fn expected(rows: &[(&'static str, &str, Class)]) -> Vec<(&'static str, String, Class)> {
        let mut rows: Vec<_> = rows
            .iter()
            .map(|(part, field, class)| (*part, (*field).to_owned(), *class))
            .collect();
        rows.sort();
        rows
    }

    /// Each committed entry has the gaps per part that its fields and its reasons state, each with
    /// its class.
    #[test]
    fn the_gaps_of_each_committed_entry_are_named_per_part_and_classed() {
        use Class::{EntryField, HarnessGap, ProductGap};
        let accountless = [
            ("1", "account", ProductGap),
            ("4", "account", ProductGap),
            ("7", "account", ProductGap),
            ("7f", "account", ProductGap),
        ];
        assert_eq!(found("kalareach/codex"), expected(&[]));
        assert_eq!(
            found("kalareach/claude-code"),
            expected(&[("4", "account.turn_line", EntryField)])
        );
        assert_eq!(
            found("kalareach/gemini-cli"),
            expected(&[
                ("4", "account.turn_line", HarnessGap),
                ("7", "account.resume_refused", EntryField),
                ("7", "account.commands.fork", EntryField),
                ("7f", "account.fork", EntryField),
                ("naming", "launch", ProductGap),
            ])
        );
        assert_eq!(
            found("kalareach/kimi-code-cli"),
            expected(&[
                ("1", "account.image_line", HarnessGap),
                ("7", "account.draft", EntryField),
                ("7", "account.resume_refused", EntryField),
                ("7f", "account.fork", EntryField),
            ])
        );
        assert_eq!(
            found("kalareach/opencode"),
            expected(&[
                ("7", "account.commands.fork", EntryField),
                ("7", "account.draft", EntryField),
                ("7", "account.resume_refused", EntryField),
            ])
        );
        let mut qoder = accountless.to_vec();
        qoder.push(("14.03a", "composer", EntryField));
        assert_eq!(found("kalareach/qoder-cli"), expected(&qoder));
        assert_eq!(found("kalareach/opencode-attach"), expected(&accountless));
        let mut kimi = accountless.to_vec();
        kimi.push(("naming", "launch", ProductGap));
        kimi.push(("6a", "newer", ProductGap));
        assert_eq!(found("kalareach/kimi-cli"), expected(&kimi));
    }

    /// A real start of a committed entry is refused only where the entry has an account and no
    /// `turn_line`.
    #[test]
    fn a_real_start_of_a_committed_entry_is_refused_only_where_it_has_no_turn_line_for_its_account()
    {
        for package in PACKAGES {
            let refusals = check(&build_of(package)).refusals;
            let wanted = match package {
                "kalareach/claude-code" | "kalareach/gemini-cli" => vec![Refusal::NoTurnLine],
                _ => Vec::new(),
            };
            assert_eq!(refusals, wanted, "{package}");
        }
    }

    /// A `turn_line` the entry lists as missing is missing and never read as empty: the real start
    /// is refused and names the field, and the entry that gives one and drops the listing is not.
    #[test]
    fn a_turn_line_listed_as_missing_is_refused_and_never_read_as_empty() {
        let claude = build_of("kalareach/claude-code");
        let report = check(&claude);
        assert!(report.refusals.contains(&Refusal::NoTurnLine), "{report:?}");
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| gap.field == "account.turn_line" && gap.reason.starts_with("not found")),
            "{report:?}"
        );
        let mut given = claude.clone();
        given.account.as_mut().expect("an account").turn_line =
            Some("\"type\":\"turn\"".to_owned());
        let both = check(&given);
        assert!(
            both.refusals.iter().any(|refusal| matches!(
                refusal, Refusal::Contradiction(text) if text.contains("account.turn_line")
            )),
            "{both:?}"
        );
        given.missing.remove("account.turn_line");
        assert_eq!(check(&given).refusals, Vec::new());
    }

    /// A key of `missing` that no part reads is refused, naming the key.
    #[test]
    fn a_key_listed_as_missing_that_no_part_reads_is_refused() {
        let mut build = build_of("kalareach/opencode");
        build
            .missing
            .insert("account.nonsense".to_owned(), "a typing mistake".to_owned());
        assert!(check(&build).refusals.iter().any(|refusal| matches!(
            refusal, Refusal::Contradiction(text) if text.contains("account.nonsense")
        )));
    }

    /// A real start is refused for an entry that lacks the isolation contract, naming what it lacks:
    /// the trees for an entry with an account, and every member for one with none. The Codex entry
    /// keeps its own.
    #[test]
    fn a_real_start_is_refused_for_an_entry_with_no_isolation_contract() {
        let mut opencode = build_of("kalareach/opencode");
        opencode.isolation = None;
        assert_eq!(
            check(&opencode).refusals,
            vec![Refusal::NoIsolation(vec!["person_trees"])]
        );
        let mut attach = build_of("kalareach/opencode-attach");
        attach.isolation = None;
        assert_eq!(
            check(&attach).refusals,
            vec![Refusal::NoIsolation(vec![
                "person_trees",
                "installs_off",
                "absent"
            ])]
        );
        let mut codex = build_of("kalareach/codex");
        codex.isolation = None;
        assert_eq!(check(&codex).refusals, Vec::new());
    }

    /// A real start is refused for a pinned or newer build that the entry does not digest.
    #[test]
    fn a_real_start_is_refused_for_a_build_the_entry_does_not_digest() {
        let mut pinned = build_of("kalareach/opencode");
        pinned.sha256 = "00".to_owned();
        assert_eq!(
            check(&pinned).refusals,
            vec![Refusal::NotDigested("the pinned build")]
        );
        let mut newer = build_of("kalareach/opencode");
        newer.newer.as_mut().expect("a newer build").sha256 = String::new();
        assert_eq!(
            check(&newer).refusals,
            vec![Refusal::NotDigested("the newer build")]
        );
        let mut unnamed = build_of("kalareach/opencode");
        unnamed.newer.as_mut().expect("a newer build").pinned = String::new();
        assert_eq!(
            check(&unnamed).refusals,
            vec![Refusal::NotDigested("the newer build")]
        );
    }

    /// The runtime of a script or a wheel has no digest in the entry; the report names it as placed,
    /// and a real start is not refused for it.
    #[test]
    fn a_runtime_the_entry_does_not_digest_is_reported_as_placed_and_not_refused() {
        let gemini = check(&build_of("kalareach/gemini-cli"));
        assert_eq!(gemini.placed, ["node"]);
        assert!(
            !gemini
                .refusals
                .iter()
                .any(|r| matches!(r, Refusal::NotDigested(_)))
        );
        let kimi = check(&build_of("kalareach/kimi-cli"));
        assert_eq!(kimi.placed, ["python3.12"]);
        assert_eq!(kimi.refusals, Vec::new());
    }

    /// Every gap the table of the driver's gaps names is a field that the list gives as missing for
    /// that package, so a change of the list that leaves the table behind fails here.
    #[test]
    fn every_harness_gap_names_a_field_the_list_gives_as_missing_for_that_package() {
        for (package, field, _) in HARNESS_GAPS {
            assert!(
                build_of(package).missing.contains_key(field),
                "{package} does not list {field} as missing"
            );
        }
    }
}
