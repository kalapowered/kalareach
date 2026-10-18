//! The support window of the public majors (KR-REQ-20.24, KR-REQ-26.07).
//!
//! `PUBLIC_MAJORS` says which majors this build lists, and where each stands: when a later major
//! replaced it, until when it is supported, and whether this build has stopped negotiating it. The
//! window is twelve months from the day a major is replaced, and nothing here reads a clock: a
//! major stops being negotiated only when a release says so (`retired`), and these rules decide
//! when a release may. Each is tested on fixed rows, and the real table is held to the same rules
//! and to the table of every release this build retains, when that release recorded one.

use jiff::civil::Date;
use kr_protocol::hello::{
    PROTOCOL_VERSION, PUBLIC_MAJORS, ProtocolVersion, PublicMajor, select_version,
    supported_versions, supported_versions_of,
};
use kr_protocol::retained::{RETAINED, RETAINED_WORKER_LEVELS};

/// A day, from the first ten characters of an ISO 8601 date or timestamp.
fn day(text: &str) -> Date {
    text.get(..10)
        .and_then(|day| day.parse().ok())
        .unwrap_or_else(|| panic!("{text} does not begin with a day"))
}

/// The day twelve months after `replaced`.
fn twelve_months_after(replaced: &str) -> Date {
    day(replaced)
        .checked_add(jiff::Span::new().months(12))
        .expect("twelve months later is a day")
}

/// What `now` must be, given the table of the release before and the day that release was built,
/// as the broken rules, each in a sentence. None broken is an empty list.
fn broken(previous: &[PublicMajor], previous_released: &str, now: &[PublicMajor]) -> Vec<String> {
    let mut broken = Vec::new();
    for before in previous {
        let Some(row) = now.iter().find(|row| row.major == before.major) else {
            broken.push(format!("major {} is gone from the table", before.major));
            continue;
        };
        if !before.versions.iter().all(|v| row.versions.contains(v)) {
            broken.push(format!("major {} lost a version", before.major));
        }
        if before.replaced.is_some() && before.replaced != row.replaced {
            broken.push(format!("major {}'s replaced day changed", before.major));
        }
        if let (Some(was), Some(is)) = (before.supported_until, row.supported_until)
            && day(is) < day(was)
        {
            broken.push(format!("major {}'s window was shortened", before.major));
        }
        if before.supported_until.is_some() && row.supported_until.is_none() {
            broken.push(format!("major {}'s window was taken away", before.major));
        }
        if before.replaced.is_none()
            && let Some(replaced) = row.replaced
            && day(replaced) < day(previous_released)
        {
            broken.push(format!(
                "major {} was replaced before the release before was built",
                before.major
            ));
        }
        if row.retired && !before.retired {
            match row.supported_until {
                Some(until) if day(previous_released) > day(until) => {}
                _ => broken.push(format!(
                    "major {} is retired in a release whose predecessor was built before its \
                     window ended",
                    before.major
                )),
            }
        }
        if before.retired && !row.retired {
            broken.push(format!("major {} was retired and is not", before.major));
        }
    }
    broken.extend(intrinsic(now));
    broken
}

/// What any table must be, whatever came before it.
fn intrinsic(table: &[PublicMajor]) -> Vec<String> {
    let mut broken = Vec::new();
    if table.iter().all(|row| row.retired) {
        broken.push("every major is retired, so nothing is negotiated".to_owned());
    }
    for row in table {
        if row.versions.is_empty() || row.versions.iter().any(|v| v.major != row.major) {
            broken.push(format!("major {}'s versions are not its own", row.major));
        }
        if table
            .iter()
            .filter(|other| other.major == row.major)
            .count()
            > 1
        {
            broken.push(format!("major {} is in the table twice", row.major));
        }
        match (row.replaced, row.supported_until) {
            (Some(replaced), Some(until)) if day(until) < twelve_months_after(replaced) => {
                broken.push(format!(
                    "major {} is supported for less than twelve months after it was replaced",
                    row.major
                ));
            }
            (None, Some(_)) => broken.push(format!(
                "major {} has a window and was never replaced",
                row.major
            )),
            _ => {}
        }
        if row.retired && (row.replaced.is_none() || row.supported_until.is_none()) {
            broken.push(format!("major {} is retired without a window", row.major));
        }
        if row.replaced.is_some() && !table.iter().any(|other| other.major > row.major) {
            broken.push(format!(
                "major {} is replaced and no later major is in the table",
                row.major
            ));
        }
    }
    broken
}

const ONE: ProtocolVersion = ProtocolVersion::new(1, 0);
const TWO: ProtocolVersion = ProtocolVersion::new(2, 0);
const TWO_ONE: ProtocolVersion = ProtocolVersion::new(2, 1);

fn replaced_major_one() -> PublicMajor {
    PublicMajor {
        major: 1,
        versions: &[ONE],
        replaced: Some("2030-03-01"),
        supported_until: Some("2031-09-01"),
        retired: false,
    }
}

fn current_major_two() -> PublicMajor {
    PublicMajor {
        major: 2,
        versions: &[TWO],
        replaced: None,
        supported_until: None,
        retired: false,
    }
}

/// KR-REQ-20.24, KR-REQ-26.07: the table of this build holds to the rules that need no earlier
/// table, lists the version this build implements, and the versions it lists are what a client
/// offers and a host selects from.
#[test]
fn the_table_of_this_build_holds_to_the_rules_and_lists_its_own_version() {
    assert_eq!(intrinsic(PUBLIC_MAJORS), Vec::<String>::new());
    assert!(supported_versions().contains(&PROTOCOL_VERSION));
    for version in supported_versions() {
        assert_eq!(
            select_version(&[version], &supported_versions()),
            Ok(version)
        );
    }
    // The levels a worker may be at while the window lasts are never none.
    assert!(!RETAINED_WORKER_LEVELS.is_empty());
}

/// KR-REQ-26.07: a major that is replaced has a later major in the table, and a window needs a
/// replacement.
#[test]
fn a_replaced_major_needs_a_later_one() {
    let alone = [replaced_major_one()];
    assert_eq!(intrinsic(&alone).len(), 1);
    assert!(intrinsic(&[replaced_major_one(), current_major_two()]).is_empty());
}

/// KR-REQ-26.07: the release before this one keeps a record of its table whatever worker levels
/// remain, from the first level whose release had a table.
#[test]
fn a_level_from_the_first_with_a_table_records_it() {
    let first = kr_protocol::update::CompatibilityLevel::of(
        kr_protocol::hello::PackageVersion::new(0, 75, 0),
    );
    for level in &RETAINED {
        if level.level >= first {
            assert!(
                level.public_majors.is_some(),
                "level {} was cut from a release that listed a table, and has no record of it",
                level.level
            );
        }
    }
}

/// KR-REQ-26.07: a table is held to the table of the release before it. The control passes; each
/// way of shortening the window or ending it early is refused: an eighteen-month promise
/// retired at twelve months, a retirement by a release whose predecessor was built before the window
/// ended, a replacement dated before the release before was built, a lowered `supported_until`, a
/// changed `replaced`, a lost version, and a major that is gone.
#[test]
fn a_table_that_shortens_or_ends_a_window_early_is_refused() {
    let previous = [replaced_major_one(), current_major_two()];
    let built = "2031-10-02T09:00:00+00:00";

    // The control: retired once the release before was built after the window had ended.
    let retired = [
        PublicMajor {
            retired: true,
            ..replaced_major_one()
        },
        current_major_two(),
    ];
    assert_eq!(broken(&previous, built, &retired), Vec::<String>::new());
    // The same retirement by a release whose predecessor was built a day before the window ended.
    assert_eq!(
        broken(&previous, "2031-08-31T09:00:00+00:00", &retired).len(),
        1
    );
    // A window of twelve months and a day is long enough; eleven months is not.
    let eleven_months = PublicMajor {
        supported_until: Some("2031-01-15"),
        ..replaced_major_one()
    };
    assert_eq!(intrinsic(&[eleven_months, current_major_two()]).len(), 1);
    // An eighteen-month window cut to twelve.
    let lowered = [
        PublicMajor {
            supported_until: Some("2031-03-01"),
            ..replaced_major_one()
        },
        current_major_two(),
    ];
    assert_eq!(broken(&previous, built, &lowered).len(), 1);
    // A replacement dated before the release before it was built.
    let before_one = [PublicMajor {
        major: 1,
        versions: &[ONE],
        replaced: None,
        supported_until: None,
        retired: false,
    }];
    let backdated = [
        PublicMajor {
            replaced: Some("2030-03-01"),
            supported_until: Some("2031-03-01"),
            ..replaced_major_one()
        },
        current_major_two(),
    ];
    assert_eq!(
        broken(&before_one, "2030-06-01T00:00:00+00:00", &backdated).len(),
        1
    );
    assert!(broken(&before_one, "2030-02-01T00:00:00+00:00", &backdated).is_empty());
    // A replaced day that moved.
    let moved = [
        PublicMajor {
            replaced: Some("2030-04-01"),
            supported_until: Some("2031-09-01"),
            ..replaced_major_one()
        },
        current_major_two(),
    ];
    assert_eq!(broken(&previous, built, &moved).len(), 1);
    // A version lost, and a major gone.
    let lost = [
        PublicMajor {
            versions: &[],
            ..replaced_major_one()
        },
        current_major_two(),
    ];
    assert!(!broken(&previous, built, &lost).is_empty());
    assert!(!broken(&previous, built, &[current_major_two()]).is_empty());
}

/// KR-REQ-26.07: a retired major is no longer listed, and one that is not retired is, with every
/// version of it.
#[test]
fn a_retired_major_is_not_listed_and_the_others_are_with_all_their_versions() {
    const ONE_ONE: ProtocolVersion = ProtocolVersion::new(1, 1);
    let table = [
        PublicMajor {
            retired: true,
            ..replaced_major_one()
        },
        PublicMajor {
            versions: &[TWO, TWO_ONE],
            ..current_major_two()
        },
    ];
    assert_eq!(supported_versions_of(&table), vec![TWO, TWO_ONE]);
    assert_eq!(
        select_version(&[ONE, ONE_ONE], &supported_versions_of(&table)).ok(),
        None
    );
}

/// KR-REQ-26.07: the table of every retained release that recorded one is held against this one
/// by the same rules. A release records its table in `retained/<level>/PUBLIC_MAJORS` as lines of
/// `major=.. versions=.. replaced=.. supported_until=.. retired=..`, and the day it was built in
/// `RELEASE`; the first release to record one is the first after the table existed.
#[test]
fn this_table_holds_to_the_table_of_each_retained_release_that_recorded_one() {
    for level in &RETAINED {
        let Some(recorded) = level.public_majors else {
            continue;
        };
        let rows = parse(recorded);
        let released = level
            .release
            .lines()
            .find_map(|line| line.strip_prefix("released="))
            .expect("a release record names the day it was built");
        assert_eq!(
            broken(&rows, released, PUBLIC_MAJORS),
            Vec::<String>::new(),
            "level {}",
            level.level
        );
    }
}

/// The text between two markers of the document on the support window.
fn block(document: &str, name: &str) -> String {
    let begin = format!("<!-- {name}:begin -->\n");
    let end = format!("<!-- {name}:end -->");
    let from = document
        .find(&begin)
        .unwrap_or_else(|| panic!("the document has no {name} block"))
        + begin.len();
    let to = document[from..]
        .find(&end)
        .unwrap_or_else(|| panic!("the {name} block does not end"));
    document[from..from + to].to_owned()
}

/// The table of public majors as the document shows it.
fn render_majors(table: &[PublicMajor]) -> String {
    let mut text = String::from(
        "| Major | Versions | Replaced | Supported until | Retired |\n| --- | --- | --- | --- | --- |\n",
    );
    for row in table {
        let versions: Vec<String> = row.versions.iter().map(ToString::to_string).collect();
        text.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row.major,
            versions.join(", "),
            row.replaced.unwrap_or("not replaced"),
            row.supported_until.unwrap_or("none"),
            if row.retired { "yes" } else { "no" },
        ));
    }
    text
}

/// The retained levels as the document shows them, each with the release and the day it was built.
fn render_levels() -> String {
    let mut text = String::from("| Level | Release | Built |\n| --- | --- | --- |\n");
    for level in &RETAINED {
        text.push_str(&format!(
            "| {} | {} | {} |\n",
            level.level,
            level
                .record("release")
                .expect("a release record names its release"),
            level
                .record("released")
                .expect("a release record names its day"),
        ));
    }
    text
}

/// KR-REQ-20.24, KR-REQ-26.07: the two tables of `docs/releases/support-window.md` are the table
/// this build has and the levels it retains, as the document is read: they are generated, and a
/// document that differs from them is the document that is wrong.
#[test]
fn the_support_window_document_shows_the_table_and_the_retained_levels() {
    let document = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/releases/support-window.md"),
    )
    .expect("the document on the support window");
    assert_eq!(
        block(&document, "public-majors"),
        render_majors(PUBLIC_MAJORS)
    );
    assert_eq!(block(&document, "retained-levels"), render_levels());
}

/// Reads a recorded table. The text of a recorded row lives for the rest of the process.
fn parse(recorded: &str) -> Vec<PublicMajor> {
    fn leak(text: &str) -> &'static str {
        Box::leak(text.to_owned().into_boxed_str())
    }
    recorded
        .lines()
        .filter(|line| line.starts_with("major="))
        .map(|line| {
            let field = |name: &str| {
                line.split(' ')
                    .find_map(|word| word.strip_prefix(&format!("{name}=")))
                    .unwrap_or_else(|| panic!("{name} is missing in {line}"))
            };
            let optional = |name: &str| (field(name) != "-").then(|| leak(field(name)));
            let versions: Vec<ProtocolVersion> = field("versions")
                .split(',')
                .map(|version| {
                    let (major, minor) = version.split_once('.').expect("major.minor");
                    ProtocolVersion::new(
                        major.parse().expect("a major"),
                        minor.parse().expect("a minor"),
                    )
                })
                .collect();
            PublicMajor {
                major: field("major").parse().expect("a major"),
                versions: Box::leak(versions.into_boxed_slice()),
                replaced: optional("replaced"),
                supported_until: optional("supported_until"),
                retired: match field("retired") {
                    "true" => true,
                    "false" => false,
                    other => panic!("retired is {other} in {line}"),
                },
            }
        })
        .collect()
}
