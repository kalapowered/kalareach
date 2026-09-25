//! The identifiers the report is keyed by, and the one grammar every source is read with.
//!
//! Three families are accepted, each in exactly one written form, which
//! `docs/conformance/README.md` spells out:
//!
//! * a requirement row: the family's prefix, a two-digit section of the specification (01 to 30),
//!   a full stop and a two-digit row within it (01 or later);
//! * a row of section 21's acceptance table, which has 35 rows: the prefix and three digits;
//! * a row of section 27's performance table, which has 10 rows: the prefix and three digits.
//!
//! Anything else that starts like one of them is refused rather than read as something close to
//! it: a bare section, a short or long number, a row past the end of its table, and any other
//! family written in the same shape. A refused mention stops the report before it runs anything,
//! because a key that is almost right is a test counted for a row nobody can find.
//!
//! A requirement row may be followed by further rows of the same family, each written as its
//! section and row alone, joined by a comma, "and", "or" or a slash: a comment that names
//! section 9's rows 12 and 13 may write the second as `09.13`. Nothing else continues a list, so a
//! number in the prose that follows is never read as a row.

use std::fmt;

use serde::Serialize;

/// The last row of section 21's acceptance table.
pub const ACCEPTANCE_ROWS: u16 = 35;

/// The last row of section 27's performance table.
pub const PERFORMANCE_ROWS: u16 = 10;

/// The specification's last section.
pub const SECTIONS: u8 = 30;

/// Which table an identifier belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// A requirement row.
    Requirement,
    /// A row of section 21's acceptance table.
    Acceptance,
    /// A row of section 27's performance table.
    Performance,
}

/// One accepted identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier {
    family: Family,
    section: u8,
    row: u16,
}

impl Identifier {
    /// A requirement row, or `None` when the section or the row is outside the grammar.
    #[must_use]
    pub fn requirement(section: u8, row: u16) -> Option<Self> {
        ((1..=SECTIONS).contains(&section) && (1..=99).contains(&row)).then_some(Self {
            family: Family::Requirement,
            section,
            row,
        })
    }

    /// A row of section 21's table, or `None` when there is no such row.
    #[must_use]
    pub fn acceptance(row: u16) -> Option<Self> {
        (1..=ACCEPTANCE_ROWS).contains(&row).then_some(Self {
            family: Family::Acceptance,
            section: 21,
            row,
        })
    }

    /// A row of section 27's table, or `None` when there is no such row.
    #[must_use]
    pub fn performance(row: u16) -> Option<Self> {
        (1..=PERFORMANCE_ROWS).contains(&row).then_some(Self {
            family: Family::Performance,
            section: 27,
            row,
        })
    }

    /// The family.
    #[must_use]
    pub const fn family(self) -> Family {
        self.family
    }

    /// Every row of section 21's and section 27's tables, which the report lists whether or not a
    /// test names them.
    #[must_use]
    pub fn table_rows() -> Vec<Self> {
        let acceptance = (1..=ACCEPTANCE_ROWS).filter_map(Self::acceptance);
        let performance = (1..=PERFORMANCE_ROWS).filter_map(Self::performance);
        acceptance.chain(performance).collect()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.family {
            Family::Requirement => write!(f, "KR-REQ-{:02}.{:02}", self.section, self.row),
            Family::Acceptance => write!(f, "KR-ACC-{:03}", self.row),
            Family::Performance => write!(f, "KR-PERF-{:03}", self.row),
        }
    }
}

impl Serialize for Identifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl std::str::FromStr for Identifier {
    type Err = Refusal;

    fn from_str(text: &str) -> Result<Self, Refusal> {
        let found = scan(text);
        match found.as_slice() {
            [
                Mention {
                    at: 0,
                    written,
                    read: Ok(identifier),
                },
            ] if written.len() == text.len() => Ok(*identifier),
            [
                Mention {
                    read: Err(refusal), ..
                },
            ] => Err(refusal.clone()),
            _ => Err(Refusal::Malformed(text.to_owned())),
        }
    }
}

/// Why a mention was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", content = "written", rename_all = "snake_case")]
pub enum Refusal {
    /// It starts like an identifier and is not in any accepted form.
    Malformed(String),
    /// An acceptance row past the end of section 21's table.
    OutsideAcceptanceTable(String),
    /// A performance row past the end of section 27's table.
    OutsidePerformanceTable(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(written) => write!(
                f,
                "{written} is not an identifier: the accepted forms are KR-REQ-SS.II, KR-ACC-NNN \
                 and KR-PERF-NNN"
            ),
            Self::OutsideAcceptanceTable(written) => write!(
                f,
                "{written} is not a row of section 21's acceptance table, which ends at \
                 KR-ACC-{ACCEPTANCE_ROWS:03}"
            ),
            Self::OutsidePerformanceTable(written) => write!(
                f,
                "{written} is not a row of section 27's performance table, which ends at \
                 KR-PERF-{PERFORMANCE_ROWS:03}"
            ),
        }
    }
}

/// One place a text names, or tries to name, an identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mention {
    /// The byte offset of the mention in the text it was found in.
    pub at: usize,
    /// What was written, without trailing sentence punctuation.
    pub written: String,
    /// The identifier, or why it was refused.
    pub read: Result<Identifier, Refusal>,
}

/// The families a mention can start with. Every one of them is read, so a family the report does
/// not accept is refused by name rather than passing unnoticed.
const FAMILIES: &[&str] = &["KR-REQ", "KR-ACC", "KR-PERF", "KR-GOAL"];

/// Finds every mention in `text`, in order, with continuations expanded.
#[must_use]
pub fn scan(text: &str) -> Vec<Mention> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let Some(family) = FAMILIES
            .iter()
            .find(|family| bytes[at..].starts_with(family.as_bytes()))
        else {
            at += 1;
            continue;
        };
        // A family glued to the word before it (`XKR-REQ`) or to letters after it (`KR-REQUEST`)
        // is some other word.
        let preceded = at > 0 && is_word(bytes[at - 1]);
        let after = at + family.len();
        let followed = bytes.get(after).is_some_and(u8::is_ascii_alphabetic);
        if preceded || followed {
            at += 1;
            continue;
        }
        let mut end = after;
        while end < bytes.len() && (is_word(bytes[end]) || bytes[end] == b'.' || bytes[end] == b'-')
        {
            end += 1;
        }
        // A full stop or a hyphen that ends the run is punctuation, not part of the mention.
        while end > after && matches!(bytes[end - 1], b'.' | b'-') {
            end -= 1;
        }
        let written = &text[at..end];
        let read = read(family, &text[after..end], written);
        let continues = matches!(read, Ok(identifier) if identifier.family == Family::Requirement);
        found.push(Mention {
            at,
            written: written.to_owned(),
            read,
        });
        at = end;
        if continues {
            at = continuations(text, at, &mut found);
        }
    }
    found
}

/// Reads the requirement rows that continue a list after a requirement row, from `at`, and
/// returns where the list ended.
fn continuations(text: &str, mut at: usize, found: &mut Vec<Mention>) -> usize {
    const JOINS: &[&str] = &[", and ", ", or ", ", ", " and ", " or ", "/", ","];
    loop {
        let rest = &text[at..];
        let Some(join) = JOINS.iter().find(|join| rest.starts_with(**join)) else {
            return at;
        };
        let start = at + join.len();
        let Some((section, row, end)) = short_row(text, start) else {
            return at;
        };
        let written = &text[start..end];
        let read = Identifier::requirement(section, row)
            .ok_or_else(|| Refusal::Malformed(written.to_owned()));
        found.push(Mention {
            at: start,
            written: written.to_owned(),
            read,
        });
        at = end;
    }
}

/// Reads `SS.II` at `at`, when that is exactly what is there: two digits, a full stop and two
/// digits, followed by neither a digit nor another digit group.
fn short_row(text: &str, at: usize) -> Option<(u8, u16, usize)> {
    let bytes = text.as_bytes();
    let digits = |from: usize| {
        bytes
            .get(from..from + 2)
            .filter(|d| d.iter().all(u8::is_ascii_digit))
    };
    let section = digits(at)?;
    if bytes.get(at + 2) != Some(&b'.') {
        return None;
    }
    let row = digits(at + 3)?;
    let end = at + 5;
    let next = bytes.get(end).copied();
    let after_next = bytes.get(end + 1).copied();
    if next.is_some_and(|b| is_word(b) || b == b'-')
        || (next == Some(b'.') && after_next.is_some_and(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let number = |pair: &[u8]| u16::from(pair[0] - b'0') * 10 + u16::from(pair[1] - b'0');
    let section = u8::try_from(number(section)).ok()?;
    Some((section, number(row), end))
}

fn read(family: &str, tail: &str, written: &str) -> Result<Identifier, Refusal> {
    let malformed = || Refusal::Malformed(written.to_owned());
    let digits = |text: &str, count: usize| {
        (text.len() == count && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse::<u16>().ok())
            .flatten()
    };
    let tail = tail.strip_prefix('-').ok_or_else(malformed)?;
    match family {
        "KR-REQ" => {
            let (section, row) = tail.split_once('.').ok_or_else(malformed)?;
            let section = digits(section, 2)
                .and_then(|s| u8::try_from(s).ok())
                .ok_or_else(malformed)?;
            let row = digits(row, 2).ok_or_else(malformed)?;
            Identifier::requirement(section, row).ok_or_else(malformed)
        }
        "KR-ACC" => {
            let row = digits(tail, 3).ok_or_else(malformed)?;
            Identifier::acceptance(row)
                .ok_or_else(|| Refusal::OutsideAcceptanceTable(written.to_owned()))
        }
        "KR-PERF" => {
            let row = digits(tail, 3).ok_or_else(malformed)?;
            Identifier::performance(row)
                .ok_or_else(|| Refusal::OutsidePerformanceTable(written.to_owned()))
        }
        _ => Err(malformed()),
    }
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The identifiers a test's own name carries, in the snake-case spelling of the accepted forms:
/// `kr_req_11_07_...`, `kr_acc_004_...` or `kr_perf_007_...`.
///
/// A name is a name, not a comment, so a name that does not spell an accepted form is not a key and
/// is not refused either: it is only a test called that.
#[must_use]
pub fn in_test_name(name: &str) -> Vec<Identifier> {
    let words: Vec<&str> = name.split('_').collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 1 < words.len() {
        if words[index] != "kr" {
            index += 1;
            continue;
        }
        let number = |word: Option<&&str>, count: usize| {
            word.filter(|w| w.len() == count && w.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|w| w.parse::<u16>().ok())
        };
        let identifier = match words[index + 1] {
            "req" => number(words.get(index + 2), 2).and_then(|section| {
                let row = number(words.get(index + 3), 2)?;
                Identifier::requirement(u8::try_from(section).ok()?, row)
            }),
            "acc" => number(words.get(index + 2), 3).and_then(Identifier::acceptance),
            "perf" => number(words.get(index + 2), 3).and_then(Identifier::performance),
            _ => None,
        };
        if let Some(identifier) = identifier {
            found.push(identifier);
        }
        index += 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(text: &str) -> Vec<String> {
        scan(text)
            .into_iter()
            .map(|mention| match mention.read {
                Ok(identifier) => identifier.to_string(),
                Err(refusal) => format!("refused {refusal:?}"),
            })
            .collect()
    }

    #[test]
    fn each_accepted_form_is_read_and_written_back_the_same() {
        assert_eq!(
            read_all("KR-REQ-08.60, KR-ACC-004 and (KR-PERF-007)."),
            ["KR-REQ-08.60", "KR-ACC-004", "KR-PERF-007"]
        );
    }

    #[test]
    fn a_list_of_short_rows_continues_a_requirement_row() {
        assert_eq!(
            read_all("KR-REQ-09.09, 09.12 and 26.16: the receipts"),
            ["KR-REQ-09.09", "KR-REQ-09.12", "KR-REQ-26.16"]
        );
        assert_eq!(
            read_all("KR-REQ-15.02 and 15.14."),
            ["KR-REQ-15.02", "KR-REQ-15.14"]
        );
    }

    #[test]
    fn a_number_in_the_prose_after_a_row_is_not_a_row() {
        assert_eq!(
            read_all("KR-REQ-24.30 and the incomplete archive of 24.21, at 12.50 MiB"),
            ["KR-REQ-24.30"]
        );
        assert_eq!(read_all("KR-REQ-01.02 and 1.53.1"), ["KR-REQ-01.02"]);
        assert_eq!(read_all("KR-REQ-01.02, 12.345"), ["KR-REQ-01.02"]);
    }

    #[test]
    fn every_other_form_is_refused_by_what_was_written() {
        for written in [
            "KR-REQ-09",
            "KR-REQ-7.84",
            "KR-REQ-07.8",
            "KR-REQ-07.084",
            "KR-REQ-31.01",
            "KR-REQ-07.00",
            "KR-REQ_07.84",
            "KR-REQ-07.84a",
            "KR-ACC-04",
            "KR-ACC-0004",
            "KR-PERF-7",
            "KR-GOAL-34",
        ] {
            let found = scan(&format!("see {written}: the text"));
            assert_eq!(found.len(), 1, "{written}");
            assert_eq!(found[0].written, written);
            assert_eq!(found[0].read, Err(Refusal::Malformed(written.to_owned())));
        }
    }

    #[test]
    fn a_row_past_the_end_of_its_table_is_refused() {
        let past = format!("KR-ACC-{:03}", ACCEPTANCE_ROWS + 1);
        assert_eq!(
            scan(&past)[0].read,
            Err(Refusal::OutsideAcceptanceTable(past.clone()))
        );
        let past = format!("KR-PERF-{:03}", PERFORMANCE_ROWS + 1);
        assert_eq!(
            scan(&past)[0].read,
            Err(Refusal::OutsidePerformanceTable(past.clone()))
        );
        assert!(scan("KR-ACC-000")[0].read.is_err());
    }

    #[test]
    fn a_family_inside_another_word_is_not_a_mention() {
        assert!(scan("KR-REQUEST-ID and XKR-REQ-01.01 and KR-CBOR-1").is_empty());
    }

    #[test]
    fn a_test_name_spells_its_rows_in_snake_case() {
        let rows = |name: &str| -> Vec<String> {
            in_test_name(name).iter().map(ToString::to_string).collect()
        };
        assert_eq!(rows("kr_req_11_07_metadata_is_refused"), ["KR-REQ-11.07"]);
        assert_eq!(
            rows("kr_acc_004_and_kr_perf_007_hold"),
            ["KR-ACC-004", "KR-PERF-007"]
        );
        assert!(rows("kr_req_09_a_request_that_went").is_empty());
        assert!(rows("kr_acc_036_is_past_the_table").is_empty());
        assert!(rows("an_ordinary_test").is_empty());
    }

    #[test]
    fn the_tables_list_every_acceptance_and_performance_row() {
        let rows = Identifier::table_rows();
        assert_eq!(rows.len(), usize::from(ACCEPTANCE_ROWS + PERFORMANCE_ROWS));
        assert_eq!(rows[0].to_string(), "KR-ACC-001");
        assert_eq!(rows[rows.len() - 1].to_string(), "KR-PERF-010");
    }
}
