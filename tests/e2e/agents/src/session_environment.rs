//! The environment of a session's shell, read at its prompt a moment before the first typing.
//!
//! The harness hands a list of variables to `kr new`, and the host's worker keeps every name of it
//! but the ones the host owns. Nothing else shows what the shell really holds, so before the agent
//! is typed (and while no agent has run) the harness types lines at the shell's prompt. They print,
//! for each name the worker keeps, the name and a digest of the run's marker, the name and the
//! value together, and the names of the variables the shell exports. The harness reads the answer
//! from the window's own screen, computes the same digests from its own list, and refuses the
//! typing on a digest that differs, a name that is missing, an exported name the build list
//! forbids, or a name of its list that the host would drop.
//!
//! **No value appears anywhere.** A value is never on a command line, on the screen, in a file or
//! in a failure text: the shell's `printf` is a builtin, and the value goes to the digest program
//! on its standard input only. A failure names the variable and never a value. The digest is keyed
//! with the run's marker, so a secret has no digest of its own value alone.
//!
//! **The answer is read whole.** The screen holds [`kr_e2e_m1b::window::ROWS`] rows, so the names
//! are asked for in parts of at most [`PART_NAMES`], one row each, on a cleared screen; every part
//! ends with a row that carries its own number, and a part is read only after that row shows.
//! A part whose end row shows but which lacks the row of a name asked for was cut, and is refused,
//! never taken for a missing variable.
//!
//! What this proves is the shell's environment at its prompt, before any agent has run. It does
//! not prove what the agent reads later: a start of the agent, a startup file and the agent's own
//! children can all change it.

use std::fmt;

use kr_protocol::hostinfo::configuration::{host_owns_variable, platform_variable_name};

use crate::keys;

/// The word every row of an answer begins with, so that a row of it is not taken for anything else
/// the screen shows (the echo of the typed line included, which holds no row of this form).
pub const ROW: &str = "KRENV";

/// The most names one typed line asks for, so that its echo and its answer fit the screen.
pub const PART_NAMES: usize = 10;

/// How many characters of the digest an answer shows: 64 bits, keyed with the run's marker.
const DIGEST_CHARACTERS: usize = 16;

/// The shortest value whose appearance on the screen the check looks for.
pub const SHORTEST_VALUE_CHECKED: usize = 8;

/// The longest name the check reads, so that a row is one row of the screen.
const NAME_CHARACTERS: usize = 60;

/// How a failure begins when the shell's environment is not as the harness gave it.
pub const NOT_AS_GIVEN: &str = "the session's environment is not as the harness gave it:";

/// How the line a pass prints begins.
pub const PASSED: &str = "the session's environment, read at its prompt before the first typing:";

/// How a failure begins when the answer could not be read whole.
pub const NOT_READ_WHOLE: &str =
    "the session's environment could not be read whole before the first typing:";

/// How a failure begins when the harness's own list holds a name the host would drop.
pub const HOST_WOULD_DROP: &str = "the harness's list holds a name the host drops from a session:";

/// What the shell answers for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// The shell does not export the name.
    Missing,
    /// The first characters of the digest of the run's marker, the name and the value.
    Digest(String),
}

/// The digest the shell and the harness both compute: the first characters of the SHA-256 of the
/// run's marker, the name and the value, each followed by a zero byte but the value. The marker
/// is in it so that no digest stands for a value alone.
#[must_use]
pub fn digest(marker: &str, name: &str, value: &str) -> String {
    let mut bytes = Vec::with_capacity(marker.len() + name.len() + value.len() + 2);
    bytes.extend_from_slice(marker.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(value.as_bytes());
    let mut text = String::with_capacity(64);
    for byte in kr_cbor::sha256(&bytes) {
        text.push_str(&format!("{byte:02x}"));
    }
    text.truncate(DIGEST_CHARACTERS);
    text
}

/// The program the shell pipes the digest's input to, by its absolute path.
const fn digest_program() -> &'static str {
    if cfg!(target_os = "macos") {
        "/usr/bin/shasum -a 256"
    } else {
        "/usr/bin/sha256sum"
    }
}

/// What the harness expects of the session's shell: the list it handed to `kr new`, less the names
/// the host owns, and what the build list forbids the shell to export.
///
/// It holds values, so what a print of it shows is the names.
pub struct Expected {
    marker_name: String,
    marker: String,
    kept: Vec<(String, String)>,
    cleared: Vec<String>,
    allowed: Vec<String>,
}

impl fmt::Debug for Expected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Expected")
            .field("marker_name", &self.marker_name)
            .field(
                "names",
                &self.kept.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .field("cleared", &self.cleared)
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

impl Expected {
    /// The expectation for the `list` handed to `kr new`, whose run is marked `marker` (name and
    /// value). `for_the_host` are the names the harness gives `kr` itself and the host drops from
    /// the session by design (the host's own directories, the terminal's identity); any other name
    /// of the list that the host owns would be dropped in silence and is refused. `cleared` are
    /// the build list's patterns for variables the shell may not export, except the names in
    /// `allowed`.
    ///
    /// # Errors
    ///
    /// Returns why, naming the variable and never a value: a name the host would drop, a name the
    /// check cannot ask the shell for, or a list that does not hold the run's marker.
    pub fn new(
        list: &[(String, String)],
        marker: (&str, &str),
        for_the_host: &[String],
        cleared: &[String],
        allowed: &[String],
    ) -> Result<Self, String> {
        let mut kept: Vec<(String, String)> = Vec::new();
        for (name, value) in list {
            if host_owns_variable(&platform_variable_name(name)) {
                if for_the_host.contains(name) {
                    continue;
                }
                return Err(format!(
                    "{HOST_WOULD_DROP} {name}, which the host owns, so no session of it would \
                     have the variable"
                ));
            }
            if !asks_for(name) {
                return Err(format!(
                    "{NOT_READ_WHOLE} the variable {name} has a name the check cannot ask the \
                     shell for (letters, digits and underscores, at most {NAME_CHARACTERS})"
                ));
            }
            // The worker holds a name once, the last value given.
            kept.retain(|(held, _)| held != name);
            kept.push((name.clone(), value.clone()));
        }
        kept.sort();
        if !kept.iter().any(|(name, _)| name == marker.0) {
            return Err(format!(
                "{NOT_AS_GIVEN} the run's marker {} is not in the list the harness gives the \
                 session",
                marker.0
            ));
        }
        Ok(Self {
            marker_name: marker.0.to_owned(),
            marker: marker.1.to_owned(),
            kept,
            cleared: cleared.to_vec(),
            allowed: allowed.to_vec(),
        })
    }

    /// The names the check asks the shell for, in the order of its parts.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.kept.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// How many typed lines ask for the digests.
    #[must_use]
    pub fn value_parts(&self) -> usize {
        self.kept.len().div_ceil(PART_NAMES)
    }

    /// The names asked for by part `part`.
    fn part(&self, part: usize) -> &[(String, String)] {
        let start = (part * PART_NAMES).min(self.kept.len());
        let end = (start + PART_NAMES).min(self.kept.len());
        &self.kept[start..end]
    }

    /// The line to type for the digests of part `part`, whose end row carries `tag`. The line holds
    /// names and the digest program, and no value.
    #[must_use]
    pub fn value_line(&self, part: usize, tag: usize) -> String {
        let names: Vec<&str> = self
            .part(part)
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        format!(
            "for n in {names}; do if [[ ${{parameters[$n]}} == *export* ]]; then \
             d=$(printf '%s\\0%s\\0%s' \"${{{marker}}}\" \"$n\" \"${{(P)n}}\" | {program}); \
             print -r -- \"{ROW} value $n ${{d[1,{DIGEST_CHARACTERS}]}}\"; \
             else print -r -- \"{ROW} value $n missing\"; fi; done; unset d n; \
             print -r -- \"{ROW} end {tag}\"",
            names = names.join(" "),
            marker = self.marker_name,
            program = digest_program(),
        )
    }

    /// The line to type for the names the shell exports, from the one after `skipped` of its sorted
    /// list on, whose end row carries `tag`: it also says how many names the shell exports.
    #[must_use]
    pub fn exported_line(skipped: usize, tag: usize) -> String {
        let (first, last) = (skipped + 1, skipped + PART_NAMES);
        format!(
            "e=(${{(ko)parameters[(R)*export*]}}); for n in ${{e[{first},{last}]}}; do \
             print -r -- \"{ROW} exported $n\"; done; print -r -- \"{ROW} total ${{#e}}\"; \
             unset e n; print -r -- \"{ROW} end {tag}\""
        )
    }

    /// The line a pass prints, so that a log shows the check ran and what it compared: the names
    /// compared, `ok`, and how many names the shell exports. Never a value and never a digest.
    #[must_use]
    pub fn passed_line(&self, exported: usize) -> String {
        format!(
            "{PASSED} ok: {} ({} names compared, {exported} exported names read)",
            self.names().join(", "),
            self.kept.len()
        )
    }

    /// The name of a variable whose value the screen's `rows` show, where one does: no line the
    /// check types holds a value and no shell prints one, so a row that shows one is a leak. A
    /// value shorter than [`SHORTEST_VALUE_CHECKED`] characters is not looked for: it would be found
    /// in the screen's own words.
    #[must_use]
    pub fn shown_on(&self, rows: &[String]) -> Option<&str> {
        self.kept
            .iter()
            .filter(|(_, value)| value.chars().count() >= SHORTEST_VALUE_CHECKED)
            .find(|(_, value)| rows.iter().any(|row| row.contains(value.as_str())))
            .map(|(name, _)| name.as_str())
    }

    /// What part `part` of the answer says, read from the `rows` of the screen once the row that
    /// ends it, numbered `tag`, shows.
    ///
    /// # Errors
    ///
    /// Returns why the answer is not whole: no end row, a name asked for with no row, or a name
    /// with two.
    pub fn read_values(
        &self,
        part: usize,
        tag: usize,
        rows: &[String],
    ) -> Result<Vec<(String, Reading)>, String> {
        let answer = rows_before_the_end(rows, tag)?;
        let mut readings = Vec::new();
        for (name, _) in self.part(part) {
            let mut said = answer.iter().filter_map(|row| match row {
                Row::Value(named, reading) if named == name => Some(reading.clone()),
                _ => None,
            });
            match (said.next(), said.next()) {
                (Some(reading), None) => readings.push((name.clone(), reading)),
                (None, _) => {
                    return Err(format!(
                        "{NOT_READ_WHOLE} the screen shows the end of part {part} and no row for \
                         {name}, so the answer was cut"
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "{NOT_READ_WHOLE} the screen shows two rows for {name}"
                    ));
                }
            }
        }
        Ok(readings)
    }

    /// Judges the whole answer: the `readings` of every name asked for and the names `exported`
    /// by the shell, as many as it said it exports.
    ///
    /// # Errors
    ///
    /// Returns why, naming each variable that differs, is missing, or is exported though the
    /// build list forbids it, and never a value.
    pub fn judge(&self, readings: &[(String, Reading)], exported: &[String]) -> Result<(), String> {
        let reading_of = |name: &str| {
            readings
                .iter()
                .find(|(named, _)| named == name)
                .map(|(_, reading)| reading)
        };
        let given = |name: &str, value: &str| Reading::Digest(digest(&self.marker, name, value));
        // The marker is in every digest: a shell whose marker is not the run's has no digest of
        // any other name that can be trusted either way.
        let marker_given = self
            .kept
            .iter()
            .find(|(name, _)| *name == self.marker_name)
            .map(|(name, value)| given(name, value));
        if reading_of(&self.marker_name) != marker_given.as_ref() {
            return Err(format!(
                "{NOT_AS_GIVEN} the run's marker {} is not in the shell as the harness gave it, \
                 so no other name was compared",
                self.marker_name
            ));
        }
        if !exported.contains(&self.marker_name) {
            return Err(format!(
                "{NOT_READ_WHOLE} the names the shell exports do not hold {}",
                self.marker_name
            ));
        }
        let mut differs = Vec::new();
        let mut missing = Vec::new();
        for (name, value) in &self.kept {
            match reading_of(name) {
                Some(Reading::Digest(shown)) if *shown == digest(&self.marker, name, value) => {}
                Some(Reading::Digest(_)) => differs.push(name.as_str()),
                Some(Reading::Missing) | None => missing.push(name.as_str()),
            }
        }
        let forbidden: Vec<&str> = exported
            .iter()
            .map(String::as_str)
            .filter(|name| !self.allowed.iter().any(|allowed| allowed == name))
            .filter(|name| keys::cleared(&self.cleared, name))
            .collect();
        let mut why = Vec::new();
        if !differs.is_empty() {
            why.push(format!(
                "the shell's value is not the one given for {}",
                differs.join(", ")
            ));
        }
        if !missing.is_empty() {
            why.push(format!(
                "the shell does not export {}, which was given",
                missing.join(", ")
            ));
        }
        if !forbidden.is_empty() {
            why.push(format!(
                "the shell exports {}, which the build list clears",
                forbidden.join(", ")
            ));
        }
        if why.is_empty() {
            Ok(())
        } else {
            Err(format!("{NOT_AS_GIVEN} {}", why.join("; ")))
        }
    }
}

/// What the screen's rows say of the names the shell exports: the names this part lists, and how
/// many names the shell exports in all.
///
/// # Errors
///
/// Returns why the answer is not whole: no end row numbered `tag`, no count, or a row as wide as
/// the screen, which a longer name would wrap.
pub fn read_exported(tag: usize, rows: &[String]) -> Result<(Vec<String>, usize), String> {
    let answer = rows_before_the_end(rows, tag)?;
    let mut names = Vec::new();
    let mut total = None;
    for row in &answer {
        match row {
            Row::Exported(name) => names.push((*name).to_owned()),
            Row::Total(count) => total = Some(*count),
            _ => {}
        }
    }
    let Some(total) = total else {
        return Err(format!(
            "{NOT_READ_WHOLE} the screen shows the end of the answer and not how many names the \
             shell exports"
        ));
    };
    let columns = usize::from(kr_e2e_m1b::window::COLUMNS);
    if rows
        .iter()
        .any(|row| row.trim_end().starts_with(ROW) && row.trim_end().chars().count() >= columns)
    {
        return Err(format!(
            "{NOT_READ_WHOLE} a name the shell exports is as wide as the screen, which wraps it"
        ));
    }
    Ok((names, total))
}

/// The rows of one answer, before the row that ends it.
enum Row<'a> {
    Value(&'a str, Reading),
    Exported(&'a str),
    Total(usize),
}

/// Reads the rows that are answer rows and that come before the row `KRENV end <tag>`.
fn rows_before_the_end(rows: &[String], tag: usize) -> Result<Vec<Row<'_>>, String> {
    let mut answer = Vec::new();
    for row in rows {
        let words: Vec<&str> = row.split_whitespace().collect();
        match words.as_slice() {
            [first, "end", number] if *first == ROW && *number == tag.to_string() => {
                return Ok(answer);
            }
            [first, "value", name, said] if *first == ROW && asks_for(name) => {
                if *said == "missing" {
                    answer.push(Row::Value(name, Reading::Missing));
                } else if said.len() == DIGEST_CHARACTERS
                    && said.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    answer.push(Row::Value(name, Reading::Digest((*said).to_owned())));
                }
            }
            [first, "exported", name] if *first == ROW => answer.push(Row::Exported(name)),
            [first, "total", count] if *first == ROW => {
                if let Ok(count) = count.parse() {
                    answer.push(Row::Total(count));
                }
            }
            _ => {}
        }
    }
    Err(format!(
        "{NOT_READ_WHOLE} the screen does not show the end row of the answer (number {tag})"
    ))
}

/// Whether the check can ask the shell for `name`: it is typed unquoted and read back as one row.
fn asks_for(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_CHARACTERS
        && !name.starts_with(|character: char| character.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "E2E_RUN_MARK";

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn texts(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_owned()).collect()
    }

    fn the_list() -> Vec<(String, String)> {
        pairs(&[
            (MARKER, "run-1"),
            ("HOME", "/run/h"),
            ("CODEX_HOME", "/run/agent-config"),
            ("PROVIDER_LOGIN", "not-a-real-login"),
            ("KR_STATE_DIR", "/run/s"),
            ("TERM", "xterm-256color"),
        ])
    }

    fn expected(cleared: &[&str], allowed: &[&str]) -> Expected {
        Expected::new(
            &the_list(),
            (MARKER, "run-1"),
            &texts(&["KR_STATE_DIR", "TERM"]),
            &texts(cleared),
            &texts(allowed),
        )
        .expect("an expectation")
    }

    /// The rows a shell that holds exactly `held` writes for every part, and the names it exports.
    fn answer_of(held: &[(&str, &str)], expected: &Expected) -> Answer {
        let held = pairs(held);
        let mut readings = Vec::new();
        for (name, _) in &expected.kept {
            readings.push((
                name.clone(),
                held.iter()
                    .find(|(held, _)| held == name)
                    .map_or(Reading::Missing, |(_, value)| {
                        Reading::Digest(digest("run-1", name, value))
                    }),
            ));
        }
        Answer {
            readings,
            exported: held.iter().map(|(name, _)| name.clone()).collect(),
        }
    }

    struct Answer {
        readings: Vec<(String, Reading)>,
        exported: Vec<String>,
    }

    fn the_run_shell() -> Vec<(&'static str, &'static str)> {
        vec![
            (MARKER, "run-1"),
            ("HOME", "/run/h"),
            ("CODEX_HOME", "/run/agent-config"),
            ("PROVIDER_LOGIN", "not-a-real-login"),
            ("PATH", "/usr/bin"),
        ]
    }

    /// The digest of a fixed marker, name and value, as `printf '%s\0%s\0%s' abc123 HOME /tmp/x |
    /// shasum -a 256` prints it: the shell and the harness compute the same.
    #[test]
    fn the_digest_is_the_one_a_shell_computes_from_its_marker_name_and_value() {
        assert_eq!(digest("abc123", "HOME", "/tmp/x"), "d8d7f90cd10cd391");
        assert_ne!(
            digest("abc123", "HOME", "/tmp/x"),
            digest("other", "HOME", "/tmp/x")
        );
    }

    #[test]
    fn a_shell_that_holds_what_it_was_given_passes() {
        let expected = expected(&["*_LOGIN"], &["PROVIDER_LOGIN"]);
        let answer = answer_of(&the_run_shell(), &expected);
        assert_eq!(expected.judge(&answer.readings, &answer.exported), Ok(()));
    }

    #[test]
    fn a_value_that_differs_is_refused_by_its_name_and_never_shows_either_value() {
        let expected = expected(&[], &[]);
        let mut shell = the_run_shell();
        shell[3] = ("PROVIDER_LOGIN", "another-login");
        let answer = answer_of(&shell, &expected);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a changed value is refused");
        assert!(why.contains("PROVIDER_LOGIN"), "{why}");
        assert!(
            !why.contains("another-login") && !why.contains("not-a-real-login"),
            "{why}"
        );
        assert!(!why.contains("HOME,") && !why.contains(" HOME"), "{why}");
    }

    #[test]
    fn a_name_the_shell_does_not_export_is_refused_by_its_name() {
        let expected = expected(&[], &[]);
        let mut shell = the_run_shell();
        shell.retain(|(name, _)| *name != "CODEX_HOME");
        let answer = answer_of(&shell, &expected);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a missing name is refused");
        assert!(
            why.contains("CODEX_HOME") && why.contains("does not export"),
            "{why}"
        );
    }

    #[test]
    fn an_exported_name_the_build_list_clears_is_refused_unless_the_list_sets_it_itself() {
        let expected = expected(&["*_API_KEY", "PROVIDER_*"], &["PROVIDER_LOGIN"]);
        let mut shell = the_run_shell();
        shell.push(("OPENAI_API_KEY", "not-a-real-key"));
        let answer = answer_of(&shell, &expected);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a forbidden exported name is refused");
        assert!(
            why.contains("OPENAI_API_KEY") && why.contains("clears"),
            "{why}"
        );
        assert!(
            !why.contains("PROVIDER_LOGIN") && !why.contains("not-a-real-key"),
            "{why}"
        );
    }

    #[test]
    fn a_name_of_the_list_the_host_would_drop_is_refused_before_anything_is_typed() {
        let mut list = the_list();
        list.push(("KR_VARIANTS".to_owned(), "1".to_owned()));
        let why = Expected::new(
            &list,
            (MARKER, "run-1"),
            &texts(&["KR_STATE_DIR", "TERM"]),
            &[],
            &[],
        )
        .expect_err("a name the host drops is refused");
        assert!(
            why.contains("KR_VARIANTS") && why.contains("drops"),
            "{why}"
        );
        // The names the harness gives `kr` itself, and the host drops by design, are not asked for.
        assert!(!expected(&[], &[]).names().contains(&"KR_STATE_DIR"));
        assert!(!expected(&[], &[]).names().contains(&"TERM"));
    }

    #[test]
    fn a_list_without_the_runs_marker_or_with_a_name_the_check_cannot_ask_for_is_refused() {
        let list = pairs(&[("HOME", "/run/h")]);
        let why = Expected::new(&list, (MARKER, "run-1"), &[], &[], &[])
            .expect_err("no marker is refused");
        assert!(why.contains(MARKER), "{why}");
        let list = pairs(&[(MARKER, "run-1"), ("A B", "x")]);
        let why = Expected::new(&list, (MARKER, "run-1"), &[], &[], &[])
            .expect_err("a name with a space is refused");
        assert!(why.contains("A B"), "{why}");
    }

    #[test]
    fn a_marker_the_shell_does_not_hold_is_the_one_failure_and_no_other_name_is_compared() {
        let expected = expected(&[], &[]);
        let mut shell = the_run_shell();
        shell[0] = (MARKER, "another-run");
        let answer = answer_of(&shell, &expected);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a marker that differs is refused");
        assert!(
            why.contains(MARKER) && why.contains("no other name was compared"),
            "{why}"
        );
        assert!(!why.contains("HOME"), "{why}");
    }

    #[test]
    fn the_names_are_asked_for_in_parts_that_fit_the_screen_and_no_line_holds_a_value() {
        let many: Vec<(String, String)> = (0..25)
            .map(|index| (format!("NAME_{index:02}"), format!("secret-value-{index}")))
            .chain([(MARKER.to_owned(), "run-1".to_owned())])
            .collect();
        let expected =
            Expected::new(&many, (MARKER, "run-1"), &[], &[], &[]).expect("an expectation");
        assert_eq!(expected.value_parts(), 3);
        let mut asked = 0;
        for part in 0..expected.value_parts() {
            let line = expected.value_line(part, part);
            assert!(
                !line.contains("secret-value") && !line.contains("run-1"),
                "{line}"
            );
            assert!(!line.contains('\n') && !line.contains('\r'), "one line");
            asked += line.matches("NAME_").count() + line.matches(MARKER).count() - 1;
        }
        assert_eq!(asked, 26, "every name is asked for once");
        for part in 0..expected.value_parts() {
            assert!(expected.part(part).len() <= PART_NAMES);
        }
    }

    #[test]
    fn an_answer_whose_rows_were_cut_is_refused_and_not_taken_for_a_missing_name() {
        let expected = expected(&[], &[]);
        let names = expected.names();
        let whole: Vec<String> = names
            .iter()
            .map(|name| format!("{ROW} value {name} {}", "0".repeat(DIGEST_CHARACTERS)))
            .chain([format!("{ROW} end 7")])
            .collect();
        assert!(expected.read_values(0, 7, &whole).is_ok());
        // The first rows scrolled off the screen.
        let scrolled = &whole[2..];
        let why = expected
            .read_values(0, 7, scrolled)
            .expect_err("a scrolled answer is refused");
        assert!(why.contains("cut") && why.contains(names[0]), "{why}");
        // The line was still running when the screen was read: no end row.
        let early = &whole[..whole.len() - 1];
        let why = expected
            .read_values(0, 7, early)
            .expect_err("an answer without its end row is refused");
        assert!(why.contains("end row"), "{why}");
        // The end row of another part is not this part's.
        let other = [
            whole[..whole.len() - 1].to_vec(),
            vec![format!("{ROW} end 6")],
        ]
        .concat();
        assert!(expected.read_values(0, 7, &other).is_err());
        // The echo of the typed line is not an answer.
        let echo = vec![expected.value_line(0, 7)];
        assert!(expected.read_values(0, 7, &echo).is_err());
        // A cut list of the exported names.
        let exported = [format!("{ROW} exported {MARKER}"), format!("{ROW} total 3")];
        assert!(read_exported(7, &exported).is_err(), "no end row");
        let width = "N".repeat(usize::from(kr_e2e_m1b::window::COLUMNS) - ROW.len() - 10);
        let wide = [
            format!("{ROW} exported {width}"),
            format!("{ROW} total 1"),
            format!("{ROW} end 7"),
        ];
        assert!(
            read_exported(7, &wide).is_err(),
            "a wrapped row is not a name"
        );
    }

    #[test]
    fn a_pass_prints_the_names_it_compared_and_ok_and_no_value_and_no_digest() {
        let expected = expected(&[], &[]);
        let line = expected.passed_line(12);
        assert!(line.starts_with(PASSED), "{line}");
        assert!(line.contains(": ok: ") && !line.contains('\n'), "{line}");
        assert!(
            line.ends_with("(4 names compared, 12 exported names read)"),
            "{line}"
        );
        for name in ["CODEX_HOME", "E2E_RUN_MARK", "HOME", "PROVIDER_LOGIN"] {
            assert!(line.contains(name), "{name} is in {line}");
        }
        for (name, value) in &the_list() {
            assert!(
                !line.contains(value.as_str()),
                "the value of {name} is in {line}"
            );
            assert!(
                !line.contains(&digest("run-1", name, value)),
                "the digest of {name} is in {line}"
            );
        }
    }

    #[test]
    fn a_row_that_shows_a_value_is_found_by_the_name_of_its_variable() {
        let expected = expected(&[], &[]);
        let quiet = vec![
            "kr-agents$ ".to_owned(),
            format!("{ROW} value HOME 0123456789abcdef"),
        ];
        assert_eq!(expected.shown_on(&quiet), None);
        let leaking = vec![format!("{ROW} value CODEX_HOME /run/agent-config")];
        assert_eq!(expected.shown_on(&leaking), Some("CODEX_HOME"));
    }

    /// The lines typed at the shell, run by the system's `zsh` the way the managed shell runs them,
    /// answer as the harness computes. Needs `zsh`, which the run's own shell is.
    #[test]
    fn the_lines_a_zsh_runs_answer_as_the_harness_computes() {
        let Some(zsh) = ["/bin/zsh", "/usr/bin/zsh"]
            .into_iter()
            .find(|path| std::path::Path::new(path).exists())
        else {
            if cfg!(target_os = "macos") {
                panic!("macOS has /bin/zsh, and this test runs the lines in it");
            }
            eprintln!("skipping: no zsh on this machine; the gateway case runs the managed shell");
            return;
        };
        let list = the_list();
        let expected = Expected::new(
            &list,
            (MARKER, "run-1"),
            &texts(&["KR_STATE_DIR", "TERM"]),
            &texts(&["*_API_KEY"]),
            &[],
        )
        .expect("an expectation");
        let run = |environment: &[(String, String)]| -> Answer {
            let ask = |line: &str| -> Vec<String> {
                let output = std::process::Command::new(zsh)
                    .args(["-f", "-c"])
                    .arg(format!("zmodload zsh/parameter; {line}"))
                    .env_clear()
                    .envs(environment.iter().cloned())
                    .output()
                    .expect("zsh runs");
                assert!(output.status.success(), "{output:?}");
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::to_owned)
                    .collect()
            };
            let mut readings = Vec::new();
            for part in 0..expected.value_parts() {
                let rows = ask(&expected.value_line(part, part));
                readings.extend(
                    expected
                        .read_values(part, part, &rows)
                        .expect("a whole answer"),
                );
            }
            let mut exported = Vec::new();
            let mut skipped = 0;
            loop {
                let rows = ask(&Expected::exported_line(skipped, 9));
                let (names, total) = read_exported(9, &rows).expect("a whole answer");
                exported.extend(names);
                skipped += PART_NAMES;
                if skipped >= total {
                    assert_eq!(exported.len(), total);
                    break;
                }
            }
            Answer { readings, exported }
        };
        let given: Vec<(String, String)> = list
            .iter()
            .filter(|(name, _)| !host_owns_variable(name))
            .cloned()
            .chain([("PATH".to_owned(), "/usr/bin:/bin".to_owned())])
            .collect();
        let pass = run(&given);
        assert_eq!(expected.judge(&pass.readings, &pass.exported), Ok(()));
        // A value that differs.
        let mut changed = given.clone();
        changed
            .iter_mut()
            .find(|(name, _)| name == "CODEX_HOME")
            .expect("held")
            .1 = "/elsewhere".to_owned();
        let answer = run(&changed);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a changed value is refused");
        assert!(
            why.contains("CODEX_HOME") && !why.contains("/elsewhere"),
            "{why}"
        );
        // A name that is not there.
        let mut lacking = given.clone();
        lacking.retain(|(name, _)| name != "PROVIDER_LOGIN");
        let answer = run(&lacking);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a missing name is refused");
        assert!(
            why.contains("PROVIDER_LOGIN") && why.contains("does not export"),
            "{why}"
        );
        // An exported name the build list clears.
        let mut forbidden = given.clone();
        forbidden.push(("GROQ_API_KEY".to_owned(), "not-a-real-key".to_owned()));
        let answer = run(&forbidden);
        let why = expected
            .judge(&answer.readings, &answer.exported)
            .expect_err("a cleared name is refused");
        assert!(
            why.contains("GROQ_API_KEY") && !why.contains("not-a-real-key"),
            "{why}"
        );
    }
}
