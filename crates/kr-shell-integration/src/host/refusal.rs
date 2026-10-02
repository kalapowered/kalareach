//! Why a startup entry was not written, or was not taken out.
//!
//! A refusal leaves a person's own file exactly as it was, and the person is owed the reason: which
//! thing about the profile stopped the install, and where it asks something of them, what to do. So
//! the reason is a value of its own and not a sentence inside a plain I/O failure, which a command
//! line must not repeat because it cannot tell what such a payload holds. A [`Refusal`] is a closed
//! set. Every sentence in it is this host's own, nothing of the profile is in one, and the one thing
//! that arrives from outside, the name PowerShell gives a parse error, is kept only when it is an
//! identifier ([`ParserError`]).
//!
//! The command line says a refusal through [`Refusal::of`], which finds one in an error that came
//! out of [`crate::host::startup`], and through its `Display`.

use std::fmt;

/// The name PowerShell gives a parse error, such as `MissingEndCurlyBrace`.
///
/// It is kept only when it is a name: letters and digits, and not longer than any parse error's.
/// Anything else PowerShell might print is not one, and is not said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserError(String);

impl ParserError {
    /// The longest name kept.
    const LONGEST: usize = 80;

    /// Returns the name when it is one.
    #[must_use]
    pub fn named(text: &str) -> Option<Self> {
        (!text.is_empty()
            && text.len() <= Self::LONGEST
            && text.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| Self(text.to_owned()))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a startup file was left as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The profile is signed, and an install would have changed the text its signature covers.
    SignedForInstall,
    /// The profile is signed, and a removal would have changed the text its signature covers.
    SignedForRemoval,
    /// The profile begins with a second byte-order mark, which reading a file takes one off and so
    /// hides.
    SecondByteOrderMark,
    /// The profile has a line end that is a carriage return alone, so its lines cannot be told apart.
    LoneCarriageReturn,
    /// A comment or a string runs over the line the `using` statements or `param` block end on.
    CommentOrStringRunsOver,
    /// Another statement shares the line the `using` statements or `param` block end on.
    StatementSharesTheLine,
    /// The entry would add parse errors the profile did not have, and PowerShell names them.
    WouldReport(Vec<ParserError>),
    /// The entry would change which parse errors PowerShell reports for the profile.
    WouldChangeTheErrors,
    /// The entry is not one block between its two marker lines.
    EntryNotOneBlock,
    /// The entry would sit inside a statement of the profile.
    EntryInsideAStatement,
    /// The entry would sit inside a block of the profile.
    EntryInsideABlock,
    /// A statement of the profile would run before the entry that has to open the bridge.
    StatementBeforeTheEntry,
    /// A statement of the profile would run after the entry that has to check the reader.
    StatementAfterTheEntry,
    /// The `using` statements or `param` block would come after the entry.
    PrologueAfterTheEntry,
    /// The statements of the profile outside the entry are not what they were.
    StatementsChanged,
    /// The `using` statements or `param` block are not what they were.
    PrologueChanged,
    /// PowerShell did not say where the entry goes: it did not answer in time or could not start.
    PlacementUnanswered,
    /// PowerShell did not check the profile with the entry in it: it did not answer in time or could
    /// not start.
    CheckUnanswered,
    /// PowerShell's answer about where the entry goes was not understood.
    PlacementNotUnderstood,
    /// PowerShell's answer about where the entry goes is not inside the profile.
    PlacementOutsideTheProfile,
    /// PowerShell's check of the profile with the entry in it was not understood.
    CheckNotUnderstood,
}

impl Refusal {
    /// The most distinct parse errors one refusal names.
    const MOST_ERRORS: usize = 32;

    /// Returns the refusal an error out of the startup entries carries, when it carries one.
    ///
    /// Any other error is an ordinary failure of the file system or of the process, and a command
    /// line says it as it says any such failure.
    #[must_use]
    pub fn of(error: &std::io::Error) -> Option<&Self> {
        error
            .get_ref()
            .and_then(|payload| payload.downcast_ref::<Self>())
    }

    /// Returns the refusal a script of this host reports, from what it printed after `kr-refused `.
    ///
    /// The scripts print a short code of their own and never a sentence, so the words are said only
    /// from here. A code this host does not know is not a refusal.
    pub(crate) fn from_script(said: &str) -> Option<Self> {
        let (code, rest) = said.split_once(' ').unwrap_or((said, ""));
        if code == "would-report" {
            let mut errors: Vec<ParserError> = Vec::new();
            for name in rest.split(',') {
                let name = ParserError::named(name)?;
                if !errors.contains(&name) {
                    errors.push(name);
                }
            }
            return (errors.len() <= Self::MOST_ERRORS).then_some(Self::WouldReport(errors));
        }
        // Every other code stands alone: anything after it is not what a script of this host prints.
        if !rest.is_empty() {
            return None;
        }
        Some(match code {
            "lone-carriage-return" => Self::LoneCarriageReturn,
            "comment-or-string-runs-over" => Self::CommentOrStringRunsOver,
            "statement-shares-the-line" => Self::StatementSharesTheLine,
            "would-change-the-errors" => Self::WouldChangeTheErrors,
            "entry-not-one-block" => Self::EntryNotOneBlock,
            "entry-inside-a-statement" => Self::EntryInsideAStatement,
            "entry-inside-a-block" => Self::EntryInsideABlock,
            "statement-before-the-entry" => Self::StatementBeforeTheEntry,
            "statement-after-the-entry" => Self::StatementAfterTheEntry,
            "prologue-after-the-entry" => Self::PrologueAfterTheEntry,
            "statements-changed" => Self::StatementsChanged,
            "prologue-changed" => Self::PrologueChanged,
            _ => return None,
        })
    }

    /// Why the profile cannot take the entry, for the refusals that are about the profile.
    const fn about_the_profile(&self) -> Option<&'static str> {
        Some(match self {
            Self::SignedForInstall => "it is signed, and any change to it breaks its signature",
            Self::SecondByteOrderMark => "it begins with a second byte-order mark",
            Self::LoneCarriageReturn => "it has a line end that is a carriage return alone",
            Self::CommentOrStringRunsOver => {
                "a comment or a string runs over the line its using statements or param block end on"
            }
            Self::StatementSharesTheLine => {
                "a statement shares the line its using statements or param block end on, and an \
                 entry cannot go between them; put it on a line of its own"
            }
            Self::WouldChangeTheErrors => {
                "the entry would change which errors PowerShell reports for the profile"
            }
            Self::EntryNotOneBlock => "its entry is not one block between its markers",
            Self::EntryInsideAStatement => "its entry would sit inside a statement of the profile",
            Self::EntryInsideABlock => "its entry would sit inside a block of the profile",
            Self::StatementBeforeTheEntry => {
                "a statement of the profile would run before the entry"
            }
            Self::StatementAfterTheEntry => "a statement of the profile would run after the entry",
            Self::PrologueAfterTheEntry => {
                "its using statements or param block would come after the entry"
            }
            Self::StatementsChanged => "the statements of the profile are not what they were",
            Self::PrologueChanged => "its using statements or param block are not what they were",
            Self::SignedForRemoval
            | Self::WouldReport(_)
            | Self::PlacementUnanswered
            | Self::CheckUnanswered
            | Self::PlacementNotUnderstood
            | Self::PlacementOutsideTheProfile
            | Self::CheckNotUnderstood => return None,
        })
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(why) = self.about_the_profile() {
            return write!(
                formatter,
                "this profile cannot take the entry: {why}, so nothing was written"
            );
        }
        match self {
            Self::WouldReport(errors) => {
                write!(
                    formatter,
                    "this profile cannot take the entry: PowerShell would report "
                )?;
                for (index, error) in errors.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    formatter.write_str(error.as_str())?;
                }
                formatter.write_str(" in it with the entry, so nothing was written")
            }
            Self::SignedForRemoval => formatter.write_str(
                "this profile cannot lose the entries: it is signed, and any change to it breaks its \
                 signature, so nothing was removed. Take the signature block out of the profile, run \
                 `kr shell remove` again, and sign the profile again",
            ),
            Self::PlacementUnanswered => formatter.write_str(
                "PowerShell did not say where the entry goes: it did not answer in time or could not \
                 start, so nothing was written",
            ),
            Self::CheckUnanswered => formatter.write_str(
                "PowerShell did not check the profile with the entry in it: it did not answer in time \
                 or could not start, so nothing was written",
            ),
            Self::PlacementNotUnderstood => formatter.write_str(
                "PowerShell's answer about where the entry goes was not understood, so nothing was \
                 written",
            ),
            Self::PlacementOutsideTheProfile => formatter.write_str(
                "PowerShell's answer about where the entry goes is not inside the profile, so nothing \
                 was written",
            ),
            Self::CheckNotUnderstood => formatter.write_str(
                "PowerShell's check of the profile with the entry in it was not understood, so \
                 nothing was written",
            ),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for std::io::Error {
    fn from(refusal: Refusal) -> Self {
        Self::other(refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal there is, with what a script prints for the ones a script reports.
    fn every_refusal() -> Vec<(Refusal, Option<&'static str>)> {
        let named = |names: &[&str]| {
            names
                .iter()
                .map(|name| ParserError::named(name).expect("a name"))
                .collect()
        };
        vec![
            (Refusal::SignedForInstall, None),
            (Refusal::SignedForRemoval, None),
            (Refusal::SecondByteOrderMark, None),
            (Refusal::LoneCarriageReturn, Some("lone-carriage-return")),
            (
                Refusal::CommentOrStringRunsOver,
                Some("comment-or-string-runs-over"),
            ),
            (
                Refusal::StatementSharesTheLine,
                Some("statement-shares-the-line"),
            ),
            (
                Refusal::WouldReport(named(&["MissingEndCurlyBrace", "UnexpectedToken"])),
                Some("would-report MissingEndCurlyBrace,UnexpectedToken"),
            ),
            (
                Refusal::WouldChangeTheErrors,
                Some("would-change-the-errors"),
            ),
            (Refusal::EntryNotOneBlock, Some("entry-not-one-block")),
            (
                Refusal::EntryInsideAStatement,
                Some("entry-inside-a-statement"),
            ),
            (Refusal::EntryInsideABlock, Some("entry-inside-a-block")),
            (
                Refusal::StatementBeforeTheEntry,
                Some("statement-before-the-entry"),
            ),
            (
                Refusal::StatementAfterTheEntry,
                Some("statement-after-the-entry"),
            ),
            (
                Refusal::PrologueAfterTheEntry,
                Some("prologue-after-the-entry"),
            ),
            (Refusal::StatementsChanged, Some("statements-changed")),
            (Refusal::PrologueChanged, Some("prologue-changed")),
            (Refusal::PlacementUnanswered, None),
            (Refusal::CheckUnanswered, None),
            (Refusal::PlacementNotUnderstood, None),
            (Refusal::PlacementOutsideTheProfile, None),
            (Refusal::CheckNotUnderstood, None),
        ]
    }

    #[test]
    fn a_script_code_is_the_refusal_it_names_and_nothing_else_is_one() {
        for (refusal, code) in every_refusal() {
            if let Some(code) = code {
                assert_eq!(Refusal::from_script(code), Some(refusal), "{code}");
            }
        }
        for not_a_code in [
            "",
            "it has a line end that is a carriage return alone",
            "lone-carriage-return and more",
            "would-report",
            "would-report ",
            "would-report A,,B",
            "would-report A B",
            "would-report not/an/id",
            "would-report C:\\Users\\someone\\profile.ps1",
        ] {
            assert_eq!(Refusal::from_script(not_a_code), None, "{not_a_code:?}");
        }
    }

    #[test]
    fn the_names_of_parse_errors_are_distinct_and_are_names() {
        assert_eq!(
            Refusal::from_script("would-report A,B,A"),
            Some(Refusal::WouldReport(vec![
                ParserError::named("A").expect("a name"),
                ParserError::named("B").expect("a name"),
            ])),
            "a name PowerShell repeats is said once"
        );
        let too_many = (0..=Refusal::MOST_ERRORS)
            .map(|index| format!("Error{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            Refusal::from_script(&format!("would-report {too_many}")),
            None
        );
        let too_long = "A".repeat(ParserError::LONGEST + 1);
        assert_eq!(
            Refusal::from_script(&format!("would-report {too_long}")),
            None
        );
    }

    /// What a refusal says is this host's own: it names what stopped the entry, never the profile.
    #[test]
    fn every_refusal_says_why_and_that_nothing_was_changed() {
        for (refusal, _) in every_refusal() {
            let said = refusal.to_string();
            assert!(
                said.contains("nothing was written") || said.contains("nothing was removed"),
                "{refusal:?} does not say the file is as it was: {said}"
            );
            assert!(said.len() > 40, "{refusal:?} says too little: {said}");
        }
        assert!(
            Refusal::SignedForRemoval
                .to_string()
                .contains("sign the profile again")
        );
        assert_eq!(
            Refusal::WouldReport(vec![
                ParserError::named("MissingEndCurlyBrace").expect("a name"),
                ParserError::named("UnexpectedToken").expect("a name"),
            ])
            .to_string(),
            "this profile cannot take the entry: PowerShell would report MissingEndCurlyBrace, \
             UnexpectedToken in it with the entry, so nothing was written"
        );
    }

    #[test]
    fn a_refusal_is_found_in_the_error_that_carries_it_and_not_in_another() {
        let carried: std::io::Error = Refusal::LoneCarriageReturn.into();
        assert_eq!(Refusal::of(&carried), Some(&Refusal::LoneCarriageReturn));
        assert_eq!(Refusal::of(&std::io::Error::other("anything")), None);
        assert_eq!(
            Refusal::of(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            None
        );
    }
}
