//! The eight commands the broker lets Git run, and the one line each is run with.
//!
//! The broker parses a request's typed arguments itself, against the tables in [`tables`], and Git
//! never sees a form no table lists. The line a command is run with is
//! `git.exe --no-pager --literal-pathspecs <settings> <command> <always-words> <accepted elements>`:
//! [`parse_operation`] builds what follows the settings, [`settings`] builds the settings, and
//! [`settings::command_arguments`] joins them.
//!
//! References resolve to checked object identifiers before the launch. A revision comes out of the
//! parser in its qualified form (a branch name as `refs/heads/<name>`, so that a tag never answers
//! to it) and the line carries, in [`OperationLine::checks`], what the readers must establish:
//! each revision to resolve, each reference that must not be symbolic (the branch every revision
//! starts at, and the one a command writes), the state the repository must be in. [`OperationLine::resolved`] puts the identifiers they return into the line. A refusal
//! names the rule that refused and the command and position of the element; it never repeats the
//! element.

pub mod grammar;
pub mod settings;
pub mod state;
pub mod tables;

use self::grammar::{MAX_PATHS, Revision, is_control};
use self::tables::{Form, GLOBAL_REFUSED, INTROSPECTION, NAMED_FORMATS, Row, Table, Typed, Values};
use crate::frame::invocation::{
    Arg, Command, Dots, Format, MAX_ARGUMENTS, NamedFormat, Part, Placeholder, RefusedKind,
};
use crate::names::{BRANCH_PREFIX, is_branch_name, is_oid};
use crate::refusal::Refusal;
use crate::repository::config::{ConfigFacts, ObjectFormat};

/// Whether a command writes to the repository or the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writes {
    /// It only reads.
    No,
    /// It writes: the index, the tree, a reference or an object.
    Yes,
}

/// What the readers must establish before the command is launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// Resolve `spec`, a qualified revision, to a commit. Where `replaces` names an element of the
    /// line, the identifier takes that element's place. Where `tree_target` is set, the commit's
    /// tree is the one the command will write to the working tree, so its attributes are scanned.
    Resolve {
        /// The revision, in the form a reader takes.
        spec: String,
        /// The element of [`OperationLine::argv`] the identifier replaces.
        replaces: Option<usize>,
        /// Whether the command writes this commit's tree to the working tree.
        tree_target: bool,
    },
    /// Resolve both sides of the range at `index`; the identifiers replace them, joined by the dots.
    ResolveRange {
        /// The element of [`OperationLine::argv`] that holds the range.
        index: usize,
        /// The left side, in the form a reader takes.
        left: String,
        /// The dots between the sides.
        dots: Dots,
        /// The right side, in the form a reader takes.
        right: String,
    },
    /// The reference must not be symbolic.
    NotSymbolic {
        /// A full reference name under `refs/heads/`.
        refname: String,
    },
    /// No tag may carry the branch's name.
    NoTag {
        /// The branch's name.
        name: String,
    },
    /// The repository's `HEAD` is what the command writes through, so it passes the same check.
    ImplicitHead,
    /// No operation may be in progress in the repository.
    OperationState,
}

/// What a request comes to: the elements after the settings, whether the command writes, and what
/// is still to be checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationLine {
    /// The command's name, the words the broker always adds, and the accepted elements.
    pub argv: Vec<String>,
    /// Whether the command writes.
    pub writes: Writes,
    /// What the readers must establish before the launch.
    pub checks: Vec<Check>,
}

/// More arguments than the frames allow.
pub const RULE_ARGUMENTS: &str = "operation-arguments";
/// A control character in an element.
pub const RULE_CONTROL: &str = "operation-control";
/// An element of a type the position does not take.
pub const RULE_TYPE: &str = "operation-type";
/// One of the options no command takes.
pub const RULE_OPTION_GLOBAL: &str = "operation-global-option";
/// An option the command's table refuses by name.
pub const RULE_OPTION_REFUSED: &str = "operation-refused-option";
/// A word no table lists.
pub const RULE_OPTION_UNLISTED: &str = "operation-unlisted-option";
/// An option written with the other spelling of its value.
pub const RULE_OPTION_SPELLING: &str = "operation-option-spelling";
/// An option with a value outside its table.
pub const RULE_OPTION_VALUE: &str = "operation-option-value";
/// An option given twice.
pub const RULE_OPTION_REPEATED: &str = "operation-option-repeated";
/// Two options of one group.
pub const RULE_OPTION_EXCLUSIVE: &str = "operation-option-exclusive";
/// An option that needs another and has none.
pub const RULE_OPTION_REQUIRES: &str = "operation-option-requires";
/// An element the form needs and the request lacks.
pub const RULE_MISSING: &str = "operation-missing";
/// An element in a place the table does not allow.
pub const RULE_ORDER: &str = "operation-order";
/// An element after the form has ended, or a form the table does not list.
pub const RULE_FORM: &str = "operation-form";
/// A path that follows no `--`, or `--` with no path.
pub const RULE_SEPARATOR: &str = "operation-separator";
/// More than [`MAX_PATHS`] paths.
pub const RULE_PATHS: &str = "operation-paths";
/// A name outside the grammar of a branch name.
pub const RULE_NAME: &str = "operation-name";
/// A reference name outside `refs/heads/` and the grammar of a branch name.
pub const RULE_REFNAME: &str = "operation-refname";
/// An object identifier that is not 40 lowercase hexadecimal digits.
pub const RULE_OID: &str = "operation-oid";
/// An object identifier of all zeros.
pub const RULE_OID_ZERO: &str = "operation-oid-zero";
/// A revision count that does not fit the form: a number of revisions, or a range with a revision.
pub const RULE_REVISIONS: &str = "operation-revisions";
/// A format outside the table.
pub const RULE_FORMAT: &str = "operation-format";
/// The identifiers the readers returned do not fit the line.
pub const RULE_RESOLVED: &str = "operation-resolved";

/// The most revisions `diff` and `log` take that are not a range.
const MAX_PLAIN_REVISIONS: usize = 2;

/// Parses a command's typed arguments against its table.
///
/// # Errors
///
/// Returns a refusal of kind `operation` that names the rule, the command and the position.
pub fn parse_operation(
    command: Command,
    args: &[Arg],
    facts: &ConfigFacts,
) -> Result<OperationLine, Refusal> {
    // The identifier grammar is the object format's: a second format needs its own digits.
    let ObjectFormat::Sha1 = facts.object_format;
    let table = tables::table(command);
    let mut parser = Parser {
        table,
        args,
        at: 0,
        argv: std::iter::once(table.name)
            .chain(table.always.iter().copied())
            .map(str::to_owned)
            .collect(),
        checks: Vec::new(),
    };
    parser.run()?;
    Ok(OperationLine {
        argv: parser.argv,
        writes: table.writes,
        checks: parser.checks,
    })
}

impl OperationLine {
    /// The line with the identifiers the readers returned in place of the revisions. There is one
    /// identifier for each [`Check::Resolve`] and two for each [`Check::ResolveRange`], in the
    /// order of the checks.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the count differs or an identifier is not one.
    pub fn resolved(&self, identifiers: &[String]) -> Result<Vec<String>, Refusal> {
        let mismatch = || {
            refuse(
                RULE_RESOLVED,
                "the identifiers the readers returned do not fit the command",
            )
        };
        let mut argv = self.argv.clone();
        let mut given = identifiers.iter();
        let mut next = || given.next().filter(|id| is_oid(id)).ok_or_else(mismatch);
        for check in &self.checks {
            match check {
                Check::Resolve { replaces, .. } => {
                    let id = next()?;
                    if let Some(index) = replaces {
                        argv[*index].clone_from(id);
                    }
                }
                Check::ResolveRange { index, dots, .. } => {
                    let left = next()?;
                    let right = next()?;
                    argv[*index] = format!("{left}{}{right}", dots_text(*dots));
                }
                _ => {}
            }
        }
        if given.next().is_some() {
            return Err(mismatch());
        }
        Ok(argv)
    }
}

/// How the dots of a range are written.
#[must_use]
pub const fn dots_text(dots: Dots) -> &'static str {
    match dots {
        Dots::Two => "..",
        Dots::Three => "...",
    }
}

fn refuse(rule: &'static str, detail: &str) -> Refusal {
    Refusal::new(RefusedKind::Operation, rule, detail)
}

/// How a word stands to one row of a table.
enum Hit {
    No,
    Match,
    Spelling,
    Value,
}

fn hit(row: &Row, word: &str) -> Hit {
    let name = row.name;
    match row.form {
        Form::Flag | Form::Separate(_) => {
            if word == name {
                Hit::Match
            } else if word.strip_prefix(name).is_some_and(|r| r.starts_with('=')) {
                Hit::Spelling
            } else {
                Hit::No
            }
        }
        Form::Attached { separator, values } => {
            if word == name {
                return Hit::Spelling;
            }
            match word
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(separator))
            {
                Some(value) if value_fits(values, value) => Hit::Match,
                Some(_) => Hit::Value,
                None => Hit::No,
            }
        }
        Form::Digits { min, max } => match word.strip_prefix('-') {
            Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                if grammar::count(digits, min, max).is_some() {
                    Hit::Match
                } else {
                    Hit::Value
                }
            }
            _ => Hit::No,
        },
    }
}

fn value_fits(values: Values, value: &str) -> bool {
    match values {
        Values::Words(words) => words.contains(&value),
        Values::Count { min, max } => grammar::count(value, min, max).is_some(),
    }
}

/// The text a placeholder is written as.
#[must_use]
pub const fn placeholder_text(placeholder: Placeholder) -> &'static str {
    match placeholder {
        Placeholder::CommitHash => "%H",
        Placeholder::CommitHashShort => "%h",
        Placeholder::TreeHash => "%T",
        Placeholder::TreeHashShort => "%t",
        Placeholder::ParentHashes => "%P",
        Placeholder::ParentHashesShort => "%p",
        Placeholder::AuthorName => "%an",
        Placeholder::AuthorEmail => "%ae",
        Placeholder::AuthorDate => "%ad",
        Placeholder::AuthorDateIso => "%aI",
        Placeholder::AuthorDateUnix => "%at",
        Placeholder::CommitterName => "%cn",
        Placeholder::CommitterEmail => "%ce",
        Placeholder::CommitterDate => "%cd",
        Placeholder::CommitterDateIso => "%cI",
        Placeholder::CommitterDateUnix => "%ct",
        Placeholder::Subject => "%s",
        Placeholder::Body => "%b",
        Placeholder::RawMessage => "%B",
        Placeholder::Newline => "%n",
        Placeholder::Percent => "%%",
    }
}

const fn named_format_text(format: NamedFormat) -> &'static str {
    match format {
        NamedFormat::Oneline => "oneline",
        NamedFormat::Short => "short",
        NamedFormat::Medium => "medium",
        NamedFormat::Full => "full",
        NamedFormat::Fuller => "fuller",
    }
}

struct Parser<'a> {
    table: &'static Table,
    args: &'a [Arg],
    at: usize,
    argv: Vec<String>,
    checks: Vec<Check>,
}

impl Parser<'_> {
    fn run(&mut self) -> Result<(), Refusal> {
        if self.args.len() > MAX_ARGUMENTS {
            return Err(refuse(
                RULE_ARGUMENTS,
                &format!("{}: too many arguments", self.table.name),
            ));
        }
        self.controls()?;
        if self.table.stops_on_state {
            self.checks.push(Check::OperationState);
        }
        if self.table.checks_implicit_head {
            self.checks.push(Check::ImplicitHead);
        }
        match self.table.command {
            Command::RevParse => self.rev_parse(),
            Command::Status => {
                self.options()?;
                self.paths(false)?;
                self.end()
            }
            Command::Diff | Command::Log => {
                self.options()?;
                let revisions = self.revisions()?;
                let before = self.argv.len();
                self.paths(false)?;
                // A file named like the last revision would make it ambiguous to Git.
                if revisions && self.argv.len() == before {
                    self.argv.push("--".to_owned());
                }
                self.end()
            }
            Command::Checkout => self.checkout(),
            Command::Add => {
                self.paths(true)?;
                self.end()
            }
            Command::UpdateRef => self.update_ref(),
            Command::Commit => {
                self.options()?;
                self.end()
            }
        }
    }

    /// The refusal for the element at the current position.
    fn refusal(&self, rule: &'static str, reason: &str) -> Refusal {
        self.refusal_at(self.at, rule, reason)
    }

    fn refusal_at(&self, at: usize, rule: &'static str, reason: &str) -> Refusal {
        refuse(
            rule,
            &format!("{}: argument {} {reason}", self.table.name, at + 1),
        )
    }

    /// Rule 4: no control character in any element, tab and newline allowed in a message only.
    fn controls(&self) -> Result<(), Refusal> {
        let bad = |text: &str| text.chars().any(is_control);
        for (at, arg) in self.args.iter().enumerate() {
            let found = match arg {
                Arg::Path(text)
                | Arg::Rev(text)
                | Arg::Name(text)
                | Arg::RefName(text)
                | Arg::Oid(text)
                | Arg::Word(text) => bad(text),
                Arg::Message(text) => text
                    .chars()
                    .any(|c| is_control(c) && c != '\t' && c != '\n'),
                Arg::Range { left, right, .. } => bad(left) || bad(right),
                Arg::Count(_) | Arg::Format(_) => false,
            };
            if found {
                return Err(self.refusal_at(at, RULE_CONTROL, "holds a control character"));
            }
        }
        Ok(())
    }

    /// The refusal for a word no row of the current position accepts.
    fn word_refusal(&self, word: &str) -> Refusal {
        let name = word.split('=').next().unwrap_or_default();
        if GLOBAL_REFUSED.contains(&name) {
            self.refusal(RULE_OPTION_GLOBAL, "is an option no command takes")
        } else if self.table.refused.contains(&name) {
            self.refusal(RULE_OPTION_REFUSED, "is an option this command refuses")
        } else {
            self.refusal(RULE_OPTION_UNLISTED, "is not in the command's table")
        }
    }

    /// Whether any row of the table knows the word, in any spelling.
    fn listed(&self, word: &str) -> bool {
        self.table
            .options
            .iter()
            .any(|row| !matches!(hit(row, word), Hit::No))
    }

    fn row_for(&self, word: &str) -> Result<&'static Row, Refusal> {
        let mut spelling = false;
        let mut value = false;
        for row in self.table.options {
            match hit(row, word) {
                Hit::Match => return Ok(row),
                Hit::Spelling => spelling = true,
                Hit::Value => value = true,
                Hit::No => {}
            }
        }
        Err(if spelling {
            self.refusal(
                RULE_OPTION_SPELLING,
                "is spelled with the other form of its value",
            )
        } else if value {
            self.refusal(RULE_OPTION_VALUE, "has a value the table does not list")
        } else {
            self.word_refusal(word)
        })
    }

    /// The options: words up to the first element that is not one, or `--`.
    fn options(&mut self) -> Result<Vec<&'static Row>, Refusal> {
        let mut seen: Vec<&'static Row> = Vec::new();
        while let Some(Arg::Word(word)) = self.args.get(self.at) {
            if word == "--" {
                break;
            }
            let row = self.row_for(word)?;
            if seen.iter().any(|earlier| std::ptr::eq(*earlier, row)) {
                return Err(self.refusal(RULE_OPTION_REPEATED, "repeats an option"));
            }
            if row.group != 0 && seen.iter().any(|earlier| earlier.group == row.group) {
                return Err(self.refusal(
                    RULE_OPTION_EXCLUSIVE,
                    "is an option of a group of which another is already given",
                ));
            }
            seen.push(row);
            self.at += 1;
            match row.form {
                Form::Separate(typed) => self.typed_value(row.name, typed)?,
                Form::Flag | Form::Attached { .. } | Form::Digits { .. } => {
                    self.argv.push(word.clone());
                }
            }
        }
        for row in &seen {
            if let Some(needed) = row.requires
                && !seen.iter().any(|other| other.name == needed)
            {
                return Err(self.refusal(RULE_OPTION_REQUIRES, "needs an option that is missing"));
            }
        }
        for name in self.table.required {
            if !seen.iter().any(|row| row.name == *name) {
                return Err(self.refusal(RULE_MISSING, "an option the form needs is missing"));
            }
        }
        Ok(seen)
    }

    /// The element after a separate option.
    fn typed_value(&mut self, name: &str, typed: Typed) -> Result<(), Refusal> {
        match (typed, self.args.get(self.at)) {
            (
                Typed::Message {
                    max_bytes,
                    one_line,
                },
                Some(Arg::Message(text)),
            ) => {
                if let Err(rule) = grammar::message(text, max_bytes, one_line) {
                    return Err(self.refusal(rule, "is a message outside the grammar"));
                }
                self.argv.push(name.to_owned());
                self.argv.push(text.clone());
            }
            (Typed::Format, Some(Arg::Format(format))) => {
                let text = self.format_text(format)?;
                self.argv.push(format!("{name}={text}"));
            }
            (_, Some(_)) => {
                return Err(self.refusal(RULE_TYPE, "is not the type this option takes"));
            }
            (_, None) => {
                return Err(self.refusal_at(
                    self.at,
                    RULE_OPTION_VALUE,
                    "is missing: the option takes a value",
                ));
            }
        }
        self.at += 1;
        Ok(())
    }

    fn format_text(&self, format: &Format) -> Result<String, Refusal> {
        match format {
            Format::Named(named) => {
                let text = named_format_text(*named);
                debug_assert!(NAMED_FORMATS.contains(&text));
                Ok(text.to_owned())
            }
            Format::Custom(parts) => {
                // Without a prefix, Git reads text that holds no `%` as the name of a built-in
                // format, by prefix: `r` is `raw`. `tformat:` makes every custom format text.
                let mut text = String::from("tformat:");
                let sound = !parts.is_empty()
                    && parts.len() <= crate::frame::invocation::MAX_FORMAT_PARTS
                    && parts.iter().all(|part| match part {
                        Part::Text(own) => {
                            !own.is_empty()
                                && own.len() <= crate::frame::invocation::MAX_FORMAT_TEXT_BYTES
                                && !own.contains('%')
                                && !own.chars().any(is_control)
                        }
                        Part::Placeholder(_) => true,
                    });
                if !sound {
                    return Err(self.refusal(RULE_FORMAT, "is a format outside the table"));
                }
                for part in parts {
                    match part {
                        Part::Text(own) => text.push_str(own),
                        Part::Placeholder(placeholder) => {
                            text.push_str(placeholder_text(*placeholder));
                        }
                    }
                }
                Ok(text)
            }
        }
    }

    /// Revisions: none to two, or one range; `rev-parse` and its callers count them themselves.
    /// Whether any was taken.
    fn revisions(&mut self) -> Result<bool, Refusal> {
        let mut plain = 0;
        let mut range = false;
        while let Some(arg) = self.args.get(self.at) {
            match arg {
                Arg::Rev(text) => {
                    plain += 1;
                    if range || plain > MAX_PLAIN_REVISIONS {
                        return Err(self.refusal(
                            RULE_REVISIONS,
                            "is one revision more than the command takes",
                        ));
                    }
                    self.revision(text)?;
                }
                Arg::Range { left, right, dots } => {
                    if range || plain > 0 {
                        return Err(self.refusal(
                            RULE_REVISIONS,
                            "is a range after another revision or range",
                        ));
                    }
                    range = true;
                    let (left, right) = (self.qualify(left)?, self.qualify(right)?);
                    self.checks.push(Check::ResolveRange {
                        index: self.argv.len(),
                        left: left.spec().to_owned(),
                        dots: *dots,
                        right: right.spec().to_owned(),
                    });
                    self.symbolic_check(&left);
                    self.symbolic_check(&right);
                    self.argv.push(format!(
                        "{}{}{}",
                        left.spec(),
                        dots_text(*dots),
                        right.spec()
                    ));
                    self.at += 1;
                }
                _ => break,
            }
        }
        Ok(plain > 0 || range)
    }

    fn qualify(&self, text: &str) -> Result<Revision, Refusal> {
        grammar::revision(text)
            .map_err(|rule| self.refusal(rule, "is a revision outside the grammar"))
    }

    /// A revision that starts at a branch has that reference checked: a symbolic reference could
    /// make another one, a tag among them, answer to the branch's name.
    fn symbolic_check(&mut self, revision: &Revision) {
        if let Some(refname) = revision.branch() {
            self.checks.push(Check::NotSymbolic {
                refname: refname.to_owned(),
            });
        }
    }

    /// One revision, qualified, with its resolution recorded and its place noted.
    fn revision(&mut self, text: &str) -> Result<(), Refusal> {
        let revision = self.qualify(text)?;
        self.checks.push(Check::Resolve {
            spec: revision.spec().to_owned(),
            replaces: Some(self.argv.len()),
            tree_target: false,
        });
        self.symbolic_check(&revision);
        self.argv.push(revision.into_spec());
        self.at += 1;
        Ok(())
    }

    /// `-- PATH...`: where `needed`, at least one; otherwise nothing, or the separator and paths.
    fn paths(&mut self, needed: bool) -> Result<(), Refusal> {
        match self.args.get(self.at) {
            Some(Arg::Word(word)) if word == "--" => {}
            Some(Arg::Path(_)) => {
                return Err(self.refusal(RULE_SEPARATOR, "is a path with no `--` before it"));
            }
            Some(Arg::Word(word)) if needed => return Err(self.word_refusal(word)),
            _ if needed => {
                return Err(self.refusal(RULE_MISSING, "the paths the command needs are missing"));
            }
            _ => return Ok(()),
        }
        self.at += 1;
        self.argv.push("--".to_owned());
        let mut taken = 0;
        while let Some(Arg::Path(text)) = self.args.get(self.at) {
            taken += 1;
            if taken > MAX_PATHS {
                return Err(self.refusal(RULE_PATHS, "is one path more than the command takes"));
            }
            if let Err(rule) = grammar::path(text) {
                return Err(self.refusal(rule, "is a path outside the grammar"));
            }
            self.argv.push(text.clone());
            self.at += 1;
        }
        if taken == 0 {
            return Err(self.refusal(RULE_SEPARATOR, "is a `--` with no path after it"));
        }
        Ok(())
    }

    /// The form has ended: nothing may follow.
    fn end(&self) -> Result<(), Refusal> {
        match self.args.get(self.at) {
            None => Ok(()),
            Some(Arg::Word(word)) if word != "--" => {
                if self.listed(word) {
                    Err(self.refusal(
                        RULE_ORDER,
                        "is an option after the elements that follow them",
                    ))
                } else {
                    Err(self.word_refusal(word))
                }
            }
            Some(_) => Err(self.refusal(RULE_FORM, "follows a form that takes no more")),
        }
    }

    fn rev_parse(&mut self) -> Result<(), Refusal> {
        if let Some(Arg::Word(word)) = self.args.first()
            && INTROSPECTION.contains(&word.as_str())
        {
            if self.args.len() != 1 {
                return Err(self.refusal_at(1, RULE_FORM, "follows an introspection word"));
            }
            self.argv.push(word.clone());
            return Ok(());
        }
        let verify = self.options()?.iter().any(|row| row.name == "--verify");
        let mut revisions = 0;
        while let Some(Arg::Rev(text)) = self.args.get(self.at) {
            revisions += 1;
            if verify && revisions > 1 {
                return Err(self.refusal(RULE_REVISIONS, "is a second revision after `--verify`"));
            }
            self.revision(text)?;
        }
        if revisions == 0 {
            return Err(self.refusal(RULE_MISSING, "the form needs a revision"));
        }
        self.end()
    }

    fn checkout(&mut self) -> Result<(), Refusal> {
        match self.args.first() {
            Some(Arg::Name(name)) => {
                if !is_branch_name(name) {
                    return Err(self.refusal(RULE_NAME, "is not a branch name"));
                }
                if self.args.len() != 1 {
                    return Err(self.refusal_at(1, RULE_FORM, "follows a switch"));
                }
                let refname = format!("{BRANCH_PREFIX}{name}");
                self.checks.push(Check::Resolve {
                    spec: refname.clone(),
                    replaces: None,
                    tree_target: true,
                });
                self.checks.push(Check::NotSymbolic { refname });
                self.checks.push(Check::NoTag { name: name.clone() });
                self.argv.push(name.clone());
                self.argv.push("--".to_owned());
                Ok(())
            }
            Some(Arg::Word(word)) if word == "--detach" => {
                self.at = 1;
                match self.args.get(1) {
                    Some(Arg::Rev(text)) => {
                        let revision = self.qualify(text)?;
                        self.checks.push(Check::Resolve {
                            spec: revision.spec().to_owned(),
                            replaces: Some(self.argv.len() + 1),
                            tree_target: true,
                        });
                        self.symbolic_check(&revision);
                        self.argv.push("--detach".to_owned());
                        self.argv.push(revision.into_spec());
                        self.argv.push("--".to_owned());
                        self.at = 2;
                        self.end()
                    }
                    Some(_) => Err(self.refusal(RULE_TYPE, "is not the revision `--detach` takes")),
                    None => {
                        Err(self.refusal(RULE_MISSING, "the revision `--detach` takes is missing"))
                    }
                }
            }
            Some(Arg::Rev(text)) => {
                let revision = self.qualify(text)?;
                self.checks.push(Check::Resolve {
                    spec: revision.spec().to_owned(),
                    replaces: Some(self.argv.len()),
                    tree_target: true,
                });
                self.symbolic_check(&revision);
                self.argv.push(revision.into_spec());
                self.at = 1;
                self.paths(true)?;
                self.end()
            }
            Some(Arg::Word(word)) if word == "--" => {
                self.paths(true)?;
                self.end()
            }
            Some(Arg::Word(word)) => Err(self.word_refusal(word)),
            Some(Arg::Path(_)) => {
                Err(self.refusal(RULE_SEPARATOR, "is a path with no `--` before it"))
            }
            Some(_) => {
                Err(self.refusal(RULE_TYPE, "is not the type a form of checkout starts with"))
            }
            None => Err(self.refusal(RULE_MISSING, "the command needs a form")),
        }
    }

    fn update_ref(&mut self) -> Result<(), Refusal> {
        self.options()?;
        let Some(Arg::RefName(refname)) = self.args.get(self.at) else {
            return Err(self.expected());
        };
        let valid = refname
            .strip_prefix(BRANCH_PREFIX)
            .is_some_and(is_branch_name);
        if !valid {
            return Err(self.refusal(RULE_REFNAME, "is not a reference under refs/heads/"));
        }
        self.checks.push(Check::NotSymbolic {
            refname: refname.clone(),
        });
        self.argv.push(refname.clone());
        self.at += 1;
        for _ in 0..2 {
            let Some(Arg::Oid(oid)) = self.args.get(self.at) else {
                return Err(self.expected());
            };
            if !is_oid(oid) {
                return Err(self.refusal(RULE_OID, "is not a full object identifier"));
            }
            if oid.bytes().all(|b| b == b'0') {
                return Err(self.refusal(RULE_OID_ZERO, "is the all-zero identifier"));
            }
            self.argv.push(oid.clone());
            self.at += 1;
        }
        self.end()
    }

    /// The refusal for a position that holds nothing or the wrong type.
    fn expected(&self) -> Refusal {
        match self.args.get(self.at) {
            None => self.refusal(RULE_MISSING, "an element the form needs is missing"),
            Some(Arg::Word(word)) if word != "--" => self.word_refusal(word),
            Some(_) => self.refusal(RULE_TYPE, "is not the type this position takes"),
        }
    }
}
