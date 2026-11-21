//! Which targets a `cargo test` command selects.
//!
//! A step that reads the output of `cargo test` runs in the root of one workspace, so it selects among
//! that workspace's packages and then among their targets, by the flags of its command and by what
//! the manifests say. [`parse`] reads the flags once, for the loader and for the report, and
//! [`Selection::covers`] names the targets of a workspace that the command selects: the ones Cargo
//! builds to test for it, which a case compares with Cargo's own build messages.
//!
//! The words are read against `cargo test --help` of Cargo 1.97: a flag that is not one of its own is
//! refused, so a flag that could change what Cargo selects is never passed over unread. A feature
//! flag changes which targets build, because Cargo leaves out a target whose `required-features` are
//! not on: [`Selection::covers`] reads how the command turns them on, and any other way that Cargo
//! turns one on is not read.

use std::collections::BTreeSet;

use crate::workspace::{Package, Target, TargetId, TargetKind};

/// A name, or a pattern of `*`, `?`, `[...]` and `**` that matches names, as Cargo reads one in `-p`,
/// `--exclude`, `--bin`, `--example`, `--test` and `--bench`. Cargo matches a name with the pattern
/// of the `glob` crate; this follows that crate's rules for a pattern and for a name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    text: String,
    tokens: Vec<Token>,
}

/// One part of a pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    One(char),
    /// `?`.
    Any,
    /// `*`.
    Run,
    /// `**` as a whole path component: it matches any number of components, none among them.
    Components,
    /// `[abc]` or `[a-c]`.
    Within(Vec<Member>),
    /// `[!abc]`.
    Except(Vec<Member>),
}

/// A character of a class, or a range of them.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Member {
    One(char),
    Range(char, char),
}

impl Pattern {
    fn new(text: &str) -> Result<Self, String> {
        let chars: Vec<char> = text.chars().collect();
        let mut tokens = Vec::new();
        let mut at = 0;
        while at < chars.len() {
            match chars[at] {
                '?' => {
                    tokens.push(Token::Any);
                    at += 1;
                }
                '*' => {
                    let start = at;
                    while chars.get(at) == Some(&'*') {
                        at += 1;
                    }
                    match at - start {
                        1 => tokens.push(Token::Run),
                        2 => {
                            // `**` is a whole path component: the pattern starts with it or a
                            // separator comes before it, and the pattern ends with it or a
                            // separator follows it.
                            let begins = start == 0 || std::path::is_separator(chars[start - 1]);
                            let ends = at == chars.len() || std::path::is_separator(chars[at]);
                            if !begins || !ends {
                                return Err(refused_run(text));
                            }
                            if at < chars.len() {
                                at += 1;
                            }
                            if tokens.last() != Some(&Token::Components) {
                                tokens.push(Token::Components);
                            }
                        }
                        _ => return Err(refused_run(text)),
                    }
                }
                '[' => {
                    // A class holds at least one member, and its first character is a member,
                    // a `]` included, after a `!`.
                    let (negated, first) = if chars.get(at + 1) == Some(&'!') {
                        (true, at + 3)
                    } else {
                        (false, at + 2)
                    };
                    let long_enough = if negated {
                        at + 4 <= chars.len()
                    } else {
                        at + 3 <= chars.len()
                    };
                    let close = long_enough
                        .then(|| chars[first..].iter().position(|one| *one == ']'))
                        .flatten();
                    let Some(close) = close else {
                        return Err(format!(
                            "names the pattern `{text}`, which has a `[` that no `]` closes"
                        ));
                    };
                    let members = members(&chars[first - 1..first + close]);
                    tokens.push(if negated {
                        Token::Except(members)
                    } else {
                        Token::Within(members)
                    });
                    at = first + close + 1;
                }
                one => {
                    tokens.push(Token::One(one));
                    at += 1;
                }
            }
        }
        Ok(Self {
            text: text.to_owned(),
            tokens,
        })
    }

    fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().collect();
        matches_from(&self.tokens, &name)
    }
}

fn refused_run(text: &str) -> String {
    format!(
        "names the pattern `{text}`, which Cargo refuses: a run of `*` is one `*`, or `**` as a \
         whole path component"
    )
}

/// The members of the class whose characters are `chars`: `a-c` is a range when three characters
/// remain, and any other character is one member.
fn members(chars: &[char]) -> Vec<Member> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if at + 3 <= chars.len() && chars[at + 1] == '-' {
            found.push(Member::Range(chars[at], chars[at + 2]));
            at += 3;
        } else {
            found.push(Member::One(chars[at]));
            at += 1;
        }
    }
    found
}

impl Token {
    /// Whether a token that matches one character matches `one`.
    fn accepts(&self, one: char) -> bool {
        let among = |members: &[Member]| {
            members.iter().any(|member| match member {
                Member::One(held) => *held == one,
                Member::Range(first, last) => (*first..=*last).contains(&one),
            })
        };
        match self {
            Self::One(held) => *held == one,
            Self::Any => true,
            Self::Within(members) => among(members),
            Self::Except(members) => !among(members),
            Self::Run | Self::Components => false,
        }
    }
}

/// Whether the tokens match the whole of `name`, as the `glob` crate matches them: `*` takes any run
/// of characters, and `**` takes whole path components, none included. A name holds no separator, so
/// `**` takes the name's whole text or nothing.
fn matches_from(tokens: &[Token], name: &[char]) -> bool {
    let Some((token, rest)) = tokens.split_first() else {
        return name.is_empty();
    };
    match token {
        Token::Run | Token::Components => {
            if matches_from(rest, name) {
                return true;
            }
            for (at, &one) in name.iter().enumerate() {
                if *token == Token::Components && !std::path::is_separator(one) {
                    continue;
                }
                if matches_from(rest, &name[at + 1..]) {
                    return true;
                }
            }
            // The crate goes on with the next token after a `**` has taken every character.
            *token == Token::Components && matches_from(rest, &[])
        }
        one => name
            .split_first()
            .is_some_and(|(&first, after)| one.accepts(first) && matches_from(rest, after)),
    }
}

/// A package spec of `-p` or `--exclude`: a package's name, or a pattern that matches names.
fn package_spec(text: &str) -> Result<Pattern, String> {
    if text.contains(['@', ':', '/', '\\', '#']) {
        return Err(format!(
            "names the package `{text}`: give a package by its name, or by a pattern of `*`, `?` and \
             `[...]` that matches names"
        ));
    }
    Pattern::new(text)
}

/// Whether a flag takes a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Takes {
    No,
    Value,
}

/// Every flag of `cargo test`, with each of its spellings; the first is the one the words below name.
const FLAGS: &[(&[&str], Takes)] = &[
    (&["--help", "-h"], Takes::No),
    (&["--no-run"], Takes::No),
    (&["--no-fail-fast"], Takes::No),
    (&["--future-incompat-report"], Takes::No),
    (&["--message-format"], Takes::Value),
    (&["--quiet", "-q"], Takes::No),
    (&["--verbose", "-v"], Takes::No),
    (&["--color"], Takes::Value),
    (&["--config"], Takes::Value),
    (&["-Z"], Takes::Value),
    (&["--package", "-p"], Takes::Value),
    (&["--workspace", "--all"], Takes::No),
    (&["--exclude"], Takes::Value),
    (&["--lib"], Takes::No),
    (&["--bins"], Takes::No),
    (&["--bin"], Takes::Value),
    (&["--examples"], Takes::No),
    (&["--example"], Takes::Value),
    (&["--tests"], Takes::No),
    (&["--test"], Takes::Value),
    (&["--benches"], Takes::No),
    (&["--bench"], Takes::Value),
    (&["--all-targets"], Takes::No),
    (&["--doc"], Takes::No),
    (&["--features", "-F"], Takes::Value),
    (&["--all-features"], Takes::No),
    (&["--no-default-features"], Takes::No),
    (&["--jobs", "-j"], Takes::Value),
    (&["--release", "-r"], Takes::No),
    (&["--profile"], Takes::Value),
    (&["--target"], Takes::Value),
    (&["--target-dir"], Takes::Value),
    (&["--unit-graph"], Takes::No),
    (&["--timings"], Takes::No),
    (&["--manifest-path", "-m"], Takes::Value),
    (&["--ignore-rust-version"], Takes::No),
    (&["--locked"], Takes::No),
    (&["--offline"], Takes::No),
    (&["--frozen"], Takes::No),
];

/// The flag that `spelling`, as `--flag` or `-f`, names.
fn flag(spelling: &str) -> Option<(&'static [&'static str], Takes)> {
    FLAGS
        .iter()
        .find(|(spellings, _)| spellings.contains(&spelling))
        .map(|(spellings, takes)| (*spellings, *takes))
}

fn not_a_flag(word: &str) -> String {
    format!(
        "gives `{word}`, which is not a flag of `cargo test`: the report reads only the flags it knows"
    )
}

fn without_value(flag: &str) -> String {
    format!("gives `{flag}` without a value")
}

/// A flag that selects nothing the report can read: `written` is how the command spells it.
fn refused(flag: &str, written: &str) -> Result<(), String> {
    match flag {
        "--help" => Err(format!("gives `{written}`, which prints help and builds nothing")),
        "--doc" => Err(
            "gives `--doc`: the report reads no doc test, and the run adds `--no-run`, which Cargo \
             refuses with `--doc`"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}

/// What the words of `flag`, the first of its spellings, are.
fn part_of(flag: &str) -> Part {
    match flag {
        "--no-run" => Part::NoRun,
        "--lib" | "--bins" | "--bin" | "--examples" | "--example" | "--tests" | "--test"
        | "--benches" | "--bench" | "--all-targets" => Part::Targets,
        _ => Part::Other,
    }
}

/// The value of `flag` in the word at `at`, which no `-` begins: `--jobs` also takes a negative number.
fn next_value(words: &[&str], at: &mut usize, flag: &str) -> Result<String, String> {
    match words.get(*at) {
        Some(next)
            if !next.starts_with('-')
                || (flag == "--jobs"
                    && next.len() > 1
                    && next[1..].bytes().all(|byte| byte.is_ascii_digit())) =>
        {
            *at += 1;
            Ok((*next).to_owned())
        }
        _ => Err(without_value(flag)),
    }
}

/// A value that a flag was given, with the index of the word of the command that held it, so that a
/// step's list of the words that hold a placeholder says which values the run gives.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Given {
    value: String,
    word: usize,
}

/// What the words of a command hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    /// `--no-run`.
    NoRun,
    /// A flag that names targets, with its value.
    Targets,
    /// A word that filters the tests by name.
    Name,
    /// Any other flag, with its value.
    Other,
}

/// One flag with its value, or one test name: the words `first` to `last` of the command, by their
/// index in it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Span {
    first: usize,
    last: usize,
    part: Part,
}

/// What a command's package flags select.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Packages {
    /// No package flag: the workspace's default members.
    Default,
    /// `-p`, once or more.
    Named(Vec<Pattern>),
    /// `--workspace`, less each `--exclude`.
    Workspace(Vec<Pattern>),
}

/// The targets of one kind that a command asks for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Rule {
    #[default]
    Off,
    /// The plural flag: every one.
    All,
    /// The singular flag, once or more: those whose name matches.
    Named(Vec<Pattern>),
}

impl Rule {
    fn asked(&self) -> bool {
        *self != Self::Off
    }

    /// Whether a singular flag names the target.
    fn names(&self, name: &str) -> bool {
        matches!(self, Self::Named(patterns) if patterns.iter().any(|pattern| pattern.matches(name)))
    }

    fn holds(&self, name: &str) -> bool {
        *self == Self::All || self.names(name)
    }
}

/// What a `cargo test` command selects, read from its words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    packages: Packages,
    lib: bool,
    bins: Rule,
    examples: Rule,
    tests: Rule,
    benches: Rule,
    all_targets: bool,
    /// The features that `--features` names, each as written: `f` or `<package>/f`.
    features: Vec<Given>,
    all_features: bool,
    no_default_features: bool,
    release: bool,
    profile: Option<Given>,
    /// Each `--target`: Cargo builds for every one.
    targets: Vec<Given>,
    configs: Vec<Given>,
    /// Every flag and test name before `--`, in the order the command gave them.
    spans: Vec<Span>,
}

/// The words read so far.
struct Parsed {
    selection: Selection,
    named: Vec<Pattern>,
    excluded: Vec<Pattern>,
    workspace: bool,
    /// What `--bin`, `--example`, `--test` and `--bench` name, as written: a plural flag beside them
    /// takes every target of its kind, so a name is read only when the whole command is.
    bin_names: Vec<String>,
    example_names: Vec<String>,
    test_names: Vec<String>,
    bench_names: Vec<String>,
}

impl Parsed {
    /// Takes `flag`, the first of its spellings, with its value, which the word at `word` of the
    /// command holds: empty for a flag that takes none.
    fn give(&mut self, flag: &str, value: String, word: usize) -> Result<(), String> {
        let given = |value: String| Given { value, word };
        let selection = &mut self.selection;
        match flag {
            "--manifest-path" => {
                return Err(
                    "gives `--manifest-path`: the step's directory is its workspace, and `-p` and \
                     `--workspace` choose the packages in it"
                        .to_owned(),
                );
            }
            "-Z" => {
                return Err(
                    "gives `-Z`, an unstable flag that can change which targets Cargo selects and \
                     that the report does not read"
                        .to_owned(),
                );
            }
            "--package" => self.named.push(package_spec(&value)?),
            "--exclude" => self.excluded.push(package_spec(&value)?),
            "--workspace" => self.workspace = true,
            "--lib" => selection.lib = true,
            "--bins" => selection.bins = Rule::All,
            "--bin" => self.bin_names.push(value),
            "--examples" => selection.examples = Rule::All,
            "--example" => self.example_names.push(value),
            "--tests" => selection.tests = Rule::All,
            "--test" => self.test_names.push(value),
            "--benches" => selection.benches = Rule::All,
            "--bench" => self.bench_names.push(value),
            "--all-targets" => selection.all_targets = true,
            "--release" => selection.release = true,
            "--all-features" => selection.all_features = true,
            "--no-default-features" => selection.no_default_features = true,
            "--profile" => selection.profile = Some(given(value)),
            "--target" => selection.targets.push(given(value)),
            "--config" => selection.configs.push(given(value)),
            "--features" => selection.features.extend(
                value
                    .split(|one: char| one == ',' || one.is_whitespace())
                    .filter(|item| !item.is_empty())
                    .map(|item| given(item.to_owned())),
            ),
            _ => {}
        }
        Ok(())
    }
}

/// Reads what the command `cargo test ...` selects.
///
/// # Errors
///
/// Returns why the command is refused, in words that follow the step's name: a flag that is not one
/// of `cargo test`'s own, a flag without its value, `--manifest-path`, `-Z`, `--doc`, `-h` or
/// `--help`, `--exclude` without `--workspace`, or a package spec or a target pattern that is not a
/// name or a pattern that Cargo reads.
pub fn parse(command: &[String]) -> Result<Selection, String> {
    if command.first().map(String::as_str) != Some("cargo")
        || command.get(1).map(String::as_str) != Some("test")
    {
        return Err(
            "reads the output of `cargo test` and its command is not `cargo test`".to_owned(),
        );
    }
    let words: Vec<&str> = command[2..]
        .iter()
        .map(String::as_str)
        .take_while(|word| *word != "--")
        .collect();
    let mut read = Parsed {
        selection: Selection {
            packages: Packages::Default,
            lib: false,
            bins: Rule::Off,
            examples: Rule::Off,
            tests: Rule::Off,
            benches: Rule::Off,
            all_targets: false,
            features: Vec::new(),
            all_features: false,
            no_default_features: false,
            release: false,
            profile: None,
            targets: Vec::new(),
            configs: Vec::new(),
            spans: Vec::new(),
        },
        named: Vec::new(),
        excluded: Vec::new(),
        workspace: false,
        bin_names: Vec::new(),
        example_names: Vec::new(),
        test_names: Vec::new(),
        bench_names: Vec::new(),
    };
    let mut test_name = false;
    let mut at = 0;
    while at < words.len() {
        let word = words[at];
        at += 1;
        // The index in the command of the word being read, which follows `cargo test`.
        let here = at + 1;
        if !word.starts_with('-') || word == "-" {
            // A word that is no flag is the name that filters the tests.
            test_name = true;
            read.selection.spans.push(Span {
                first: here,
                last: here,
                part: Part::Name,
            });
        } else if let Some(long) = word.strip_prefix("--") {
            let (name, held) = match long.split_once('=') {
                Some((name, held)) => (name, Some(held)),
                None => (long, None),
            };
            let spelling = format!("--{name}");
            let Some((spellings, takes)) = flag(&spelling) else {
                return Err(not_a_flag(word));
            };
            let flag = spellings[0];
            refused(flag, &spelling)?;
            let mut at_word = here;
            let value = match (takes, held) {
                (Takes::No, None) => String::new(),
                (Takes::No, Some(_)) => {
                    return Err(format!("gives `{word}`, but `{flag}` takes no value"));
                }
                (Takes::Value, Some("")) if flag == "--features" => String::new(),
                (Takes::Value, Some("")) => return Err(without_value(flag)),
                (Takes::Value, Some(held)) => held.to_owned(),
                (Takes::Value, None) => {
                    let value = next_value(&words, &mut at, flag)?;
                    at_word = at + 1;
                    value
                }
            };
            read.selection.spans.push(Span {
                first: here,
                last: at_word,
                part: part_of(flag),
            });
            read.give(flag, value, at_word)?;
        } else {
            // Short flags may be written together, as `-qp a`: each takes the next letter, until one
            // takes a value, which is the rest of the word or, with none, the next word.
            let mut rest = &word[1..];
            let mut last = here;
            while let Some(letter) = rest.chars().next() {
                let spelling = format!("-{letter}");
                let Some((spellings, takes)) = flag(&spelling) else {
                    return Err(not_a_flag(&spelling));
                };
                let flag = spellings[0];
                refused(flag, &spelling)?;
                rest = &rest[letter.len_utf8()..];
                if takes == Takes::No {
                    read.give(flag, String::new(), here)?;
                    continue;
                }
                // `-F=` gives an empty list of features, and the next word is not its value.
                let mut at_word = here;
                let written = rest.strip_prefix('=');
                let held = written.unwrap_or(rest);
                let value = if !held.is_empty() || (written.is_some() && flag == "--features") {
                    held.to_owned()
                } else if written.is_some() {
                    return Err(without_value(flag));
                } else {
                    let value = next_value(&words, &mut at, flag)?;
                    at_word = at + 1;
                    value
                };
                last = at_word;
                read.give(flag, value, at_word)?;
                break;
            }
            read.selection.spans.push(Span {
                first: here,
                last,
                part: Part::Other,
            });
        }
    }
    if !read.excluded.is_empty() && !read.workspace {
        return Err("gives `--exclude` without `--workspace`, which Cargo refuses".to_owned());
    }
    let mut selection = read.selection;
    // `--all-targets` takes the library and every kind whole, as each plural flag does, and Cargo
    // reads no singular flag beside it.
    if selection.all_targets {
        selection.lib = true;
        selection.bins = Rule::All;
        selection.examples = Rule::All;
        selection.tests = Rule::All;
        selection.benches = Rule::All;
    }
    // A plural flag takes every target of its kind and Cargo reads no name beside it, so only the
    // names of a kind that no plural flag takes are read as patterns.
    for (rule, names) in [
        (&mut selection.bins, read.bin_names),
        (&mut selection.examples, read.example_names),
        (&mut selection.tests, read.test_names),
        (&mut selection.benches, read.bench_names),
    ] {
        if *rule == Rule::Off && !names.is_empty() {
            *rule = Rule::Named(
                names
                    .iter()
                    .map(|name| Pattern::new(name))
                    .collect::<Result<_, _>>()?,
            );
        }
    }
    // A test name and no flag that names targets: Cargo builds the library, whatever its `test` key
    // says, and each target that is tested.
    if test_name && !selection.asks_for_targets() {
        selection.lib = true;
        selection.tests = Rule::All;
    }
    selection.packages = if read.workspace {
        Packages::Workspace(read.excluded)
    } else if read.named.is_empty() {
        Packages::Default
    } else {
        Packages::Named(read.named)
    };
    Ok(selection)
}

impl Selection {
    /// The words of a command that runs one test of `target` with the build that `command` made, as
    /// `cargo test` takes them before `--`: the command's own words, as written and in order, less
    /// `--no-run` and each word that holds a placeholder with its flag (`held` lists their indexes in
    /// `command`). Where `built`, the targets that the command's build made, holds `target` and every
    /// target that the test's own flag names in the selected packages among `packages`, that flag
    /// replaces the command's target flags and test names. Otherwise they stay.
    ///
    /// Cargo reads features from the whole set of packages and flags, so no other word changes. It
    /// applies a singular target flag to each selected package and refuses it for a target whose
    /// features are off, so the test's flag replaces the command's only for targets that the build
    /// made.
    #[must_use]
    pub fn test_words(
        &self,
        command: &[String],
        held: &[usize],
        target: &TargetId,
        packages: &[&Package],
        built: &[TargetId],
    ) -> Vec<String> {
        let narrowed = self.names_only_built(target, packages, built);
        let mut words = Vec::new();
        for span in &self.spans {
            let left_out = match span.part {
                Part::NoRun => true,
                Part::Targets | Part::Name => narrowed,
                Part::Other => false,
            };
            if left_out || (span.first..=span.last).any(|index| held.contains(&index)) {
                continue;
            }
            words.extend(command[span.first..=span.last].iter().cloned());
        }
        if narrowed {
            words.extend(
                target
                    .kind
                    .selector(&target.name)
                    .split(' ')
                    .map(str::to_owned),
            );
        }
        words
    }

    /// Whether `built` holds `target` and every target that the flag naming it names in the selected
    /// packages among `packages`: `--lib` names each package's library, and `--bin`, `--example`,
    /// `--test` and `--bench` the targets of their kind that bear the name.
    fn names_only_built(
        &self,
        target: &TargetId,
        packages: &[&Package],
        built: &[TargetId],
    ) -> bool {
        built.contains(target)
            && packages
                .iter()
                .filter(|package| self.selects_package(package))
                .flat_map(|package| &package.targets)
                .filter(|named| {
                    named.id.kind == target.kind
                        && (target.kind == TargetKind::Lib || named.id.name == target.name)
                })
                .all(|named| built.contains(&named.id))
    }

    /// The targets of `packages`, which are the members of one workspace, that the command selects.
    #[must_use]
    pub fn covers(&self, packages: &[&Package]) -> BTreeSet<TargetId> {
        packages
            .iter()
            .filter(|package| self.selects_package(package))
            .flat_map(|package| {
                package
                    .targets
                    .iter()
                    .filter(move |target| self.selects_target(package, target))
            })
            .map(|target| target.id.clone())
            .collect()
    }

    fn selects_package(&self, package: &Package) -> bool {
        match &self.packages {
            Packages::Default => package.workspace_default_members.contains(&package.name),
            Packages::Named(specs) => specs.iter().any(|spec| spec.matches(&package.name)),
            Packages::Workspace(excluded) => {
                !excluded.iter().any(|spec| spec.matches(&package.name))
            }
        }
    }

    /// The features of `package` that the command turns on: `--all-features` turns on every one;
    /// otherwise the `default` feature is on unless `--no-default-features` is given, and so is each
    /// feature `--features` names for the package (`f` or `<package>/f`) and each feature of its
    /// dev-dependency on itself. Each feature turns on the features its table lists.
    fn enabled(&self, package: &Package) -> BTreeSet<String> {
        let mut pending: Vec<String> = Vec::new();
        if self.all_features {
            pending.extend(package.features.keys().cloned());
        } else if !self.no_default_features {
            pending.push("default".to_owned());
        }
        for item in self.features.iter().map(|item| &item.value) {
            match item.split_once('/') {
                None => pending.push(item.clone()),
                Some((owner, feature)) if owner.trim_end_matches('?') == package.name => {
                    pending.push(feature.to_owned());
                }
                Some(_) => {}
            }
        }
        pending.extend(package.self_dev_features.iter().cloned());
        let mut on = BTreeSet::new();
        while let Some(feature) = pending.pop() {
            if !on.insert(feature.clone()) {
                continue;
            }
            for turned_on in package.features.get(&feature).into_iter().flatten() {
                match turned_on.split_once('/') {
                    None => pending.push(turned_on.clone()),
                    Some((owner, own)) if owner.trim_end_matches('?') == package.name => {
                        pending.push(own.to_owned());
                    }
                    Some(_) => {}
                }
            }
        }
        on
    }

    fn asks_for_targets(&self) -> bool {
        self.lib
            || self.all_targets
            || self.bins.asked()
            || self.examples.asked()
            || self.tests.asked()
            || self.benches.asked()
    }

    /// Whether Cargo builds the target to test it. With no flag that names targets, it builds each
    /// target that its manifest says is tested. With one, a plural flag takes every target of its
    /// kind, and `--tests` and `--benches` take every target of any kind that is tested or
    /// benchmarked, a library and the binaries among them; a singular flag takes the targets whose
    /// name it matches, and any of them builds the target to test it whatever its manifest says.
    fn selects_target(&self, package: &Package, target: &Target) -> bool {
        let name = &target.id.name;
        // Cargo leaves out a target whose features are not on when the command takes it by default,
        // by a plural flag or by a test name. When `--bin`, `--example`, `--test` or `--bench` names
        // it, Cargo refuses the command instead, so the target stays covered and the step's failure
        // is the reason of its tests.
        let named = match target.id.kind {
            TargetKind::Lib => false,
            TargetKind::Bin => self.bins.names(name),
            TargetKind::Example => self.examples.names(name),
            TargetKind::Test => self.tests.names(name),
            TargetKind::Bench => self.benches.names(name),
        };
        if !named && !target.required_features.is_empty() {
            let on = self.enabled(package);
            if !target
                .required_features
                .iter()
                .all(|feature| on.contains(feature))
            {
                return false;
            }
        }
        if !self.asks_for_targets() {
            return target.tested_by_default;
        }
        let all = self.all_targets;
        let by_kind = match target.id.kind {
            TargetKind::Lib => self.lib || all,
            TargetKind::Bin => all || self.bins.holds(name),
            TargetKind::Example => all || self.examples.holds(name),
            TargetKind::Test => self.tests.names(name),
            TargetKind::Bench => self.benches.names(name),
        };
        by_kind
            || ((all || self.tests == Rule::All) && target.tested_by_default)
            || ((all || self.benches == Rule::All) && target.benchmarked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn words(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    fn target(package: &str, kind: TargetKind, name: &str, tested: bool) -> Target {
        Target {
            id: TargetId {
                package: package.to_owned(),
                kind,
                name: name.to_owned(),
            },
            src_path: PathBuf::from("x.rs"),
            tested_by_default: tested,
            benchmarked: matches!(kind, TargetKind::Lib | TargetKind::Bin | TargetKind::Bench),
            required_features: Vec::new(),
            harness: true,
            edition: "2024".to_owned(),
        }
    }

    fn package(name: &str, targets: Vec<Target>, defaults: &[&str]) -> Package {
        Package {
            name: name.to_owned(),
            version: "0.1.0".to_owned(),
            targets,
            features: BTreeMap::new(),
            self_dev_features: BTreeSet::new(),
            manifest: PathBuf::from("Cargo.toml"),
            registry_crates: BTreeSet::new(),
            dependency_names: BTreeSet::new(),
            workspace: ".".to_owned(),
            workspace_members: vec!["a".to_owned(), "ab".to_owned(), "b".to_owned()],
            workspace_default_members: defaults.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    /// A workspace whose default member is `a`: `a` has a library, the binaries `x` and `z` (`z` is
    /// not tested), the integration test `t`, an example and a benchmark; `ab` and `b` have a
    /// library each.
    fn workspace() -> Vec<Package> {
        use TargetKind::{Bench, Bin, Example, Lib, Test};
        vec![
            package(
                "a",
                vec![
                    target("a", Lib, "a", true),
                    target("a", Bin, "x", true),
                    target("a", Bin, "z", false),
                    target("a", Test, "t", true),
                    target("a", Example, "e", false),
                    target("a", Bench, "m", false),
                ],
                &["a"],
            ),
            package("ab", vec![target("ab", Lib, "ab", true)], &["a"]),
            package("b", vec![target("b", Lib, "b", true)], &["a"]),
        ]
    }

    fn covered(line: &str) -> Vec<String> {
        let packages = workspace();
        let members: Vec<&Package> = packages.iter().collect();
        let selection = parse(&words(line)).unwrap_or_else(|why| panic!("{line}: {why}"));
        selection
            .covers(&members)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_pattern_matches_a_package_name_by_its_star_its_question_mark_and_its_classes() {
        let rows: &[(&str, &str, bool)] = &[
            ("a*", "a", true),
            ("a*", "ab", true),
            ("a*", "ba", false),
            ("*b", "ab", true),
            ("*", "anything", true),
            ("**", "anything", true),
            ("a?c", "abc", true),
            ("a?", "ab", true),
            ("a?", "a", false),
            ("a?", "abc", false),
            ("[ab]c", "bc", true),
            ("[ab]c", "cc", false),
            ("[a-c]x", "bx", true),
            ("[a-c]x", "dx", false),
            ("[!a]x", "bx", true),
            ("[!a]x", "ax", false),
            ("a*c*", "abxc", true),
            ("a*c*", "abx", false),
            ("kr-*", "kr-worker", true),
            ("kr-*", "other-kr-worker", false),
            ("**/single", "single", true),
            ("**/single", "xsingle", false),
            ("**/s*", "single", true),
            ("**/s*", "other", false),
            ("**/**/single", "single", true),
            ("**/**/s?ngle", "single", true),
            ("**/[sx]ingle", "single", true),
            ("a/**", "a", false),
            ("a/b", "a", false),
            ("[!]]x", "ax", true),
            ("[!]]x", "]x", false),
            ("[]a]x", "]x", true),
            ("[a-]x", "-x", true),
            ("[a-]x", "bx", false),
        ];
        let mut wrong = Vec::new();
        for (pattern, name, expected) in rows {
            let spec = Pattern::new(pattern).expect("a pattern");
            if spec.matches(name) != *expected {
                wrong.push(format!("`{pattern}` against `{name}` is not {expected}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn a_target_pattern_may_hold_a_recursive_component_and_a_pattern_a_plural_flag_supersedes_is_not_read()
     {
        // `**` as a whole component matches the name with no component before it.
        assert_eq!(covered("cargo test --test **/t"), ["a --test t"]);
        assert_eq!(covered("cargo test --test **/**/t"), ["a --test t"]);
        assert_eq!(covered("cargo test --bin **/x*"), ["a --bin x"]);
        assert_eq!(
            covered("cargo test --test **/nothing"),
            Vec::<String>::new()
        );
        // A plural flag takes every target of its kind and Cargo reads no pattern beside it, in
        // either order, so a pattern it refuses is not refused.
        let tests = covered("cargo test --tests");
        for line in [
            "cargo test --tests --test ***",
            "cargo test --test *** --tests",
            "cargo test --test a** --tests --test x**",
        ] {
            let read = parse(&words(line));
            assert!(read.is_ok(), "{line}: {read:?}");
            assert_eq!(covered(line), tests, "{line}");
        }
        assert_eq!(
            covered("cargo test --bins --bin ***"),
            covered("cargo test --bins")
        );
        // A pattern that no plural flag supersedes is read, and refused when Cargo refuses it.
        for line in ["cargo test --test ***", "cargo test --bins --test ***"] {
            assert!(parse(&words(line)).is_err(), "{line}");
        }
    }

    #[test]
    fn each_spelling_of_a_flag_that_takes_a_value_gives_the_same_selection() {
        let one = covered("cargo test -p b");
        assert_eq!(one, ["b --lib"]);
        for spelling in [
            "cargo test -pb",
            "cargo test -p=b",
            "cargo test --package b",
            "cargo test --package=b",
        ] {
            let read = parse(&words(spelling));
            assert!(read.is_ok(), "{spelling}: {read:?}");
            assert_eq!(covered(spelling), one, "{spelling}");
        }
        assert_eq!(covered("cargo test --bin=x"), ["a --bin x"]);
        assert_eq!(covered("cargo test --test t"), ["a --test t"]);
    }

    #[test]
    fn short_flags_written_together_take_the_value_of_the_one_that_takes_one() {
        let one = covered("cargo test -p b");
        for spelling in [
            "cargo test -qp b",
            "cargo test -rp b",
            "cargo test -vvp b",
            "cargo test -qpb",
            "cargo test -qp=b",
            "cargo test -rqpb",
        ] {
            let read = parse(&words(spelling));
            assert!(read.is_ok(), "{spelling}: {read:?}");
            assert_eq!(covered(spelling), one, "{spelling}");
        }
        let plain = covered("cargo test");
        for spelling in [
            "cargo test -j 4",
            "cargo test -j4",
            "cargo test -j=4",
            "cargo test -j -1",
            "cargo test -j=-1",
            "cargo test --jobs -1",
            "cargo test --jobs=-1",
            "cargo test --jobs -1 -qr",
        ] {
            let read = parse(&words(spelling));
            assert!(read.is_ok(), "{spelling}: {read:?}");
            assert_eq!(covered(spelling), plain, "{spelling}");
        }
    }

    #[test]
    fn a_command_selects_the_targets_cargo_builds_for_its_flags() {
        let rows: &[(&str, &[&str])] = &[
            ("cargo test", &["a --lib", "a --bin x", "a --test t"]),
            (
                "cargo test --locked --no-fail-fast",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            (
                "cargo test -q -vv -j 4 --features f",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            (
                "cargo test --release --no-run foo",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            (
                "cargo test -- --lib",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            (
                "cargo test -p a*",
                &["a --lib", "a --bin x", "a --test t", "ab --lib"],
            ),
            (
                "cargo test --workspace --exclude b",
                &["a --lib", "a --bin x", "a --test t", "ab --lib"],
            ),
            ("cargo test --all --exclude a*", &["b --lib"]),
            (
                "cargo test --workspace -p b",
                &["a --lib", "a --bin x", "a --test t", "ab --lib", "b --lib"],
            ),
            ("cargo test --lib", &["a --lib"]),
            (
                "cargo test --workspace --lib",
                &["a --lib", "ab --lib", "b --lib"],
            ),
            ("cargo test --bins", &["a --bin x", "a --bin z"]),
            ("cargo test --bin z", &["a --bin z"]),
            ("cargo test --lib --bin x", &["a --lib", "a --bin x"]),
            ("cargo test --bins --bin x", &["a --bin x", "a --bin z"]),
            (
                "cargo test --tests",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            (
                "cargo test --test t --tests",
                &["a --lib", "a --bin x", "a --test t"],
            ),
            ("cargo test --examples", &["a --example e"]),
            ("cargo test --example e", &["a --example e"]),
            (
                "cargo test --benches",
                &["a --lib", "a --bin x", "a --bin z", "a --bench m"],
            ),
            ("cargo test --bench m", &["a --bench m"]),
            (
                "cargo test --all-targets",
                &[
                    "a --lib",
                    "a --bin x",
                    "a --bin z",
                    "a --test t",
                    "a --example e",
                    "a --bench m",
                ],
            ),
            ("cargo test -p nowhere", &[]),
            ("cargo test --bin nowhere", &[]),
            ("cargo test --bin [xz]", &["a --bin x", "a --bin z"]),
            ("cargo test --bin ?", &["a --bin x", "a --bin z"]),
            ("cargo test --bin x*", &["a --bin x"]),
            ("cargo test --bin x --bin z*", &["a --bin x", "a --bin z"]),
            ("cargo test --test t*", &["a --test t"]),
            ("cargo test --test ?", &["a --test t"]),
            ("cargo test --test [!t]", &[]),
            ("cargo test --example *", &["a --example e"]),
            ("cargo test --bench m*", &["a --bench m"]),
            ("cargo test --bench **", &["a --bench m"]),
            ("cargo test smoke", &["a --lib", "a --bin x", "a --test t"]),
            ("cargo test smoke --bin x", &["a --bin x"]),
        ];
        let mut wrong = Vec::new();
        for (line, expected) in rows {
            let mut want: Vec<String> =
                expected.iter().map(|target| (*target).to_owned()).collect();
            want.sort();
            let mut have = covered(line);
            have.sort();
            if have != want {
                wrong.push(format!("{line}: covers {have:?}, not {want:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn all_targets_takes_every_kind_whole_and_reads_no_singular_flag_beside_it() {
        use TargetKind::{Bench, Lib, Test};
        let packages = [package(
            "a",
            vec![
                target("a", Lib, "a", true),
                target("a", Test, "t", true),
                target("a", Test, "off", false),
                target("a", Bench, "nb", false),
            ],
            &["a"],
        )];
        let members: Vec<&Package> = packages.iter().collect();
        let found = |line: &str| -> Vec<String> {
            parse(&words(line))
                .unwrap_or_else(|why| panic!("{line}: {why}"))
                .covers(&members)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        let read = parse(&words("cargo test --all-targets"));
        assert!(read.is_ok(), "{read:?}");
        let all = found("cargo test --all-targets");
        assert_eq!(all, ["a --lib", "a --test t", "a --bench nb"]);
        for line in [
            "cargo test --all-targets --test off",
            "cargo test --test off --all-targets",
            "cargo test --all-targets --bench nb --test t",
            "cargo test --all-targets --test ***",
            "cargo test --bench *** --all-targets",
        ] {
            let read = parse(&words(line));
            assert!(read.is_ok(), "{line}: {read:?}");
            assert_eq!(found(line), all, "{line}");
        }
        // Without it, a singular flag takes its target whatever its manifest says.
        let read = parse(&words("cargo test --test off"));
        assert!(read.is_ok(), "{read:?}");
        assert_eq!(found("cargo test --test off"), ["a --test off"]);
    }

    #[test]
    fn a_target_the_manifest_tests_by_default_is_covered_by_a_command_that_names_none() {
        use TargetKind::{Bench, Example, Lib};
        let packages = [package(
            "a",
            vec![
                target("a", Lib, "a", true),
                target("a", Example, "checked", true),
                target("a", Bench, "timed", true),
                target("a", Example, "plain", false),
            ],
            &["a"],
        )];
        let members: Vec<&Package> = packages.iter().collect();
        let selection = parse(&words("cargo test")).expect("a command");
        let found: Vec<String> = selection
            .covers(&members)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(found, ["a --lib", "a --bench timed", "a --example checked"]);
    }

    #[test]
    fn a_test_name_with_no_flag_that_names_targets_builds_the_library_whatever_its_test_key_says() {
        use TargetKind::{Bin, Lib, Test};
        let packages = [package(
            "a",
            vec![
                target("a", Lib, "a", false),
                target("a", Bin, "x", true),
                target("a", Test, "t", true),
                target("a", Test, "off", false),
            ],
            &["a"],
        )];
        let members: Vec<&Package> = packages.iter().collect();
        let found = |line: &str| -> Vec<String> {
            parse(&words(line))
                .expect("a command")
                .covers(&members)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(found("cargo test"), ["a --bin x", "a --test t"]);
        assert_eq!(
            found("cargo test smoke"),
            ["a --lib", "a --bin x", "a --test t"]
        );
        assert_eq!(
            found("cargo test -q smoke -- --nocapture"),
            found("cargo test smoke")
        );
        assert_eq!(
            found("cargo test --tests smoke"),
            ["a --bin x", "a --test t"]
        );
        assert_eq!(found("cargo test smoke --lib"), ["a --lib"]);
    }

    #[test]
    fn a_target_is_benchmarked_by_its_bench_key_and_by_its_kind_where_it_has_none() {
        use TargetKind::{Bench, Bin, Example, Lib, Test};
        let with = |kind, name: &str, tested: bool, benchmarked: bool| {
            let mut one = target("a", kind, name, tested);
            one.benchmarked = benchmarked;
            one
        };
        let packages = [package(
            "a",
            vec![
                with(Lib, "a", true, false),
                with(Bin, "x", true, true),
                with(Test, "t", true, true),
                with(Test, "u", false, true),
                with(Example, "e", false, true),
                with(Example, "f", false, false),
                with(Bench, "m", false, true),
                with(Bench, "n", false, false),
            ],
            &["a"],
        )];
        let members: Vec<&Package> = packages.iter().collect();
        let found = |line: &str| -> Vec<String> {
            parse(&words(line))
                .expect("a command")
                .covers(&members)
                .iter()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let sorted = |names: &[&str]| -> Vec<String> {
            let mut names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
            names.sort();
            names
        };
        assert_eq!(
            found("cargo test --benches"),
            sorted(&[
                "a --bin x",
                "a --bench m",
                "a --test t",
                "a --test u",
                "a --example e"
            ])
        );
        assert_eq!(
            found("cargo test --all-targets"),
            sorted(&[
                "a --lib",
                "a --bin x",
                "a --bench m",
                "a --test t",
                "a --test u",
                "a --example e",
                "a --example f"
            ])
        );
        assert_eq!(found("cargo test --bench n"), ["a --bench n"]);
        assert_eq!(
            found("cargo test --tests"),
            sorted(&["a --lib", "a --bin x", "a --test t"])
        );
    }

    #[test]
    fn a_target_with_required_features_is_covered_when_the_command_turns_each_one_on() {
        use TargetKind::{Lib, Test};
        let needs = |package: &str, name: &str, features: &[&str]| {
            let mut one = target(package, Test, name, true);
            one.required_features = features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect();
            one
        };
        let table = |entries: &[(&str, &[&str])]| -> BTreeMap<String, Vec<String>> {
            entries
                .iter()
                .map(|(name, on)| {
                    (
                        (*name).to_owned(),
                        on.iter().map(|feature| (*feature).to_owned()).collect(),
                    )
                })
                .collect()
        };
        let mut first = package(
            "a",
            vec![
                target("a", Lib, "a", true),
                needs("a", "free", &[]),
                needs("a", "f", &["f"]),
                needs("a", "d", &["d"]),
                needs("a", "g", &["g"]),
                needs("a", "fd", &["f", "d"]),
            ],
            &["a"],
        );
        first.features = table(&[
            ("default", &["d"]),
            ("d", &[]),
            ("f", &[]),
            ("g", &["f", "x?/y", "dep:x"]),
            ("x", &["dep:x"]),
        ]);
        // The second package turns on `s` through a dev-dependency on itself that leaves the default
        // features off, and the third turns on `default` through one that does not.
        let mut second = package(
            "b",
            vec![needs("b", "s", &["s"]), needs("b", "d", &["d"])],
            &["a"],
        );
        second.features = table(&[("default", &["d"]), ("d", &[]), ("s", &[])]);
        second.self_dev_features = BTreeSet::from(["s".to_owned()]);
        let mut third = package("c", vec![needs("c", "d", &["d"])], &["a"]);
        third.features = table(&[("default", &["d"]), ("d", &[])]);
        third.self_dev_features = BTreeSet::from(["default".to_owned()]);
        let packages = [first, second, third];
        let members: Vec<&Package> = packages.iter().collect();
        let found = |line: &str| -> Vec<String> {
            parse(&words(line))
                .expect("a command")
                .covers(&members)
                .iter()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let a = |names: &[&str]| -> Vec<String> {
            let mut shown: Vec<String> = names
                .iter()
                .map(|name| match *name {
                    "lib" => "a --lib".to_owned(),
                    other => format!("a --test {other}"),
                })
                .collect();
            shown.sort();
            shown
        };
        assert_eq!(found("cargo test"), a(&["lib", "d", "free"]));
        assert_eq!(
            found("cargo test --features f"),
            a(&["lib", "d", "f", "fd", "free"])
        );
        assert_eq!(
            found("cargo test -F a/f"),
            a(&["lib", "d", "f", "fd", "free"])
        );
        assert_eq!(
            found("cargo test --features f,g"),
            a(&["lib", "d", "f", "fd", "g", "free"])
        );
        assert_eq!(
            found("cargo test --features=g"),
            a(&["lib", "d", "f", "fd", "g", "free"])
        );
        assert_eq!(found("cargo test --features b/f"), a(&["lib", "d", "free"]));
        // Cargo splits a feature list at commas and at any whitespace.
        for line in [
            "cargo test --features f\tg",
            "cargo test --features f\ng",
            "cargo test --features f,\tg",
            "cargo test -F f\t\tg",
        ] {
            let read = parse(&words(line));
            assert!(read.is_ok(), "{line}: {read:?}");
            assert_eq!(
                found(line),
                a(&["lib", "d", "f", "fd", "g", "free"]),
                "{line}"
            );
        }
        // An empty list is a list: `--features=` and `-F=` take no word after them, so a word that
        // follows is the filter that names tests, which selects the library and the tested targets.
        for line in [
            "cargo test --features=",
            "cargo test -F=",
            "cargo test --features= --no-default-features",
        ] {
            let read = parse(&words(line));
            assert!(read.is_ok(), "{line}: {read:?}");
            let plain = if line.contains("--no-default") {
                a(&["lib", "free"])
            } else {
                a(&["lib", "d", "free"])
            };
            assert_eq!(found(line), plain, "{line}");
        }
        for line in ["cargo test -F= f", "cargo test -F= --test f"] {
            let read = parse(&words(line));
            assert!(read.is_ok(), "{line}: {read:?}");
        }
        assert_eq!(found("cargo test -F= f"), a(&["lib", "d", "free"]));
        assert_eq!(
            found("cargo test -F= --test f"),
            a(&["f"]),
            "the word after an empty list is not its value"
        );
        assert_eq!(
            found("cargo test --no-default-features"),
            a(&["lib", "free"])
        );
        assert_eq!(
            found("cargo test --no-default-features --features f"),
            a(&["lib", "f", "free"])
        );
        assert_eq!(
            found("cargo test --all-features"),
            a(&["lib", "d", "f", "fd", "g", "free"])
        );
        // A singular flag that names a target whose features are off keeps it covered: Cargo refuses
        // the command, and the step's failure is the reason of the target's tests.
        assert_eq!(found("cargo test --test f"), a(&["f"]));
        assert_eq!(found("cargo test --test f*"), a(&["f", "fd", "free"]));
        assert_eq!(found("cargo test --test f --features f"), a(&["f"]));
        assert_eq!(
            found("cargo test --tests --test f"),
            a(&["lib", "d", "free"])
        );
        let own = |line: &str, package: &str| -> Vec<String> {
            found(line)
                .into_iter()
                .filter(|target| target.starts_with(package))
                .collect()
        };
        assert_eq!(
            own("cargo test --workspace --no-default-features", "b"),
            ["b --test s"]
        );
        assert_eq!(
            own("cargo test --workspace --no-default-features", "c"),
            ["c --test d"]
        );
        assert_eq!(
            own("cargo test --workspace", "b"),
            ["b --test d", "b --test s"]
        );
    }

    #[test]
    fn a_command_that_cannot_be_read_is_refused_for_each_fault_by_its_reason() {
        let rows: &[(&str, &str)] = &[
            (
                "cargo build -p a",
                "reads the output of `cargo test` and its command is not `cargo test`",
            ),
            (
                "cargo",
                "reads the output of `cargo test` and its command is not `cargo test`",
            ),
            (
                "cargo +nightly test",
                "reads the output of `cargo test` and its command is not `cargo test`",
            ),
            (
                "cargo test --manifest-path other/Cargo.toml",
                "gives `--manifest-path`: the step's directory is its workspace, and `-p` and `--workspace` choose the packages in it",
            ),
            ("cargo test -m other/Cargo.toml", "gives `--manifest-path`"),
            (
                "cargo test --manifest-path=other/Cargo.toml",
                "gives `--manifest-path`",
            ),
            (
                "cargo test -Z unstable-options",
                "gives `-Z`, an unstable flag that can change which targets Cargo selects and that the report does not read",
            ),
            ("cargo test -Zunstable-options", "gives `-Z`"),
            (
                "cargo test --exclude b",
                "gives `--exclude` without `--workspace`, which Cargo refuses",
            ),
            (
                "cargo test -p a --exclude b",
                "gives `--exclude` without `--workspace`",
            ),
            (
                "cargo test --workspace --nope",
                "gives `--nope`, which is not a flag of `cargo test`: the report reads only the flags it knows",
            ),
            (
                "cargo test -x",
                "gives `-x`, which is not a flag of `cargo test`",
            ),
            (
                "cargo test --helpful",
                "gives `--helpful`, which is not a flag of `cargo test`",
            ),
            ("cargo test -p", "gives `--package` without a value"),
            ("cargo test -p --lib", "gives `--package` without a value"),
            ("cargo test --bin", "gives `--bin` without a value"),
            ("cargo test --test --lib", "gives `--test` without a value"),
            (
                "cargo test --features",
                "gives `--features` without a value",
            ),
            ("cargo test --package=", "gives `--package` without a value"),
            (
                "cargo test --workspace=yes",
                "gives `--workspace=yes`, but `--workspace` takes no value",
            ),
            (
                "cargo test -p a@0.1.0",
                "names the package `a@0.1.0`: give a package by its name, or by a pattern of `*`, `?` and `[...]` that matches names",
            ),
            ("cargo test -p a:0.1.0", "names the package `a:0.1.0`"),
            ("cargo test -p ../a", "names the package `../a`"),
            (
                "cargo test -p https://example.test/a#a",
                "names the package `https://example.test/a#a`",
            ),
            (
                "cargo test --workspace --exclude a@1",
                "names the package `a@1`",
            ),
            (
                "cargo test -p a[b",
                "names the pattern `a[b`, which has a `[` that no `]` closes",
            ),
            (
                "cargo test --doc",
                "gives `--doc`: the report reads no doc test, and the run adds `--no-run`, which Cargo refuses with `--doc`",
            ),
            (
                "cargo test --lib --doc",
                "gives `--doc`: the report reads no doc test",
            ),
            (
                "cargo test -h",
                "gives `-h`, which prints help and builds nothing",
            ),
            (
                "cargo test --help",
                "gives `--help`, which prints help and builds nothing",
            ),
            (
                "cargo test -qh",
                "gives `-h`, which prints help and builds nothing",
            ),
            (
                "cargo test --timings=html",
                "gives `--timings=html`, but `--timings` takes no value",
            ),
            ("cargo test -qp", "gives `--package` without a value"),
            ("cargo test -j", "gives `--jobs` without a value"),
            ("cargo test -j -x", "gives `--jobs` without a value"),
            (
                "cargo test -qx",
                "gives `-x`, which is not a flag of `cargo test`",
            ),
            (
                "cargo test -p a**",
                "names the pattern `a**`, which Cargo refuses: a run of `*` is one `*`, or `**` as a whole path component",
            ),
            (
                "cargo test --workspace --exclude **a",
                "names the pattern `**a`, which Cargo refuses",
            ),
            (
                "cargo test --test **x",
                "names the pattern `**x`, which Cargo refuses",
            ),
            (
                "cargo test --test x/**y",
                "names the pattern `x/**y`, which Cargo refuses",
            ),
            (
                "cargo test --test ***",
                "names the pattern `***`, which Cargo refuses",
            ),
            (
                "cargo test --bin a*b**",
                "names the pattern `a*b**`, which Cargo refuses",
            ),
            (
                "cargo test --example x[y",
                "names the pattern `x[y`, which has a `[` that no `]` closes",
            ),
        ];
        let mut wrong = Vec::new();
        for (line, why) in rows {
            match parse(&words(line)) {
                Ok(_) => wrong.push(format!("{line}: read, not refused")),
                Err(refusal) if refusal.contains(why) => {}
                Err(refusal) => wrong.push(format!(
                    "{line}: refused as `{refusal}`, which lacks `{why}`"
                )),
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    fn id(package: &str, kind: TargetKind, name: &str) -> TargetId {
        TargetId {
            package: package.to_owned(),
            kind,
            name: name.to_owned(),
        }
    }

    /// The words of a test of `target` for the command `line`, whose words at the `held` places hold
    /// a placeholder, where the targets the command built are `built`.
    fn test_words_of(
        line: &str,
        held: &[&str],
        packages: &[&Package],
        target: &TargetId,
        built: &[TargetId],
    ) -> Vec<String> {
        let command = words(line);
        let held: Vec<usize> = held
            .iter()
            .map(|word| command.iter().position(|one| one == word).expect("a word"))
            .collect();
        parse(&command)
            .unwrap_or_else(|why| panic!("{line}: {why}"))
            .test_words(&command, &held, target, packages, built)
    }

    /// A command's words stay as it wrote them and in order, less `--no-run`, each word that holds a
    /// placeholder with its flag, and its target flags and test names, which the test's own flag
    /// replaces. Nothing is added, `--locked` included.
    #[test]
    fn a_tests_words_are_the_commands_own_less_its_target_flags_names_and_placeholders() {
        use TargetKind::Lib;
        let one = package("a", vec![target("a", Lib, "a", true)], &["a"]);
        let packages = [&one];
        let a = id("a", Lib, "a");
        let built = [a.clone()];
        for (line, expected) in [
            // A short group stays whole, and so does a pattern as written.
            (
                "cargo test -qp a* --release -F f,a/g --features=h --no-run foo --lib --bins -j 2 --all-targets",
                "-qp a* --release -F f,a/g --features=h -j 2 --lib",
            ),
            (
                "cargo test --locked --offline --config=c=1 --target t --frozen --message-format short",
                "--locked --offline --config=c=1 --target t --frozen --message-format short --lib",
            ),
            // `--locked` is the step's own, or it is not there.
            ("cargo test -p a", "-p a --lib"),
            ("cargo test -r --bin x --example y", "-r --lib"),
        ] {
            assert_eq!(
                test_words_of(line, &[], &packages, &a, &built).join(" "),
                expected,
                "{line}"
            );
        }
        // A word that holds a placeholder goes with its flag, and each other word stays.
        let line = "cargo test -p a --target {s}/t --target u --config=c={s} --config d=2 --profile {s} --features {s},f --test {s}";
        let held = ["{s}/t", "--config=c={s}", "{s}", "{s},f"];
        assert_eq!(
            test_words_of(line, &held, &packages, &a, &built).join(" "),
            "-p a --target u --config d=2 --lib"
        );
        assert_eq!(
            test_words_of(line, &[], &packages, &a, &built).join(" "),
            "-p a --target {s}/t --target u --config=c={s} --config d=2 --profile {s} --features {s},f --lib"
        );
    }

    /// The test's own flag stands for the command's target flags only where the build made every
    /// target that flag names in the selected packages; where it did not, the command's own target
    /// flags and test names stay. The packages that the command does not select count for nothing.
    #[test]
    fn a_tests_own_flag_stands_for_the_target_flags_only_where_the_build_made_every_target_it_names()
     {
        use TargetKind::{Lib, Test};
        let a = package(
            "a",
            vec![target("a", Lib, "a", true), target("a", Test, "t", true)],
            &["a", "b"],
        );
        let b = package(
            "b",
            vec![target("b", Lib, "b", true), target("b", Test, "t", true)],
            &["a", "b"],
        );
        let c = package("c", vec![target("c", Test, "t", true)], &["a", "b"]);
        let packages = [&a, &b, &c];
        let (a_lib, b_lib) = (id("a", Lib, "a"), id("b", Lib, "b"));
        let (a_t, b_t, c_t) = (id("a", Test, "t"), id("b", Test, "t"), id("c", Test, "t"));
        for (line, target, built, expected) in [
            // Each target the flag names is built: the flag stands.
            (
                "cargo test --workspace foo",
                &a_t,
                vec![a_t.clone(), b_t.clone(), c_t.clone()],
                "--workspace --test t",
            ),
            (
                "cargo test --workspace --lib",
                &a_lib,
                vec![a_lib.clone(), b_lib.clone()],
                "--workspace --lib",
            ),
            // A package the command does not select counts for nothing.
            (
                "cargo test -p a -p b --tests",
                &a_t,
                vec![a_t.clone(), b_t.clone()],
                "-p a -p b --test t",
            ),
            (
                "cargo test --workspace --exclude c --test t",
                &a_t,
                vec![a_t.clone(), b_t.clone()],
                "--workspace --exclude c --test t",
            ),
            // The default members are `a` and `b`, so `c` counts for nothing here too.
            (
                "cargo test",
                &b_t,
                vec![a_t.clone(), b_t.clone()],
                "--test t",
            ),
            // One of them is not built: the command's own flags and test names stay.
            (
                "cargo test --workspace foo",
                &a_t,
                vec![a_t.clone(), b_t.clone()],
                "--workspace foo",
            ),
            (
                "cargo test --workspace --all-targets",
                &a_lib,
                vec![a_lib.clone()],
                "--workspace --all-targets",
            ),
            (
                "cargo test --workspace --tests --no-run",
                &a_t,
                vec![b_t.clone(), c_t.clone()],
                "--workspace --tests",
            ),
            // The step built nothing the test is: the command's own flags stay.
            ("cargo test -p a --tests", &a_t, Vec::new(), "-p a --tests"),
        ] {
            let rows = test_words_of(line, &[], &packages, target, &built);
            assert_eq!(rows.join(" "), expected, "{line}");
        }
    }
}
