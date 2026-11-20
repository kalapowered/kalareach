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
//! flag and `--target` change which targets build; a target that Cargo leaves out for one of them is
//! covered here and reads as not run, because no listing returned it.

use std::collections::BTreeSet;

use crate::workspace::{Package, Target, TargetId, TargetKind};

/// A name, or a pattern of `*`, `?` and `[...]` that matches names, as Cargo reads one in `-p`,
/// `--exclude`, `--bin`, `--example`, `--test` and `--bench`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern(String);

impl Pattern {
    fn new(text: &str) -> Result<Self, String> {
        let pattern: Vec<char> = text.chars().collect();
        let mut at = 0;
        while at < pattern.len() {
            match pattern[at] {
                '[' => match class_end(&pattern, at) {
                    Some(end) => at = end,
                    None => {
                        return Err(format!(
                            "names the pattern `{text}`, which has a `[` that no `]` closes"
                        ));
                    }
                },
                '*' => {
                    // Cargo reads `**` as a pattern only where it is a whole path component, and a
                    // name has one component.
                    let run = pattern[at..].iter().take_while(|one| **one == '*').count();
                    if run > 2 || (run == 2 && pattern.len() != 2) {
                        return Err(format!(
                            "names the pattern `{text}`, which Cargo refuses: a run of `*` is one \
                             `*`, or the whole pattern `**`"
                        ));
                    }
                    at += run - 1;
                }
                _ => {}
            }
            at += 1;
        }
        Ok(Self(text.to_owned()))
    }

    fn matches(&self, name: &str) -> bool {
        let pattern: Vec<char> = self.0.chars().collect();
        let name: Vec<char> = name.chars().collect();
        glob(&pattern, &name)
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

/// The index of the `]` that closes the class that opens at `open`, if one does.
fn class_end(pattern: &[char], open: usize) -> Option<usize> {
    let mut at = open + 1;
    if pattern.get(at) == Some(&'!') {
        at += 1;
    }
    // The first character of a class is a member, a `]` included.
    at += 1;
    while at < pattern.len() {
        if pattern[at] == ']' {
            return Some(at);
        }
        at += 1;
    }
    None
}

/// Whether `name` matches `pattern`, where `*` is any run of characters, `?` is one, and a class
/// `[abc]`, `[a-c]` or `[!abc]` is one character in it or, with the `!`, not in it.
fn glob(pattern: &[char], name: &[char]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some('*') => (0..=name.len()).any(|skip| glob(&pattern[1..], &name[skip..])),
        Some('?') => !name.is_empty() && glob(&pattern[1..], &name[1..]),
        Some('[') => {
            let Some(end) = class_end(pattern, 0) else {
                return false;
            };
            let Some(&have) = name.first() else {
                return false;
            };
            let negated = pattern.get(1) == Some(&'!');
            let members = &pattern[if negated { 2 } else { 1 }..end];
            let mut found = false;
            let mut at = 0;
            while at < members.len() {
                if members.get(at + 1) == Some(&'-') && at + 2 < members.len() {
                    found |= (members[at]..=members[at + 2]).contains(&have);
                    at += 3;
                } else {
                    found |= members[at] == have;
                    at += 1;
                }
            }
            found != negated && glob(&pattern[end + 1..], &name[1..])
        }
        Some(&one) => name.first() == Some(&one) && glob(&pattern[1..], &name[1..]),
    }
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

    fn name(&mut self, text: &str) -> Result<(), String> {
        let pattern = Pattern::new(text)?;
        match self {
            Self::All => {}
            Self::Named(patterns) => patterns.push(pattern),
            Self::Off => *self = Self::Named(vec![pattern]),
        }
        Ok(())
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
    carried: Vec<String>,
}

/// The words read so far.
struct Parsed {
    selection: Selection,
    named: Vec<Pattern>,
    excluded: Vec<Pattern>,
    workspace: bool,
}

impl Parsed {
    /// Takes `flag`, the first of its spellings, with its value: empty for a flag that takes none.
    fn give(&mut self, flag: &str, value: String) -> Result<(), String> {
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
            "--bin" => selection.bins.name(&value)?,
            "--examples" => selection.examples = Rule::All,
            "--example" => selection.examples.name(&value)?,
            "--tests" => selection.tests = Rule::All,
            "--test" => selection.tests.name(&value)?,
            "--benches" => selection.benches = Rule::All,
            "--bench" => selection.benches.name(&value)?,
            "--all-targets" => selection.all_targets = true,
            "--release" | "--all-features" | "--no-default-features" => {
                selection.carried.push(flag.to_owned());
            }
            "--profile" | "--features" => {
                selection.carried.push(flag.to_owned());
                selection.carried.push(value);
            }
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
            carried: Vec::new(),
        },
        named: Vec::new(),
        excluded: Vec::new(),
        workspace: false,
    };
    let mut test_name = false;
    let mut at = 0;
    while at < words.len() {
        let word = words[at];
        at += 1;
        if !word.starts_with('-') || word == "-" {
            // A word that is no flag is the name that filters the tests.
            test_name = true;
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
            let value = match (takes, held) {
                (Takes::No, None) => String::new(),
                (Takes::No, Some(_)) => {
                    return Err(format!("gives `{word}`, but `{flag}` takes no value"));
                }
                (Takes::Value, Some("")) => return Err(without_value(flag)),
                (Takes::Value, Some(held)) => held.to_owned(),
                (Takes::Value, None) => next_value(&words, &mut at, flag)?,
            };
            read.give(flag, value)?;
        } else {
            // Short flags may be written together, as `-qp a`: each takes the next letter, until one
            // takes a value, which is the rest of the word or, with none, the next word.
            let mut rest = &word[1..];
            while let Some(letter) = rest.chars().next() {
                let spelling = format!("-{letter}");
                let Some((spellings, takes)) = flag(&spelling) else {
                    return Err(not_a_flag(&spelling));
                };
                let flag = spellings[0];
                refused(flag, &spelling)?;
                rest = &rest[letter.len_utf8()..];
                if takes == Takes::No {
                    read.give(flag, String::new())?;
                    continue;
                }
                let held = rest.strip_prefix('=').unwrap_or(rest);
                let value = if held.is_empty() {
                    next_value(&words, &mut at, flag)?
                } else {
                    held.to_owned()
                };
                read.give(flag, value)?;
                break;
            }
        }
    }
    if !read.excluded.is_empty() && !read.workspace {
        return Err("gives `--exclude` without `--workspace`, which Cargo refuses".to_owned());
    }
    let mut selection = read.selection;
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
    /// The words of the command that choose the features and the profile, which a command that runs
    /// one test of the step repeats.
    #[must_use]
    pub fn carried(&self) -> &[String] {
        &self.carried
    }

    /// The targets of `packages`, which are the members of one workspace, that the command selects.
    #[must_use]
    pub fn covers(&self, packages: &[&Package]) -> BTreeSet<TargetId> {
        packages
            .iter()
            .filter(|package| self.selects_package(package))
            .flat_map(|package| &package.targets)
            .filter(|target| self.selects_target(target))
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
    fn selects_target(&self, target: &Target) -> bool {
        if !self.asks_for_targets() {
            return target.tested_by_default;
        }
        let all = self.all_targets;
        let name = &target.id.name;
        // A library, a binary and a benchmark are benchmarked unless their manifest says they are
        // not; the metadata does not carry that, so a target that says `bench = false` is covered
        // here and listed by Cargo as not built.
        let benchmarked = matches!(
            target.id.kind,
            TargetKind::Lib | TargetKind::Bin | TargetKind::Bench
        );
        let by_kind = match target.id.kind {
            TargetKind::Lib => self.lib || all,
            TargetKind::Bin => all || self.bins.holds(name),
            TargetKind::Example => all || self.examples.holds(name),
            TargetKind::Test => self.tests.names(name),
            TargetKind::Bench => self.benches.names(name),
        };
        by_kind
            || ((all || self.tests == Rule::All) && target.tested_by_default)
            || ((all || self.benches == Rule::All) && benchmarked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            harness: true,
            edition: "2024".to_owned(),
        }
    }

    fn package(name: &str, targets: Vec<Target>, defaults: &[&str]) -> Package {
        Package {
            name: name.to_owned(),
            version: "0.1.0".to_owned(),
            targets,
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
    fn each_spelling_of_a_flag_that_takes_a_value_gives_the_same_selection() {
        let one = covered("cargo test -p b");
        assert_eq!(one, ["b --lib"]);
        for spelling in [
            "cargo test -pb",
            "cargo test -p=b",
            "cargo test --package b",
            "cargo test --package=b",
        ] {
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
                "names the pattern `a**`, which Cargo refuses: a run of `*` is one `*`, or the whole pattern `**`",
            ),
            (
                "cargo test --workspace --exclude **a",
                "names the pattern `**a`, which Cargo refuses",
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

    #[test]
    fn a_command_repeats_the_features_and_the_profile_it_was_given_and_nothing_else() {
        let carried = |line: &str| parse(&words(line)).expect("a command").carried().to_vec();
        assert_eq!(
            carried(
                "cargo test --locked -p a --release --features f,g --all-features --no-default-features --profile ci -j 2 -- --nocapture"
            ),
            [
                "--release",
                "--features",
                "f,g",
                "--all-features",
                "--no-default-features",
                "--profile",
                "ci"
            ]
        );
        assert_eq!(
            carried("cargo test -F f -r"),
            ["--features", "f", "--release"]
        );
        assert_eq!(carried("cargo test -qr"), ["--release"]);
        assert_eq!(
            carried("cargo test --features=f --profile=ci"),
            ["--features", "f", "--profile", "ci"]
        );
        assert!(carried("cargo test --workspace --locked").is_empty());
    }
}
