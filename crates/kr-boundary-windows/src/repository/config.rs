//! The classifier of a repository's configuration listing.
//!
//! The broker never lets Git read the repository's configuration file unchecked. It reads the file
//! through its own handle and has Git list that copy as `git config --file <copy> --list --null`;
//! this module is the allowlist over that listing. A listing is a sequence of records, each ended
//! by a NUL byte. A record is a key, or a key, a newline and a value: it splits at its first
//! newline, a value may hold more, and no newline at all means the key has no value, which is not
//! the same as an empty one.
//!
//! Only the keys of the table below are admitted, each with the values its type allows. A key that
//! is not in the table is refused and the refusal names the family it belongs to, so that a person
//! reads why: an include, a setting that names a program, a setting that names another location,
//! a setting for connecting to another computer. The families are only names for the refusal; the
//! table is the boundary.
//!
//! The classifier is given the listing and nothing else. It does not hold the configuration file's
//! bytes or their digest: those belong to the hold the broker keeps on the file, and the facts here
//! are what the operations need from a listing that has been admitted.

use std::collections::BTreeSet;

use crate::frame::invocation::{RefusedKind, printable};
use crate::names::{BRANCH_PREFIX, is_branch_name};
use crate::operation::grammar;
use crate::refusal::Refusal;

/// The bounds on a listing, each checked before anything of the listing is parsed or copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes of a listing.
    pub listing_bytes: usize,
    /// The most records of a listing.
    pub records: usize,
    /// The most bytes of one record, without its NUL: the key, the newline and the value.
    pub record_bytes: usize,
    /// The most bytes of the subsection part of a key.
    pub subsection_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            listing_bytes: 1_048_576,
            records: 4096,
            record_bytes: 8192,
            subsection_bytes: 256,
        }
    }
}

/// The object format of a repository.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectFormat {
    /// SHA-1, the only format the broker admits.
    #[default]
    Sha1,
}

/// A value of `core.autocrlf` that the repository's own file sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoCrlf {
    /// `true`.
    True,
    /// `false`.
    False,
    /// `input`.
    Input,
}

/// What the operations need from an admitted listing. Where a key repeats, the last value is the
/// one Git uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigFacts {
    /// The repository's object format.
    pub object_format: ObjectFormat,
    /// `core.symlinks` as the file sets it: only `false` is admitted.
    pub symlinks_local: Option<bool>,
    /// `core.autocrlf` as the file sets it.
    pub autocrlf_local: Option<AutoCrlf>,
    /// The names of the remotes the file defines, sorted, each once.
    pub remotes: Vec<String>,
    /// Whether `core.sparseCheckout` is on.
    pub sparse: bool,
}

/// The listing is over [`Limits::listing_bytes`].
pub const RULE_LISTING_TOO_LARGE: &str = "config-listing-too-large";
/// The listing's last byte is not a NUL.
pub const RULE_TRUNCATED: &str = "config-truncated";
/// The listing has more than [`Limits::records`] records.
pub const RULE_TOO_MANY_RECORDS: &str = "config-too-many-records";
/// A record is over [`Limits::record_bytes`].
pub const RULE_RECORD_TOO_LARGE: &str = "config-record-too-large";
/// A key's subsection is over [`Limits::subsection_bytes`].
pub const RULE_SUBSECTION_TOO_LARGE: &str = "config-subsection-too-large";
/// A record has no key, or a key that is not valid text with a section and a variable.
pub const RULE_RECORD_KEY: &str = "config-record-key";
/// An include.
pub const RULE_INCLUDE: &str = "config-include";
/// A key that names a program.
pub const RULE_PROGRAM: &str = "config-program";
/// A key that names another location.
pub const RULE_LOCATION: &str = "config-location";
/// A key for connecting to another computer.
pub const RULE_TRANSPORT: &str = "config-transport";
/// An extension, or an extension's value, that is not admitted.
pub const RULE_EXTENSION: &str = "config-extension";
/// A repository with a configuration of its own for its worktree.
pub const RULE_WORKTREE_CONFIG: &str = "config-worktree-config";
/// A key that is in no family and not in the table.
pub const RULE_UNLISTED: &str = "config-unlisted";
/// An admitted key whose value is outside its type.
pub const RULE_VALUE: &str = "config-value";
/// `core.symlinks` that is not `false`.
pub const RULE_SYMLINKS: &str = "config-symlinks";
/// `core.bare` that is not `false`.
pub const RULE_BARE: &str = "config-bare";
/// An address that names a helper program.
pub const RULE_URL_HELPER: &str = "config-url-helper";

/// Classifies the bytes of a NUL-framed configuration listing.
///
/// The checks run in this order, so that none of the later ones works on bytes an earlier bound
/// has not accepted: the listing's size; its framing; the record count; each record's length; then
/// each record's key and value. None of the first four copies a byte. An empty listing is valid and
/// has no records.
///
/// # Errors
///
/// Returns a refusal of kind `configuration` naming the rule: a bound, the framing, a key or a
/// value.
pub fn classify_config(listing: &[u8], limits: &Limits) -> Result<ConfigFacts, Refusal> {
    let Some(body) = frame(listing, limits)? else {
        return Ok(ConfigFacts::default());
    };
    let records = || body.split(|byte| *byte == 0);
    let mut facts = ConfigFacts::default();
    let mut remotes = BTreeSet::new();
    for record in records() {
        admit(record, limits, &mut facts, &mut remotes)?;
    }
    facts.remotes = remotes.into_iter().collect();
    Ok(facts)
}

/// Classifies the bytes of the NUL-framed listing of a `.gitmodules` file, which has the framing
/// and the bounds of a configuration listing and a table of four keys of its own: for each
/// submodule `path` (a path of the tree), `url` (text that names no transport helper), `branch` (a
/// branch name) and `ignore` (`none`, `untracked`, `dirty` or `all`). Every other key refuses the
/// repository, by name. An empty listing is valid.
///
/// # Errors
///
/// Returns a refusal of kind `configuration` naming the rule: a bound, the framing, a key that is
/// not one of the four or a value outside its type.
pub fn classify_gitmodules(listing: &[u8], limits: &Limits) -> Result<(), Refusal> {
    let Some(body) = frame(listing, limits)? else {
        return Ok(());
    };
    for record in body.split(|byte| *byte == 0) {
        let (key, value) = split_record(record);
        let key = Key::parse(key, limits)?;
        let Some(entry) = SUBMODULE_TABLE.iter().find(|entry| entry.matches(&key)) else {
            return Err(key.refusal(
                RULE_UNLISTED,
                "is not a setting of a submodule file that this release admits",
            ));
        };
        check_value(entry, &key, value)?;
    }
    Ok(())
}

/// Checks a listing's size, framing, record count and record lengths, in that order, and returns
/// its records without their last NUL: `None` for an empty listing, which has no records.
fn frame<'a>(listing: &'a [u8], limits: &Limits) -> Result<Option<&'a [u8]>, Refusal> {
    if listing.len() > limits.listing_bytes {
        return Err(refusal(
            RULE_LISTING_TOO_LARGE,
            "the configuration listing is too large for this release",
        ));
    }
    let Some((&last, body)) = listing.split_last() else {
        return Ok(None);
    };
    if last != 0 {
        return Err(refusal(
            RULE_TRUNCATED,
            "malformed listing: the last record does not end",
        ));
    }
    let records = || body.split(|byte| *byte == 0);
    if records().nth(limits.records).is_some() {
        return Err(refusal(
            RULE_TOO_MANY_RECORDS,
            "the configuration listing has too many records for this release",
        ));
    }
    if records().any(|record| record.len() > limits.record_bytes) {
        return Err(refusal(
            RULE_RECORD_TOO_LARGE,
            "a record of the configuration listing is too long for this release",
        ));
    }
    Ok(Some(body))
}

/// Splits a record at its first newline into the key and the value; no newline means no value.
fn split_record(record: &[u8]) -> (&[u8], Option<&[u8]>) {
    match record.iter().position(|byte| *byte == b'\n') {
        Some(at) => (&record[..at], Some(&record[at + 1..])),
        None => (record, None),
    }
}

/// Checks the value of a key against the type of its row.
fn check_value(entry: &Entry, key: &Key<'_>, value: Option<&[u8]>) -> Result<(), Refusal> {
    let Err(rule) = entry.value.admit(value, entry.rule) else {
        return Ok(());
    };
    let reason = match rule {
        RULE_URL_HELPER => {
            "names a helper program as the remote's address, which this release does not allow"
        }
        RULE_SYMLINKS => "must be false: this release does not create symbolic links",
        RULE_BARE => "must be false: this release does not work in a bare repository",
        RULE_EXTENSION => "is an extension, or a value of one, that this release does not support",
        _ => "has a value this release does not admit",
    };
    Err(key.refusal(rule, reason))
}

/// Checks one record against the table and records what it says.
fn admit(
    record: &[u8],
    limits: &Limits,
    facts: &mut ConfigFacts,
    remotes: &mut BTreeSet<String>,
) -> Result<(), Refusal> {
    let (key, value) = split_record(record);
    let key = Key::parse(key, limits)?;
    let Some(entry) = TABLE.iter().find(|entry| entry.matches(&key)) else {
        let (rule, reason) = family(&key);
        return Err(key.refusal(rule, reason));
    };
    check_value(entry, &key, value)?;
    match entry.fact {
        Fact::None => {}
        Fact::Symlinks => facts.symlinks_local = Some(false),
        Fact::AutoCrlf => {
            let value = value.unwrap_or_default();
            facts.autocrlf_local = Some(if value.eq_ignore_ascii_case(b"input") {
                AutoCrlf::Input
            } else if value.eq_ignore_ascii_case(b"true") {
                AutoCrlf::True
            } else {
                AutoCrlf::False
            });
        }
        Fact::Sparse => facts.sparse = boolean(value) == Some(true),
        Fact::Remote => {
            if let Some(name) = key.subsection
                && !remotes.contains(name)
            {
                remotes.insert(name.to_owned());
            }
        }
    }
    Ok(())
}

/// A record's key, split into the parts that the table and the families compare.
struct Key<'a> {
    text: &'a str,
    section: &'a str,
    subsection: Option<&'a str>,
    variable: &'a str,
}

impl<'a> Key<'a> {
    /// Splits a key as Git writes it in a listing: the section, then an optional subsection that
    /// may hold dots, then the variable. The section and the variable are letters, digits and
    /// hyphens, and the variable starts with a letter. The subsection is any text with no control
    /// character, at most `limits.subsection_bytes` long.
    fn parse(bytes: &'a [u8], limits: &Limits) -> Result<Self, Refusal> {
        let malformed = || {
            refusal(
                RULE_RECORD_KEY,
                "malformed listing: a record has no usable key",
            )
        };
        let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
        if text.chars().any(char::is_control) {
            return Err(malformed());
        }
        let (Some(first), Some(last)) = (text.find('.'), text.rfind('.')) else {
            return Err(malformed());
        };
        let section = &text[..first];
        let variable = &text[last + 1..];
        let subsection = (first != last).then(|| &text[first + 1..last]);
        let name = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        };
        let sound = name(section)
            && name(variable)
            && variable.as_bytes()[0].is_ascii_alphabetic()
            && subsection.is_none_or(|subsection| !subsection.is_empty());
        if !sound {
            return Err(malformed());
        }
        if subsection.is_some_and(|subsection| subsection.len() > limits.subsection_bytes) {
            return Err(refusal(
                RULE_SUBSECTION_TOO_LARGE,
                "a setting name in the configuration is too long for this release",
            ));
        }
        Ok(Self {
            text,
            section,
            subsection,
            variable,
        })
    }

    fn is(&self, section: &str, variable: &str) -> bool {
        self.section.eq_ignore_ascii_case(section) && self.variable.eq_ignore_ascii_case(variable)
    }

    fn in_section(&self, sections: &[&str]) -> bool {
        sections
            .iter()
            .any(|section| self.section.eq_ignore_ascii_case(section))
    }

    fn refusal(&self, rule: &'static str, reason: &str) -> Refusal {
        let name = printable(self.text, MAX_KEY_IN_REFUSAL);
        refusal(rule, &format!("{name} {reason}"))
    }
}

/// The most bytes of a key a refusal repeats.
const MAX_KEY_IN_REFUSAL: usize = 120;

/// What a key that is not in the table is, for the refusal's name and text.
fn family(key: &Key<'_>) -> (&'static str, &'static str) {
    const PROGRAM_SECTIONS: &[&str] = &[
        "alias",
        "filter",
        "diff",
        "merge",
        "mergetool",
        "difftool",
        "credential",
        "gpg",
        "trailer",
        "pager",
        "sequence",
        "lfs",
    ];
    const PROGRAM_CORE: &[&str] = &[
        "fsmonitor",
        "hookspath",
        "sshcommand",
        "askpass",
        "editor",
        "pager",
        "gitproxy",
        "alternaterefscommand",
    ];
    const LOCATION_SECTIONS: &[&str] = &["url", "mailmap", "safe"];
    const LOCATION_CORE: &[&str] = &["worktree", "attributesfile", "excludesfile"];
    const TRANSPORT_SECTIONS: &[&str] = &[
        "http",
        "protocol",
        "uploadpack",
        "receive",
        "transfer",
        "fetch",
        "pull",
        "push",
    ];
    let core = |variables: &[&str]| {
        key.section.eq_ignore_ascii_case("core")
            && variables
                .iter()
                .any(|variable| key.variable.eq_ignore_ascii_case(variable))
    };
    if key.in_section(&["include", "includeif"]) {
        (
            RULE_INCLUDE,
            "includes another configuration file, which this release does not read",
        )
    } else if key.section.eq_ignore_ascii_case("extensions") {
        if key.variable.eq_ignore_ascii_case("worktreeconfig") {
            (
                RULE_WORKTREE_CONFIG,
                "gives each worktree a configuration of its own, which this release does not support",
            )
        } else {
            (
                RULE_EXTENSION,
                "is an extension that this release does not support",
            )
        }
    } else if key.in_section(PROGRAM_SECTIONS)
        || core(PROGRAM_CORE)
        || (key.is("submodule", "update") && key.subsection.is_some())
    {
        (
            RULE_PROGRAM,
            "names a program, which this release does not allow",
        )
    } else if key.in_section(LOCATION_SECTIONS)
        || core(LOCATION_CORE)
        || key.is("init", "templatedir")
        || key.is("commit", "template")
    {
        (
            RULE_LOCATION,
            "names another location, which this release does not allow",
        )
    } else if key.in_section(TRANSPORT_SECTIONS)
        || (key.section.eq_ignore_ascii_case("remote") && key.subsection.is_some())
    {
        (
            RULE_TRANSPORT,
            "is for connecting to another computer, which this release does not do",
        )
    } else {
        (RULE_UNLISTED, "is not a setting this release admits")
    }
}

/// The type of an admitted key's value.
#[derive(Clone, Copy)]
enum Value {
    /// One of these words, ignoring case, and never no value.
    Words(&'static [&'static str]),
    /// A boolean: `true false yes no on off 1 0`, ignoring case, or no value (which is true).
    Boolean,
    /// A boolean or one of these words.
    BooleanOr(&'static [&'static str]),
    /// One line of text with no control character.
    Text,
    /// One line of text that does not name a transport helper.
    Url,
    /// A path of the tree, in the grammar of the argument tables, which has no control character.
    Path,
    /// A refspec of the characters `A-Za-z0-9._/*-`: an optional `+`, then two patterns around one
    /// colon.
    Refspec,
    /// A name of the branch grammar.
    RemoteName,
    /// `refs/heads/` and a name of the branch grammar.
    BranchRef,
}

impl Value {
    /// Whether `value` is one of the type's, or the rule to refuse it by.
    #[expect(
        clippy::disallowed_methods,
        reason = "a text or bytes in hand are parsed here: that they are not valid is the whole answer, and nothing was read from the machine"
    )]
    fn admit(self, value: Option<&[u8]>, rule: &'static str) -> Result<(), &'static str> {
        let text = value.map(std::str::from_utf8);
        let line = |text: &str| !text.chars().any(char::is_control);
        let ok = match (self, text) {
            (Self::Words(words), Some(Ok(text))) => {
                words.iter().any(|word| text.eq_ignore_ascii_case(word))
            }
            (Self::Boolean, _) => boolean(value).is_some(),
            (Self::BooleanOr(words), Some(Ok(text))) => {
                boolean(value).is_some() || words.iter().any(|word| text.eq_ignore_ascii_case(word))
            }
            (Self::BooleanOr(_), None) => true,
            (Self::Text, Some(Ok(text))) => line(text),
            (Self::Url, Some(Ok(text))) => {
                if !line(text) {
                    false
                } else if names_helper(text) {
                    return Err(RULE_URL_HELPER);
                } else {
                    true
                }
            }
            (Self::Path, Some(Ok(text))) => grammar::path(text).is_ok(),
            (Self::Refspec, Some(Ok(text))) => refspec(text),
            (Self::RemoteName, Some(Ok(text))) => is_branch_name(text),
            (Self::BranchRef, Some(Ok(text))) => {
                text.strip_prefix(BRANCH_PREFIX).is_some_and(is_branch_name)
            }
            _ => false,
        };
        if ok { Ok(()) } else { Err(rule) }
    }
}

/// A boolean as Git reads one: no value is true, and an empty value is not a boolean here.
fn boolean(value: Option<&[u8]>) -> Option<bool> {
    let Some(value) = value else {
        return Some(true);
    };
    let is = |words: &[&str]| {
        words
            .iter()
            .any(|word| value.eq_ignore_ascii_case(word.as_bytes()))
    };
    if is(&["true", "yes", "on", "1"]) {
        Some(true)
    } else if is(&["false", "no", "off", "0"]) {
        Some(false)
    } else {
        None
    }
}

/// Whether an address starts with a transport helper's name and two colons. Git reads a letter or
/// digit and then letters, digits, `+`, `.` and `-` as the name; this takes any run of those
/// characters, the empty run too, so that it refuses everything Git reads as a helper and a little
/// more.
fn names_helper(address: &str) -> bool {
    let scheme = address
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
        .count();
    address[scheme..].starts_with("::")
}

fn refspec(text: &str) -> bool {
    let pattern = |side: &str| {
        !side.is_empty()
            && side.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'*' | b'-')
            })
    };
    let text = text.strip_prefix('+').unwrap_or(text);
    text.split_once(':')
        .is_some_and(|(source, destination)| pattern(source) && pattern(destination))
}

/// What an admitted key sets in [`ConfigFacts`].
#[derive(Clone, Copy)]
enum Fact {
    None,
    Symlinks,
    AutoCrlf,
    Sparse,
    Remote,
}

/// One admitted key: where it may stand, the type of its value, the rule that refuses a value of
/// another type, and what it sets.
struct Entry {
    section: &'static str,
    subsection: bool,
    variable: &'static str,
    value: Value,
    rule: &'static str,
    fact: Fact,
}

impl Entry {
    fn matches(&self, key: &Key<'_>) -> bool {
        key.is(self.section, self.variable) && key.subsection.is_some() == self.subsection
    }
}

const fn entry(
    section: &'static str,
    variable: &'static str,
    value: Value,
    rule: &'static str,
    fact: Fact,
) -> Entry {
    Entry {
        section,
        subsection: false,
        variable,
        value,
        rule,
        fact,
    }
}

const fn named(section: &'static str, variable: &'static str, value: Value, fact: Fact) -> Entry {
    Entry {
        section,
        subsection: true,
        variable,
        value,
        rule: RULE_VALUE,
        fact,
    }
}

const fn core_boolean(variable: &'static str, fact: Fact) -> Entry {
    entry("core", variable, Value::Boolean, RULE_VALUE, fact)
}

/// Every key the broker admits. A key in no row is refused.
static TABLE: &[Entry] = &[
    entry(
        "core",
        "repositoryformatversion",
        Value::Words(&["0", "1"]),
        RULE_VALUE,
        Fact::None,
    ),
    core_boolean("filemode", Fact::None),
    core_boolean("ignorecase", Fact::None),
    core_boolean("precomposeunicode", Fact::None),
    core_boolean("longpaths", Fact::None),
    core_boolean("trustctime", Fact::None),
    core_boolean("quotepath", Fact::None),
    core_boolean("preloadindex", Fact::None),
    core_boolean("fscache", Fact::None),
    core_boolean("sparsecheckout", Fact::Sparse),
    core_boolean("sparsecheckoutcone", Fact::None),
    entry(
        "core",
        "symlinks",
        Value::Words(&["false"]),
        RULE_SYMLINKS,
        Fact::Symlinks,
    ),
    entry(
        "core",
        "logallrefupdates",
        Value::BooleanOr(&["always"]),
        RULE_VALUE,
        Fact::None,
    ),
    entry(
        "core",
        "bare",
        Value::Words(&["false"]),
        RULE_BARE,
        Fact::None,
    ),
    entry(
        "core",
        "autocrlf",
        Value::Words(&["true", "false", "input"]),
        RULE_VALUE,
        Fact::AutoCrlf,
    ),
    entry(
        "core",
        "eol",
        Value::Words(&["lf", "crlf", "native"]),
        RULE_VALUE,
        Fact::None,
    ),
    entry(
        "core",
        "safecrlf",
        Value::Words(&["true", "false", "warn"]),
        RULE_VALUE,
        Fact::None,
    ),
    entry(
        "core",
        "protectntfs",
        Value::Words(&["true"]),
        RULE_VALUE,
        Fact::None,
    ),
    entry(
        "core",
        "protecthfs",
        Value::Words(&["true"]),
        RULE_VALUE,
        Fact::None,
    ),
    entry(
        "extensions",
        "objectformat",
        Value::Words(&["sha1"]),
        RULE_EXTENSION,
        Fact::None,
    ),
    entry(
        "extensions",
        "refstorage",
        Value::Words(&["files"]),
        RULE_EXTENSION,
        Fact::None,
    ),
    entry("user", "name", Value::Text, RULE_VALUE, Fact::None),
    entry("user", "email", Value::Text, RULE_VALUE, Fact::None),
    named("remote", "url", Value::Url, Fact::Remote),
    named("remote", "fetch", Value::Refspec, Fact::Remote),
    named("submodule", "url", Value::Url, Fact::None),
    named("submodule", "active", Value::Boolean, Fact::None),
    named("branch", "remote", Value::RemoteName, Fact::None),
    named("branch", "merge", Value::BranchRef, Fact::None),
];

/// Every key of a `.gitmodules` file the broker admits. A key in no row is refused.
static SUBMODULE_TABLE: &[Entry] = &[
    named("submodule", "path", Value::Path, Fact::None),
    named("submodule", "url", Value::Url, Fact::None),
    named("submodule", "branch", Value::RemoteName, Fact::None),
    named(
        "submodule",
        "ignore",
        Value::Words(&["none", "untracked", "dirty", "all"]),
        Fact::None,
    ),
];

fn refusal(rule: &'static str, detail: &str) -> Refusal {
    Refusal::new(RefusedKind::Configuration, rule, detail)
}
