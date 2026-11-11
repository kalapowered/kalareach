//! The readers the broker runs against a repository's objects, outside the eight commands of a
//! request, and the contract every one of them keeps.
//!
//! A revision resolves in two reads, never by a name alone. Git applies its search for a name to a
//! full name too, so with no `refs/heads/x` the name `refs/heads/x` can answer from
//! `refs/heads/refs/heads/x` or from a tag. R1a therefore reads exactly one reference, with no
//! search, and R1b peels the identifier it printed together with the revision's steps. R1c is the
//! answer that no tag of a name exists.
//!
//! A reader is a fixed argument line, started by the broker with the settings and the environment
//! of any other command, with the three paths of the repository set as for the operation. Its
//! output is data: this module frames it and refuses what does not frame, and a refusal names the
//! rule and the reader and never what the repository held.
//!
//! One contract holds for every reader. Its result is an exit code in the form's result set, with
//! complete framing, before its deadline. Any other exit code, a deadline, a cut or malformed
//! output or a count that differs fails the invocation. None of them writes, and every process
//! they started has ended before the next phase begins; that last part is the launcher's, not
//! this module's.

use std::time::Duration;

use crate::frame::invocation::{MAX_REF_NAME_BYTES, RefusedKind};
use crate::names::{BRANCH_PREFIX, TAG_PREFIX, is_branch_name, is_oid};
use crate::operation::grammar::split_revision;
use crate::operation::{OperationLine, Writes};
use crate::refusal::Refusal;

/// The exit code Git ends with after a fatal error: a reference or object that is absent or cannot
/// be read, among others.
const GIT_FATAL: u32 = 128;
/// The exit code of `show-ref --exists` for a reference that does not exist.
const EXISTS_MISSING: u32 = 2;

/// The most bytes of the output of a listing reader.
pub const MAX_LISTING_BYTES: usize = 1_048_576;
/// The most records of a listing reader.
pub const MAX_LISTING_RECORDS: usize = 100_000;
/// The most blobs one batch reader answers.
pub const MAX_BLOBS: usize = 4096;
/// The most bytes of one blob.
pub const MAX_BLOB_BYTES: usize = 1024 * 1024;
/// The most bytes of all the blobs of one batch.
pub const MAX_BLOB_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// The most bytes of the reference a symbolic reference names, which the reader prints.
pub const MAX_SYMBOLIC_TARGET_BYTES: usize = 1024;

/// A reader's argument is outside what its form takes.
pub const RULE_READER_ARGUMENT: &str = "reader-argument";
/// An exit code outside the form's result set.
pub const RULE_READER_EXIT: &str = "reader-exit";
/// The reader did not end before its deadline.
pub const RULE_READER_DEADLINE: &str = "reader-deadline";
/// Output that does not frame: cut, malformed or out of order.
pub const RULE_READER_FRAMING: &str = "reader-framing";
/// Output over a bound.
pub const RULE_READER_BOUNDS: &str = "reader-bounds";
/// A different number of answers than requests.
pub const RULE_READER_COUNT: &str = "reader-count";
/// An object the batch reader does not have.
pub const RULE_READER_MISSING: &str = "reader-missing";
/// A revision that does not resolve to a commit.
pub const RULE_UNRESOLVED: &str = "reader-unresolved";

/// The readers. R1 is three forms, which resolve a revision in two reads and check a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reader {
    /// Reads exactly one reference and prints the identifier it holds.
    R1a,
    /// Peels an identifier, with the steps of a revision, to a commit.
    R1b,
    /// Says whether a tag of a given name exists.
    R1c,
    /// Says whether a branch reference is symbolic.
    R2,
    /// Lists every file of a commit's tree.
    R3,
    /// Lists every file of the index.
    R4,
    /// Prints the blobs whose identifiers it is given on its standard input.
    R5,
}

/// What a reader's argument is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argument {
    /// None.
    Nothing,
    /// A reference to read exactly: `HEAD`, `refs/heads/<name>` or `refs/tags/<name>`.
    Reference,
    /// An identifier followed by the steps of a revision, which the line carries with `^{commit}`
    /// after it.
    Peel,
    /// A full reference name under `refs/tags/`.
    Tag,
    /// A full reference name under `refs/heads/`.
    RefName,
    /// An object identifier.
    Oid,
}

/// One reader's fixed form.
#[derive(Clone, Copy, Debug)]
pub struct ReaderForm {
    /// Which reader.
    pub reader: Reader,
    /// Its name in a refusal.
    pub name: &'static str,
    /// The words before its argument, command name included.
    pub argv: &'static [&'static str],
    /// What its argument is.
    pub argument: Argument,
    /// The exit codes that are a result.
    pub results: &'static [u32],
    /// How long it may run.
    pub deadline: Duration,
}

/// The forms.
pub const READERS: [ReaderForm; 7] = [
    ReaderForm {
        reader: Reader::R1a,
        name: "R1a",
        argv: &["show-ref", "--verify", "--end-of-options"],
        argument: Argument::Reference,
        results: &[0, GIT_FATAL],
        deadline: Duration::from_secs(10),
    },
    ReaderForm {
        reader: Reader::R1b,
        name: "R1b",
        argv: &["rev-parse", "--verify", "--end-of-options"],
        argument: Argument::Peel,
        results: &[0, GIT_FATAL],
        deadline: Duration::from_secs(10),
    },
    ReaderForm {
        reader: Reader::R1c,
        name: "R1c",
        argv: &["show-ref", "--exists", "--end-of-options"],
        argument: Argument::Tag,
        results: &[0, EXISTS_MISSING],
        deadline: Duration::from_secs(10),
    },
    ReaderForm {
        reader: Reader::R2,
        name: "R2",
        argv: &["symbolic-ref", "-q"],
        argument: Argument::RefName,
        results: &[0, 1],
        deadline: Duration::from_secs(10),
    },
    ReaderForm {
        reader: Reader::R3,
        name: "R3",
        argv: &["ls-tree", "-r", "-z", "--full-tree"],
        argument: Argument::Oid,
        results: &[0],
        deadline: Duration::from_secs(30),
    },
    ReaderForm {
        reader: Reader::R4,
        name: "R4",
        argv: &["ls-files", "-z", "--stage"],
        argument: Argument::Nothing,
        results: &[0],
        deadline: Duration::from_secs(30),
    },
    ReaderForm {
        reader: Reader::R5,
        name: "R5",
        argv: &["cat-file", "--batch"],
        argument: Argument::Nothing,
        results: &[0],
        deadline: Duration::from_secs(60),
    },
];

/// The form of a reader.
#[must_use]
pub const fn form(reader: Reader) -> &'static ReaderForm {
    match reader {
        Reader::R1a => &READERS[0],
        Reader::R1b => &READERS[1],
        Reader::R1c => &READERS[2],
        Reader::R2 => &READERS[3],
        Reader::R3 => &READERS[4],
        Reader::R4 => &READERS[5],
        Reader::R5 => &READERS[6],
    }
}

fn unresolved(name: &str) -> Refusal {
    refuse(RULE_UNRESOLVED, &format!("unresolved {name}"))
}

fn refuse(rule: &'static str, detail: &str) -> Refusal {
    Refusal::new(RefusedKind::Operation, rule, detail)
}

fn failed(form: &ReaderForm, rule: &'static str, what: &str) -> Refusal {
    refuse(rule, &format!("reader {} failed: {what}", form.name))
}

/// The line of a reader: its fixed words and its argument.
///
/// # Errors
///
/// Returns a refusal when the argument is missing, is given to a reader that takes none, or is
/// outside the grammar of its type.
pub fn reader_line(reader: Reader, argument: Option<&str>) -> Result<OperationLine, Refusal> {
    let form = form(reader);
    let bad = || {
        failed(
            form,
            RULE_READER_ARGUMENT,
            "the argument is missing or outside its form",
        )
    };
    let last = match (form.argument, argument) {
        (Argument::Nothing, None) => None,
        (Argument::Reference, Some(text))
            if matches!(
                resolution(text),
                Ok(Resolution { base: Base::Reference(_), steps }) if steps.is_empty()
            ) =>
        {
            Some(text.to_owned())
        }
        (Argument::Peel, Some(text))
            if matches!(
                resolution(text),
                Ok(Resolution {
                    base: Base::Identifier(_),
                    ..
                })
            ) =>
        {
            Some(format!("{text}^{{commit}}"))
        }
        (Argument::Tag, Some(text))
            if text.strip_prefix(TAG_PREFIX).is_some_and(is_branch_name) =>
        {
            Some(text.to_owned())
        }
        (Argument::RefName, Some(name))
            if name.len() <= MAX_REF_NAME_BYTES
                && name.strip_prefix(BRANCH_PREFIX).is_some_and(is_branch_name) =>
        {
            Some(name.to_owned())
        }
        (Argument::Oid, Some(oid)) if is_oid(oid) => Some(oid.to_owned()),
        _ => return Err(bad()),
    };
    let mut argv: Vec<String> = form.argv.iter().map(|word| (*word).to_owned()).collect();
    argv.extend(last);
    Ok(OperationLine {
        argv,
        writes: Writes::No,
        checks: Vec::new(),
    })
}

/// What a reader left behind: how it ended and what it printed.
#[derive(Clone, Copy, Debug)]
pub struct Output<'a> {
    /// The exit code, or `None` when the reader was ended at its deadline.
    pub exit: Option<u32>,
    /// Everything it wrote to its standard output.
    pub stdout: &'a [u8],
}

/// The exit code of a reader that ended in time with a code of its result set.
fn result_code(form: &ReaderForm, output: &Output<'_>) -> Result<u32, Refusal> {
    match output.exit {
        None => Err(failed(form, RULE_READER_DEADLINE, "it did not end in time")),
        Some(code) if form.results.contains(&code) => Ok(code),
        Some(code) => Err(failed(
            form,
            RULE_READER_EXIT,
            &format!("it ended with code {code}"),
        )),
    }
}

/// Where a qualified revision starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Base {
    /// A reference, which R1a reads first: `HEAD`, `refs/heads/<name>` or `refs/tags/<name>`.
    Reference(String),
    /// An object identifier, which R1b peels as it is.
    Identifier(String),
}

/// A qualified revision taken apart for the readers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// Where the revision starts.
    pub base: Base,
    /// The steps after the base: `^`, `^{commit}`, `~N` and `^N`, at most four.
    pub steps: String,
}

/// Takes a qualified revision apart.
///
/// # Errors
///
/// Returns a refusal when the text is not a qualified revision.
pub fn resolution(spec: &str) -> Result<Resolution, Refusal> {
    let (base, steps) = split_revision(spec).map_err(|_| {
        failed(
            form(Reader::R1a),
            RULE_READER_ARGUMENT,
            "the revision is outside its form",
        )
    })?;
    let base = if is_oid(base) {
        Base::Identifier(base.to_owned())
    } else {
        Base::Reference(base.to_owned())
    };
    Ok(Resolution {
        base,
        steps: steps.to_owned(),
    })
}

impl Resolution {
    /// The argument of R1b: the identifier the base has, then the steps. `read` is the identifier
    /// R1a printed, and is given exactly when the base is a reference.
    ///
    /// # Errors
    ///
    /// Returns a refusal when `read` is missing, is given for an identifier base, or is not an
    /// identifier.
    pub fn peel_argument(&self, read: Option<&str>) -> Result<String, Refusal> {
        let oid = match (&self.base, read) {
            (Base::Reference(_), Some(oid)) => Some(oid),
            (Base::Identifier(oid), None) => Some(oid.as_str()),
            _ => None,
        };
        let oid = match oid {
            Some(oid) if is_oid(oid) => oid,
            _ => {
                return Err(failed(
                    form(Reader::R1b),
                    RULE_READER_ARGUMENT,
                    "the identifier to peel does not fit the revision",
                ));
            }
        };
        Ok(format!("{oid}{}", self.steps))
    }
}

/// Reads R1a's answer for `reference`: the identifier it holds, from one line
/// `<identifier> SP <reference> LF` that names the reference asked for and no other.
///
/// # Errors
///
/// Returns a refusal for a reference that is absent or cannot be read, an exit code outside the
/// result set, a deadline, or output that is not that one line.
pub fn parse_r1a(output: &Output<'_>, reference: &str) -> Result<String, Refusal> {
    let form = form(Reader::R1a);
    if result_code(form, output)? == GIT_FATAL {
        return Err(unresolved(reference));
    }
    output
        .stdout
        .strip_suffix(b"\n")
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_once(' '))
        .filter(|(oid, name)| is_oid(oid) && *name == reference)
        .map(|(oid, _)| oid.to_owned())
        .ok_or_else(|| {
            failed(
                form,
                RULE_READER_FRAMING,
                "the answer is not one identifier and the reference asked for",
            )
        })
}

/// Reads R1b's answer: the commit's identifier, as one line of 40 hexadecimal digits. Exit 128 is a
/// revision that does not peel to a commit, and the refusal names `name`, the revision as it was
/// asked for.
///
/// # Errors
///
/// Returns a refusal for an unresolved revision, an exit code outside the result set, a deadline,
/// or output that is not one line.
pub fn parse_r1b(output: &Output<'_>, name: &str) -> Result<String, Refusal> {
    let form = form(Reader::R1b);
    if result_code(form, output)? == GIT_FATAL {
        return Err(unresolved(name));
    }
    output
        .stdout
        .strip_suffix(b"\n")
        .and_then(|line| std::str::from_utf8(line).ok())
        .filter(|line| is_oid(line))
        .map(str::to_owned)
        .ok_or_else(|| {
            failed(
                form,
                RULE_READER_FRAMING,
                "the answer is not one identifier",
            )
        })
}

/// R1c's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exists {
    /// The reference exists, whatever object it names.
    Yes,
    /// It does not exist: the only answer that proves absence.
    No,
}

/// Reads R1c's answer: exit 0 for a reference that exists and exit 2 for one that does not, both
/// with nothing on the standard output.
///
/// # Errors
///
/// Returns a refusal for any other exit code, a deadline, or output on the standard output.
pub fn parse_r1c(output: &Output<'_>) -> Result<Exists, Refusal> {
    let form = form(Reader::R1c);
    let code = result_code(form, output)?;
    if !output.stdout.is_empty() {
        return Err(failed(form, RULE_READER_FRAMING, "it printed something"));
    }
    Ok(if code == 0 { Exists::Yes } else { Exists::No })
}

/// R2's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symbolic {
    /// The reference is symbolic.
    Yes,
    /// It is not: a missing reference is not either.
    No,
}

/// Reads R2's answer. Exit 1 is a reference that is not symbolic, or does not exist, and prints
/// nothing; exit 0 is a symbolic reference, and Git prints the reference it names as one line.
///
/// # Errors
///
/// Returns a refusal for any other exit code, a deadline, or output that does not frame.
pub fn parse_r2(output: &Output<'_>) -> Result<Symbolic, Refusal> {
    let form = form(Reader::R2);
    let framing = || failed(form, RULE_READER_FRAMING, "the answer does not frame");
    match result_code(form, output)? {
        1 if output.stdout.is_empty() => Ok(Symbolic::No),
        0 => {
            let target = output.stdout.strip_suffix(b"\n").ok_or_else(framing)?;
            let sound = !target.is_empty()
                && target.len() <= MAX_SYMBOLIC_TARGET_BYTES
                && !target.iter().any(|byte| matches!(byte, b'\n' | 0));
            if sound {
                Ok(Symbolic::Yes)
            } else {
                Err(framing())
            }
        }
        _ => Err(framing()),
    }
}

/// A file a listing names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The mode, as a number: 0o100644, 0o100755, 0o120000 or 0o160000.
    pub mode: u32,
    /// The object's identifier.
    pub oid: String,
    /// The index stage, 0 to 3; 0 for a tree's file.
    pub stage: u8,
    /// The path, as the bytes Git printed. It is the repository's text and is never repeated in a
    /// refusal.
    pub path: Vec<u8>,
}

/// The mode of a gitlink, a commit of another repository.
pub const MODE_GITLINK: u32 = 0o160_000;

const MODES: [&str; 4] = ["100644", "100755", "120000", "160000"];

/// Splits a listing into its records after the bounds and the framing: every record ends in a
/// NUL, an empty listing is a valid listing of none.
fn listing<'a>(form: &ReaderForm, stdout: &'a [u8]) -> Result<Vec<&'a [u8]>, Refusal> {
    if stdout.len() > MAX_LISTING_BYTES {
        return Err(failed(form, RULE_READER_BOUNDS, "the listing is too large"));
    }
    let Some((&last, body)) = stdout.split_last() else {
        return Ok(Vec::new());
    };
    if last != 0 {
        return Err(failed(form, RULE_READER_FRAMING, "the last record is cut"));
    }
    let records: Vec<&[u8]> = body.split(|byte| *byte == 0).collect();
    if records.len() > MAX_LISTING_RECORDS {
        return Err(failed(
            form,
            RULE_READER_BOUNDS,
            "the listing has too many records",
        ));
    }
    Ok(records)
}

fn mode_of(text: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(text).ok()?;
    MODES
        .contains(&text)
        .then(|| u32::from_str_radix(text, 8).ok())
        .flatten()
}

fn oid_of(text: &[u8]) -> Option<String> {
    std::str::from_utf8(text)
        .ok()
        .filter(|text| is_oid(text))
        .map(str::to_owned)
}

/// Reads R3's listing: `<mode> SP <type> SP <oid> TAB <path> NUL` for every file below a commit's
/// tree. A gitlink is a `commit`, every other mode a `blob`.
///
/// # Errors
///
/// Returns a refusal for a deadline, an exit code outside the result set, a bound, or a record
/// that does not frame.
pub fn parse_r3(output: &Output<'_>) -> Result<Vec<Entry>, Refusal> {
    let form = form(Reader::R3);
    result_code(form, output)?;
    let malformed = || failed(form, RULE_READER_FRAMING, "a record is malformed");
    listing(form, output.stdout)?
        .into_iter()
        .map(|record| {
            let tab = record
                .iter()
                .position(|b| *b == b'\t')
                .ok_or_else(malformed)?;
            let (head, path) = (&record[..tab], &record[tab + 1..]);
            let mut words = head.split(|b| *b == b' ');
            let (Some(mode), Some(kind), Some(oid), None) =
                (words.next(), words.next(), words.next(), words.next())
            else {
                return Err(malformed());
            };
            let mode = mode_of(mode).ok_or_else(malformed)?;
            let expected: &[u8] = if mode == MODE_GITLINK {
                b"commit"
            } else {
                b"blob"
            };
            if kind != expected || path.is_empty() {
                return Err(malformed());
            }
            Ok(Entry {
                mode,
                oid: oid_of(oid).ok_or_else(malformed)?,
                stage: 0,
                path: path.to_vec(),
            })
        })
        .collect()
}

/// Reads R4's listing: `<mode> SP <oid> SP <stage> TAB <path> NUL` for every file of the index.
///
/// # Errors
///
/// Returns a refusal for a deadline, an exit code outside the result set, a bound, or a record
/// that does not frame.
pub fn parse_r4(output: &Output<'_>) -> Result<Vec<Entry>, Refusal> {
    let form = form(Reader::R4);
    result_code(form, output)?;
    let malformed = || failed(form, RULE_READER_FRAMING, "a record is malformed");
    listing(form, output.stdout)?
        .into_iter()
        .map(|record| {
            let tab = record
                .iter()
                .position(|b| *b == b'\t')
                .ok_or_else(malformed)?;
            let (head, path) = (&record[..tab], &record[tab + 1..]);
            let mut words = head.split(|b| *b == b' ');
            let (Some(mode), Some(oid), Some(stage), None) =
                (words.next(), words.next(), words.next(), words.next())
            else {
                return Err(malformed());
            };
            let stage = match stage {
                [digit @ b'0'..=b'3'] => digit - b'0',
                _ => return Err(malformed()),
            };
            if path.is_empty() {
                return Err(malformed());
            }
            Ok(Entry {
                mode: mode_of(mode).ok_or_else(malformed)?,
                oid: oid_of(oid).ok_or_else(malformed)?,
                stage,
                path: path.to_vec(),
            })
        })
        .collect()
}

/// Whether the last component of a path is one that Git reads attributes from on a Windows
/// file system: `.gitattributes` in any case, with the trailing dots and spaces Windows drops,
/// or the short name NTFS gives it. Over-matching is safe: it only makes the scan read more.
fn names_attributes(path: &[u8]) -> bool {
    let name = path.rsplit(|b| *b == b'/').next().unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    let trimmed: &[u8] = {
        let end = lower
            .iter()
            .rposition(|b| !matches!(b, b'.' | b' '))
            .map_or(0, |at| at + 1);
        &lower[..end]
    };
    trimmed == b".gitattributes"
        || trimmed
            .strip_prefix(b"gitatt~")
            .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

/// The entries whose files Git reads attributes from. A gitlink is not a file and is left out.
#[must_use]
pub fn attributes_entries(entries: &[Entry]) -> Vec<&Entry> {
    entries
        .iter()
        .filter(|entry| entry.mode != MODE_GITLINK && names_attributes(&entry.path))
        .collect()
}

/// What R5 reads on its standard input: each identifier and a newline.
///
/// # Errors
///
/// Returns a refusal for more than [`MAX_BLOBS`] identifiers or one that is not an identifier.
pub fn blob_request(oids: &[String]) -> Result<Vec<u8>, Refusal> {
    let form = form(Reader::R5);
    if oids.len() > MAX_BLOBS {
        return Err(failed(form, RULE_READER_BOUNDS, "too many blobs requested"));
    }
    let mut input = Vec::with_capacity(oids.len() * 41);
    for oid in oids {
        if !is_oid(oid) {
            return Err(failed(
                form,
                RULE_READER_ARGUMENT,
                "an identifier is outside its form",
            ));
        }
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    Ok(input)
}

/// Reads R5's answers: for each identifier asked, in order, `<oid> SP blob SP <size> LF`, that
/// many bytes and `LF`. The answers are the blobs' bytes, in the order asked.
///
/// # Errors
///
/// Returns a refusal for a deadline, an exit code outside the result set, a missing object, a
/// different number of answers, an answer out of order or of another type, a size over
/// [`MAX_BLOB_BYTES`], a total over [`MAX_BLOB_TOTAL_BYTES`], or bytes that do not frame to the
/// sizes.
pub fn parse_r5<'a>(requested: &[String], output: &Output<'a>) -> Result<Vec<&'a [u8]>, Refusal> {
    let form = form(Reader::R5);
    result_code(form, output)?;
    if requested.len() > MAX_BLOBS {
        return Err(failed(form, RULE_READER_BOUNDS, "too many blobs requested"));
    }
    let framing = |what: &str| failed(form, RULE_READER_FRAMING, what);
    let mut rest = output.stdout;
    let mut total = 0usize;
    let mut blobs = Vec::with_capacity(requested.len());
    for oid in requested {
        if rest.is_empty() {
            return Err(failed(
                form,
                RULE_READER_COUNT,
                "fewer answers than requests",
            ));
        }
        let line_end = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| framing("an answer's header is cut"))?;
        let (header, after) = (&rest[..line_end], &rest[line_end + 1..]);
        let mut words = header.split(|b| *b == b' ');
        let (Some(answered), Some(kind), size, None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return Err(framing("an answer's header is malformed"));
        };
        if answered != oid.as_bytes() {
            return Err(framing("an answer is out of order"));
        }
        if kind == b"missing" && size.is_none() {
            return Err(failed(form, RULE_READER_MISSING, "an object is missing"));
        }
        let size = match (kind, size) {
            (b"blob", Some(size)) => std::str::from_utf8(size)
                .ok()
                .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| framing("an answer's size is malformed"))?,
            _ => return Err(framing("an answer is not a blob")),
        };
        let size = size
            .parse::<usize>()
            .ok()
            .filter(|size| *size <= MAX_BLOB_BYTES)
            .ok_or_else(|| failed(form, RULE_READER_BOUNDS, "a blob is too large"))?;
        total += size;
        if total > MAX_BLOB_TOTAL_BYTES {
            return Err(failed(
                form,
                RULE_READER_BOUNDS,
                "the blobs are too large together",
            ));
        }
        if after.len() <= size || after[size] != b'\n' {
            return Err(framing("a blob does not frame to its size"));
        }
        blobs.push(&after[..size]);
        rest = &after[size + 1..];
    }
    if rest.is_empty() {
        Ok(blobs)
    } else {
        Err(failed(
            form,
            RULE_READER_COUNT,
            "more answers than requests",
        ))
    }
}
