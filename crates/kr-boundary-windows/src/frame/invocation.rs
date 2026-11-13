//! The frames of one invocation of Git: the request to run one of the eight commands, the request
//! to cancel it, and the three replies.
//!
//! A request holds only what a person's host knows: the tree, the command, its typed arguments, the
//! identity to commit under and the host's line-ending setting. Nothing in it names a handle, a
//! process, a token, a program, a variable or a configuration option, in either direction, and a
//! field this module does not name is a parse error. What the arguments may hold beyond their
//! length (a path's components, a revision's form) is the argument tables' rule; this module only
//! bounds them, so that no field can make the broker hold or print more than its limit.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use super::{Class, FieldError, FrameError, MAX_FRAME, read_body, write_within};

/// The most bytes an [`OperateRequest`]'s frame may carry: 256 paths of 240 bytes, a message of 8
/// KiB and the options of any table, each as long as JSON can make it, fit.
pub const MAX_OPERATE_FRAME: usize = 1024 * 1024;
/// The most arguments one request may carry.
pub const MAX_ARGUMENTS: usize = 512;
/// The most bytes of a path argument.
pub const MAX_PATH_BYTES: usize = 240;
/// The most bytes of a branch name.
pub const MAX_NAME_BYTES: usize = 200;
/// The most bytes of a full reference name, `refs/heads/` and a branch name.
pub const MAX_REF_NAME_BYTES: usize = 211;
/// The most bytes of a revision: a branch name and four suffixes.
pub const MAX_REV_BYTES: usize = 240;
/// The most bytes of an object identifier: the longest hexadecimal name of any object format.
pub const MAX_OID_BYTES: usize = 64;
/// The most bytes of a message.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;
/// The largest count.
pub const MAX_COUNT: u32 = 1000;
/// The most bytes of a fixed word of a table.
pub const MAX_WORD_BYTES: usize = 64;
/// The most parts of a custom format.
pub const MAX_FORMAT_PARTS: usize = 64;
/// The most bytes of the text between the placeholders of a custom format.
pub const MAX_FORMAT_TEXT_BYTES: usize = 256;
/// The most bytes of the name or the address of the identity.
pub const MAX_IDENTITY_BYTES: usize = 200;
/// The most UTF-16 units of a directory: the platform's own limit for a path.
pub const MAX_DIRECTORY_UNITS: usize = 32_767;
/// The most bytes of any text a reply carries for a person to read.
pub const MAX_DETAIL_BYTES: usize = 200;
/// The most bytes of a pipe's name.
pub const MAX_PIPE_NAME_BYTES: usize = 256;
/// The most notes a result carries.
pub const MAX_NOTES: usize = 64;
/// The most bytes of one note.
pub const MAX_NOTE_BYTES: usize = 200;
/// The most bytes of JSON the notes of a result may take, so that a result with every note at its
/// limit and every character escaped still fits [`MAX_FRAME`].
const NOTES_JSON_BUDGET: usize = 14 * 1024;
/// The digits of an invocation's identifier: 128 bits in lowercase hexadecimal.
const INVOCATION_DIGITS: usize = 32;

/// The eight commands a request may name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Command {
    /// `rev-parse`.
    RevParse,
    /// `status`.
    Status,
    /// `diff`.
    Diff,
    /// `log`.
    Log,
    /// `add`.
    Add,
    /// `checkout`.
    Checkout,
    /// `commit`.
    Commit,
    /// `update-ref`.
    UpdateRef,
}

/// The host's value of `core.autocrlf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LineEndings {
    /// The host has no value.
    Unset,
    /// `true`.
    True,
    /// `false`.
    False,
    /// `input`.
    Input,
    /// The host could not find out. A command that writes refuses it.
    Unknown,
}

/// The name and address a reflog entry and a commit carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The name.
    pub name: String,
    /// The address.
    pub email: String,
}

/// Whether a range holds the commits reachable from one side only, or from either side only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dots {
    /// `..`.
    Two,
    /// `...`.
    Three,
}

/// A format that Git names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NamedFormat {
    /// `oneline`.
    Oneline,
    /// `short`.
    Short,
    /// `medium`.
    Medium,
    /// `full`.
    Full,
    /// `fuller`.
    Fuller,
}

/// The placeholders a custom format may use, written on the wire as Git writes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Placeholder {
    /// The commit's full identifier.
    #[serde(rename = "%H")]
    CommitHash,
    /// The commit's abbreviated identifier.
    #[serde(rename = "%h")]
    CommitHashShort,
    /// The tree's full identifier.
    #[serde(rename = "%T")]
    TreeHash,
    /// The tree's abbreviated identifier.
    #[serde(rename = "%t")]
    TreeHashShort,
    /// The parents' full identifiers.
    #[serde(rename = "%P")]
    ParentHashes,
    /// The parents' abbreviated identifiers.
    #[serde(rename = "%p")]
    ParentHashesShort,
    /// The author's name.
    #[serde(rename = "%an")]
    AuthorName,
    /// The author's address.
    #[serde(rename = "%ae")]
    AuthorEmail,
    /// The author's date.
    #[serde(rename = "%ad")]
    AuthorDate,
    /// The author's date, strict ISO 8601.
    #[serde(rename = "%aI")]
    AuthorDateIso,
    /// The author's date, as a UNIX timestamp.
    #[serde(rename = "%at")]
    AuthorDateUnix,
    /// The committer's name.
    #[serde(rename = "%cn")]
    CommitterName,
    /// The committer's address.
    #[serde(rename = "%ce")]
    CommitterEmail,
    /// The committer's date.
    #[serde(rename = "%cd")]
    CommitterDate,
    /// The committer's date, strict ISO 8601.
    #[serde(rename = "%cI")]
    CommitterDateIso,
    /// The committer's date, as a UNIX timestamp.
    #[serde(rename = "%ct")]
    CommitterDateUnix,
    /// The subject.
    #[serde(rename = "%s")]
    Subject,
    /// The body.
    #[serde(rename = "%b")]
    Body,
    /// The raw message.
    #[serde(rename = "%B")]
    RawMessage,
    /// A newline.
    #[serde(rename = "%n")]
    Newline,
    /// A percent sign.
    #[serde(rename = "%%")]
    Percent,
}

/// One part of a custom format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Part {
    /// Text that holds no percent sign and no control character: a percent sign is the
    /// [`Placeholder::Percent`] part, so that no text can spell a placeholder outside the list.
    Text(String),
    /// A placeholder.
    Placeholder(Placeholder),
}

/// The format of a `log`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// One of Git's own formats.
    Named(NamedFormat),
    /// Text and placeholders.
    Custom(Vec<Part>),
}

/// One typed argument of a command. The type says which grammar the argument tables apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Arg {
    /// A path in the tree.
    Path(String),
    /// A revision.
    Rev(String),
    /// A branch name.
    Name(String),
    /// A full reference name.
    RefName(String),
    /// A full object identifier.
    Oid(String),
    /// A message.
    Message(String),
    /// A count.
    Count(u32),
    /// A fixed word of a table, such as an option.
    Word(String),
    /// Two revisions and the dots between them.
    Range {
        /// The first revision.
        left: String,
        /// The second revision.
        right: String,
        /// The dots between them.
        dots: Dots,
    },
    /// A format.
    Format(Format),
}

/// The request to run one command in a granted tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperateRequest {
    /// The protocol version the host speaks.
    pub protocol_version: u32,
    /// The boundary account to run as.
    pub class: Class,
    /// The granted tree's root.
    pub directory: String,
    /// The command.
    pub command: Command,
    /// The command's typed arguments.
    pub arguments: Vec<Arg>,
    /// The identity Git records.
    pub identity: Identity,
    /// The host's line-ending setting.
    pub line_endings: LineEndings,
}

/// The identifier the broker gives an invocation: 128 bits in lowercase hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InvocationId(String);

impl InvocationId {
    /// The identifier of 128 random bits.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(hex::encode(bytes))
    }

    /// The identifier's digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InvocationId {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let digits = text.len() == INVOCATION_DIGITS
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if digits {
            Ok(Self(text))
        } else {
            Err("an invocation is 32 lowercase hexadecimal digits".to_owned())
        }
    }
}

impl From<InvocationId> for String {
    fn from(id: InvocationId) -> Self {
        id.0
    }
}

/// What a client asks about an invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InvocationRequest {
    /// Run a command.
    Operate(OperateRequest),
    /// End an invocation by its normal path.
    Cancel {
        /// The invocation to end.
        invocation: InvocationId,
    },
}

/// Why the broker refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusedKind {
    /// The caller is not a person the broker serves, or its token is one the broker does not
    /// model.
    Authentication,
    /// Another invocation holds the tree.
    Busy,
    /// An earlier invocation left something on the tree that is not cleared.
    Leftover,
    /// The command or an argument is not one the tables admit.
    Operation,
    /// The repository's configuration is not one the broker admits.
    Configuration,
    /// The repository holds something the broker does not admit.
    Repository,
    /// The tree cannot be granted to the invocation.
    Admission,
    /// The command would connect to another computer, which this release does not do.
    Transport,
    /// A limit was over.
    Limit,
    /// The broker refuses new invocations.
    Maintenance,
}

impl RefusedKind {
    /// The kind's name as a person reads it in front of the detail.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Busy => "busy",
            Self::Leftover => "leftover",
            Self::Operation => "operation",
            Self::Configuration => "configuration",
            Self::Repository => "repository",
            Self::Admission => "admission",
            Self::Transport => "transport",
            Self::Limit => "limit",
            Self::Maintenance => "maintenance",
        }
    }
}

impl std::fmt::Display for RefusedKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What ended an invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndedBy {
    /// The primary Git exited.
    Exit,
    /// The client's process exited.
    ClientExit,
    /// The client's connection ended.
    Disconnect,
    /// The client asked for the end.
    Cancel,
    /// The deadline passed.
    Deadline,
    /// The broker was stopping.
    Stop,
}

/// What kind of object a leftover is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeftoverClass {
    /// A file or folder of the person's tree.
    Tree,
    /// The repository's own files.
    Repository,
    /// An end that is not certain.
    Uncertain,
    /// The invocation's private root.
    Root,
}

/// How the release and the clean-up ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Cleanup {
    /// Everything the invocation granted is released and its root is removed.
    Clean,
    /// Something is left.
    Failed {
        /// What is left, as printable text.
        object: String,
        /// What kind of object it is.
        class: LeftoverClass,
    },
    /// The end of the invocation is not certain, so nothing was released.
    Uncertain,
}

/// Whether the repository's configuration is still the one that was read. A changed one means the
/// effects are unknown: neither an error nor a cancel promises that no write happened, and the host
/// must not retry on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConfigurationState {
    /// The configuration is the one that was read.
    Same,
    /// The configuration changed.
    Changed {
        /// What changed, as printable text.
        name: String,
    },
}

/// The shared-read notes of a result, bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
    /// The notes, each printable text of at most [`MAX_NOTE_BYTES`] bytes.
    pub items: Vec<String>,
    /// How many notes were left out or shortened to fit.
    pub cut: u32,
}

impl Notes {
    /// Bounds a list of notes: each becomes printable text of at most [`MAX_NOTE_BYTES`] bytes, at
    /// most [`MAX_NOTES`] stay and no more than the frame has room for. `cut` counts every note
    /// that was left out and every note that was shortened.
    #[must_use]
    pub fn bounded<I, S>(notes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut kept = Self::default();
        let mut room = NOTES_JSON_BUDGET;
        for note in notes {
            let note = note.as_ref();
            let text = printable(note, MAX_NOTE_BYTES);
            let shortened = text.len() < note.len();
            // The note, its quotes, any escapes and the comma after it.
            #[expect(
                clippy::disallowed_methods,
                reason = "a note that cannot be written as JSON counts as too large and is left out; nothing was read from the machine"
            )]
            let size = serde_json::to_vec(&text).map_or(usize::MAX, |json| json.len() + 1);
            if kept.items.len() < MAX_NOTES && size <= room {
                room -= size;
                kept.items.push(text);
                kept.cut = kept.cut.saturating_add(u32::from(shortened));
            } else {
                kept.cut = kept.cut.saturating_add(1);
            }
        }
        kept
    }
}

/// What the broker answers about an invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InvocationReply {
    /// The invocation is made. The host opens each pipe once, for reading, to receive Git's output.
    Accepted {
        /// The invocation.
        invocation: InvocationId,
        /// The name of the pipe that carries Git's standard output.
        stdout_pipe: String,
        /// The name of the pipe that carries Git's standard error.
        stderr_pipe: String,
    },
    /// The request was refused and nothing was started.
    Refused {
        /// Why.
        kind: RefusedKind,
        /// Printable text of at most [`MAX_DETAIL_BYTES`] bytes.
        detail: String,
    },
    /// The invocation ended.
    Finished {
        /// The primary Git's exit code, or none.
        exit: Option<u32>,
        /// What ended the invocation.
        ended_by: EndedBy,
        /// How the release and the clean-up ended.
        cleanup: Cleanup,
        /// Whether the configuration changed.
        configuration: ConfigurationState,
        /// The shared-read notes.
        notes: Notes,
        /// How many files with a protected list the invocation replaced.
        replaced_protected: u32,
    },
}

impl InvocationReply {
    /// A refusal whose detail is made printable and cut to [`MAX_DETAIL_BYTES`]: a hostile name
    /// loses its non-printable bytes to `?` and its tail.
    #[must_use]
    pub fn refused(kind: RefusedKind, detail: &str) -> Self {
        Self::Refused {
            kind,
            detail: printable(detail, MAX_DETAIL_BYTES),
        }
    }

    /// Whether every text and list of the reply is within its bounds.
    ///
    /// # Errors
    ///
    /// Returns the first field outside its bounds.
    pub fn check(&self) -> Result<(), FieldError> {
        match self {
            Self::Accepted {
                stdout_pipe,
                stderr_pipe,
                ..
            } => {
                text_within("stdout_pipe", stdout_pipe, MAX_PIPE_NAME_BYTES)?;
                text_within("stderr_pipe", stderr_pipe, MAX_PIPE_NAME_BYTES)
            }
            Self::Refused { detail, .. } => text_within("detail", detail, MAX_DETAIL_BYTES),
            Self::Finished {
                cleanup,
                configuration,
                notes,
                ..
            } => {
                if let Cleanup::Failed { object, .. } = cleanup {
                    text_within("cleanup object", object, MAX_DETAIL_BYTES)?;
                }
                if let ConfigurationState::Changed { name } = configuration {
                    text_within("configuration name", name, MAX_DETAIL_BYTES)?;
                }
                if notes.items.len() > MAX_NOTES {
                    return Err(FieldError::TooMany {
                        field: "notes",
                        max: MAX_NOTES,
                        got: notes.items.len(),
                    });
                }
                notes
                    .items
                    .iter()
                    .try_for_each(|note| text_within("note", note, MAX_NOTE_BYTES))
            }
        }
    }
}

impl OperateRequest {
    /// Whether every field is within its bounds.
    ///
    /// # Errors
    ///
    /// Returns the first field outside its bounds.
    pub fn check(&self) -> Result<(), FieldError> {
        let directory = &self.directory;
        if directory.encode_utf16().count() > MAX_DIRECTORY_UNITS {
            return Err(FieldError::TooLong {
                field: "directory",
                max: MAX_DIRECTORY_UNITS,
                got: directory.len(),
            });
        }
        if directory.is_empty() || directory.contains('\0') {
            return Err(FieldError::Form { field: "directory" });
        }
        single_line("identity name", &self.identity.name)?;
        single_line("identity email", &self.identity.email)?;
        if self.arguments.len() > MAX_ARGUMENTS {
            return Err(FieldError::TooMany {
                field: "arguments",
                max: MAX_ARGUMENTS,
                got: self.arguments.len(),
            });
        }
        self.arguments.iter().try_for_each(Arg::check)
    }
}

impl Arg {
    fn check(&self) -> Result<(), FieldError> {
        match self {
            Self::Path(text) => longest("path", text, MAX_PATH_BYTES),
            Self::Rev(text) => longest("revision", text, MAX_REV_BYTES),
            Self::Name(text) => longest("name", text, MAX_NAME_BYTES),
            Self::RefName(text) => longest("reference name", text, MAX_REF_NAME_BYTES),
            Self::Oid(text) => longest("object identifier", text, MAX_OID_BYTES),
            Self::Message(text) => longest("message", text, MAX_MESSAGE_BYTES),
            Self::Word(text) => longest("word", text, MAX_WORD_BYTES),
            Self::Count(count) if *count > MAX_COUNT => Err(FieldError::TooLong {
                field: "count",
                max: MAX_COUNT as usize,
                got: *count as usize,
            }),
            Self::Count(_) | Self::Format(Format::Named(_)) => Ok(()),
            Self::Range { left, right, .. } => {
                longest("revision", left, MAX_REV_BYTES)?;
                longest("revision", right, MAX_REV_BYTES)
            }
            Self::Format(Format::Custom(parts)) => {
                if parts.len() > MAX_FORMAT_PARTS {
                    return Err(FieldError::TooMany {
                        field: "format parts",
                        max: MAX_FORMAT_PARTS,
                        got: parts.len(),
                    });
                }
                parts.iter().try_for_each(|part| match part {
                    Part::Text(text) => {
                        longest("format text", text, MAX_FORMAT_TEXT_BYTES)?;
                        if text.contains('%') || text.chars().any(char::is_control) {
                            return Err(FieldError::Form {
                                field: "format text",
                            });
                        }
                        Ok(())
                    }
                    Part::Placeholder(_) => Ok(()),
                })
            }
        }
    }
}

impl InvocationRequest {
    /// Whether every field is within its bounds.
    ///
    /// # Errors
    ///
    /// Returns the first field outside its bounds.
    pub fn check(&self) -> Result<(), FieldError> {
        match self {
            Self::Operate(request) => request.check(),
            Self::Cancel { .. } => Ok(()),
        }
    }
}

/// The bytes of `text` that Git and a person may be shown: printable ASCII stays, every other byte
/// becomes `?`, and the result is at most `max` bytes.
#[must_use]
pub fn printable(text: &str, max: usize) -> String {
    text.bytes()
        .take(max)
        .map(|byte| {
            if (0x20..=0x7e).contains(&byte) {
                char::from(byte)
            } else {
                '?'
            }
        })
        .collect()
}

fn longest(field: &'static str, text: &str, max: usize) -> Result<(), FieldError> {
    if text.len() > max {
        return Err(FieldError::TooLong {
            field,
            max,
            got: text.len(),
        });
    }
    Ok(())
}

fn single_line(field: &'static str, text: &str) -> Result<(), FieldError> {
    longest(field, text, MAX_IDENTITY_BYTES)?;
    if text.chars().any(char::is_control) {
        return Err(FieldError::Form { field });
    }
    Ok(())
}

fn text_within(field: &'static str, text: &str, max: usize) -> Result<(), FieldError> {
    longest(field, text, max)?;
    if text.bytes().any(|byte| !(0x20..=0x7e).contains(&byte)) {
        return Err(FieldError::NotPrintable { field });
    }
    Ok(())
}

/// Reads a request. An [`OperateRequest`] may take [`MAX_OPERATE_FRAME`] bytes and every other
/// request takes [`MAX_FRAME`], so the broker holds at most the larger limit while it reads, and
/// the request's fields are checked before it is returned.
///
/// # Errors
///
/// Returns [`FrameError::Closed`] when the peer ended the connection before a frame began,
/// [`FrameError::TooLong`] for a frame over its limit (before its body is read when even the
/// larger limit is over), [`FrameError::Malformed`] for a body that is not a request or that holds
/// a field the protocol does not name, [`FrameError::Field`] for a field outside its bounds and
/// [`FrameError::Io`] for a connection that failed or ended inside a frame.
pub fn read_request<R: Read>(reader: &mut R) -> Result<InvocationRequest, FrameError> {
    let body = read_body(reader, MAX_OPERATE_FRAME)?;
    let request: InvocationRequest =
        serde_json::from_slice(&body).map_err(|error| FrameError::Malformed(error.to_string()))?;
    if body.len() > MAX_FRAME && !matches!(request, InvocationRequest::Operate(_)) {
        return Err(FrameError::TooLong(body.len()));
    }
    request.check()?;
    Ok(request)
}

/// Writes a request, with the limit that [`read_request`] applies to it.
///
/// # Errors
///
/// Returns [`FrameError::Field`] for a field outside its bounds, [`FrameError::TooLong`] for a
/// request over its frame's limit and [`FrameError::Io`] when the connection fails.
pub fn write_request<W: Write>(
    writer: &mut W,
    request: &InvocationRequest,
) -> Result<(), FrameError> {
    request.check()?;
    let limit = match request {
        InvocationRequest::Operate(_) => MAX_OPERATE_FRAME,
        InvocationRequest::Cancel { .. } => MAX_FRAME,
    };
    write_within(writer, request, limit)
}

/// Reads a reply and checks its fields.
///
/// # Errors
///
/// As [`super::read`], and [`FrameError::Field`] for a field outside its bounds.
pub fn read_reply<R: Read>(reader: &mut R) -> Result<InvocationReply, FrameError> {
    let reply: InvocationReply = super::read(reader)?;
    reply.check()?;
    Ok(reply)
}

/// Writes a reply after checking its fields.
///
/// # Errors
///
/// Returns [`FrameError::Field`] for a field outside its bounds, and otherwise as [`super::write`].
pub fn write_reply<W: Write>(writer: &mut W, reply: &InvocationReply) -> Result<(), FrameError> {
    reply.check()?;
    super::write(writer, reply)
}
