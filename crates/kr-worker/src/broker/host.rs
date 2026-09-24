//! Reverse operations, performed through the host resources a session granted.
//!
//! Section 12 has an upstream ask this host to read and write files, and requires that such a
//! request runs "in the selected host environment with scoped broker resources", "with its
//! existing user identity". Section 11 keeps filesystem access a grant of its own, apart from every
//! other right an upstream or a component holds. This module is where the two meet: a request
//! names a file, and what it names is resolved beneath a directory this host was granted, through
//! the handle that grant holds, or it is refused.
//!
//! Three rules are the whole of it.
//!
//! * **The grant is the only authority.** A path in a request is a name, never a permission. It is
//!   read relative to the granted directory's handle, one component at a time and following no
//!   link, by the transfer service's handle-based file authority ([`kr_transfer::authority`]). A
//!   name that leaves the directory, a link on the way, an object that is not a regular file, a
//!   grant held for another environment: each is refused before anything is opened for writing.
//!   The worker takes that authority and nothing else of the transfer service: its previews and
//!   the image decoders linked with them are never reached from here.
//! * **What can be decided without the filesystem is decided first.** Whether a request is one this
//!   host performs, whether a grant covers it, whether its name stays beneath the granted
//!   directory and whether it fits its bounds are all read from the request and the grant, under
//!   the broker's lock, before the one admission is taken and the marker committed. Only then does
//!   the operation run, and what the authority itself refuses as it opens is refused before
//!   anything is written.
//! * **Every operation is bounded.** A read returns at most the grant's byte bound, and a file
//!   larger than that is refused rather than cut short; a write carries at most its own bound; an
//!   operation has a deadline and a connection a limit on how many run at once. Terminal operations
//!   are not performed at all: the session's terminal takes input through its own lease, and a
//!   reverse request is not a second way in.

use std::io::{Read as _, Write as _};
use std::path::{Component, Path};
use std::sync::Arc;

use kr_protocol::gateway::{NativeMethodClass, ReverseOperation};
use kr_protocol::ids::{EnvironmentId, UpstreamRequestId};
use kr_transfer::authority::{AuthorisedDirectory, Escape, ObjectKind, ObjectPolicy, RelativeName};

/// The most bytes one reverse read returns.
///
/// A grant may set less. A file larger than the bound is refused rather than cut short, because an
/// answer that silently ended early would read as the whole file.
pub const MAX_REVERSE_READ_BYTES: u64 = 256 * 1024;

/// The most bytes one reverse write carries.
///
/// A grant may set less. A request frame is itself bounded, and this is the smaller bound on what
/// one request may put into a file.
pub const MAX_REVERSE_WRITE_BYTES: u64 = 256 * 1024;

/// The most bytes one answer to a reverse request may encode to.
///
/// A read's content is escaped when it is encoded, and escaping can multiply it. An answer that
/// would outgrow this is replaced by a refusal that says so, rather than queued into a connection
/// whose byte bound it would fill.
pub const MAX_REVERSE_ANSWER_BYTES: usize = 512 * 1024;

/// How long one reverse operation has to finish before the upstream is told it did not.
///
/// The operation itself cannot be stopped once the platform is performing it. The answer is not
/// held for it, and a write that has not finished by then is recorded as an outcome nobody can
/// establish.
pub const REVERSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How many reverse operations one connection may have running at once.
///
/// An operation that has passed its deadline still holds its place until the platform returns
/// from it, so an upstream cannot turn a stalled filesystem into an unbounded number of stalled
/// threads.
pub const MAX_REVERSE_IN_FLIGHT: usize = 4;

/// What one grant lets an upstream do with the files beneath its directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccess {
    /// Read files, and nothing else.
    Read,
    /// Read files, and write them.
    ReadWrite,
}

/// A directory this host granted to one application instance's upstream, and the bounds with it.
///
/// It holds the directory as the file authority's opened handle. The handle is the grant: a name
/// is resolved beneath it and never beside it, and a rename of the directory moves the grant with
/// the object rather than handing it to whatever takes the old name.
///
/// The handle is confined to the mount it was opened on. A directory or file mounted over a name
/// inside the tree reaches another tree entirely, and nothing in the path says so; a grant that did
/// not refuse that would let an upstream read or write whatever was mounted there.
#[derive(Debug)]
pub struct HostFiles {
    root: AuthorisedDirectory,
    access: FileAccess,
    max_read_bytes: u64,
    max_write_bytes: u64,
}

impl HostFiles {
    /// Grants one opened directory, confined to its own mount, with the default bounds.
    ///
    /// # Errors
    ///
    /// Returns the file authority's refusal when this host cannot say which mount the directory
    /// was opened on. The rule is refused rather than approximated: a grant that could not tell two
    /// mounts apart would reach whatever was mounted beneath it.
    pub fn new(root: AuthorisedDirectory, access: FileAccess) -> Result<Self, Escape> {
        Ok(Self {
            root: root.confined_to_one_mount()?,
            access,
            max_read_bytes: MAX_REVERSE_READ_BYTES,
            max_write_bytes: MAX_REVERSE_WRITE_BYTES,
        })
    }

    /// Returns this grant with smaller byte bounds.
    ///
    /// A bound can only come down: what is asked for above the defaults is held at the defaults.
    #[must_use]
    pub fn with_bounds(mut self, max_read_bytes: u64, max_write_bytes: u64) -> Self {
        self.max_read_bytes = max_read_bytes.min(MAX_REVERSE_READ_BYTES);
        self.max_write_bytes = max_write_bytes.min(MAX_REVERSE_WRITE_BYTES);
        self
    }

    /// Returns the environment the granted directory belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.root.environment_id()
    }

    /// Returns what the grant permits.
    #[must_use]
    pub const fn access(&self) -> FileAccess {
        self.access
    }

    /// Returns true when the grant covers one operation.
    const fn permits(&self, operation: ReverseOperation) -> bool {
        match operation {
            ReverseOperation::FilesystemRead => true,
            ReverseOperation::FilesystemWrite => matches!(self.access, FileAccess::ReadWrite),
            ReverseOperation::Terminal => false,
        }
    }
}

/// Why this host did not perform a reverse request, as the upstream is told it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    code: i64,
    message: String,
}

impl Refusal {
    /// The request names an operation this host does not perform for an upstream.
    const UNSUPPORTED: i64 = -32_601;
    /// The request's parameters are not ones the operation takes.
    const INVALID: i64 = -32_602;
    /// The grant, a bound or the file authority refused it, or it failed.
    const REFUSED: i64 = -32_000;

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            code: Self::UNSUPPORTED,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: Self::INVALID,
            message: message.into(),
        }
    }

    fn refused(message: impl Into<String>) -> Self {
        Self {
            code: Self::REFUSED,
            message: message.into(),
        }
    }

    /// Returns the error code the upstream is answered with.
    #[must_use]
    pub const fn code(&self) -> i64 {
        self.code
    }

    /// Returns what the upstream is told.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What this host answers one reverse request with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The operation ran, and this is its result.
    Result(serde_json::Value),
    /// The operation did not run, or did not finish, and this says why.
    Refused(Refusal),
}

/// One reverse request as the core reads it, before a grant is consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ask {
    /// Read one text file, optionally from a line and for a number of lines.
    Read {
        path: String,
        first_line: u64,
        lines: Option<u64>,
    },
    /// Replace one text file's content, creating it where nothing is.
    Write { path: String, content: String },
    /// Anything to do with a terminal.
    Terminal,
}

/// What this host will do about one reverse request, decided before its admission is taken.
#[derive(Debug)]
pub enum Plan {
    /// Perform the operation through the grant.
    Perform(Performance),
    /// Answer with this refusal. Nothing is performed.
    Refuse(Refusal),
}

/// One operation this host decided to perform, with the grant it runs under.
#[derive(Debug)]
pub struct Performance {
    files: Arc<HostFiles>,
    name: RelativeName,
    work: Work,
}

/// The operation itself.
#[derive(Debug)]
enum Work {
    Read { first_line: u64, lines: Option<u64> },
    Write { content: String },
}

/// What performing an operation came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Performed {
    /// What the upstream is answered with.
    pub answer: Answer,
    /// False when the operation may have changed a file it did not finish with.
    ///
    /// An answer is still written for such an operation, and it says so; the resource it answers
    /// is recorded as an outcome nobody can establish rather than as one that resolved cleanly.
    pub certain: bool,
}

impl Performed {
    const fn done(answer: Answer) -> Self {
        Self {
            answer,
            certain: true,
        }
    }

    fn refused(refusal: Refusal) -> Self {
        Self::done(Answer::Refused(refusal))
    }

    fn unfinished(message: impl Into<String>) -> Self {
        Self {
            answer: Answer::Refused(Refusal::refused(message)),
            certain: false,
        }
    }

    /// The answer for an operation that did not finish within its deadline.
    ///
    /// A read has changed nothing whether or not it ever returns. A write may be part way through
    /// changing its file, so it is recorded as an outcome nobody can establish.
    #[must_use]
    pub fn overran(operation: ReverseOperation, deadline: std::time::Duration) -> Self {
        let message = format!(
            "{} did not finish within {} milliseconds",
            operation.as_str(),
            deadline.as_millis()
        );
        if operation.class() == NativeMethodClass::Observation {
            return Self::refused(Refusal::refused(message));
        }
        Self::unfinished(format!(
            "{message}, so whether the file was changed cannot be established"
        ))
    }

    /// The answer for an operation that stopped part way for a reason of this host's own.
    ///
    /// Like an overrun, a read changed nothing and a write may have changed its file.
    #[must_use]
    pub fn interrupted(operation: ReverseOperation) -> Self {
        let message = format!("{} stopped before it finished", operation.as_str());
        if operation.class() == NativeMethodClass::Observation {
            return Self::refused(Refusal::refused(message));
        }
        Self::unfinished(format!(
            "{message}, so whether the file was changed cannot be established"
        ))
    }

    /// The answer for an operation this host admitted and then could not run at all.
    #[must_use]
    pub fn not_run(message: impl Into<String>) -> Self {
        Self::refused(Refusal::refused(message))
    }
}

impl Plan {
    /// Decides what this host does about one reverse request.
    ///
    /// Nothing here touches the filesystem. It is the part of the decision the request and the
    /// grant settle between them, so it runs under the broker's lock, before the admission.
    ///
    /// `durable` is whether the marker this answer's admission commits reaches the journal. A
    /// write whose marker cannot be recorded is refused: section 11 fences work that changes
    /// something while the journal is faulted, and a reverse write changes a file.
    #[must_use]
    pub fn decide(
        body: &serde_json::Map<String, serde_json::Value>,
        params_field: &str,
        operation: ReverseOperation,
        grant: Option<&Arc<HostFiles>>,
        site: EnvironmentId,
        durable: bool,
    ) -> Self {
        match Self::decided(body, params_field, operation, grant, site, durable) {
            Ok(performance) => Self::Perform(performance),
            Err(refusal) => Self::Refuse(refusal),
        }
    }

    fn decided(
        body: &serde_json::Map<String, serde_json::Value>,
        params_field: &str,
        operation: ReverseOperation,
        grant: Option<&Arc<HostFiles>>,
        site: EnvironmentId,
        durable: bool,
    ) -> Result<Performance, Refusal> {
        let ask = read_ask(body, params_field, operation)?;
        let (path, work) = match ask {
            Ask::Terminal => {
                return Err(Refusal::unsupported(
                    "this host does not run terminal operations for an upstream: the session's \
                     terminal takes input through its own lease, and a reverse request is not a \
                     second way in",
                ));
            }
            Ask::Read {
                path,
                first_line,
                lines,
            } => (path, Work::Read { first_line, lines }),
            Ask::Write { path, content } => (path, Work::Write { content }),
        };
        if operation.class() != NativeMethodClass::Observation && !durable {
            return Err(Refusal::refused(format!(
                "the journal cannot record that {} is about to run, so this host changes no file \
                 until storage recovers",
                operation.as_str()
            )));
        }
        let files = grant.ok_or_else(|| {
            Refusal::refused(format!(
                "no host directory is granted to this upstream, so {} is refused",
                operation.as_str()
            ))
        })?;
        if !files.permits(operation) {
            return Err(Refusal::refused(format!(
                "the directory granted to this upstream permits reading only, so {} is refused",
                operation.as_str()
            )));
        }
        // The grant runs where its handle belongs. A handle from another environment names another
        // machine's or another distribution's files, which section 12 rules out by name.
        if files.environment_id() != site {
            return Err(Refusal::refused(format!(
                "the granted directory belongs to environment {} and this upstream runs in {site}, \
                 so its handle is not one this request may use",
                files.environment_id()
            )));
        }
        let name = beneath(files.root.display_path(), &path)?;
        if let Work::Write { content } = &work {
            let length = u64::try_from(content.len()).unwrap_or(u64::MAX);
            if length > files.max_write_bytes {
                return Err(Refusal::refused(format!(
                    "this write carries {length} bytes and one reverse write carries at most {}",
                    files.max_write_bytes
                )));
            }
        }
        Ok(Performance {
            files: Arc::clone(files),
            name,
            work,
        })
    }
}

impl Performance {
    /// Performs the operation through the grant's handle.
    ///
    /// This blocks on the filesystem, so it runs away from any reader: a slow or stalled file
    /// holds its own thread and nothing that carries native traffic.
    #[must_use]
    pub fn perform(&self) -> Performed {
        match &self.work {
            Work::Read { first_line, lines } => read(&self.files, &self.name, *first_line, *lines),
            Work::Write { content } => write(&self.files, &self.name, content),
        }
    }
}

/// Reads what one reverse request asks for out of its frame.
fn read_ask(
    body: &serde_json::Map<String, serde_json::Value>,
    params_field: &str,
    operation: ReverseOperation,
) -> Result<Ask, Refusal> {
    if operation == ReverseOperation::Terminal {
        return Ok(Ask::Terminal);
    }
    let params = body
        .get(params_field)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Refusal::invalid(format!(
                "{} takes its parameters as an object in {params_field}",
                operation.as_str()
            ))
        })?;
    let path = params
        .get("path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Refusal::invalid("this request names no path as a string"))?
        .to_owned();
    match operation {
        ReverseOperation::FilesystemRead => Ok(Ask::Read {
            path,
            first_line: positive(params, "line")?.unwrap_or(1),
            lines: positive(params, "limit")?,
        }),
        ReverseOperation::FilesystemWrite => {
            let content = params
                .get("content")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Refusal::invalid("this request carries no content as a string"))?
                .to_owned();
            Ok(Ask::Write { path, content })
        }
        ReverseOperation::Terminal => Ok(Ask::Terminal),
    }
}

/// Reads one optional member that has to be a whole number of at least one.
fn positive(
    params: &serde_json::Map<String, serde_json::Value>,
    member: &str,
) -> Result<Option<u64>, Refusal> {
    match params.get(member) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|number| *number >= 1)
            .map(Some)
            .ok_or_else(|| Refusal::invalid(format!("{member} is a whole number of at least one"))),
    }
}

/// Turns the path a request names into a name beneath the granted directory.
///
/// An absolute path is read against the path the grant's directory was opened from, component by
/// component, and one that does not start there names nothing this grant covers. A relative path is
/// read from the directory itself. What remains has to be plain names: a parent segment, a root or
/// a drive anywhere in it is refused here, and the file authority refuses the rest of what could
/// leave the directory (a link, a mount, a device name) as it resolves the name through the handle.
fn beneath(root: &Path, requested: &str) -> Result<RelativeName, Refusal> {
    let outside = |why: &str| {
        Refusal::refused(format!(
            "{requested} is not beneath the granted directory: {why}"
        ))
    };
    let asked = Path::new(requested);
    let remainder = if asked.is_absolute() {
        asked
            .strip_prefix(root)
            .map_err(|_| outside("it names a place outside it"))?
    } else {
        asked
    };
    let mut names = Vec::new();
    for component in remainder.components() {
        match component {
            Component::Normal(name) => names.push(
                name.to_str()
                    .ok_or_else(|| outside("a component of it is not text"))?,
            ),
            Component::ParentDir => return Err(outside("it climbs out through a parent segment")),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(outside("it names a root or a drive"));
            }
        }
    }
    if names.is_empty() {
        return Err(outside(
            "it names the directory itself rather than a file in it",
        ));
    }
    RelativeName::parse(&names.join("/")).map_err(|escape| outside(&escape.to_string()))
}

/// Reads one file beneath the grant, whole or from a line.
fn read(files: &HostFiles, name: &RelativeName, first_line: u64, lines: Option<u64>) -> Performed {
    let opened = match files.root.open_read(name, ObjectPolicy::ReadableFile) {
        Ok(opened) => opened,
        Err(escape) => return Performed::refused(authority_refusal(&escape)),
    };
    // Measured through the handle before a byte is read: a file over the bound is refused whole,
    // and nothing of it is read to find that out.
    if opened.byte_len() > files.max_read_bytes {
        return Performed::refused(Refusal::refused(format!(
            "{name} holds {} bytes and one reverse read returns at most {}",
            opened.byte_len(),
            files.max_read_bytes
        )));
    }
    let mut bytes = Vec::new();
    // One byte past the bound is asked for, so a file that grew after it was measured is caught
    // rather than cut short.
    let limit = files.max_read_bytes.saturating_add(1);
    if let Err(error) = opened.into_handle().take(limit).read_to_end(&mut bytes) {
        return Performed::refused(Refusal::refused(format!(
            "{name} could not be read: {error}"
        )));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > files.max_read_bytes {
        return Performed::refused(Refusal::refused(format!(
            "{name} grew past {} bytes while it was read, and one reverse read returns at most that",
            files.max_read_bytes
        )));
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Performed::refused(Refusal::refused(format!(
            "{name} is not text, and this operation reads text"
        )));
    };
    let skip = usize::try_from(first_line.saturating_sub(1)).unwrap_or(usize::MAX);
    let take = lines.map_or(usize::MAX, |lines| {
        usize::try_from(lines).unwrap_or(usize::MAX)
    });
    let content: String = text.split_inclusive('\n').skip(skip).take(take).collect();
    Performed::done(Answer::Result(serde_json::json!({ "content": content })))
}

/// Replaces one file's content beneath the grant, creating the file where nothing is.
fn write(files: &HostFiles, name: &RelativeName, content: &str) -> Performed {
    // The directory the file is in is resolved through the grant's handle like any other name, so
    // the file is created or opened in the directory the descent checked.
    let components = name.components();
    let (leaf, parents) = match components.split_last() {
        Some((leaf, parents)) => (*leaf, parents),
        None => return Performed::refused(Refusal::refused("this request names no file")),
    };
    let held;
    let directory = if parents.is_empty() {
        &files.root
    } else {
        let above = match RelativeName::parse(&parents.join("/")) {
            Ok(above) => above,
            Err(escape) => return Performed::refused(authority_refusal(&escape)),
        };
        held = match files.root.subdirectory(&above) {
            Ok(held) => held,
            Err(escape) => return Performed::refused(authority_refusal(&escape)),
        };
        &held
    };
    let leaf = match RelativeName::parse(leaf) {
        Ok(leaf) => leaf,
        Err(escape) => return Performed::refused(authority_refusal(&escape)),
    };
    // A name that is taken by a regular file is opened and has its content replaced. A name that is
    // free is created, and a creation is itself a change: the authority checks what it opened only
    // after the platform has made it, so a creation it then refuses can leave a file under the
    // name. From the creation on, a failure is an outcome nobody can establish.
    let (opened, created) = match directory.probe(&leaf) {
        Ok(ObjectKind::File) => (directory.open_write(&leaf), false),
        Err(Escape::NotFound { .. }) => (directory.create_new(&leaf), true),
        Ok(kind) => {
            return Performed::refused(Refusal::refused(format!(
                "{name} is {}, and this operation writes a regular file",
                match kind {
                    ObjectKind::Directory => "a directory",
                    ObjectKind::Link => "a link",
                    ObjectKind::File | ObjectKind::Other => "not a regular file",
                }
            )));
        }
        Err(escape) => return Performed::refused(authority_refusal(&escape)),
    };
    let mut file = match opened {
        Ok(file) => file,
        Err(escape) if created => {
            return Performed::unfinished(format!(
                "{name} could not be created ({escape}), and whether a file was left under its \
                 name cannot be established"
            ));
        }
        Err(escape) => return Performed::refused(authority_refusal(&escape)),
    };
    let handle = file.handle_mut();
    // An existing file has not changed until its length does. From that point a failure leaves it
    // holding something nobody asked for, and the answer says the outcome cannot be established.
    if let Err(error) = handle.set_len(0) {
        if created {
            return Performed::unfinished(format!(
                "{name} was created and could not be prepared for its content ({error}), so what \
                 is left under its name cannot be established"
            ));
        }
        return Performed::refused(Refusal::refused(format!(
            "{name} could not be emptied for its new content: {error}"
        )));
    }
    if let Err(error) = handle.write_all(content.as_bytes()) {
        return Performed::unfinished(format!(
            "{name} was emptied and its new content could not be written in full ({error}), so \
             what it holds cannot be established"
        ));
    }
    if let Err(error) = handle.sync_all() {
        return Performed::unfinished(format!(
            "{name} was written and could not be made durable ({error}), so what it holds after \
             a failure cannot be established"
        ));
    }
    // A new file's content is durable once the file is flushed; its name is durable once the
    // directory that holds the name is. Without this a power failure can take the name away after
    // the answer said the file was written.
    if created && let Err(escape) = directory.sync() {
        return Performed::unfinished(format!(
            "{name} was written and its new name could not be made durable ({escape}), so whether \
             it survives a failure cannot be established"
        ));
    }
    Performed::done(Answer::Result(serde_json::json!({})))
}

/// Turns what the file authority refused into what the upstream is told.
fn authority_refusal(escape: &Escape) -> Refusal {
    Refusal::refused(format!("the file authority refused it: {escape}"))
}

/// Builds the answer frame, in the connection's own members, under the identifier the upstream
/// used.
///
/// An answer that would encode past [`MAX_REVERSE_ANSWER_BYTES`] is replaced by a refusal that says
/// so. The identifier goes back with its JSON type, as every answer this host writes does.
#[must_use]
pub fn answer_frame(
    shape: &AnswerShape,
    upstream_request_id: &UpstreamRequestId,
    answer: &Answer,
) -> Vec<u8> {
    let identifier: serde_json::Value =
        serde_json::from_str(upstream_request_id.as_str()).unwrap_or(serde_json::Value::Null);
    let encoded = encode(shape, &identifier, answer);
    if encoded.len() <= MAX_REVERSE_ANSWER_BYTES {
        return encoded;
    }
    encode(
        shape,
        &identifier,
        &Answer::Refused(Refusal::refused(format!(
            "the answer would encode to {} bytes and an answer to a reverse request is at most \
             {MAX_REVERSE_ANSWER_BYTES}",
            encoded.len()
        ))),
    )
}

fn encode(shape: &AnswerShape, identifier: &serde_json::Value, answer: &Answer) -> Vec<u8> {
    let mut frame = serde_json::Map::new();
    frame.insert(shape.response_id_field.clone(), identifier.clone());
    match answer {
        Answer::Result(result) => {
            frame.insert(shape.result_field.clone(), result.clone());
        }
        Answer::Refused(refusal) => {
            frame.insert(
                shape.error_field.clone(),
                serde_json::json!({ "code": refusal.code, "message": refusal.message }),
            );
        }
    }
    serde_json::to_vec(&serde_json::Value::Object(frame)).unwrap_or_default()
}

/// The members of one connection's frames an answer is written with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerShape {
    /// The member a response carries the identifier it answers in.
    pub response_id_field: String,
    /// The member a successful response carries its result in.
    pub result_field: String,
    /// The member a failed response carries its error in.
    pub error_field: String,
}

impl AnswerShape {
    /// Reads the answer members out of a connection's qualified table.
    #[must_use]
    pub fn of(table: &kr_protocol::gateway::DeclarativeTable) -> Self {
        Self {
            response_id_field: table.response_id_field.clone(),
            result_field: table.result_field.clone(),
            error_field: table.error_field.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_beneath_the_root_is_read_relative_to_it_and_nothing_else_is() {
        // Built from this platform's own absolute paths, so a drive-rooted path on Windows and a
        // slash-rooted one elsewhere are each the absolute form being tested.
        let parent = std::env::temp_dir().join("work");
        let root = parent.join("project");
        let text = |path: &Path| path.to_str().expect("a test path is text").to_owned();
        assert_eq!(
            beneath(&root, &text(&root.join("src").join("main.rs")))
                .expect("beneath")
                .as_str(),
            "src/main.rs"
        );
        assert_eq!(
            beneath(&root, "notes/today.md").expect("beneath").as_str(),
            "notes/today.md"
        );
        for outside in [
            text(&parent.join("project2").join("src").join("main.rs")),
            text(&parent.join("other").join("file")),
            text(&root),
            "../project/file".to_owned(),
            "src/../../escape".to_owned(),
            String::new(),
        ] {
            assert!(
                beneath(&root, &outside).is_err(),
                "{outside} is not a file beneath the root"
            );
        }
    }

    #[test]
    fn a_grant_is_confined_to_the_mount_its_directory_was_opened_on() {
        let directory = std::env::temp_dir();
        let root = AuthorisedDirectory::open_root(
            EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16])),
            &directory,
        )
        .expect("the directory opens");
        assert!(
            root.mount().is_none(),
            "an opened directory is not confined by itself"
        );
        let files = HostFiles::new(root, FileAccess::Read).expect("the grant is made");
        assert!(
            files.root.mount().is_some(),
            "the grant carries the one-mount rule, and every name beneath it is held to it"
        );
    }

    #[test]
    fn a_read_takes_whole_numbers_and_a_write_takes_text() {
        let body = |params: serde_json::Value| {
            serde_json::json!({ "id": 1, "method": "fs/read_text_file", "params": params })
                .as_object()
                .cloned()
                .expect("an object")
        };
        assert_eq!(
            read_ask(
                &body(serde_json::json!({ "path": "a", "line": 3, "limit": 2 })),
                "params",
                ReverseOperation::FilesystemRead
            ),
            Ok(Ask::Read {
                path: "a".to_owned(),
                first_line: 3,
                lines: Some(2)
            })
        );
        for params in [
            serde_json::json!({ "path": "a", "line": 0 }),
            serde_json::json!({ "path": "a", "limit": -1 }),
            serde_json::json!({ "path": 7 }),
            serde_json::json!({}),
        ] {
            assert_eq!(
                read_ask(
                    &body(params.clone()),
                    "params",
                    ReverseOperation::FilesystemRead
                )
                .expect_err("refused")
                .code(),
                Refusal::INVALID,
                "{params} is refused as a request the operation does not take"
            );
        }
        assert!(
            read_ask(
                &body(serde_json::json!({ "path": "a" })),
                "params",
                ReverseOperation::FilesystemWrite
            )
            .is_err(),
            "a write without content is not a write"
        );
    }

    #[test]
    fn an_answer_that_would_outgrow_its_bound_becomes_a_refusal_that_says_so() {
        let shape = AnswerShape {
            response_id_field: "id".to_owned(),
            result_field: "result".to_owned(),
            error_field: "error".to_owned(),
        };
        let id = UpstreamRequestId::new("\"r-1\"").expect("valid");
        // Control characters are escaped six bytes each, so this is far past the bound encoded.
        let content = "\u{1}".repeat(MAX_REVERSE_ANSWER_BYTES / 2);
        let frame = answer_frame(
            &shape,
            &id,
            &Answer::Result(serde_json::json!({ "content": content })),
        );
        assert!(frame.len() <= MAX_REVERSE_ANSWER_BYTES);
        let answer: serde_json::Value = serde_json::from_slice(&frame).expect("readable");
        assert_eq!(answer["id"], serde_json::json!("r-1"));
        assert!(answer.get("result").is_none());
        assert!(
            answer["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("at most")),
            "{answer}"
        );
    }
}
