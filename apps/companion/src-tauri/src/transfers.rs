//! Moving a dropped file into the session, through the shared transfer service.
//!
//! Section 12 says the desktop applications own the drag-and-drop interaction and use the shared
//! Rust transfer services for what happens next. The platform hands this process a path, never the
//! bytes, so the page never sees the file: it is told what was dropped, and this reads it and
//! drives the upload.
//!
//! The sequence itself is the client library's and is the same on every platform: the plan,
//! [`kr_client::uploads::Upload`], and its driver, [`kr_client::uploads::send`], which reserves,
//! asks and publishes on the session and sends every chunk on the environment's attachment-chunk
//! lane. What is here is the part that is this application's: reading the file, naming the host
//! it goes to, and handing back the verified handle.
//!
//! A file pasted onto the window, or picked on a phone, is different in one way: the platform gave
//! it to the page rather than giving this process a path, so the page hands its bytes over and
//! they go through the same sequence. Those are bounded by [`MAX_HANDED_BYTES`].

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_client::Session;
use kr_client::chunks::ChunkRoute;
use kr_client::uploads::{Content, Held, Subject, Upload};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::scalars::Digest256;
use kr_protocol::transfer::AttachmentHandle;

use crate::error::{CommandError, Result};

/// The largest file this application will read for one drop.
///
/// The host applies its own environment budget; this is the bound on what one window will hold
/// open and hash before it has asked the host for anything at all.
pub const MAX_DROPPED_BYTES: u64 = 512 * 1024 * 1024;

/// The largest file the page may hand over as bytes, pasted onto the window or picked on a phone.
///
/// The bytes cross the page's own channel to this process in one piece, so they are held here in
/// full before the first chunk goes; a dropped file, which this process reads from its path in
/// chunks, may be larger.
pub const MAX_HANDED_BYTES: usize = 64 * 1024 * 1024;

/// The most bytes of a handed file's name that are kept.
const MAX_NAME_BYTES: usize = 255;

/// A file the page handed over: its bytes, and the name it came with as metadata.
#[derive(Debug)]
pub struct HandedFile {
    content: Held,
    name: String,
    media_type: String,
}

/// What is said of a pasted or picked file above the size limit. The limit is said in megabytes,
/// which is what a person reads. A desktop window takes a larger file dropped on it and a phone has
/// no window to drop on, so only the desktop is told so.
fn too_large_to_hand() -> String {
    let megabytes = MAX_HANDED_BYTES / (1024 * 1024);
    let said = format!("a pasted or picked file is at most {megabytes} MiB");
    if cfg!(mobile) {
        said
    } else {
        format!("{said}; drop a larger one on the window")
    }
}

impl HandedFile {
    /// Takes the bytes the page handed over and the name the platform gave the file.
    ///
    /// The name is metadata and nothing else: only its last component is kept, without control
    /// characters, and the media type is declared from it as a dropped file's is.
    ///
    /// # Errors
    ///
    /// Returns `QUOTA_EXCEEDED` when the file is larger than [`MAX_HANDED_BYTES`].
    pub fn new(bytes: Vec<u8>, name: &str) -> Result<Self> {
        if bytes.len() > MAX_HANDED_BYTES {
            return Err(CommandError::too_large(too_large_to_hand()));
        }
        let name = handed_name(name);
        let media_type = media_type_of(Path::new(&name));
        Ok(Self {
            content: Held::new(bytes),
            name,
            media_type,
        })
    }

    /// The filename, as metadata.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The media type this client believes it is sending.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// A handed file's name as metadata: its last component, printable, bounded, never empty.
fn handed_name(raw: &str) -> String {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let printable: String = last
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let trimmed = printable.trim();
    let mut kept = String::new();
    for character in trimmed.chars() {
        if kept.len() + character.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        kept.push(character);
    }
    if kept.is_empty() || kept == "." || kept == ".." {
        "attachment".to_owned()
    } else {
        kept
    }
}

/// A file on this machine, read in the chunks the protocol's layout asks for.
#[derive(Debug)]
pub struct DroppedFile {
    file: Mutex<std::fs::File>,
    byte_len: u64,
    digest: Digest256,
    name: String,
    media_type: String,
}

impl DroppedFile {
    /// Opens a dropped file and digests it once.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` when the path is not a readable file, and `QUOTA_EXCEEDED` when
    /// it is larger than [`MAX_DROPPED_BYTES`].
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .map_err(|error| CommandError::invalid(format!("that file cannot be read: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| CommandError::invalid(format!("that file cannot be read: {error}")))?;
        if !metadata.is_file() {
            return Err(CommandError::invalid("only a file can be attached"));
        }
        let byte_len = metadata.len();
        if byte_len > MAX_DROPPED_BYTES {
            return Err(CommandError::too_large(format!(
                "that file is larger than the {MAX_DROPPED_BYTES}-byte limit for one attachment"
            )));
        }

        // Digested here, once, before anything is declared: `upload.begin` states the digest and
        // `upload.finish` repeats it, so a client that had not read the file could not say either.
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                CommandError::invalid(format!("that file cannot be read: {error}"))
            })?;
            if read == 0 {
                break;
            }
            sha2::Digest::update(&mut hasher, &buffer[..read]);
        }
        let digest = Digest256::from_bytes(sha2::Digest::finalize(hasher).into());

        Ok(Self {
            file: Mutex::new(file),
            byte_len,
            digest,
            name: file_name(path),
            media_type: media_type_of(path),
        })
    }

    /// The filename, as metadata.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The media type this client believes it is sending.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

impl Content for DroppedFile {
    fn byte_len(&self) -> u64 {
        self.byte_len
    }

    fn digest(&self) -> Digest256 {
        self.digest
    }

    fn read_at(&self, offset: u64, len: u64) -> kr_client::Result<Vec<u8>> {
        let mut file = self.file.lock().map_err(|_| read_failed())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| read_failed())?;
        let mut bytes = vec![0_u8; usize::try_from(len).map_err(|_| read_failed())?];
        file.read_exact(&mut bytes).map_err(|_| read_failed())?;
        Ok(bytes)
    }
}

fn read_failed() -> kr_client::ClientError {
    kr_client::ClientError::Host(kr_protocol::error::ProtocolError::new(
        kr_protocol::error::ErrorCode::AttachmentIntegrity,
        "the file changed or could not be read while it was being sent",
    ))
}

/// The filename, with everything that is not part of one removed.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".to_owned())
}

/// The media type a filename suggests.
///
/// Declared, not sniffed: the handle records what the client believed it sent, and the host's own
/// decoder decides whether it is an image.
fn media_type_of(path: &Path) -> String {
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
    .to_owned()
}

/// Sends one file to the host on this machine and returns the verified handle.
///
/// The host is the one [`crate::connection::connect_local`] reached: the environment `environment_id`
/// names, under the host paths this process discovers the same way.
///
/// # Errors
///
/// Returns `RESOURCE_UNAVAILABLE` when the host's paths cannot be read, and whatever [`upload_to`]
/// returns.
pub async fn upload(
    session: &Session,
    target: ActionTarget,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: Option<kr_protocol::ids::SessionId>,
    path: PathBuf,
) -> Result<AttachmentHandle> {
    let paths = kr_ipc::paths::HostPaths::discover()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    upload_to(
        session,
        &paths.environment(environment_id),
        target,
        session_id,
        path,
    )
    .await
}

/// Sends one file to `environment`, whose controller `session` is connected to, and returns the
/// verified handle.
///
/// The reservation and the publication go on the session and every chunk on the environment's
/// attachment-chunk endpoint, which is what lets a chunk be the protocol's full size.
///
/// # Errors
///
/// Returns the host's refusal, and the client's own when the file changed while it was being sent.
pub async fn upload_to(
    session: &Session,
    environment: &EnvironmentPaths,
    target: ActionTarget,
    session_id: Option<kr_protocol::ids::SessionId>,
    path: PathBuf,
) -> Result<AttachmentHandle> {
    let content = tauri::async_runtime::spawn_blocking(move || DroppedFile::open(&path))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the file was not read: {error}"))
        })??;

    // The name and the media type are the file's own, read here rather than taken from the page:
    // what the handle records is what this client actually opened.
    let name = content.name().to_owned();
    let media_type = content.media_type().to_owned();
    send(
        session,
        environment,
        target,
        session_id,
        Box::new(content),
        name,
        media_type,
    )
    .await
}

/// Sends one file the page handed over to the host on this machine, and returns the verified
/// handle.
///
/// # Errors
///
/// Returns `RESOURCE_UNAVAILABLE` when the host's paths cannot be read, and whatever
/// [`upload_handed_to`] returns.
pub async fn upload_handed(
    session: &Session,
    target: ActionTarget,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: Option<kr_protocol::ids::SessionId>,
    file: HandedFile,
) -> Result<AttachmentHandle> {
    let paths = kr_ipc::paths::HostPaths::discover()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    upload_handed_to(
        session,
        &paths.environment(environment_id),
        target,
        session_id,
        file,
    )
    .await
}

/// Sends one file the page handed over to `environment`, whose controller `session` is connected
/// to, and returns the verified handle.
///
/// # Errors
///
/// Returns the host's refusal.
pub async fn upload_handed_to(
    session: &Session,
    environment: &EnvironmentPaths,
    target: ActionTarget,
    session_id: Option<kr_protocol::ids::SessionId>,
    file: HandedFile,
) -> Result<AttachmentHandle> {
    let HandedFile {
        content,
        name,
        media_type,
    } = file;
    send(
        session,
        environment,
        target,
        session_id,
        Box::new(content),
        name,
        media_type,
    )
    .await
}

/// Declares, sends and publishes one file's content, under the name and media type it carries.
async fn send(
    session: &Session,
    environment: &EnvironmentPaths,
    target: ActionTarget,
    session_id: Option<kr_protocol::ids::SessionId>,
    content: Box<dyn Content>,
    name: String,
    media_type: String,
) -> Result<AttachmentHandle> {
    let subject = Subject {
        environment_id: environment.environment_id(),
        session_id,
        device_id: None,
        declared_media_type: media_type,
        original_file_name: name,
    };
    let route = ChunkRoute::local(environment, crate::connection::build_id()?)?;
    let mut plan = Upload::new(subject, content);
    Ok(kr_client::uploads::send(
        session,
        &route,
        &target,
        &mut plan,
        crate::commands::MUTATION_TTL,
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn a_dropped_file_is_digested_once_and_read_in_the_ranges_the_layout_asks_for() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("notes.txt");
        let mut file = std::fs::File::create(&path).expect("a file");
        file.write_all(b"the quick brown fox").expect("written");
        drop(file);

        let dropped = DroppedFile::open(&path).expect("a readable file");
        assert_eq!(dropped.byte_len(), 19);
        assert_eq!(
            dropped.digest(),
            Digest256::from_bytes(kr_cbor::sha256(b"the quick brown fox"))
        );
        assert_eq!(dropped.name(), "notes.txt");
        assert_eq!(dropped.media_type(), "text/plain");
        assert_eq!(dropped.read_at(4, 5).expect("a range"), b"quick");
    }

    #[test]
    fn a_directory_is_not_an_attachment() {
        let directory = tempfile::tempdir().expect("a directory");
        let error = DroppedFile::open(directory.path()).expect_err("a directory is not a file");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_media_type_is_declared_from_the_name_rather_than_sniffed() {
        assert_eq!(media_type_of(Path::new("a/b/diagram.PNG")), "image/png");
        assert_eq!(
            media_type_of(Path::new("archive.tar.zst")),
            "application/octet-stream"
        );
        assert_eq!(
            media_type_of(Path::new("no-extension")),
            "application/octet-stream"
        );
    }

    #[test]
    fn a_handed_name_is_its_last_component_printable_and_bounded() {
        assert_eq!(
            handed_name("Screenshot 2026-09-27.png"),
            "Screenshot 2026-09-27.png"
        );
        assert_eq!(handed_name("../../etc/passwd"), "passwd");
        assert_eq!(handed_name("C:\\Users\\me\\notes.txt"), "notes.txt");
        assert_eq!(handed_name("bell\u{7}.txt"), "bell.txt");
        assert_eq!(handed_name(".."), "attachment");
        assert_eq!(handed_name("   "), "attachment");
        let long = "é".repeat(200);
        assert!(handed_name(&long).len() <= MAX_NAME_BYTES);
        assert!(handed_name(&long).chars().all(|character| character == 'é'));
    }

    #[test]
    fn a_handed_file_declares_its_type_from_its_name_and_is_bounded() {
        let file = HandedFile::new(b"hello".to_vec(), "diagram.PNG").expect("a small file");
        assert_eq!(file.name(), "diagram.PNG");
        assert_eq!(file.media_type(), "image/png");
        assert_eq!(file.content.byte_len(), 5);
        let error = HandedFile::new(vec![0; MAX_HANDED_BYTES + 1], "big.bin")
            .expect_err("a file past the bound is refused");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::QuotaExceeded);
    }

    #[test]
    fn a_name_is_the_last_component_and_never_a_path() {
        assert_eq!(file_name(Path::new("/tmp/pictures/a.png")), "a.png");
        assert_eq!(file_name(Path::new("/")), "attachment");
    }
}
