//! Moving a dropped file into the session, through the shared transfer service.
//!
//! Section 12 says the desktop applications own the drag-and-drop interaction and use the shared
//! Rust transfer services for what happens next. The platform hands this process a path, never the
//! bytes, so the page never sees the file: it is told what was dropped, and this reads it and
//! drives the upload.
//!
//! The sequence itself is [`kr_client::uploads::Upload`], which is the client library's and is the
//! same on every platform. What is here is the part that is this application's: reading the file,
//! sending each step over the session, and handing back the verified handle.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_client::Session;
use kr_client::uploads::{Answer, Content, Step, Subject, Upload};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::method::Method;
use kr_protocol::scalars::Digest256;
use kr_protocol::transfer::AttachmentHandle;

use crate::error::{CommandError, Result};

/// The largest file this application will read for one drop.
///
/// The host applies its own environment budget; this is the bound on what one window will hold
/// open and hash before it has asked the host for anything at all.
pub const MAX_DROPPED_BYTES: u64 = 512 * 1024 * 1024;

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

/// Sends one file to the host and returns the verified handle.
///
/// # Errors
///
/// Returns the host's refusal, and the client's own when the file changed while it was being sent.
pub async fn upload(
    session: &Session,
    target: ActionTarget,
    environment_id: kr_protocol::ids::EnvironmentId,
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
    let subject = Subject {
        environment_id,
        session_id,
        device_id: None,
        declared_media_type: content.media_type().to_owned(),
        original_file_name: content.name().to_owned(),
    };
    let mut plan = Upload::new(subject, Box::new(content));
    loop {
        match plan.next()? {
            Step::Begin(params) => {
                let settled = session
                    .mutate(
                        Method::UploadBegin,
                        target.clone(),
                        None,
                        &Empty {},
                        &*params,
                        crate::commands::MUTATION_TTL,
                    )
                    .await?;
                plan.accept(Answer::Begun(Box::new(result_of(&settled)?)))?;
            }
            Step::Chunk(params) => {
                let settled = session
                    .mutate(
                        Method::UploadChunk,
                        target.clone(),
                        None,
                        &Empty {},
                        &*params,
                        crate::commands::MUTATION_TTL,
                    )
                    .await?;
                plan.accept(Answer::Chunked(Box::new(result_of(&settled)?)))?;
            }
            Step::Finish(params) => {
                let settled = session
                    .mutate(
                        Method::UploadFinish,
                        target.clone(),
                        None,
                        &Empty {},
                        &params,
                        crate::commands::MUTATION_TTL,
                    )
                    .await?;
                plan.accept(Answer::Finished(Box::new(result_of(&settled)?)))?;
            }
            Step::Done(handle) => return Ok(*handle),
        }
    }
}

/// The preconditions this application states, which are none: every one it relies on is a
/// parameter of the method itself.
#[derive(Debug, serde::Serialize)]
struct Empty {}

/// The method's own result, or the failure when the host answered with only a receipt.
fn result_of<R>(settled: &kr_client::Settled) -> Result<R>
where
    R: serde::de::DeserializeOwned + serde::Serialize,
{
    settled.to_typed::<R>().map_err(CommandError::from)
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
    fn a_name_is_the_last_component_and_never_a_path() {
        assert_eq!(file_name(Path::new("/tmp/pictures/a.png")), "a.png");
        assert_eq!(file_name(Path::new("/")), "attachment");
    }
}
