//! A device's own transfer of an image to the host, driven by the client library's upload driver.
//!
//! The specification's case 1 asks for the remote device's own transfer: the device begins the
//! upload, sends the image's bytes on the route the host serves, finishes it, and the image the
//! agent is given is the one that transfer published. [`kr_client::uploads::send`] drives all of
//! that, so nothing of the sequence is written here: this module says who sends, where the chunks
//! travel and what is read of the outcome.
//!
//! Where the chunks travel is [`device_route`] for a paired device: the data streams of its own
//! connection.
//!
//! What the host published is found where the host stages it ([`staged_file`]), because no device
//! is shown a path: the attachment handle names a transfer, not a location.

use std::path::{Path, PathBuf};

use kr_client::Session as ClientSession;
use kr_client::chunks::ChunkRoute;
use kr_client::error::ClientError;
use kr_client::ipc::IpcTransport;
use kr_client::uploads::{self, Held, Subject, Upload};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{BuildId, SessionId, TransferId};
use kr_protocol::scalars::DurationMs;
use kr_protocol::transfer::AttachmentHandle;

/// How long each of the transfer's calls asks the host to keep it.
const REQUESTED_TTL: DurationMs = DurationMs::new(60_000);

/// Who sends the transfer's calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    /// The paired device, over its own connection: the case's transfer.
    Device,
    /// The host's own owner on this machine, over the local control endpoint. It is not the case's
    /// transfer and never passes the part; it shows what the rest of the part does with an image a
    /// host publishes, where the host serves no transfer to a device.
    LocalOwner,
}

impl Caller {
    /// The word a record names the caller by.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Device => "paired device",
            Self::LocalOwner => "local owner",
        }
    }
}

/// The step of the transfer a call belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `upload.begin`: the reservation.
    Begin,
    /// `upload.chunk`: the bytes.
    Chunk,
    /// `upload.finish`: the publication.
    Finish,
}

impl Step {
    /// The method the step is.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Begin => "upload.begin",
            Self::Chunk => "upload.chunk",
            Self::Finish => "upload.finish",
        }
    }
}

/// What the transfer came to.
#[derive(Clone, Debug)]
pub enum Transfer {
    /// The host published the attachment.
    Sent(Box<AttachmentHandle>),
    /// The host refused a step with this code of the protocol.
    Refused {
        /// The step it refused.
        step: Step,
        /// The code.
        code: String,
    },
    /// A step failed with no code of the host's: the connection, or an answer that could not be
    /// read.
    Failed {
        /// The step it failed at.
        step: Step,
        /// What went wrong, without any bytes of the transfer.
        error: String,
    },
}

impl Transfer {
    /// The transfer as evidence: the caller, the steps, and what the host published, never the
    /// bytes or a name of the file.
    #[must_use]
    pub fn evidence(&self, caller: Caller, lane: Lane) -> serde_json::Value {
        match self {
            Self::Sent(handle) => serde_json::json!({
                "caller": caller.word(),
                "route": lane.word(),
                "driver": "kr-client uploads::send",
                "published": {
                    "byte_len": handle.byte_len.get(),
                    "content_digest": hex_of(handle.content_digest.as_bytes()),
                    "declared_media_type": handle.declared_media_type,
                    "presented_as_image": handle.presented_as_image,
                },
            }),
            Self::Refused { step, code } => serde_json::json!({
                "caller": caller.word(),
                "route": lane.word(),
                "driver": "kr-client uploads::send",
                "refused": { "call": step.method(), "code": code },
            }),
            Self::Failed { step, error } => serde_json::json!({
                "caller": caller.word(),
                "route": lane.word(),
                "driver": "kr-client uploads::send",
                "failed": { "call": step.method(), "error": error },
            }),
        }
    }
}

/// Whose lane a transfer's chunks travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// The host's local attachment-chunk endpoint, which only the host's own owner on this machine
    /// reaches: chunks sent on it are not a paired device's, whoever began the upload.
    Local,
    /// The data streams of the connection a paired device holds to the host: the lane a device's
    /// chunks travel.
    Network,
}

impl Lane {
    /// The word a record names the lane by.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Local => "local endpoint",
            Self::Network => "paired host's data streams",
        }
    }

    /// Whether a paired device's chunks travel it.
    #[must_use]
    pub const fn is_a_devices(self) -> bool {
        match self {
            Self::Local => false,
            Self::Network => true,
        }
    }
}

/// The route a paired device's chunks travel: the data streams of the host its own `session` is
/// connected to, which the host says it takes before anything is reserved.
///
/// # Errors
///
/// Returns the client library's refusal when the connection has no data streams or the host takes
/// no attachment stream from a device.
pub async fn device_route(
    session: &ClientSession,
    environment: &EnvironmentPaths,
) -> Result<(ChunkRoute, Lane), ClientError> {
    Ok((
        ChunkRoute::network(session, environment.environment_id()).await?,
        Lane::Network,
    ))
}

/// A session of the host's own owner on this machine, over the local control endpoint, as the
/// native client opens one.
///
/// # Errors
///
/// Returns why the endpoint could not be reached.
pub async fn local_session(
    environment: &EnvironmentPaths,
    build_id: BuildId,
) -> Result<ClientSession, ClientError> {
    let endpoint = environment.controller_endpoint()?;
    let transport = IpcTransport::connect(&endpoint, build_id).await?;
    ClientSession::start(transport.shared())
}

/// Transfers `bytes` as `session` and `target` say, with the client library's driver: the
/// reservation on `session`, every chunk on the lane `route` opens, and the publication.
pub async fn send_image(
    session: &ClientSession,
    route: &ChunkRoute,
    target: &ActionTarget,
    subject: Subject,
    bytes: Vec<u8>,
) -> Transfer {
    let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut plan = Upload::new(subject, Box::new(Held::new(bytes)));
    // The driver reports its progress on a channel; nothing here watches it.
    let progress = tokio::sync::watch::channel(uploads::Progress::default()).0;
    match uploads::send(session, route, target, &mut plan, REQUESTED_TTL, &progress).await {
        Ok(handle) => Transfer::Sent(Box::new(handle)),
        Err(error) => {
            // What the plan holds says how far the host got: no transfer yet, so the reservation;
            // a transfer whose chunks are not all acknowledged, so a chunk; else the publication.
            let step = if plan.transfer_id().is_none() {
                Step::Begin
            } else if plan.acknowledged_chunks() < chunks_of(total) {
                Step::Chunk
            } else {
                Step::Finish
            };
            match error {
                ClientError::Host(refusal) => Transfer::Refused {
                    step,
                    code: refusal.code.as_str().to_owned(),
                },
                other => Transfer::Failed {
                    step,
                    error: other.to_string(),
                },
            }
        }
    }
}

/// How many chunks `total` bytes make.
fn chunks_of(total: u64) -> u64 {
    kr_protocol::transfer::ChunkLayout::for_length(total)
        .chunk_count
        .get()
}

/// The subject of an image the device sends for `session_id`.
#[must_use]
pub fn image_subject(
    environment: &EnvironmentPaths,
    session_id: SessionId,
    file_name: &str,
) -> Subject {
    Subject {
        environment_id: environment.environment_id(),
        session_id: Some(session_id),
        device_id: None,
        declared_media_type: "image/png".to_owned(),
        original_file_name: file_name.to_owned(),
    }
}

/// The file the host published for `transfer_id`, found in the host's staging area for the
/// environment: a regular file under the transfers directory whose name begins with the transfer's
/// identifier as thirty-two hexadecimal digits and which is not an unfinished payload.
///
/// Nothing a device is shown names it, so this is the harness reading the host's own directory, as
/// the person on the host's machine can.
#[must_use]
pub fn staged_file(environment: &EnvironmentPaths, transfer_id: &TransferId) -> Option<PathBuf> {
    use std::fmt::Write as _;

    let mut stem = String::with_capacity(32);
    for byte in transfer_id.get().as_bytes() {
        let _ = write!(stem, "{byte:02x}");
    }
    let root = environment.state_dir().join("transfers");
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&stem) && !name.ends_with(".part") {
                return Some(path);
            }
        }
    }
    None
}

/// The SHA-256 of the file at `path`, as lower-case hexadecimal, where it can be read.
#[must_use]
pub fn digest_of(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex_of(&kr_cbor::sha256(&bytes)))
}

/// `bytes` as lower-case hexadecimal.
#[must_use]
pub fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The digests of the images a conversation's `text` records as given to the agent: each line the
/// build list's `marker` is in, with the base64 text after each `base64,` in it decoded and hashed,
/// so a message that holds several images gives one digest for each. A line the marker is in with
/// no image text after it, or whose image cannot be decoded, gives `None`.
#[must_use]
pub fn images_recorded(text: &str, marker: &str) -> Vec<Option<String>> {
    use base64::Engine as _;

    let mut found = Vec::new();
    for line in text.lines().filter(|line| line.contains(marker)) {
        let mut images = line.split("base64,").skip(1).peekable();
        if images.peek().is_none() {
            found.push(None);
        }
        for after in images {
            let encoded: String = after
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
                })
                .collect();
            found.push(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .ok()
                    .map(|bytes| hex_of(&kr_cbor::sha256(&bytes))),
            );
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn a_message_that_holds_several_images_gives_a_digest_for_each() {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let line = format!(
            r#"{{"role":"user","content":[{{"type":"input_image","image_url":"data:image/png;base64,{}"}},{{"type":"input_image","image_url":"data:image/png;base64,{}"}}]}}"#,
            encode(b"first image"),
            encode(b"second image")
        );
        let found = images_recorded(&format!("{line}\n"), "\"type\":\"input_image\"");
        assert_eq!(
            found,
            vec![
                Some(hex_of(&kr_cbor::sha256(b"first image"))),
                Some(hex_of(&kr_cbor::sha256(b"second image")))
            ]
        );
    }
}
