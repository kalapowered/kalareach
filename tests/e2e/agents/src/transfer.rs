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
    match uploads::send(
        session,
        route,
        target,
        &mut plan,
        REQUESTED_TTL,
        &progress,
        &uploads::NoJournal,
    )
    .await
    {
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

fn digest_of_base64(encoded: &str) -> Option<String> {
    use base64::Engine as _;

    if encoded.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()
        .map(|bytes| hex_of(&kr_cbor::sha256(&bytes)))
}

/// The byte ranges of the objects of the JSON text `line`, each from its `{` to just past its `}`,
/// found by a scan that knows strings. An object that the line leaves open has none.
fn object_ranges(line: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (at, byte) in line.bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => open.push(at),
            b'}' => {
                if let Some(start) = open.pop() {
                    ranges.push((start, at + 1));
                }
            }
            _ => {}
        }
    }
    ranges
}

/// The digests of the images that the object `object` holds.
fn images_of(object: &str) -> Vec<Option<String>> {
    if object.contains("base64,") {
        return object
            .split("base64,")
            .skip(1)
            .map(|after| {
                let encoded: String = after
                    .chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
                    })
                    .collect();
                digest_of_base64(&encoded)
            })
            .collect();
    }
    let data = serde_json::from_str::<serde_json::Value>(object)
        .ok()
        .and_then(|value| value.get("data")?.as_str().map(str::to_owned));
    vec![data.and_then(|text| digest_of_base64(&text))]
}

/// The digests of the images a conversation's `text` records as given to the agent: for each mark
/// of the build list's `marker` in a line, the image of the object that holds the end of the mark.
/// An object that holds `base64,` gives each text after a `base64,` in it, decoded and hashed, as
/// Codex and OpenCode write an image. Any other object gives its own `data` member, as Claude Code
/// and Gemini CLI write an image. An object with no image text, or whose text is empty, unfinished
/// or cannot be decoded, gives `None`; text of another object, or of the line outside the object,
/// is no image text of it.
#[must_use]
pub fn images_recorded(text: &str, marker: &str) -> Vec<Option<String>> {
    let mut found = Vec::new();
    for line in text.lines().filter(|line| line.contains(marker)) {
        let objects = object_ranges(line);
        for (at, _) in line.match_indices(marker) {
            let last = at + marker.len().saturating_sub(1);
            let own = objects
                .iter()
                .filter(|(start, end)| *start <= last && last < *end)
                .max_by_key(|(start, _)| *start);
            match own {
                Some(&(start, end)) => found.extend(images_of(&line[start..end])),
                None => found.push(None),
            }
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

    /// The digests of the images a record holds in a data member are read after the mark, as Claude
    /// Code and Gemini CLI write them.
    #[test]
    fn the_images_a_record_holds_in_a_data_member_are_read_after_the_mark() {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let digest = |bytes: &[u8]| Some(hex_of(&kr_cbor::sha256(bytes)));
        let claude = format!(
            r#"{{"type":"user","message":{{"content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{}"}}}},{{"type":"text","text":"x"}}]}}}}"#,
            encode(b"first image")
        );
        assert_eq!(
            images_recorded(
                &format!("{claude}\n"),
                r#""type":"image","source":{"type":"base64""#
            ),
            vec![digest(b"first image")],
            "the digests of the images a record holds in a data member are read after the mark, as \
             Claude Code and Gemini CLI write them"
        );
        let gemini = format!(
            r#"{{"type":"user","content":[{{"inlineData":{{"data":"{}","mimeType":"image/png"}}}},{{"inlineData":{{"data":"{}","mimeType":"image/png"}}}}]}}"#,
            encode(b"first image"),
            encode(b"second image")
        );
        assert_eq!(
            images_recorded(&format!("{gemini}\n"), r#""inlineData":{"data":""#),
            vec![digest(b"first image"), digest(b"second image")],
            "a message that holds several images gives one digest for each"
        );
    }

    /// A mark with no image text after it gives `None`.
    #[test]
    fn a_mark_with_no_data_member_gives_none() {
        let line = r#"{"type":"user","message":{"content":[{"type":"image","source":{"type":"base64","media_type":"image/png"}}]}}"#;
        assert_eq!(
            images_recorded(
                &format!("{line}\n"),
                r#""type":"image","source":{"type":"base64""#
            ),
            vec![None],
            "a mark with no data member gives None"
        );
    }

    /// An image whose text cannot be decoded gives `None`.
    #[test]
    fn text_in_the_data_member_that_is_not_base64_gives_none() {
        let line = r#"{"type":"user","message":{"content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"not base64!"}}]}}"#;
        assert_eq!(
            images_recorded(
                &format!("{line}\n"),
                r#""type":"image","source":{"type":"base64""#
            ),
            vec![None],
            "text in the data member that is not base64 gives None"
        );
    }

    /// The mark of Claude Code's image.
    const CLAUDE_MARK: &str = r#""type":"image","source":{"type":"base64""#;

    /// An image is read in its own form, whatever text of the line looks like another form.
    #[test]
    fn an_image_is_read_in_its_own_form_whatever_text_of_the_line_looks_like_another_form() {
        let line = r#"{"type":"user","message":{"content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"Yg=="}},{"type":"text","text":"base64,YQ=="}]}}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), CLAUDE_MARK),
            vec![Some(hex_of(&kr_cbor::sha256(b"b")))],
            "the image's own data member is read, not the text after a `base64,` elsewhere in the line"
        );
    }

    /// A data member outside the marked image's own object is no text of that image.
    #[test]
    fn a_data_member_outside_the_marked_images_own_object_is_no_text_of_that_image() {
        let line = r#"{"type":"image","source":{"type":"base64"},"other":{"data":"YQ=="}}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), CLAUDE_MARK),
            vec![None],
            "a data member of another object gives None"
        );
    }

    /// A line that holds an image in a data member and an image in a data URL gives each its own
    /// digest.
    #[test]
    fn a_line_that_holds_both_forms_gives_each_image_its_own_digest() {
        let line = r#"{"parts":[{"mime":"image/png","data":"Yg=="},{"mime":"image/png","url":"data:image/png;base64,Yw=="}]}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), r#""mime":"image/png""#),
            vec![
                Some(hex_of(&kr_cbor::sha256(b"b"))),
                Some(hex_of(&kr_cbor::sha256(b"c")))
            ],
            "each image is read in its own form"
        );
    }

    /// An image with no text in its data member gives `None`.
    #[test]
    fn an_empty_data_member_gives_none() {
        let line = r#"{"content":[{"type":"image","source":{"type":"base64","data":""}}]}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), CLAUDE_MARK),
            vec![None],
            "an empty data member gives None"
        );
    }

    /// An image whose data member the line leaves unfinished gives `None`.
    #[test]
    fn an_unfinished_data_member_gives_none() {
        let line = r#"{"content":[{"type":"image","source":{"type":"base64","data":"YQ=="#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), CLAUDE_MARK),
            vec![None],
            "an unfinished data member gives None"
        );
    }

    /// An image with no text after the `base64,` of its data URL gives `None`.
    #[test]
    fn an_empty_data_url_gives_none() {
        let line = r#"{"type":"input_image","image_url":"data:image/png;base64,"}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), r#""type":"input_image""#),
            vec![None],
            "an empty data URL gives None"
        );
    }

    /// A marked object with no image text gives `None` and does not take the text of the next image.
    #[test]
    fn a_marked_object_with_no_image_text_does_not_take_the_text_of_the_next_image() {
        let line = r#"{"content":[{"type":"image","source":{"type":"base64"}},{"type":"image","source":{"type":"base64","data":"YQ=="}}]}"#;
        assert_eq!(
            images_recorded(&format!("{line}\n"), CLAUDE_MARK),
            vec![None, Some(hex_of(&kr_cbor::sha256(b"a")))],
            "the first image has no text, the second has"
        );
    }
}
