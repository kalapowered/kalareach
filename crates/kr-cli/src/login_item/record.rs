//! The record of the login item kr wrote, and what it names before a step makes a path.
//!
//! A record is refused, and left as it is with the file untouched, when it is not this build's:
//! a later version, a field it does not know, text that is not JSON, or a path that is not the
//! shape this login item writes, so a record cannot point a deletion at another file.

use std::path::{Path, PathBuf};

use kr_client::shown;
use kr_client::shown::Shown;
use serde::{Deserialize, Serialize};

use super::render::Kind;

/// The version of the record this build writes and reads.
pub(super) const VERSION: u32 = 1;

/// The largest record or file this build reads: far more than it ever writes.
pub(super) const READ_LIMIT: u64 = 64 * 1024;

/// What a step that is under way does to the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    /// A fresh file is published.
    Publish,
    /// A file kr wrote is replaced by new bytes.
    Replace,
    /// A file kr wrote is taken out.
    Remove,
}

impl Operation {
    /// The word a `--json` document says it with.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Replace => "replace",
            Self::Remove => "remove",
        }
    }
}

/// The paths a step can leave, named before the step that makes them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    /// What is under way.
    pub operation: Operation,
    /// A replacement only: the bytes it publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents: Option<String>,
    /// A replacement and a removal: where the file is moved aside for its check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aside: Option<PathBuf>,
    /// A publication and a replacement: the file the new bytes are staged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging: Option<PathBuf>,
}

kr_client::debug_fields!(Pending { operation });

/// The record of the login item.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    /// The version of this record.
    pub version: u32,
    /// The kind of file.
    pub kind: Kind,
    /// The label, which names the file.
    pub label: String,
    /// Where the file is.
    pub path: PathBuf,
    /// The bytes the file holds when nothing is under way; while a publication is under way, the
    /// bytes it will hold.
    pub contents: String,
    /// What is under way, or nothing.
    pub pending: Option<Pending>,
}

kr_client::debug_fields!(Record { version, kind });

impl Record {
    /// A record with nothing under way.
    pub(super) fn clean(kind: Kind, label: &str, path: &Path, contents: &str) -> Self {
        Self {
            version: VERSION,
            kind,
            label: label.to_owned(),
            path: path.to_owned(),
            contents: contents.to_owned(),
            pending: None,
        }
    }

    /// This record with `pending` under way.
    pub(super) fn with(&self, pending: Pending) -> Self {
        Self {
            pending: Some(pending),
            ..self.clone()
        }
    }

    /// The bytes the file holds when what is under way is done, where there is a new string.
    pub(super) fn new_bytes(&self) -> &str {
        match &self.pending {
            Some(Pending {
                operation: Operation::Replace,
                contents: Some(new),
                ..
            }) => new,
            _ => &self.contents,
        }
    }

    /// Whether `bytes` are one of the strings kr holds for the file.
    pub(super) fn vouches_for(&self, bytes: &[u8]) -> bool {
        bytes == self.contents.as_bytes() || bytes == self.new_bytes().as_bytes()
    }

    /// The record as the bytes of its file.
    pub(super) fn bytes(&self) -> Vec<u8> {
        // A record of strings and paths always encodes.
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }
}

/// Where an environment's record is.
pub(super) fn path(directory: &Path) -> PathBuf {
    directory.join(super::RECORD_FILE)
}

/// Whether `name` is `.<file name>.<uuid>.<extension>`, the name kr gives a path it leaves beside
/// the file.
fn named_beside(name: &str, file_name: &str, extension: &str) -> bool {
    let Some(rest) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_prefix(file_name))
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(extension))
        .and_then(|rest| rest.strip_suffix('.'))
    else {
        return false;
    };
    rest.parse::<kr_protocol::scalars::Uuid>().is_ok()
}

/// The name kr gives a path it leaves beside `file`, with a new identifier.
pub(super) fn beside(file: &Path, extension: &str) -> PathBuf {
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    file.with_file_name(format!(".{name}.{}.{extension}", kr_ipc::new_uuid()))
}

/// What is wrong with the shape of a record's fields, as the name of the field.
fn shape(record: &Record, kind: Kind, label: &str) -> Option<&'static str> {
    if record.kind != kind {
        return Some("kind");
    }
    if record.label != label {
        return Some("label");
    }
    let file_name = record.path.file_name().and_then(|name| name.to_str());
    let directory = record.path.parent();
    let own = file_name == Some(format!("{label}.{}", kind.extension()).as_str())
        && record.path.is_absolute()
        && directory
            .and_then(Path::file_name)
            .is_some_and(|name| name == kind.directory());
    if !own {
        return Some("path");
    }
    let file_name = file_name.unwrap_or_default();
    let beside_the_file = |path: &Path, extension: &str| {
        path.parent() == directory
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| named_beside(name, file_name, extension))
    };
    let Some(pending) = &record.pending else {
        return None;
    };
    let (wants_contents, wants_aside, wants_staging) = match pending.operation {
        Operation::Publish => (false, false, true),
        Operation::Replace => (true, true, true),
        Operation::Remove => (false, true, false),
    };
    if pending.contents.is_some() != wants_contents
        || pending.aside.is_some() != wants_aside
        || pending.staging.is_some() != wants_staging
    {
        return Some("pending");
    }
    if let Some(aside) = &pending.aside
        && !beside_the_file(aside, "kr-moving")
    {
        return Some("aside");
    }
    if let Some(staging) = &pending.staging
        && !beside_the_file(staging, "kr-staging")
    {
        return Some("staging");
    }
    None
}

/// Reads the record in `directory`: none when it has none, and what is wrong with it when it
/// cannot be used. `said` is the record as a sentence says it.
///
/// # Errors
///
/// Returns the reason when a record is there and is not one this build writes for `label`.
pub(super) fn read(
    directory: &Path,
    kind: Kind,
    label: &str,
    said: &Shown,
) -> Result<Option<Record>, Shown> {
    let bytes = match kr_ipc::paths::read_owner_only_file(&path(directory), READ_LIMIT) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(shown!(
                "the record {} cannot be used: it cannot be read: {}",
                *said,
                Shown::ipc(&error)
            ));
        }
    };
    let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
        shown!(
            "the record {} cannot be used: it is not one this build writes: {}",
            *said,
            Shown::json(&error)
        )
    })?;
    if record.version != VERSION {
        return Err(shown!(
            "the record {} cannot be used: it is at version {}, which this build does not read",
            *said,
            record.version
        ));
    }
    if let Some(field) = shape(&record, kind, label) {
        return Err(shown!(
            "the record {} cannot be used: its {} is not what this login item writes",
            *said,
            field
        ));
    }
    Ok(Some(record))
}
