//! The marker test: one marker, planted in each input this library takes, and no rendering that
//! holds it.
//!
//! The marker goes where input goes, found by walking the input rather than by naming its fields:
//! every text leaf of a valid value in turn (so the value stays valid and what a reader returns is
//! rendered), every map key (a member the reader does not know) and every other leaf (a value of
//! the wrong type, which a decoder's own message would quote). Bytes the encoder cannot write are
//! built by hand: a duplicate key, keys out of order, trailing bytes. Each planted input goes
//! through the real reader, and every rendering of what comes back is held to not carrying the
//! marker in any spelling: its text, its bytes as decimals, as hexadecimal, or in base64.
//!
//! The neutral control plants a value that is not the marker the same way, and holds the
//! rendering of the failure to naming its class and its place, so that a rendering which said
//! nothing at all would not pass as one that said nothing it should not.

use std::fmt;

use base64::Engine as _;
use kr_cbor::{CanonicalMap, CanonicalValue};

/// Stands for everything a diagnostic must not show.
pub(crate) const MARKER: &str = "kr-marker-7c1e";

/// A value planted the same way that is not the marker, for the neutral control.
pub(crate) const NEUTRAL: &str = "neutral-value";

/// Every spelling of the marker a rendering could carry it in.
fn spellings() -> Vec<String> {
    let bytes = MARKER.as_bytes();
    let decimal = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // A base64 spelling depends on where the text starts inside a longer run of bytes, so every
    // alignment is looked for, without the characters the edges share with their neighbours.
    let mut spellings = vec![MARKER.to_owned(), decimal, hex];
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        for lead in 0..3 {
            let mut padded = vec![0_u8; lead];
            padded.extend_from_slice(bytes);
            let encoded = engine.encode(&padded);
            // The first four characters hold the leading bytes and the last three may hold what
            // follows; what is between is the marker's own in every alignment.
            let inner = &encoded[4..encoded.len() - 3];
            spellings.push(inner.to_owned());
        }
    }
    spellings
}

/// The marker as each kind of input could carry it: as text, and its bytes as decimal numbers, as
/// hexadecimal digits, as base64 and as base64url.
pub(crate) fn planted_spellings() -> [String; 5] {
    let bytes = MARKER.as_bytes();
    [
        MARKER.to_owned(),
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        base64::engine::general_purpose::STANDARD.encode(bytes),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    ]
}

/// Holds every rendering to carrying no spelling of the marker.
///
/// Each rendering is looked at as it is and with its whitespace taken out, because the indented
/// `Debug` form writes a byte list one number to a line.
pub(crate) fn assert_unmarked(label: &str, renderings: &[String]) {
    let spellings = spellings();
    for rendering in renderings {
        let condensed = rendering.split_whitespace().collect::<String>();
        for spelling in &spellings {
            let spelling_condensed = spelling.split_whitespace().collect::<String>();
            assert!(
                !rendering.contains(spelling.as_str())
                    && !condensed.contains(spelling_condensed.as_str()),
                "{label}: a rendering carries the marker ({spelling}): {rendering}"
            );
        }
    }
}

/// Every way a failure renders: `Display`, both `Debug` forms, each of its sources, and the panic
/// an `expect` on it raises.
pub(crate) fn failure_renderings<E>(error: E) -> Vec<String>
where
    E: std::error::Error + Send + 'static,
{
    let mut renderings = vec![
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
    ];
    let mut source = error.source();
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    renderings.push(panic_message(move || {
        // Through `black_box`, so what runs is `expect` on a result as a caller holds one.
        let failed: std::result::Result<(), E> = std::hint::black_box(Err(error));
        failed.expect("the reader refused");
    }));
    renderings
}

/// Both `Debug` forms of a value.
pub(crate) fn debug_renderings(value: &impl fmt::Debug) -> Vec<String> {
    vec![format!("{value:?}"), format!("{value:#?}")]
}

/// What a panic says, taken from the panic itself rather than from a hook.
pub(crate) fn panic_message(work: impl FnOnce() + Send + 'static) -> String {
    let caught =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).expect_err("the work panics");
    caught
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| caught.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default()
}

/// One input with the marker, or the neutral value, planted in one place.
pub(crate) struct Planted<T> {
    /// Where it was planted.
    pub(crate) at: String,
    /// The input.
    pub(crate) input: T,
}

/// Every planting of `planted` in a KR-CBOR-1 value: each text leaf, each map key and each other
/// leaf in turn, then the bytes no encoder writes.
pub(crate) fn cbor_plantings(value: &CanonicalValue, planted: &str) -> Vec<Planted<Vec<u8>>> {
    let mut paths = Vec::new();
    leaves(value, &mut Vec::new(), &mut paths);
    let mut plantings = Vec::new();
    for (path, kind) in paths {
        plantings.push(Planted {
            at: format!("{kind:?} at /{}", path.join("/")),
            input: kr_cbor::encode(&planted_copy(value, &path, kind, planted)),
        });
    }
    plantings.extend(malformed(value, planted));
    plantings
}

/// What kind of place one planting is.
#[derive(Clone, Copy, Debug)]
enum Place {
    /// A text leaf: the marker replaces the text, and the value stays its shape.
    Text,
    /// A map key: the member is renamed to the marker.
    Key,
    /// Any other leaf: the marker replaces it as text, which is the wrong type there.
    Other,
}

fn leaves(value: &CanonicalValue, path: &mut Vec<String>, found: &mut Vec<(Vec<String>, Place)>) {
    match value {
        CanonicalValue::Text(_) => found.push((path.clone(), Place::Text)),
        CanonicalValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                leaves(item, path, found);
                path.pop();
            }
        }
        CanonicalValue::Map(map) => {
            for (key, member) in map.entries() {
                path.push(key.clone());
                found.push((path.clone(), Place::Key));
                leaves(member, path, found);
                path.pop();
            }
        }
        CanonicalValue::Null
        | CanonicalValue::Bool(_)
        | CanonicalValue::Integer(_)
        | CanonicalValue::Bytes(_) => found.push((path.clone(), Place::Other)),
    }
}

/// A copy of `value` with the marker planted at one place.
///
/// A canonical map is changed by building it again, so each map on the way down is rebuilt around
/// the member the path goes into.
fn planted_copy(
    value: &CanonicalValue,
    path: &[String],
    place: Place,
    planted: &str,
) -> CanonicalValue {
    let Some((step, rest)) = path.split_first() else {
        return CanonicalValue::text(planted);
    };
    match value {
        CanonicalValue::Array(items) => {
            let index = step.parse::<usize>().expect("an index");
            let mut items = items.clone();
            items[index] = planted_copy(&items[index], rest, place, planted);
            CanonicalValue::Array(items)
        }
        CanonicalValue::Map(map) => {
            let mut entries = map.entries().to_vec();
            let position = entries
                .iter()
                .position(|(key, _)| key == step)
                .expect("a member");
            if rest.is_empty() && matches!(place, Place::Key) {
                let (_, member) = entries.remove(position);
                entries.push((planted.to_owned(), member));
                // A planted name that is a member already leaves nothing new to plant here.
                return CanonicalMap::from_entries(entries)
                    .map_or_else(|_| value.clone(), CanonicalValue::Map);
            }
            entries[position].1 = planted_copy(&entries[position].1, rest, place, planted);
            CanonicalValue::Map(CanonicalMap::from_entries(entries).expect("the same keys"))
        }
        _ => unreachable!("a path only goes through arrays and maps"),
    }
}

/// The bytes no encoder writes, each with the planted text in the part a decoder quotes.
fn malformed(value: &CanonicalValue, planted: &str) -> Vec<Planted<Vec<u8>>> {
    let text = |content: &str| kr_cbor::encode(&CanonicalValue::text(content));
    let mut duplicate = vec![0xa2];
    duplicate.extend(text(planted));
    duplicate.push(0x00);
    duplicate.extend(text(planted));
    duplicate.push(0x00);
    // A longer key before a shorter one is out of canonical order.
    let mut unsorted = vec![0xa2];
    unsorted.extend(text(&format!("{planted}{planted}")));
    unsorted.push(0x00);
    unsorted.extend(text(planted));
    unsorted.push(0x00);
    let mut trailing = kr_cbor::encode(value);
    trailing.extend(text(planted));
    let mut truncated = kr_cbor::encode(value);
    truncated.extend(text(planted));
    truncated.truncate(truncated.len() - 1);
    vec![
        Planted {
            at: "a duplicate key".to_owned(),
            input: duplicate,
        },
        Planted {
            at: "keys out of order".to_owned(),
            input: unsorted,
        },
        Planted {
            at: "bytes after the value".to_owned(),
            input: trailing,
        },
        Planted {
            at: "a value cut short".to_owned(),
            input: truncated,
        },
    ]
}

/// Every planting of `planted` in a JSON value: each string leaf, each member name and each other
/// leaf in turn.
pub(crate) fn json_plantings(
    value: &serde_json::Value,
    planted: &str,
) -> Vec<Planted<serde_json::Value>> {
    let mut paths = Vec::new();
    json_leaves(value, &mut Vec::new(), &mut paths);
    paths
        .into_iter()
        .map(|(path, place)| {
            let mut attempt = value.clone();
            json_plant(&mut attempt, &path, place, planted);
            Planted {
                at: format!("{place:?} at /{}", path.join("/")),
                input: attempt,
            }
        })
        .collect()
}

fn json_leaves(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    found: &mut Vec<(Vec<String>, Place)>,
) {
    match value {
        serde_json::Value::String(_) => found.push((path.clone(), Place::Text)),
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                json_leaves(item, path, found);
                path.pop();
            }
        }
        serde_json::Value::Object(members) => {
            for (name, member) in members {
                path.push(name.clone());
                found.push((path.clone(), Place::Key));
                json_leaves(member, path, found);
                path.pop();
            }
        }
        _ => found.push((path.clone(), Place::Other)),
    }
}

fn json_plant(value: &mut serde_json::Value, path: &[String], place: Place, planted: &str) {
    let Some((last, parents)) = path.split_last() else {
        *value = serde_json::Value::String(planted.to_owned());
        return;
    };
    let mut cursor = value;
    for step in parents {
        cursor = match cursor {
            serde_json::Value::Array(items) => &mut items[step.parse::<usize>().expect("an index")],
            serde_json::Value::Object(members) => members.get_mut(step).expect("a member"),
            _ => unreachable!("a path only goes through arrays and objects"),
        };
    }
    match (cursor, place) {
        (serde_json::Value::Object(members), Place::Key) => {
            let member = members.remove(last).expect("the member");
            members.insert(planted.to_owned(), member);
        }
        (serde_json::Value::Object(members), _) => {
            members.insert(last.clone(), serde_json::Value::String(planted.to_owned()));
        }
        (serde_json::Value::Array(items), _) => {
            items[last.parse::<usize>().expect("an index")] =
                serde_json::Value::String(planted.to_owned());
        }
        _ => unreachable!("a leaf is in an array or an object"),
    }
}

/* -------------------------------------------------------------------------- */
/* The cases                                                                    */
/* -------------------------------------------------------------------------- */

mod cases {
    use std::path::Path;
    use std::sync::Arc;

    use kr_cbor::CborError;
    use kr_protocol::ids::{DeviceId, DraftId, QuestionId, SessionId, SyncObjectId};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    use super::*;
    use crate::error::ClientError;
    use crate::shown::{IoFault, Shown};

    fn temporary() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("kr-marker-")
            .tempdir_in(std::env::temp_dir())
            .expect("a directory on the internal disk")
    }

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    /// Every failure a decoder can raise, with the marker where the decoder puts what it read.
    fn cbor_failures(planted: &str) -> Vec<CborError> {
        vec![
            CborError::DuplicateKey {
                key: planted.to_owned(),
            },
            CborError::UnsortedMapKeys {
                previous: planted.to_owned(),
                current: planted.to_owned(),
            },
            CborError::UnknownField {
                at: format!("Draft at /{planted}"),
                field: planted.to_owned(),
            },
            CborError::UnknownVariant {
                at: planted.to_owned(),
                tag: planted.to_owned(),
                variant: planted.to_owned(),
            },
            CborError::UnnegotiatedExtension {
                at: planted.to_owned(),
                extension: planted.to_owned(),
            },
            CborError::Deserialize {
                message: format!("invalid type: string \"{planted}\", expected u64"),
            },
            CborError::Serialize {
                message: planted.to_owned(),
            },
        ]
    }

    /// The failures of another crate a client failure holds, each carrying the marker wherever that
    /// crate puts text it did not write.
    fn held_failures(planted: &str) -> Vec<ClientError> {
        let io = || std::io::Error::other(planted.to_owned());
        let mut failures = Vec::new();
        for cbor in cbor_failures(planted) {
            failures.push(ClientError::from(cbor.clone()));
            failures.push(ClientError::Ipc(kr_ipc::IpcError::Frame(
                kr_protocol::frame::FrameError::Cbor(cbor.clone()),
            )));
            failures.push(ClientError::Transport(kr_transport::TransportError::Cbor(
                cbor.clone(),
            )));
            failures.push(ClientError::Transport(
                kr_transport::TransportError::Crypto(kr_crypto::CryptoError::Encoding(cbor)),
            ));
        }
        failures.extend([
            ClientError::Ipc(kr_ipc::IpcError::Io {
                operation: "read",
                path: std::path::PathBuf::from("/runtime"),
                source: io(),
            }),
            ClientError::Ipc(kr_ipc::IpcError::Socket {
                operation: "connect",
                source: io(),
            }),
            ClientError::Ipc(kr_ipc::IpcError::PeerUnknown { source: io() }),
            ClientError::Ipc(kr_ipc::IpcError::VersionMismatch {
                host: "1".to_owned(),
                offered: planted.to_owned(),
            }),
            ClientError::Ipc(kr_ipc::IpcError::EnvironmentPrefixCollision {
                path: std::path::PathBuf::from("/runtime"),
                holder: planted.to_owned(),
                requested: planted.to_owned(),
            }),
            ClientError::Ipc(kr_ipc::IpcError::DirectoryAccessRefused {
                path: std::path::PathBuf::from("/runtime"),
                detail: planted.to_owned(),
            }),
            ClientError::Ipc(kr_ipc::IpcError::IdentityUnavailable {
                what: "the boot identity",
                detail: planted.to_owned(),
            }),
            ClientError::Transport(kr_transport::TransportError::Configuration {
                what: planted.to_owned(),
                kind: "relay",
                reason: planted.to_owned(),
            }),
            ClientError::Transport(kr_transport::TransportError::Bind(planted.to_owned())),
            ClientError::Transport(kr_transport::TransportError::Connect(planted.to_owned())),
            ClientError::Transport(kr_transport::TransportError::Stream(planted.to_owned())),
            ClientError::Transport(kr_transport::TransportError::Closed(planted.to_owned())),
            ClientError::Transport(kr_transport::TransportError::Crypto(
                kr_crypto::CryptoError::SecretStore {
                    message: planted.to_owned(),
                },
            )),
            ClientError::Transport(kr_transport::TransportError::Crypto(
                kr_crypto::CryptoError::StoredSecretLength {
                    name: planted.to_owned(),
                    expected: 32,
                    actual: 3,
                },
            )),
        ]);
        failures
    }

    /// KR-REQ-20.02 and section 23's redacted diagnostics: no failure this library holds says what a
    /// decoder read, what a peer or a platform wrote, or a payload a reader put in an I/O failure;
    /// and each still names its class and its place.
    #[test]
    fn no_failure_says_what_a_decoder_read_or_a_peer_wrote() {
        for failure in held_failures(MARKER) {
            let label = format!("{failure:?}");
            assert_unmarked(&label, &failure_renderings(failure));
        }
        for cbor in cbor_failures(MARKER) {
            assert_unmarked(
                "a sync store failure",
                &failure_renderings(crate::sync::SyncError::from(cbor.clone())),
            );
            assert_unmarked(
                "a recovery failure",
                &failure_renderings(crate::recovery::RecoveryError::from(cbor.clone())),
            );
            assert_unmarked(
                "a membership failure",
                &failure_renderings(crate::sync::membership::MembershipError::from(cbor.clone())),
            );
            assert_unmarked(
                "a crypto failure in the sync store",
                &failure_renderings(crate::sync::SyncError::from(
                    kr_crypto::CryptoError::Encoding(cbor),
                )),
            );
        }
        let fault = IoFault::from(std::io::Error::other(MARKER));
        assert_unmarked("an I/O fault", &debug_renderings(&fault));
        assert_unmarked("an I/O fault", &[fault.to_string()]);

        // The neutral control: the same failures still name the class and, where there is one, the
        // place.
        for (cbor, expected) in [
            (
                CborError::DuplicateKey {
                    key: NEUTRAL.to_owned(),
                },
                "duplicate_key",
            ),
            (
                CborError::UnexpectedEnd { offset: 12 },
                "unexpected_end at byte 12",
            ),
            (
                CborError::Deserialize {
                    message: NEUTRAL.to_owned(),
                },
                "deserialize",
            ),
        ] {
            let said = ClientError::from(cbor).to_string();
            assert!(said.contains(expected), "{said}");
            assert!(!said.contains(NEUTRAL), "{said}");
        }
        // A local connection's failure names the file by the names the host's tree writes, and
        // replaces a name a listing could have found, with the platform's own separator
        // throughout. The file is in this machine's temporary directory, a real place on every
        // platform, whatever that directory is rendered as.
        let separator = std::path::MAIN_SEPARATOR;
        let said = ClientError::Ipc(kr_ipc::IpcError::Io {
            operation: "read",
            path: std::env::temp_dir()
                .join(NEUTRAL)
                .join("sessions")
                .join("0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr"),
            source: std::io::Error::from_raw_os_error(2),
        })
        .to_string();
        assert!(said.starts_with("read "), "{said}");
        assert!(
            said.contains(&format!(
                "{separator}[a name]{separator}sessions{separator}\
                 0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr: "
            )),
            "{said}"
        );
        assert!(!said.contains(NEUTRAL), "{said}");
        assert!(said.ends_with("(os error 2)"), "{said}");
    }

    fn draft_target() -> crate::drafts::DraftTarget {
        crate::drafts::DraftTarget {
            session_id: SessionId::new(uuid(3)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A stored draft that cannot be read says the class and the place of the fault and nothing it
    /// held, and one that can be read renders none of its text: the draft store's file, planted
    /// everywhere.
    #[test]
    fn a_stored_draft_says_nothing_of_what_it_holds() {
        let directory = temporary();
        let store = crate::drafts::DraftStore::open(directory.path(), DeviceId::new(uuid(1)))
            .expect("a draft store");
        let draft = store
            .create(draft_target(), MARKER.to_owned(), TimestampMs::new(1_000))
            .expect("a draft");
        assert_unmarked("a draft", &debug_renderings(&draft));
        let record = crate::drafts::DraftStore::encode_record(&draft).expect("a record");
        let value = kr_cbor::decode(&record, &kr_cbor::Limits::DEFAULT).expect("a value");
        let path = directory.path().join(format!("{}.draft", draft.draft_id));
        let (mut accepted, mut refused) = (0, 0);
        for planted in cbor_plantings(&value, MARKER) {
            std::fs::write(&path, &planted.input).expect("written");
            match store.load(draft.draft_id) {
                Ok(read) => {
                    accepted += 1;
                    assert_unmarked(&planted.at, &debug_renderings(&read));
                }
                Err(error) => {
                    refused += 1;
                    assert_unmarked(&planted.at, &failure_renderings(error));
                }
            }
            // What a service carried is read by the same decoder under a smaller bound.
            match crate::drafts::DraftStore::decode_payload(&planted.input) {
                Ok(read) => assert_unmarked(&planted.at, &debug_renderings(&read)),
                Err(error) => assert_unmarked(&planted.at, &failure_renderings(error)),
            }
        }
        assert!(
            accepted > 0 && refused > 0,
            "{accepted} read, {refused} refused"
        );

        // The neutral control: a refused record says which file and what kind of fault.
        for planted in cbor_plantings(&value, NEUTRAL) {
            std::fs::write(&path, &planted.input).expect("written");
            if let Err(error) = store.load(draft.draft_id) {
                let said = error.to_string();
                assert!(said.contains("could not be read"), "{}: {said}", planted.at);
                assert!(
                    said.contains(&format!("{}.draft", draft.draft_id)),
                    "{}: {said}",
                    planted.at
                );
            }
        }
    }

    fn answer_draft(text: &str) -> crate::answers::AnswerDraft {
        crate::answers::AnswerDraft {
            target: kr_protocol::envelope::ActionTarget {
                environment_id: kr_protocol::ids::EnvironmentId::new(uuid(2)),
                session_id: Nullable::some(SessionId::new(uuid(3))),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            session_id: SessionId::new(uuid(3)),
            question_id: QuestionId::new(uuid(4)),
            question_revision: kr_protocol::ids::QuestionRevision::new(1),
            answer: kr_protocol::question::QuestionAnswer::Input {
                text: text.to_owned(),
            },
            drafted_at_ms: TimestampMs::new(1_000),
        }
    }

    /// A kept answer that cannot be read says the class and the place of the fault and nothing it
    /// held; one that can renders none of its answer; and a file the store did not name is not
    /// named either.
    #[test]
    fn a_kept_answer_says_nothing_of_what_it_holds_or_of_a_name_the_store_did_not_write() {
        let directory = temporary();
        let drafts =
            crate::answers::AnswerDrafts::open(directory.path().join("answers")).expect("a store");
        let kept = answer_draft(MARKER);
        drafts.keep(&kept).expect("kept");
        for read in drafts.drafts().expect("the kept answers") {
            assert_unmarked("a kept answer", &debug_renderings(&read));
        }
        let path = directory
            .path()
            .join("answers")
            .join(format!("{}.answer", kept.question_id));
        let record = kr_cbor::to_canonical_vec(&kept).expect("a record");
        let value = kr_cbor::decode(&record, &kr_cbor::Limits::DEFAULT).expect("a value");
        for planted in cbor_plantings(&value, MARKER) {
            std::fs::write(&path, &planted.input).expect("written");
            match drafts.drafts() {
                Ok(read) => assert_unmarked(&planted.at, &debug_renderings(&read)),
                Err(error) => assert_unmarked(&planted.at, &failure_renderings(error)),
            }
        }
        // A file by a name the store never writes is found by the listing, and its name is not
        // repeated when it cannot be read.
        std::fs::remove_file(&path).expect("removed");
        std::fs::write(
            directory
                .path()
                .join("answers")
                .join(format!("{MARKER}.answer")),
            b"not a record",
        )
        .expect("written");
        let refused = drafts.drafts().expect_err("an unreadable answer");
        let said = refused.to_string();
        assert!(said.contains("[a name this store did not write]"), "{said}");
        assert_unmarked(
            "a file the store did not name",
            &failure_renderings(refused),
        );
    }

    /// A stored settings object that cannot be read says the class and the place of the fault and
    /// nothing it held, and one that can renders none of its settings.
    #[test]
    fn a_stored_settings_object_says_nothing_of_what_it_holds() {
        let directory = temporary();
        let store = crate::sync::SyncStore::open(directory.path().join("sync")).expect("a store");
        let object_id = SyncObjectId::new(uuid(5));
        let object = crate::sync::SyncObject {
            object_id,
            revision: crate::sync::fresh_revision().expect("a revision"),
            device_id: DeviceId::new(uuid(1)),
            updated_at_ms: TimestampMs::new(1_000),
            body: crate::sync::SyncBody::Settings(crate::sync::SyncSettings {
                values: [(
                    MARKER.to_owned(),
                    crate::sync::SettingValue::Text(MARKER.to_owned()),
                )]
                .into_iter()
                .collect(),
                pinned_labels: [MARKER.to_owned()].into_iter().collect(),
            }),
        };
        assert_unmarked("a settings object", &debug_renderings(&object));
        store.put_object(&object).expect("stored");
        let path = directory
            .path()
            .join("sync")
            .join(format!("{}.object", object_id.get()));
        let value = kr_cbor::decode(
            &std::fs::read(&path).expect("the stored object"),
            &kr_cbor::Limits::DEFAULT,
        )
        .expect("a value");
        for planted in cbor_plantings(&value, MARKER) {
            std::fs::write(&path, &planted.input).expect("written");
            match store.object(object_id) {
                Ok(read) => assert_unmarked(&planted.at, &debug_renderings(&read)),
                Err(error) => assert_unmarked(&planted.at, &failure_renderings(error)),
            }
        }

        // The neutral control: a refused object says which file and the rule its bytes broke,
        // and nothing it held.
        let mut refused = 0;
        for planted in cbor_plantings(&value, NEUTRAL) {
            std::fs::write(&path, &planted.input).expect("written");
            if let Err(error) = store.object(object_id) {
                refused += 1;
                let said = error.to_string();
                assert!(
                    said.contains(&format!("{}.object could not be read", object_id.get())),
                    "{}: {said}",
                    planted.at
                );
                assert!(!said.contains(NEUTRAL), "{}: {said}", planted.at);
                // The reason is the rule the store's own decoder reports for these bytes.
                match kr_cbor::from_canonical_slice::<crate::sync::SyncObject>(
                    &planted.input,
                    &kr_cbor::Limits::DEFAULT,
                ) {
                    Err(broken) => assert!(
                        said.ends_with(&Shown::cbor(&broken).into_string()),
                        "{}: {said}",
                        planted.at
                    ),
                    Ok(_) => assert!(said.contains("it holds object"), "{}: {said}", planted.at),
                }
            }
        }
        assert!(refused > 0, "the neutral plantings are refused too");
    }

    /// What a service serves as a sealed object is read without a word of it reaching a failure.
    #[test]
    fn a_sealed_object_a_service_served_says_nothing_of_itself() {
        use crate::drafts::DraftSealer as _;

        const COLLECTION: &str = "0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
        let keys = Arc::new(crate::sync::MemoryCollectionKeys::new());
        keys.draw(COLLECTION, 1).expect("a key");
        let sealer = crate::sync::CollectionSealer::new(
            Arc::clone(&keys) as Arc<dyn crate::sync::CollectionKeys>,
            COLLECTION,
            1,
        );
        let sealed = sealer.seal(MARKER.as_bytes()).expect("sealed");
        let value = kr_cbor::decode(&sealed, &kr_cbor::Limits::DEFAULT).expect("a value");
        for planted in cbor_plantings(&value, MARKER) {
            if let Err(error) = sealer.open(&planted.input) {
                assert_unmarked(&planted.at, &failure_renderings(error));
            }
        }
    }

    /// An account token document names its origin by scheme, host and port and its scopes by the
    /// names this build knows, whatever the file holds, and a document that cannot be read says
    /// where and nothing of what.
    #[test]
    fn an_account_token_names_its_origin_and_scopes_and_nothing_else() {
        use crate::services::voice::{AccountTokenFile, StoredAccountToken};

        let document = serde_json::json!({
            "origin": "https://reach.example",
            "accessToken": "a-value-that-is-never-shown",
            "scopes": ["voice", "billing.read"],
            "expiresAtMs": 1_700_000_000_000_u64,
        });
        for planted in json_plantings(&document, MARKER) {
            let bytes = serde_json::to_vec(&planted.input).expect("a document");
            match StoredAccountToken::read(&bytes) {
                Ok(stored) => {
                    assert_unmarked(&planted.at, &debug_renderings(&stored));
                    assert_unmarked(&planted.at, &[stored.description().into_string()]);
                }
                Err(error) => assert_unmarked(&planted.at, &failure_renderings(error)),
            }
        }
        for origin in [
            format!("https://{MARKER}:{MARKER}@reach.example"),
            format!("https://{MARKER}@reach.example"),
            format!("https://reach.example/{MARKER}"),
            format!("https://reach.example?{MARKER}"),
            format!("https://reach.example#{MARKER}"),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "origin": origin,
                "accessToken": MARKER,
                "scopes": [MARKER, "voice"],
            }))
            .expect("a document");
            match StoredAccountToken::read(&bytes) {
                Ok(stored) => {
                    assert_unmarked(&origin, &debug_renderings(&stored));
                    let described = stored.description().into_string();
                    assert_unmarked(&origin, std::slice::from_ref(&described));
                    assert!(
                        described.contains("voice and 1 scope(s) this build does not know"),
                        "{described}"
                    );
                }
                Err(error) => assert_unmarked(&origin, &failure_renderings(error)),
            }
            let file = AccountTokenFile::at(std::path::PathBuf::from("/runtime/token.json"))
                .for_origin(origin.clone());
            assert_unmarked(&origin, &debug_renderings(&file));
        }
        let broken = StoredAccountToken::read(format!("{{\"origin\": {MARKER}").as_bytes())
            .expect_err("not a document");
        let said = broken.to_string();
        assert!(said.contains("line 1"), "{said}");
        assert_unmarked("a broken document", &failure_renderings(broken));
    }

    /// A stored sign-in names none of what it holds, whatever the file says: every text leaf, key and
    /// other leaf of the document planted in turn and read through the store's own reader.
    #[test]
    fn a_stored_grant_says_nothing_of_what_it_holds() {
        use crate::services::account::{Client, ISSUER, StoredGrant};

        let document = |planted: &str| {
            serde_json::json!({
                "grantId": planted,
                "revision": 3,
                "issuer": ISSUER,
                "clientId": Client::Desktop.id(),
                "subject": planted,
                "email": planted,
                "name": planted,
                "nonce": planted,
                "refreshToken": planted,
                "accessToken": planted,
                "accessExpiresAtMs": 1_700_000_000_000_u64,
                "scopes": [planted, "voice"],
            })
        };
        // The negative control: the document as written reads, and holds the marker in every
        // text field, the grant's identifier among them.
        let whole = serde_json::to_vec(&document(MARKER)).expect("a document");
        let grant = StoredGrant::read(&whole).expect("the document reads");
        assert_eq!(grant.grant_id(), MARKER);
        assert_unmarked("a stored grant", &debug_renderings(&grant));
        let (mut read, mut refused) = (0, 0);
        for planted in json_plantings(&document("a-stored-value"), MARKER) {
            let bytes = serde_json::to_vec(&planted.input).expect("a document");
            match StoredGrant::read(&bytes) {
                Ok(grant) => {
                    read += 1;
                    assert_unmarked(&planted.at, &debug_renderings(&grant));
                }
                Err(error) => {
                    refused += 1;
                    assert_unmarked(&planted.at, &failure_renderings(error));
                }
            }
        }
        assert!(read > 0 && refused > 0, "{read} read, {refused} refused");
        // The neutral control: a document that is not one says the class of the fault and where
        // it is, and nothing it held.
        let said = StoredGrant::read(format!("{{\"grantId\": {NEUTRAL}").as_bytes())
            .expect_err("not a document")
            .to_string();
        assert!(
            said.starts_with("STORAGE_UNAVAILABLE: the stored sign-in could not be read: "),
            "{said}"
        );
        assert!(said.contains("line 1"), "{said}");
        assert!(!said.contains(NEUTRAL), "{said}");
    }

    /// Each type that holds a document, an origin, a locator or bytes renders what it is and none
    /// of what it holds, exactly.
    #[test]
    fn each_type_holding_a_document_an_origin_or_bytes_renders_only_what_it_is() {
        use crate::services::rendering::renders_only;

        let draft = crate::drafts::Draft {
            draft_id: DraftId::new(uuid(6)),
            revision: kr_protocol::ids::DraftRevision::new(2),
            device_id: DeviceId::new(uuid(1)),
            target: draft_target(),
            state: kr_protocol::transfer::DraftState::Open,
            text: MARKER.to_owned(),
            attachments: Vec::new(),
            conflict_of: Nullable::null(),
            retained: Nullable::null(),
            created_at_ms: TimestampMs::new(1),
            updated_at_ms: TimestampMs::new(2),
        };
        assert_unmarked("a draft", &debug_renderings(&draft));
        assert!(format!("{draft:?}").contains("text_bytes: 14"), "{draft:?}");

        let kept = answer_draft(MARKER);
        assert_unmarked("a kept answer", &debug_renderings(&kept));
        assert_unmarked(
            "an answer kept",
            &debug_renderings(&crate::answers::Answered::Kept(kept)),
        );

        let label = crate::sync::PinnedLabel {
            label: MARKER.to_owned(),
            pinned_at_ms: TimestampMs::new(3),
        };
        renders_only(
            &label,
            "PinnedLabel{label_bytes:14,pinned_at_ms:TimestampMs(U64(3))}",
        );

        for value in [
            crate::sync::SettingValue::Text(MARKER.to_owned()),
            crate::sync::SettingValue::Number(kr_protocol::scalars::U64::new(4)),
            crate::sync::SettingValue::Flag(true),
        ] {
            assert_unmarked("a setting", &debug_renderings(&value));
        }
        renders_only(
            &crate::sync::SettingValue::Text(MARKER.to_owned()),
            "Text{bytes:14}",
        );

        let delivery = crate::viewport::Delivery::Bytes {
            cursor: 9,
            bytes: MARKER.as_bytes().to_vec(),
        };
        renders_only(&delivery, "Bytes{cursor:9,bytes:14}");

        #[cfg(feature = "terminal")]
        let painted = crate::projection::paint::Painted {
            bytes: MARKER.as_bytes().to_vec(),
            comparison: crate::projection::paint::Comparison::default(),
        };
        #[cfg(feature = "terminal")]
        assert_unmarked("painted bytes", &debug_renderings(&painted));

        let subject = crate::uploads::Subject {
            environment_id: kr_protocol::ids::EnvironmentId::new(uuid(2)),
            session_id: None,
            device_id: None,
            declared_media_type: MARKER.to_owned(),
            original_file_name: MARKER.to_owned(),
        };
        assert_unmarked("an upload's subject", &debug_renderings(&subject));

        let key = crate::encoder::Key::Char('k');
        renders_only(&key, "Char(..)");

        let access = crate::recovery::ServiceAccess::new(
            crate::recovery::RetrievalPolicy::Account,
            format!("https://{MARKER}:{MARKER}@reach.example/{MARKER}"),
            std::sync::Arc::new(crate::services::NullService),
        );
        assert_unmarked("service access", &debug_renderings(&access));

        let context = kr_protocol::archive::RecoveryContext {
            service_origin: format!("https://{MARKER}@reach.example"),
            bundle_locator: MARKER.to_owned(),
        };
        let record = crate::recovery::MigrationRecord {
            from: context.clone(),
            to: context,
            bundle_revision: 1,
            bundle_position: crate::services::SyncPosition::at(
                1,
                crate::services::SyncRevision::new(uuid(7)),
                None,
            ),
            verified_at_ms: TimestampMs::new(5),
        };
        assert_unmarked("a migration record", &debug_renderings(&record));
        assert_unmarked("a migration record", &[record.describe().into_string()]);

        // The rest of the named renderings, each exactly.
        renders_only(
            &draft,
            "Draft{draft_id:DraftId(Uuid(06060606-0606-0606-0606-060606060606)),\
             revision:DraftRevision(U64(2)),device_id:DeviceId(Uuid(\
             01010101-0101-0101-0101-010101010101)),target:DraftTarget{session_id:SessionId(\
             Uuid(03030303-0303-0303-0303-030303030303)),application_instance_id:Nullable(None),\
             agent_binding_revision:Nullable(None)},state:Open,text_bytes:14,attachments:0,\
             conflict_of:Nullable(None),retained:Nullable(None),created_at_ms:TimestampMs(U64(1)),\
             updated_at_ms:TimestampMs(U64(2))}",
        );
        renders_only(
            &subject,
            "Subject{environment_id:EnvironmentId(Uuid(02020202-0202-0202-0202-020202020202)),\
             session_id:None,device_id:None,declared_media_type_bytes:14,\
             original_file_name_bytes:14}",
        );
        renders_only(
            &access,
            "ServiceAccess{policy:Account,service_origin:\"<notprinted>\",..}",
        );
        #[cfg(feature = "terminal")]
        renders_only(
            &painted,
            "Painted{bytes:14,comparison:Comparison{runs_replaced:0,cells_clipped:0,\
             rows_clipped:0,clusters_replaced:0,pending_wrap:false,cursor_outside:false,\
             soft_wraps:0,truncated_rows:0,rows_outside:0,cells_outside:0,keyboard_withheld:false,\
             keyboard_stack:0,controls_dropped:0,rows_unreachable:0,geometry_withheld:false}}",
        );
        let question = kr_protocol::question::Question {
            question_id: kr_protocol::ids::QuestionId::new(uuid(8)),
            revision: kr_protocol::ids::QuestionRevision::new(1),
            state: kr_protocol::question::QuestionState::Pending,
            session_id: SessionId::new(uuid(3)),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            kind: kr_protocol::question::QuestionKind::Confirm,
            context: MARKER.to_owned(),
            question: MARKER.to_owned(),
            choices: vec![kr_protocol::question::QuestionChoice::something_else()],
            source: kr_protocol::question::QuestionSource {
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(uuid(9)),
                process: kr_protocol::identity::ProcessStartIdentity::new(
                    42,
                    kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                    7,
                ),
                executable: Nullable::some(MARKER.to_owned()),
                agent_label: Nullable::some(MARKER.to_owned()),
                connection_id: kr_protocol::ids::ConnectionId::new(uuid(10)),
                launch_channel: false,
                session_member: true,
                ancestry: true,
                agent_binding_revision: Nullable::null(),
            },
            created_at_ms: TimestampMs::new(1_000),
            expires_at_ms: TimestampMs::new(2_000),
            answer: Nullable::null(),
            resolved_at_ms: Nullable::null(),
        };
        renders_only(
            &crate::answers::Answered::Sent(Box::new(question)),
            "Sent{question_id:QuestionId(Uuid(08080808-0808-0808-0808-080808080808)),\
             revision:QuestionRevision(U64(1)),state:Pending,..}",
        );
        let rendered = crate::controls::read_document(&[serde_json::json!({
            "id": "greeting",
            "revision": "1",
            "body": { "kind": "markdown", "source": MARKER }
        })]);
        renders_only(&rendered[0], "Node{controls:0,..}");
        renders_only(
            &crate::encoder::KeyEvent {
                key: crate::encoder::Key::Char('k'),
                base: Some('k'),
                modifiers: crate::encoder::Modifiers::default(),
                kind: crate::encoder::KeyEventKind::Press,
            },
            "KeyEvent{key:Char(..),base:Some(\"..\"),modifiers:Modifiers{shift:false,\
             alt:false,control:false,superkey:false},kind:Press}",
        );
    }

    /// Nothing a reader here does is written to a log: every event raised while planted drafts are
    /// read is captured, and none carries the marker.
    #[test]
    fn a_reader_writes_nothing_of_what_it_read_to_a_log() {
        let written = capture::Written::default();
        let guard = tracing::subscriber::set_default(written.clone());
        a_stored_draft_says_nothing_of_what_it_holds();
        drop(guard);
        assert_unmarked("a log event", &written.events());
    }

    mod capture {
        use std::fmt;
        use std::sync::{Arc, Mutex};

        /// Every event and field written through `tracing` while this is the subscriber.
        #[derive(Clone, Default)]
        pub(super) struct Written(Arc<Mutex<Vec<String>>>);

        impl Written {
            pub(super) fn events(&self) -> Vec<String> {
                self.0.lock().expect("the events").clone()
            }
        }

        struct Fields(String);

        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }

        impl tracing::Subscriber for Written {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                let mut fields = Fields(String::new());
                span.record(&mut fields);
                self.0.lock().expect("the events").push(fields.0);
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
                let mut fields = Fields(String::new());
                values.record(&mut fields);
                self.0.lock().expect("the events").push(fields.0);
            }

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, event: &tracing::Event<'_>) {
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().expect("the events").push(fields.0);
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }
    }

    /// An invitation that cannot be read says which rule its payload broke and names a member by
    /// its name, and says nothing the payload carried: not a mode it named, not a member's value and
    /// not a decoder's words about one. A direct invitation's payload carries its pairing secret.
    #[test]
    fn an_invitation_that_cannot_be_read_says_nothing_it_carries() {
        use kr_protocol::pairing::{QrPayload, RendezvousOrigin};

        use crate::pairing::failure::FailureKind;
        use crate::pairing::invitation::read_invitation;

        let published: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pairing/codes.json"),
            )
            .expect("the published vectors"),
        )
        .expect("JSON");
        let configured = RendezvousOrigin::new("https://reach.kala.to").expect("an origin");
        let payload = |pointer: &str| {
            let text = published
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .expect("a vector");
            let bytes = kr_protocol::scalars::from_base64url(text).expect("base64url");
            kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT).expect("a value")
        };
        let (mut refused, mut quoted) = (0, 0);
        for pointer in ["/qr/code/text", "/qr/direct/text"] {
            for planted in cbor_plantings(&payload(pointer), MARKER) {
                let text = kr_protocol::scalars::to_base64url(&planted.input);
                // The negative control: the payload reader's own failure quotes what it read.
                if QrPayload::from_text(&text)
                    .is_err_and(|error| error.to_string().contains(MARKER))
                {
                    quoted += 1;
                }
                if let Err(failure) = read_invitation(&text, &configured) {
                    refused += 1;
                    assert_unmarked(&planted.at, &failure_renderings(failure));
                }
            }
        }
        assert!(
            refused > 0 && quoted > 0,
            "{refused} refused, {quoted} quoting the marker"
        );
        // The neutral control: a payload naming a mode this build does not read says so, and says
        // what kind of failure it is, with none of the mode.
        let neutral = cbor_plantings(&payload("/qr/code/text"), NEUTRAL)
            .into_iter()
            .find(|planted| planted.at == "Text at /mode")
            .expect("the mode is planted");
        let failure = read_invitation(
            &kr_protocol::scalars::to_base64url(&neutral.input),
            &configured,
        )
        .map(|_| ())
        .expect_err("no such mode");
        assert_eq!(failure.kind, FailureKind::NotAnInvitation);
        assert_eq!(
            failure.to_string(),
            "NotAnInvitation: the QR payload names a mode this build does not read"
        );
    }

    /// A failure names a synchronised object's collection with the name the collection has, for
    /// every kind the protocol defines, the recovery bundle among them. Both parts are closed
    /// values, a kind from the protocol and an identifier, so there is no place to plant a marker:
    /// the name is held exactly instead.
    #[test]
    fn a_failure_names_each_kinds_collection_as_the_collection_is_named() {
        use crate::sync::store::{collection_of, shown_collection};

        let object_id = SyncObjectId::new(uuid(9));
        for kind in kr_protocol::sync::SyncObjectKind::ALL {
            assert_eq!(
                shown_collection(kind, object_id).as_str(),
                collection_of(kind, object_id),
                "{kind}"
            );
        }
        assert_eq!(
            shown_collection(kr_protocol::sync::SyncObjectKind::RecoveryBundle, object_id).as_str(),
            "recovery_bundle/09090909-0909-0909-0909-090909090909"
        );
    }

    #[allow(dead_code, reason = "a path helper some cases share")]
    fn named(path: &Path) -> Shown {
        Shown::root(path)
    }
}
