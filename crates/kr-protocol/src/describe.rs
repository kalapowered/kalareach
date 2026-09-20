//! The parameters and results of `session.describe` and `session.rename`.
//!
//! Section 23 is explicit about what `session.describe` is: *an authorised read of filtered
//! metadata, not an arbitrary model-control method*. The types here say the same thing in a shape a
//! client cannot argue with. [`SessionDescribeParams`] names a session and nothing else: there is
//! no prompt, no model, no sampler, no temperature and no way to ask for a description *now*.
//! Whether a description exists, how current it is and when the queue will reach this session are
//! answers, never requests.
//!
//! `session.rename` is the other half. A pinned name is the one thing a person sets directly, and
//! section 22 never lets generated text overwrite one, so the write method is a pin and its
//! clearing rather than a general label setter.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::SessionId;
use crate::scalars::{Nullable, TimestampMs, U64};

/// The longest session title, in Unicode codepoints.
pub const MAX_SESSION_TITLE_CODEPOINTS: u32 = 64;

/// The longest session activity line, in Unicode codepoints.
pub const MAX_SESSION_ACTIVITY_CODEPOINTS: u32 = 160;

/// Where a session's shown title came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    /// A person pinned it. Generated text never replaces one.
    Pinned,
    /// Deterministic metadata: the directory, the repository or the application. Every host has
    /// this, with no model and no network.
    Metadata,
    /// A local model produced it. It is shown as generated wherever it appears.
    Generated,
}

/// How current a generated description is.
///
/// There is no variant meaning "probably current". When demand exceeds capacity a client is shown
/// the delay or the staleness rather than text that implies the session is doing what it was doing
/// five minutes ago.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionFreshness {
    /// It was produced at the context revision in force.
    Current,
    /// It is at the revision in force, and a newer job has been waiting.
    Delayed,
    /// The session has moved on since it was produced.
    Stale,
    /// There is no generated description at all, and the title is the deterministic one.
    None,
}

/// Why a host is not running description inference now.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionPause {
    /// Loading would leave less than the memory reserve.
    MemoryReserve,
    /// The reserve stopped holding while a model was resident.
    MemoryPressure,
    /// The host is thermally limited.
    Thermal,
    /// The host is on battery and inference on battery has not been enabled.
    Battery,
    /// The host cannot read a signal the decision needs.
    SignalUnqualified,
    /// An owner turned descriptions off.
    Disabled,
    /// This environment runs no model: a WSL distribution with no data-access choice, or a mobile
    /// device.
    NoModelHere,
}

/// What state description inference is in on the host serving this session.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionState {
    /// Nothing is loaded and nothing is stopping a load.
    Ready,
    /// A model is mapped and jobs are running.
    Resident,
    /// Inference is paused. Deterministic titles are unaffected.
    ResourcePaused,
}

/// The provenance of one generated description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionProvenance {
    /// The model profile that produced it.
    pub profile_id: String,
    /// That profile's revision. A description produced under a revision the host no longer has
    /// mapped is not replaced silently; it is shown with the revision it came from.
    pub profile_revision: U64,
    /// The context revision it was produced at.
    pub context_revision: U64,
    /// The first semantic cursor it covers.
    pub source_cursor_from: U64,
    /// The last semantic cursor it covers.
    pub source_cursor_to: U64,
    /// When it was produced.
    pub produced_at_ms: TimestampMs,
}

/// Parameters of `session.describe`.
///
/// One session, and nothing else. There is deliberately no field that selects a model, sets a
/// sampler, supplies a prompt or asks for a description to be produced now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDescribeParams {
    /// The session to describe.
    pub session_id: SessionId,
}

/// The result of `session.describe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDescribeResult {
    /// The session.
    pub session_id: SessionId,
    /// The title to show. Every host has one.
    pub title: String,
    /// Where the title came from.
    pub source: LabelSource,
    /// The activity line, when a generated description supplied one.
    pub activity_text: Nullable<String>,
    /// How current the generated description is.
    pub freshness: DescriptionFreshness,
    /// What produced the generated description, when one is shown.
    pub provenance: Nullable<DescriptionProvenance>,
    /// How long this session's queued description job has been waiting.
    pub queued_age_ms: Nullable<U64>,
    /// When this session last had a description published.
    pub last_success_ms: Nullable<TimestampMs>,
    /// The cadence the host is running at, which is not a promise about this session.
    pub cadence_ms: U64,
    /// What state inference is in on the host.
    pub state: DescriptionState,
    /// Why inference is paused, when it is.
    pub paused: Nullable<DescriptionPause>,
}

/// Parameters of `session.rename`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRenameParams {
    /// The session to rename.
    pub session_id: SessionId,
    /// The pinned name, or null to clear the pin.
    ///
    /// Clearing is explicit because section 24 keeps a pinned label *unless explicitly cleared*:
    /// there is no other operation in this protocol that removes one.
    pub title: Nullable<String>,
}

/// The result of `session.rename`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRenameResult {
    /// The session.
    pub session_id: SessionId,
    /// The title now shown.
    pub title: String,
    /// Where it came from. After a pin this is [`LabelSource::Pinned`]; after a clearing it is
    /// whatever the host has instead, which is a generated description or the deterministic title.
    pub source: LabelSource,
    /// Whether a pin is in force.
    pub pinned: bool,
}

/// The state description setup is in, for the host's own setup surface.
///
/// Section 22 offers descriptions during host setup *with visible asset size, cancel/disable
/// controls and no hosted-account dependency*. These are those facts, so the surface that shows
/// them does not have to work them out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionSetup {
    /// Whether this host can offer descriptions at all.
    pub offered: bool,
    /// Whether an owner has enabled them.
    pub enabled: bool,
    /// The profile that would be fetched.
    pub profile_id: Nullable<String>,
    /// Exactly how many bytes that is, before anything is fetched.
    pub asset_bytes: U64,
    /// How many of those bytes have arrived.
    pub fetched_bytes: U64,
    /// Whether a running fetch can be cancelled now.
    pub can_cancel: bool,
    /// Whether the feature can be turned off now.
    pub can_disable: bool,
    /// Whether any of this needs a hosted account. It never does.
    pub needs_hosted_account: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        DescriptionFreshness, LabelSource, SessionDescribeParams, SessionRenameParams,
        SessionRenameResult,
    };
    use crate::ids::SessionId;
    use crate::scalars::{Nullable, Uuid};

    /// KR-REQ-22.18: describing a session names the session and asks for nothing else.
    #[test]
    fn describing_a_session_carries_no_model_control_at_all() {
        let params = SessionDescribeParams {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
        };
        let encoded = serde_json::to_value(&params).expect("a request encodes");
        let object = encoded.as_object().expect("an object");
        assert_eq!(object.len(), 1, "one field, and it is the session");
        assert!(object.contains_key("session_id"));
    }

    /// KR-REQ-22.19: clearing a pin is a distinct, explicit request rather than an empty name.
    #[test]
    fn clearing_a_pin_is_an_explicit_null_rather_than_an_empty_name() {
        let clearing = SessionRenameParams {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            title: Nullable(None),
        };
        let encoded = serde_json::to_value(&clearing).expect("a request encodes");
        assert!(encoded["title"].is_null());

        let decoded: SessionRenameParams =
            serde_json::from_value(encoded).expect("it decodes again");
        assert_eq!(decoded.title.0, None);
    }

    /// KR-REQ-24.14: a rename answers with where the title now comes from.
    #[test]
    fn a_rename_answers_with_the_source_of_the_title_it_leaves_behind() {
        let result = SessionRenameResult {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            title: "kalareach (main)".to_owned(),
            source: LabelSource::Metadata,
            pinned: false,
        };
        let encoded = serde_json::to_value(&result).expect("a result encodes");
        assert_eq!(encoded["source"], "metadata");
        assert_eq!(encoded["pinned"], false);
        assert_eq!(
            serde_json::to_value(DescriptionFreshness::Stale).expect("a freshness encodes"),
            "stale"
        );
    }
}
