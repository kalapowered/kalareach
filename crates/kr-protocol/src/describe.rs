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
//!
//! The host's own surfaces set descriptions up through `description.setup`, `description.configure`
//! and `description.download`: what is offered and what it costs before anything is fetched, the
//! two settings an owner has, and the fetch itself. Nothing in them reaches a hosted account.
//!
//! The control daemon learns what a session is doing from its worker, over a connection of its own.
//! The worker keeps one small record of facts per session and answers the daemon's request for it
//! with a page; the types for both are [`DescriptionFactsRequest`] and [`DescriptionFactsPage`].
//! No keystroke, query or resize reaches either: a fact is something the session did, never
//! something it was sent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::SessionId;
use crate::scalars::{Nullable, TimestampMs, U64};

/// The longest session title, in Unicode codepoints.
pub const MAX_SESSION_TITLE_CODEPOINTS: u32 = 64;

/// The longest session activity line, in Unicode codepoints.
pub const MAX_SESSION_ACTIVITY_CODEPOINTS: u32 = 160;

/// The longest a worker may hold a request for its session's description facts, in milliseconds.
pub const MAX_DESCRIPTION_FACTS_WAIT_MS: u64 = 300_000;

/// The most recent events one record of facts carries.
pub const MAX_DESCRIPTION_FACT_EVENTS: usize = 8;

/// The longest text one fact carries, in Unicode codepoints. A fact longer than this is clipped on
/// a codepoint boundary by the worker that recorded it.
pub const MAX_DESCRIPTION_FACT_CODEPOINTS: usize = 120;

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
    /// The selected profile's files are not on this host, or are not the files the profile
    /// records. Nothing is fetched until an owner asks.
    NotDownloaded,
    /// The description process failed three times in a row, and the next start waits out its
    /// delay.
    InferenceFailed,
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
    /// [`LabelSource::Metadata`], the deterministic title. A generated description is read with
    /// `session.describe`, which filters it for whoever asks.
    pub source: LabelSource,
    /// Whether a pin is in force.
    pub pinned: bool,
}

/// Parameters of `description.setup`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionSetupParams {}

/// How fetching the selected profile's files is going.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionDownload {
    /// Nothing has been fetched, and nothing is being fetched.
    NotStarted,
    /// A fetch is running.
    Running,
    /// Every file is here and its digest matched.
    Verified,
    /// An owner cancelled the fetch, and what it had written is gone.
    Cancelled,
    /// The fetch failed; [`DescriptionSetup::failure`] says how.
    Failed,
}

/// The state description setup is in, for the host's own setup surface: the answer to
/// `description.setup`, `description.configure` and `description.download`.
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
    /// Whether inference may run while the host is on battery.
    pub on_battery: bool,
    /// The profile that would be fetched.
    pub profile_id: Nullable<String>,
    /// Exactly how many bytes that is, before anything is fetched.
    pub asset_bytes: U64,
    /// Where the fetch would reach: the hosts, and nothing else.
    pub sources: Vec<String>,
    /// How the fetch is going.
    pub download: DescriptionDownload,
    /// How many of those bytes have arrived.
    pub fetched_bytes: U64,
    /// What went wrong, when the fetch failed.
    pub failure: Nullable<String>,
    /// Whether a running fetch can be cancelled now.
    pub can_cancel: bool,
    /// Whether the feature can be turned off now.
    pub can_disable: bool,
    /// Whether any of this needs a hosted account. It never does.
    pub needs_hosted_account: bool,
    /// Why this host offers nothing, when it offers nothing.
    pub unavailable: Nullable<String>,
    /// What state inference is in on this host.
    pub state: DescriptionState,
    /// Why inference is paused, when it is.
    pub paused: Nullable<DescriptionPause>,
}

/// Parameters of `description.configure`: the two settings an owner has.
///
/// A null leaves that setting as it is; a value sets it. Both apply at once, with no restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionConfigureParams {
    /// Whether descriptions are on. Turning them off stops admission and dispatch, cancels the
    /// work in flight and ends the description process.
    pub enabled: Nullable<bool>,
    /// Whether inference may run while the host is on battery. Off unless an owner turns it on.
    pub on_battery: Nullable<bool>,
}

/// What `description.download` is asked to do.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionDownloadAction {
    /// Fetch the selected profile's files, check them and keep them.
    Start,
    /// Stop a running fetch and delete what it had written.
    Cancel,
}

/// Parameters of `description.download`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionDownloadParams {
    /// What to do.
    pub action: DescriptionDownloadAction,
}

/// What a worker did with a session's last command, as it recorded it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionCompletion {
    /// It finished with a zero exit status.
    Succeeded,
    /// It finished with another status.
    Failed,
}

/// The kinds of semantic event a description may be built from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionEventKind {
    /// A command was accepted.
    CommandAccepted,
    /// A task started.
    TaskStarted,
    /// A task finished.
    TaskCompleted,
    /// An approval was requested.
    ApprovalRequested,
    /// A file changed. The path is carried; the contents are not.
    FileChanged,
}

/// One recent semantic event: its place in the session's stream, its kind and a clipped summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionEvent {
    /// The cursor the event sits at in the session's semantic stream.
    pub cursor: U64,
    /// What kind of event it is.
    pub kind: DescriptionEventKind,
    /// A summary of at most [`MAX_DESCRIPTION_FACT_CODEPOINTS`] codepoints.
    pub summary: String,
}

/// The repository a session's directory is inside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionRepository {
    /// The repository's name.
    pub name: String,
    /// The branch checked out, when there is one.
    pub branch: Nullable<String>,
}

/// What one session was doing, as its worker recorded it: the whole of what a description is built
/// from, and nothing a person typed into the terminal.
///
/// Each field is something the session did or was asked to do: the directory a command ran in, the
/// program it ran, how it ended, the prompt an agent was given, the thread it selected and the
/// last few semantic events. No keystroke, no output and no query's answer is in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionFacts {
    /// The record's revision. It moves with every change to any fact, and with nothing else.
    pub revision: U64,
    /// The privacy generation the facts were captured under.
    pub generation: U64,
    /// The directory's last component.
    pub directory: Nullable<String>,
    /// The repository the directory is inside, when it is inside one.
    pub repository: Nullable<DescriptionRepository>,
    /// The program name of the newest command, without its arguments.
    pub application: Nullable<String>,
    /// How the newest command ended, when it has.
    pub completion: Nullable<DescriptionCompletion>,
    /// The last prompt an agent in the session was given.
    pub intent: Nullable<String>,
    /// The thread the session selected.
    pub thread: Nullable<String>,
    /// The most recent events, newest first, at most [`MAX_DESCRIPTION_FACT_EVENTS`].
    pub events: Vec<DescriptionEvent>,
}

/// The control daemon's request for one session's description facts, made over the connection it
/// reads them on.
///
/// The worker answers at once when the facts have moved past `after`, or when its privacy state is
/// not the one `generation` names, and otherwise holds the request for up to `wait_ms`. A newer
/// request on the connection replaces a held one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionFactsRequest {
    /// Correlates the page with this request.
    pub request_id: crate::ids::RequestId,
    /// The last revision the daemon has read, or nought for none.
    pub after: U64,
    /// How long the worker may hold the request while it has nothing newer, bounded by
    /// [`MAX_DESCRIPTION_FACTS_WAIT_MS`]. Nought answers at once.
    pub wait_ms: U64,
    /// The session's privacy generation the daemon has recorded, or null when it has recorded
    /// none. A worker whose privacy state is past it answers at once, so the daemon learns of a
    /// transition without waiting for the request's bound.
    pub generation: Nullable<U64>,
}

/// The worker's answer to a [`DescriptionFactsRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptionFactsPage {
    /// The request this answers.
    pub request_id: crate::ids::RequestId,
    /// The session.
    pub session_id: SessionId,
    /// The privacy generation the session holds, or null when it holds none.
    pub privacy_generation: Nullable<U64>,
    /// Whether privacy mode is on in the session. While it is, no facts are carried and none are
    /// captured.
    pub private: bool,
    /// The session's facts, when their revision is past the request's `after` and privacy mode is
    /// off; null otherwise.
    pub facts: Nullable<DescriptionFacts>,
}

#[cfg(test)]
mod tests {
    use super::{
        DescriptionCompletion, DescriptionDownload, DescriptionDownloadAction,
        DescriptionDownloadParams, DescriptionEvent, DescriptionEventKind, DescriptionFacts,
        DescriptionFactsPage, DescriptionFactsRequest, DescriptionFreshness, DescriptionPause,
        DescriptionRepository, DescriptionSetup, DescriptionState, LabelSource,
        MAX_DESCRIPTION_FACT_EVENTS, SessionDescribeParams, SessionRenameParams,
        SessionRenameResult,
    };
    use crate::ids::{RequestId, SessionId};
    use crate::scalars::{Nullable, U64, Uuid};

    fn facts() -> DescriptionFacts {
        DescriptionFacts {
            revision: U64::new(7),
            generation: U64::new(3),
            directory: Nullable::some("kalareach".to_owned()),
            repository: Nullable::some(DescriptionRepository {
                name: "kalareach".to_owned(),
                branch: Nullable::some("main".to_owned()),
            }),
            application: Nullable::some("cargo".to_owned()),
            completion: Nullable::some(DescriptionCompletion::Succeeded),
            intent: Nullable::some("check the pairing flow".to_owned()),
            thread: Nullable::null(),
            events: vec![DescriptionEvent {
                cursor: U64::new(41),
                kind: DescriptionEventKind::CommandAccepted,
                summary: "cargo test".to_owned(),
            }],
        }
    }

    /// A page of facts carries the generation they were captured under and the revision they are
    /// at, and decodes to the same page; a request for facts carries the cursor, the wait and the
    /// generation the daemon has recorded. Nothing in either is a keystroke, an output or a query.
    #[test]
    fn a_facts_page_carries_its_revision_and_the_generation_it_was_captured_under() {
        let page = DescriptionFactsPage {
            request_id: RequestId::new(9),
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            privacy_generation: Nullable::some(U64::new(3)),
            private: false,
            facts: Nullable::some(facts()),
        };
        let encoded = serde_json::to_value(&page).expect("a page encodes");
        assert_eq!(encoded["facts"]["revision"], "7");
        assert_eq!(encoded["facts"]["generation"], "3");
        assert_eq!(encoded["facts"]["events"][0]["kind"], "command_accepted");
        assert_eq!(encoded["facts"]["completion"], "succeeded");
        let decoded: DescriptionFactsPage = serde_json::from_value(encoded).expect("it decodes");
        assert_eq!(decoded, page);

        let request = DescriptionFactsRequest {
            request_id: RequestId::new(9),
            after: U64::new(6),
            wait_ms: U64::new(30_000),
            generation: Nullable::null(),
        };
        let encoded = serde_json::to_value(&request).expect("a request encodes");
        let keys: Vec<_> = encoded.as_object().expect("an object").keys().collect();
        assert_eq!(keys, ["after", "generation", "request_id", "wait_ms"]);
        let decoded: DescriptionFactsRequest = serde_json::from_value(encoded).expect("it decodes");
        assert_eq!(decoded, request);
    }

    /// A page from a session in privacy mode carries no facts, and says it is private; a field
    /// this build does not know is refused rather than ignored.
    #[test]
    fn a_private_session_answers_with_no_facts_and_unknown_fields_are_refused() {
        let page = DescriptionFactsPage {
            request_id: RequestId::new(1),
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            privacy_generation: Nullable::some(U64::new(4)),
            private: true,
            facts: Nullable::null(),
        };
        let encoded = serde_json::to_value(&page).expect("a page encodes");
        assert!(encoded["facts"].is_null());
        assert_eq!(encoded["private"], true);

        let mut crowded = serde_json::to_value(facts()).expect("facts encode");
        crowded["keystrokes"] = serde_json::json!("ls");
        assert!(
            serde_json::from_value::<DescriptionFacts>(crowded).is_err(),
            "a record of facts has no field a keystroke could travel in"
        );
        assert_eq!(MAX_DESCRIPTION_FACT_EVENTS, 8);
    }

    /// The setup answer says what is offered and what it costs before anything is fetched, how a
    /// fetch is going, and what is wrong when something is; the two new pauses have wire names.
    #[test]
    fn the_setup_answer_carries_size_sources_progress_and_failure() {
        let setup = DescriptionSetup {
            offered: true,
            enabled: true,
            on_battery: false,
            profile_id: Nullable::some("minicpm5-2b-q4-k-m".to_owned()),
            asset_bytes: U64::new(1_561_318_368),
            sources: vec!["huggingface.co".to_owned()],
            download: DescriptionDownload::Failed,
            fetched_bytes: U64::new(1_000),
            failure: Nullable::some("the connection closed".to_owned()),
            can_cancel: false,
            can_disable: true,
            needs_hosted_account: false,
            unavailable: Nullable::null(),
            state: DescriptionState::ResourcePaused,
            paused: Nullable::some(DescriptionPause::NotDownloaded),
        };
        let encoded = serde_json::to_value(&setup).expect("a setup encodes");
        assert_eq!(encoded["asset_bytes"], "1561318368");
        assert_eq!(encoded["download"], "failed");
        assert_eq!(encoded["paused"], "not_downloaded");
        assert_eq!(encoded["needs_hosted_account"], false);
        assert_eq!(
            serde_json::to_value(DescriptionPause::InferenceFailed).expect("a pause encodes"),
            "inference_failed"
        );
        let decoded: DescriptionSetup = serde_json::from_value(encoded).expect("it decodes");
        assert_eq!(decoded, setup);

        let start = DescriptionDownloadParams {
            action: DescriptionDownloadAction::Start,
        };
        assert_eq!(
            serde_json::to_value(&start).expect("a request encodes")["action"],
            "start"
        );
    }

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
