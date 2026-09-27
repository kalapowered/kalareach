//! Privacy mode: the environment's switch, what it reports, and the notice each worker is told.
//!
//! Section 24 makes privacy mode one generation per environment. `privacy.set` records the change
//! and advances the generation before any subsystem is touched, and `privacy.status` reads where it
//! stands. Both answer a [`PrivacyReport`]: whether the change has finished taking effect, what each
//! session still owes, what this host keeps and why, and what had already left it, which is shown
//! rather than erased.
//!
//! The control daemon tells each of the environment's workers the generation in force with a
//! [`PrivacyGenerationNotice`], and a worker answers with a [`PrivacyGenerationAck`] once its
//! session holds that generation, saying where its own cleanup stands. Completion is never
//! claimed for a worker that has not said so.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{EnvironmentId, SessionId};
use crate::scalars::{TimestampMs, U64};

/// Parameters of `privacy.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacySetParams {
    /// True turns privacy mode on, false turns it off. Each change advances the generation; asking
    /// for the state already in force changes nothing and answers where it stands.
    pub enabled: bool,
}

/// Parameters of `privacy.status`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyStatusParams {}

/// Where privacy mode stands for the environment: the answer to `privacy.set` and to
/// `privacy.status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyReport {
    /// The environment's privacy generation. Turning privacy mode on and turning it off each
    /// advance it.
    pub generation: U64,
    /// Whether privacy mode is on.
    pub enabled: bool,
    /// When it last changed.
    pub changed_at_ms: TimestampMs,
    /// Whether the last change has finished taking effect.
    pub completion: PrivacyCompletion,
    /// Each session whose own cleanup is still owed, and where it stands.
    pub sessions: Vec<PrivacySession>,
    /// What privacy mode stops while it is on.
    pub disabled: Vec<PrivacyDisabled>,
    /// What this host keeps while privacy mode is on, and why.
    pub kept: Vec<PrivacyKept>,
    /// What had already left this host before privacy mode was turned on.
    pub exported: Vec<PrivacyExported>,
    /// Each subsystem that could not list what had left, and its reason. The list above is then
    /// incomplete, and says so here rather than by being empty.
    pub unlisted: Vec<PrivacyUnavailable>,
}

/// Whether privacy mode's last change has finished taking effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivacyCompletion {
    /// Every subsystem and every session has reconciled. The only state reported as complete.
    Complete,
    /// Work is still settling, and these are why.
    Reconciling {
        /// Each subsystem with work outstanding, and how much.
        outstanding: Vec<PrivacyOutstanding>,
    },
    /// Something is in the way: a subsystem could not take a step or cannot say where its cleanup
    /// stands. Cleanup is not complete, and it is not merely waiting for work to settle.
    Unavailable {
        /// Each subsystem that could not answer, with its reason.
        unavailable: Vec<PrivacyUnavailable>,
        /// Each subsystem with work outstanding, and how much.
        outstanding: Vec<PrivacyOutstanding>,
    },
}

/// One subsystem's outstanding work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyOutstanding {
    /// The subsystem, by its stable name.
    pub subsystem: String,
    /// How many pieces of work it is still waiting on.
    pub count: U64,
}

/// One subsystem that could not answer, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyUnavailable {
    /// The subsystem, by its stable name.
    pub subsystem: String,
    /// What its store said.
    pub reason: String,
}

/// One session's own cleanup that privacy mode is still owed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacySession {
    /// The session.
    pub session_id: SessionId,
    /// The generation whose cleanup it owes.
    pub generation: U64,
    /// Where it stands.
    pub standing: PrivacySessionStanding,
}

/// Where one session's cleanup stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivacySessionStanding {
    /// Its worker has not said yet.
    AwaitingWorker,
    /// Its worker says its cleanup is still settling.
    Reconciling {
        /// How much its worker says is outstanding.
        outstanding: U64,
    },
    /// Its worker says something is in the way.
    Unavailable {
        /// What its worker said.
        reason: String,
    },
    /// Its worker ended before it said its cleanup was complete. What it retained is the
    /// archive's, and the session stays owed until something shows it is gone.
    WorkerEnded,
}

/// Something privacy mode stops while it is on.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDisabled {
    /// Keeping the content of a session's history.
    ContentHistoryRetention,
    /// Producing generated session descriptions.
    DescriptionInference,
    /// Producing sync work.
    Sync,
    /// Producing backup work.
    Backup,
}

/// Something this host keeps while privacy mode is on, named rather than kept quietly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyKept {
    /// What is kept.
    pub what: String,
    /// Why a host that stopped keeping it could not do its job.
    pub why: String,
}

/// A copy that had already left this host before privacy mode was turned on.
///
/// It is not erased, and this host does not claim it could be: it is shown, and deleting it is an
/// action of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyExported {
    /// What kind of copy it is.
    pub kind: String,
    /// The opaque reference a person is shown, never a path on a client.
    pub reference: String,
    /// When it left.
    pub left_at_ms: TimestampMs,
    /// Whether this host holds a reference it can ask for the copy's removal through. It says
    /// there is a way to ask, not that asking will succeed or that no other copy exists.
    pub deletable: bool,
}

/// The environment's privacy generation, as the control daemon tells one of its workers.
///
/// Sent on the daemon's authority connection to the worker whenever the generation it holds for
/// the session is not the one in force, and repeated until the worker answers that its cleanup is
/// complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyGenerationNotice {
    /// The environment the generation belongs to.
    pub environment_id: EnvironmentId,
    /// The generation in force.
    pub generation: U64,
    /// Whether privacy mode is on at that generation.
    pub enabled: bool,
}

/// A worker's answer to a [`PrivacyGenerationNotice`]: the generation its session holds now, in
/// which state, and where its own cleanup stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyGenerationAck {
    /// The session that answered.
    pub session_id: SessionId,
    /// The generation the session holds.
    pub generation: U64,
    /// Whether privacy mode is on in the session at that generation.
    pub enabled: bool,
    /// Where the session's own cleanup stands.
    pub completion: PrivacyCompletion,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ControlFrame, ParamsValue};

    /// A completion says which state it is in on the wire, carries its lists only where the state
    /// has them, and refuses a field it does not have.
    #[test]
    fn a_completion_names_its_state_and_carries_only_its_own_lists() {
        let complete = serde_json::to_value(PrivacyCompletion::Complete).expect("encodes");
        assert_eq!(complete, serde_json::json!({ "state": "complete" }));

        let unavailable = PrivacyCompletion::Unavailable {
            unavailable: vec![PrivacyUnavailable {
                subsystem: "backup".to_owned(),
                reason: "the store is read-only".to_owned(),
            }],
            outstanding: vec![PrivacyOutstanding {
                subsystem: "delivery".to_owned(),
                count: U64::new(2),
            }],
        };
        let json = serde_json::to_value(&unavailable).expect("encodes");
        assert_eq!(json["state"], "unavailable");
        assert_eq!(json["unavailable"][0]["subsystem"], "backup");
        assert_eq!(json["outstanding"][0]["count"], serde_json::json!("2"));
        let back: PrivacyCompletion = serde_json::from_value(json).expect("decodes");
        assert_eq!(back, unavailable);

        // Read the way a message is read, against its schema first.
        let read = |value: serde_json::Value| {
            ParamsValue::from_typed(&value)
                .expect("a params value")
                .to_typed::<PrivacyCompletion>()
        };
        assert!(read(serde_json::json!({ "state": "complete" })).is_ok());
        assert!(
            read(serde_json::json!({ "state": "complete", "outstanding": [] })).is_err(),
            "a complete state has no outstanding list"
        );
        assert!(
            read(serde_json::json!({ "state": "reconciling" })).is_err(),
            "a reconciling state says what is outstanding"
        );
    }

    /// The notice and its answer travel as control frames, each under its own name.
    #[test]
    fn the_notice_and_its_answer_are_control_frames_of_their_own() {
        let notice = ControlFrame::PrivacyGeneration(PrivacyGenerationNotice {
            environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([7; 16])),
            generation: U64::new(3),
            enabled: true,
        });
        let json = serde_json::to_value(&notice).expect("encodes");
        assert_eq!(
            json["privacy_generation"]["generation"],
            serde_json::json!("3")
        );
        let back: ControlFrame = serde_json::from_value(json).expect("decodes");
        assert_eq!(back, notice);

        let ack = ControlFrame::PrivacyGenerationAck(Box::new(PrivacyGenerationAck {
            session_id: SessionId::new(crate::scalars::Uuid::from_bytes([9; 16])),
            generation: U64::new(3),
            enabled: true,
            completion: PrivacyCompletion::Reconciling {
                outstanding: vec![PrivacyOutstanding {
                    subsystem: "history".to_owned(),
                    count: U64::new(1),
                }],
            },
        }));
        let value = ParamsValue::from_typed(&ack).expect("a params value");
        let back: ControlFrame = value.to_typed().expect("decodes");
        assert_eq!(back, ack);
    }
}
