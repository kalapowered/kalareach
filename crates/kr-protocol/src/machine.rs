//! Machine groups: the group an environment records for itself, and the three steps that change it.
//!
//! A machine group is a random, owner-approved grouping of environments. It is never a hardware
//! fingerprint and it grants nothing by itself: a host name, a serial number or a matching path
//! never puts an environment in a group, and a group names no grant, route or pairing. Each
//! environment records its own group and changes it only by its own owner-approved step, so a
//! group exists only as the value its members record.
//!
//! Three steps change the group an environment records. `machine.join` moves the environment
//! into a group the owner names. `machine.merge` is the environment's part in merging its group
//! into another: a merge of independent environments is one such step on each of them, each taken
//! over that environment's own connection. `machine.split` moves the environment into a fresh
//! group of its own, minted by the environment.
//!
//! Every step names the record it was approved against, the group and the revision the owner saw,
//! so a step that meets any other record changes nothing (`DRAFT_CONFLICT`) and a step is never
//! applied to a record it was not approved against. Undoing a step is joining the group it left,
//! with the step's own result as the precondition.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{EnvironmentId, MachineId};
use crate::scalars::{Nullable, U64};

/// What wrote an environment's current group record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MachineChange {
    /// The environment's first start minted its group.
    Created,
    /// The owner moved the environment into a group they named.
    Joined,
    /// The owner merged the environment's group into another, and this was the environment's part.
    Merged,
    /// The owner moved the environment into a fresh group of its own.
    Split,
}

impl MachineChange {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Joined => "joined",
            Self::Merged => "merged",
            Self::Split => "split",
        }
    }
}

/// The machine group an environment records for itself.
///
/// This type is closed: a step's result carries it, and a result is never read-only metadata. A
/// member added later is a new schema for every reader of `host.info` and `environment.list`,
/// which hold it as an optional member, and so is a new [`MachineChange`] kind: a reader whose
/// schema predates it refuses the whole `host.info` or `environment.list` answer that carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineGroup {
    /// The group the environment is in.
    pub machine_id: MachineId,
    /// The record's revision: 1 when the environment first minted its group, and one more for
    /// every step after that. With the group it is every step's precondition, so a group the
    /// environment left and came back to is never mistaken for the one it was in.
    pub revision: U64,
    /// The step that wrote this revision.
    pub change: MachineChange,
    /// The group the environment left by that step, which undoing the step joins again. Null for
    /// the first record.
    pub previous: Nullable<MachineId>,
}

/// The record an owner approved a step against: the group and the revision they saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineExpected {
    /// The group the environment was in.
    pub machine_id: MachineId,
    /// The revision of the record that said so.
    pub revision: U64,
}

/// Parameters of `machine.join`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineJoinParams {
    /// The group to join. Any group identifier is accepted, including one whose members have all
    /// left it: a group is only the value its members record, and an environment cannot see the
    /// others.
    pub machine_id: MachineId,
    /// The record this step was approved against.
    pub expected: MachineExpected,
}

/// Parameters of `machine.merge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineMergeParams {
    /// The group this environment's group is merged into.
    pub machine_id: MachineId,
    /// The record this step was approved against: the group being merged away, at the revision
    /// the owner saw.
    pub expected: MachineExpected,
}

/// Parameters of `machine.split`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineSplitParams {
    /// The record this step was approved against.
    pub expected: MachineExpected,
}

/// The result of `machine.join`, `machine.merge` and `machine.split`, and the receipt each leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineStepResult {
    /// The environment whose record the step changed. A step never changes another's.
    pub environment_id: EnvironmentId,
    /// The group the environment records now.
    pub machine: MachineGroup,
}
