//! The launch commands a host saves, beside the agents its launch buttons already offer.
//!
//! A person names a label, a program and separate arguments. No command line is parsed: the
//! vector is the one form the managed integration quotes safely for every shell, and it is what a
//! press sends through `shell.launch` unchanged. The list belongs to the host, in a store of its
//! own, and is served by three methods the daemon answers itself: `shell.launch.commands.list`,
//! `shell.launch.commands.save` and `shell.launch.commands.remove`.
//!
//! A write names the revision of the list it was decided from. A request against a revision the
//! list has left changes nothing and is answered with the list as it stands, `applied: false`; a
//! request against the current revision that asks for what the list already holds changes nothing
//! and says so. The revision is a random non-zero number made for each change and is compared for
//! equality only; zero means the host has saved nothing yet.
//!
//! Only the list result carries the read-only metadata marker: a later release may add an optional
//! member to it. The requests and the write results are closed, so a later quoted form is a new
//! method.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::U64;

/// One saved launch command: the label a button shows, the program, and the arguments as the
/// person wrote them. An argument may be empty. The host refuses a control, format, invisible or
/// line-break character in any of the three fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedLaunch {
    /// What the button shows: 1 to 48 characters once trimmed, unique on this host when compared
    /// in lower case.
    pub label: String,
    /// The program: 1 to 512 bytes, a full path or a program on the shell's path.
    pub program: String,
    /// The arguments, at most 16 of at most 512 bytes each; the whole command is at most 3,072
    /// bytes.
    pub arguments: Vec<String>,
}

/// The parameters of `shell.launch.commands.list`. There are none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchCommandsListParams {}

/// The result of `shell.launch.commands.list`: the commands the host holds, in the order they
/// were first saved, and the revision of the list.
///
/// This is the only launch-command type that carries read-only metadata, so a later release may
/// add an optional member to it without a change of level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kalareach-read-only-metadata" = true))]
pub struct ShellLaunchCommandsListResult {
    /// The revision of the list; 0 when the host has saved no command.
    pub revision: U64,
    /// The saved commands.
    pub commands: Vec<NamedLaunch>,
}

/// The parameters of `shell.launch.commands.save`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchCommandsSaveParams {
    /// The revision of the list this save was decided from.
    pub expected_revision: U64,
    /// The command to add, or to put in place of the command with the same label.
    pub command: NamedLaunch,
}

/// The result of `shell.launch.commands.save`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchCommandsSaveResult {
    /// Whether the save was decided against the current revision. False means the list changed
    /// first: nothing was written and `commands` is the list as it stands.
    pub applied: bool,
    /// Whether the list changed. False when it already held this command as written.
    pub changed: bool,
    /// Whether the command took the place of a saved command with the same label.
    pub replaced: bool,
    /// The revision of the list after the request.
    pub revision: U64,
    /// The list after the request.
    pub commands: Vec<NamedLaunch>,
}

/// The parameters of `shell.launch.commands.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchCommandsRemoveParams {
    /// The revision of the list this removal was decided from.
    pub expected_revision: U64,
    /// The label to remove, compared in lower case.
    pub label: String,
}

/// The result of `shell.launch.commands.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchCommandsRemoveResult {
    /// Whether the removal was decided against the current revision. False means the list changed
    /// first: nothing was written and `commands` is the list as it stands.
    pub applied: bool,
    /// Whether a command was removed. False when no saved command has that label.
    pub removed: bool,
    /// The revision of the list after the request.
    pub revision: U64,
    /// The list after the request.
    pub commands: Vec<NamedLaunch>,
}
