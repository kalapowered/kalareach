//! Claude Code's native bridge.
//!
//! The Claude Code plugin package installs three registration files into the user's own Claude
//! Code directory: a plugin manifest, an MCP server entry that starts `kr-hook claude-code channel`
//! over standard input and output, and a hooks file that starts `kr-hook claude-code hook` for
//! `SessionStart`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure` and `Notification`. Claude
//! Code starts both itself, so both run under its permissions and outside the KalaReach plugin
//! sandbox, and both inherit the environment of the session Claude Code runs in.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`hook`] | One lifecycle or tool hook: prompt, neutral, and never a decision |
//! | [`channel`] | The Channels server: Claude Code's MCP session and the worker's exchange |

pub mod channel;
pub mod hook;

/// The application name this bridge declares to the worker, as its registration invokes it.
pub const APPLICATION: &str = "claude-code";
