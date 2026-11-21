//! What the page is told of a session's launch surface, and what it presses to start something.
//!
//! The surface is read from the session's worker, which answers whether a launch could be made at
//! the root editor now. A host that does not serve the read is not an error: the page is told so,
//! and says the launch is not available there.
//!
//! A press is made on a raw terminal view's own link, since only a link that holds the session's
//! input can have a launch accepted. The page names the command to install and the prompt it was
//! drawn at; the session is the view's own and no other.

use kr_protocol::ids::SessionId;
use kr_protocol::launch_commands::ShellLaunchCommandsListResult;
use kr_protocol::root::{
    EditorBufferRevision, LaunchCommand, PromptGeneration, ShellLaunchParams,
    ShellLaunchSurfaceResult,
};
use serde::{Deserialize, Serialize};

/// What a read of a launch surface came to, as the page is told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LaunchSurfaceAnswer {
    /// The worker answered.
    Served {
        /// What it answered.
        surface: ShellLaunchSurfaceResult,
    },
    /// The host is of a release that does not serve the read, or so is its session's worker.
    NotServed,
}

impl From<kr_client::LaunchSurfaceRead> for LaunchSurfaceAnswer {
    fn from(read: kr_client::LaunchSurfaceRead) -> Self {
        match read {
            kr_client::LaunchSurfaceRead::Served(surface) => Self::Served { surface },
            kr_client::LaunchSurfaceRead::NotServed => Self::NotServed,
        }
    }
}

/// What a read of the host's saved launch commands came to, as the page is told.
///
/// The answer holds the commands, which may name a secret, so it has no `Debug` that shows them.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LaunchCommandsAnswer {
    /// The host served the list.
    Served {
        /// The list as the host holds it, and its revision.
        list: ShellLaunchCommandsListResult,
    },
    /// The host is of a release that does not serve the list.
    NotServed,
    /// This connection does not hold the right to read the list.
    Refused,
}

impl From<kr_client::LaunchCommandsRead> for LaunchCommandsAnswer {
    fn from(read: kr_client::LaunchCommandsRead) -> Self {
        match read {
            kr_client::LaunchCommandsRead::Served(list) => Self::Served { list },
            kr_client::LaunchCommandsRead::NotServed => Self::NotServed,
            kr_client::LaunchCommandsRead::Refused => Self::Refused,
        }
    }
}

impl std::fmt::Debug for LaunchCommandsAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Served { .. } => "LaunchCommandsAnswer::Served",
            Self::NotServed => "LaunchCommandsAnswer::NotServed",
            Self::Refused => "LaunchCommandsAnswer::Refused",
        })
    }
}

/// A launch as the page presses it: the command to install, and the prompt generation and the
/// buffer revision of the read its button was drawn from.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Press {
    /// What to install in the editor.
    pub command: LaunchCommand,
    /// The prompt generation the read named.
    pub expected_prompt_generation: PromptGeneration,
    /// The buffer revision the read named.
    pub expected_buffer_revision: EditorBufferRevision,
}

impl Press {
    /// The launch for `session_id`.
    #[must_use]
    pub fn for_session(self, session_id: SessionId) -> ShellLaunchParams {
        ShellLaunchParams {
            session_id,
            command: self.command,
            expected_prompt_generation: self.expected_prompt_generation,
            expected_buffer_revision: self.expected_buffer_revision,
        }
    }
}
