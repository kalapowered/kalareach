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
