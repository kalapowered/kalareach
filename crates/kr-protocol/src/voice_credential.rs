//! The key a host owner sets for voice calls that run on the owner's own provider account.
//!
//! The owner sets the key once, at this machine, with `voice.credential.set`, and the host keeps it
//! in its secret store. `voice.credential.remove` deletes it. No method answers with the key
//! afterwards, no field of any answer has room for it, and a paired device never sees it: the
//! methods are on the local socket alone.
//!
//! The key is a [`SecretText`], so it redacts itself in debug output and clears its bytes when it
//! is dropped.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::delivery::SecretText;

/// The shortest key this host takes, in bytes.
pub const MIN_VOICE_KEY_LEN: usize = 20;

/// The longest key this host takes, in bytes.
pub const MAX_VOICE_KEY_LEN: usize = 256;

/// The providers a key can be kept for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VoiceCredentialKind {
    /// OpenAI's live voice sessions.
    OpenaiLive,
}

impl VoiceCredentialKind {
    /// The name the stored item and the JSON form carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiLive => "openai_live",
        }
    }
}

/// Parameters of `voice.credential.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceCredentialSetParams {
    /// Which provider the key is for.
    pub kind: VoiceCredentialKind,
    /// The key: printable ASCII with no whitespace, 20 to 256 bytes.
    pub key: SecretText,
}

/// The result of `voice.credential.set`. It never carries the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceCredentialSetResult {
    /// Which provider the key is for.
    pub kind: VoiceCredentialKind,
    /// Whether this host holds the key now.
    pub in_force: bool,
}

/// Parameters of `voice.credential.remove`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceCredentialRemoveParams {
    /// Which provider's key to delete.
    pub kind: VoiceCredentialKind,
}

/// The result of `voice.credential.remove`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceCredentialRemoveResult {
    /// Which provider's key the answer is about.
    pub kind: VoiceCredentialKind,
    /// Whether the host held a key that this call deleted.
    pub removed: bool,
}

/// Checks the shape of a key: 20 to 256 bytes of printable ASCII with no whitespace.
///
/// No prefix test: the format of a key belongs to the provider that issues it, and a guess about
/// it would refuse a good key or accept a bad one.
///
/// # Errors
///
/// Returns the rule the key broke. The key itself is never part of the answer.
pub fn check_voice_key(key: &SecretText) -> Result<(), &'static str> {
    let text = key.expose();
    if text.len() < MIN_VOICE_KEY_LEN || text.len() > MAX_VOICE_KEY_LEN {
        return Err("a voice key is 20 to 256 characters long");
    }
    if !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("a voice key is printable ASCII with no space");
    }
    Ok(())
}
