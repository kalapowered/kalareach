//! Who sent a prompt that goes out on a channel.
//!
//! A channel carries a message into an agent that cannot tell who typed it, so the host says what
//! it verified about the sender: the actor, how the request entered the host, and the device and
//! grant it came under. The sender travels with the prompt and nothing reads it yet.

use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{ActorId, DeviceId, GrantId};

use crate::broker::methods::Caller;

/// What the host verified about the sender of one prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptSender {
    /// The host-verified actor.
    pub actor_id: ActorId,
    /// Where the request entered the host.
    pub ingress: ActorIngress,
    /// The paired device it came from, when it came from one.
    pub device_id: Option<DeviceId>,
    /// The grant the actor's authority comes from, when one does.
    pub grant_id: Option<GrantId>,
}

impl PromptSender {
    /// The sender a caller presents.
    #[must_use]
    pub fn of(caller: &Caller) -> Self {
        Self {
            actor_id: caller.actor_id.clone(),
            ingress: caller.ingress,
            device_id: caller.device_id,
            grant_id: caller.grant_id,
        }
    }
}
