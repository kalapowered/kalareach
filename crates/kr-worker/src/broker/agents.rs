//! What the broker tells the question ledger about the agent a process belongs to.
//!
//! The broker launched the agent and knows its process by its start identity, so a contact helper
//! that agent starts is found by the kernel's parent chain, link by link, and its questions belong
//! to the agent's application instance: they end when that instance ends.
//!
//! That chain proves which application a helper serves and nothing about which thread a request
//! came from. One helper can serve several threads, one after another or at once, and a request
//! made in one thread can arrive after the broker has seen another selected. Section 11 records a
//! thread binding only with verified per-request source context, so this bridge attests none: the
//! questions are application-scoped and no thread-switch detection is claimed for them.

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId};

use crate::broker::Broker;
use crate::questions::binding::{AgentBinding, AgentBindings, nearest_of};

impl AgentBindings for Broker {
    fn binding_of(&self, process: &ProcessStartIdentity) -> Option<AgentBinding> {
        // The launched processes are read under the lock and the walk happens after it is
        // released: the walk reads the process table, and nothing that holds the broker waits on
        // that. An instance that ends between the two is found ended by the next sweep.
        let launched: Vec<(ApplicationInstanceId, ProcessStartIdentity)> = {
            let state = self.state();
            state
                .instances
                .values()
                .filter_map(|instance| {
                    instance.process.as_ref().map(|launched| {
                        (instance.application_instance_id, launched.process.clone())
                    })
                })
                .collect()
        };
        let identities: Vec<ProcessStartIdentity> = launched
            .iter()
            .map(|(_, identity)| identity.clone())
            .collect();
        let nearest = nearest_of(process, &identities)?;
        let (application_instance_id, _) = launched.get(nearest)?;
        Some(AgentBinding {
            application_instance_id: *application_instance_id,
            revision: None,
        })
    }

    fn current(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<AgentBindingRevision> {
        self.binding_state(application_instance_id)
            .ok()
            .map(|state| state.binding_revision)
    }
}
