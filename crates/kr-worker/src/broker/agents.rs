//! What the broker tells the question ledger about the agent a process belongs to.
//!
//! The broker is the qualified bridge section 11 means: it launched the agent, knows its process by
//! its start identity, and advances the agent's binding revision when the upstream owner or the
//! selected thread changes. A contact helper that agent starts asks its questions under that
//! binding, and [`crate::questions`] invalidates the unanswered ones when it moves on.

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId};

use crate::broker::Broker;
use crate::questions::binding::{AgentBinding, AgentBindings, nearest_of};

impl AgentBindings for Broker {
    fn binding_of(&self, process: &ProcessStartIdentity) -> Option<AgentBinding> {
        // The launched processes are read under the lock and the walk happens after it is
        // released: the walk reads the process table, and nothing that holds the broker waits on
        // that. A revision that advances between the two leaves a question asked under the older
        // one, which the next sweep invalidates, so the race costs a question and never an answer.
        let launched: Vec<(
            ApplicationInstanceId,
            ProcessStartIdentity,
            AgentBindingRevision,
        )> = {
            let state = self.state();
            state
                .instances
                .values()
                .filter_map(|instance| {
                    instance.process.as_ref().map(|launched| {
                        (
                            instance.application_instance_id,
                            launched.process.clone(),
                            instance.binding_revision,
                        )
                    })
                })
                .collect()
        };
        let identities: Vec<ProcessStartIdentity> = launched
            .iter()
            .map(|(_, identity, _)| identity.clone())
            .collect();
        let nearest = nearest_of(process, &identities)?;
        let (application_instance_id, _, revision) = launched.get(nearest)?;
        Some(AgentBinding {
            application_instance_id: *application_instance_id,
            revision: *revision,
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
