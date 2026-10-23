//! The identifier of a mutation at the local door, checked in every record domain this daemon keeps.
//!
//! An action is spent under its actor and its identifier, and each of the daemon's stores keeps its
//! own record of the actions it performed. Every store compares an arriving mutation with its own
//! records alone, so an identifier a project change spent would pass for a workflow change, and the
//! change would be performed twice under one name. The device door claims the identifier first in
//! the device directory and so has no such gap. The local door has none to claim in, so it asks the
//! other stores: before a first admission it reads, in every record domain but the one that serves
//! the method, whether the actor already holds a record under the identifier. A hit is an
//! identifier spent on another method, and the mutation is refused before its effect.
//!
//! Only presence is asked, because a record in another domain is a record of another method. The
//! reads take no lock a service holds: each store is opened read-only through a connection of its
//! own, and the record of an installation is a file, so a catalogue synchronisation that is
//! fetching, or an installation that is under way, holds nothing up. A read that fails refuses the
//! admission, because a store that cannot be read is not one that holds nothing.
//!
//! Two arrivals under one identifier at once could both read nothing before either has written.
//! The daemon therefore keeps, in memory, the identifiers it is performing, with the digest of the
//! mutation each is performed for. An arrival whose identifier is being performed for a different
//! mutation is refused; one for the same mutation goes on and meets the store's own claim, as a
//! retry does. One daemon runs per environment, so memory is enough for the arrivals that are
//! simultaneous, and the reads cover the ones that follow, a restart among them.
//!
//! What this does not cover: a mutation forwarded to a worker (a close, a prompt) is kept in that
//! worker's journal, which the daemon does not read here; and four methods keep no record of their
//! action and so spend no identifier (`organisation.policy.apply`, `membership.present`,
//! `backup.enable` and `backup.bundle.write`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::envelope::MutationRequest;
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Digest256;

use super::Controller;
use super::local::{RETAINED_AUTHORITY_ANSWERS, RETAINED_MACHINE_ANSWERS};
use crate::error::{ControllerError, Result};

/// Where this daemon keeps a record of an action under its actor and its identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    /// The grant store's claims, which keep the answer of an authority change, a voice change, a
    /// machine group step and the host's own settings.
    AuthorityClaims,
    /// The registry's reservations, which keep the token a session create named.
    SessionReservations,
    /// The records of a pairing action.
    Pairing,
    /// The device directory's routes and declarations.
    DeviceDirectory,
    /// The project store.
    Project,
    /// The transfer store.
    Transfer,
    /// The change-set store.
    ChangeSets,
    /// The workflow journal.
    Automation,
    /// The attention store.
    Attention,
    /// The plugin catalogue's receipts.
    Catalogue,
    /// The answers kept for the disclosed capability checks.
    CapabilityAnswers,
    /// The files that record an installation or a removal of the agent tools.
    AgentTools,
}

/// Every domain, in the order they are asked.
const DOMAINS: [Domain; 12] = [
    Domain::AuthorityClaims,
    Domain::SessionReservations,
    Domain::Pairing,
    Domain::DeviceDirectory,
    Domain::Project,
    Domain::Transfer,
    Domain::ChangeSets,
    Domain::Automation,
    Domain::Attention,
    Domain::Catalogue,
    Domain::CapabilityAnswers,
    Domain::AgentTools,
];

impl Domain {
    /// The domain a method keeps the record of its action in, when it keeps one the daemon reads.
    ///
    /// A method that records in two domains would be refused for its own first attempt, left half
    /// done and asked again, so each method's arm in `write_method` was read for where it records.
    /// None records in two. A method that is forwarded to a worker, and one that keeps no record
    /// of its action, are in none.
    fn of(method: Method) -> Option<Self> {
        if matches!(method, Method::AgentToolsInstall | Method::AgentToolsRemove) {
            Some(Self::AgentTools)
        } else if RETAINED_AUTHORITY_ANSWERS.contains(&method)
            || RETAINED_MACHINE_ANSWERS.contains(&method)
            || crate::voice::VoiceModule::serves(method)
        {
            Some(Self::AuthorityClaims)
        } else if method == Method::EnvironmentCapabilitiesCheck {
            Some(Self::CapabilityAnswers)
        } else if method == Method::SessionCreate {
            Some(Self::SessionReservations)
        } else if method == Method::DeviceKeysComplete {
            Some(Self::DeviceDirectory)
        } else if crate::transfer::TransferModule::serves(method) {
            Some(Self::Transfer)
        } else if crate::project::ProjectModule::serves(method) {
            Some(Self::Project)
        } else if crate::catalogue::CatalogueModule::serves(method) {
            Some(Self::Catalogue)
        } else if crate::changeset::ChangeSetModule::serves(method) {
            Some(Self::ChangeSets)
        } else if crate::automation::AutomationModule::serves(method) {
            Some(Self::Automation)
        } else if crate::attention::AttentionModule::serves(method) {
            Some(Self::Attention)
        } else if super::net::methods::serves(method) {
            Some(Self::Pairing)
        } else {
            None
        }
    }

    /// Whether the actor holds a record under the identifier in this domain.
    fn holds(
        self,
        paths: &EnvironmentPaths,
        actor_id: &ActorId,
        action_id: ActionId,
    ) -> Result<bool> {
        let registry = paths.registry_database();
        match self {
            Self::AuthorityClaims => {
                crate::grants::GrantDirectory::holds_action(&registry, actor_id, action_id)
            }
            Self::SessionReservations => {
                crate::registry::Registry::holds_token(&registry, actor_id, action_id.get())
            }
            Self::Pairing => {
                super::net::invitations::holds_pairing_action(&registry, actor_id, action_id)
            }
            Self::DeviceDirectory => {
                super::net::devices::DeviceDirectory::holds_action(&registry, actor_id, action_id)
            }
            Self::Project => {
                kr_project::ProjectService::holds_action(paths, actor_id, action_id.get())
                    .map_err(storage)
            }
            Self::Transfer => {
                kr_transfer::TransferService::holds_action(paths, actor_id, action_id.get())
                    .map_err(storage)
            }
            Self::ChangeSets => {
                kr_changeset::ChangeSetService::holds_action(paths, actor_id, action_id.get())
                    .map_err(storage)
            }
            Self::Automation => kr_automation::store::WorkflowStore::holds_action(
                paths.state_dir(),
                actor_id.as_str(),
                &action_id.to_string(),
            )
            .map_err(storage),
            Self::Attention => kr_attention::Attention::holds_action(
                paths.state_dir().join("attention.sqlite3"),
                actor_id,
                &action_id.to_string(),
            )
            .map_err(storage),
            Self::Catalogue => kr_plugin_catalogue::db::holds_action(
                &paths.state_dir().join("catalogue"),
                actor_id.as_str(),
                &action_id.to_string(),
            )
            .map_err(storage),
            Self::CapabilityAnswers => {
                crate::capability_answers::Record::holds(paths.state_dir(), actor_id, action_id)
            }
            Self::AgentTools => crate::agent_tools::holds_installation_action(
                paths.state_dir(),
                actor_id,
                action_id,
            ),
        }
    }
}

/// A store's refusal to be read, as the daemon says it.
fn storage(error: impl std::fmt::Display) -> ControllerError {
    ControllerError::Storage {
        operation: "check whether another action spent this identifier",
        detail: error.to_string(),
    }
}

/// The identifiers being performed: each with the digest of the mutation it is performed for and
/// how many arrivals are performing it.
type Held = HashMap<(ActorId, ActionId), (Digest256, usize)>;

/// The identifiers this daemon is performing, each with the digest of the mutation it is performed
/// for and how many arrivals are performing it.
#[derive(Debug, Default)]
pub(super) struct Performing {
    held: Arc<Mutex<Held>>,
}

/// An identifier being performed, until the effect it was taken for has ended.
#[must_use = "the identifier is released when this is dropped"]
pub(super) struct Spending {
    held: Arc<Mutex<Held>>,
    key: (ActorId, ActionId),
}

impl Performing {
    /// Takes the identifier for the mutation whose digest this is, or says it is being performed
    /// for another.
    fn take(&self, actor_id: &ActorId, action_id: ActionId, digest: Digest256) -> Option<Spending> {
        let key = (actor_id.clone(), action_id);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        match held.get_mut(&key) {
            Some((taken, _)) if *taken != digest => return None,
            Some((_, count)) => *count += 1,
            None => {
                held.insert(key.clone(), (digest, 1));
            }
        }
        Some(Spending {
            held: Arc::clone(&self.held),
            key,
        })
    }
}

impl Drop for Spending {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, count)) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

impl Controller {
    /// Checks that a first admission at the local door spends an identifier no other method of the
    /// same actor has spent, and takes the identifier for the effect.
    ///
    /// Nothing is taken for a method that keeps no record of its action here.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when another method holds a record of the actor's
    /// action under the identifier, or is being performed under it, and a storage error when a
    /// domain cannot be read.
    pub(super) async fn spend_the_identifier(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<Option<Spending>> {
        let Some(own) = Domain::of(method) else {
            return Ok(None);
        };
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let conflict = || ControllerError::IdConflict {
            token: mutation.action_id.to_string(),
        };
        // Taken before the stores are read, so an arrival that is still performing its effect when
        // this one reads is met here and not missed there.
        let spending = self
            .identifiers_performing
            .take(actor_id, mutation.action_id, digest)
            .ok_or_else(conflict)?;
        let paths = self.paths.clone();
        let (actor, action_id) = (actor_id.clone(), mutation.action_id);
        let spent_elsewhere = tokio::task::spawn_blocking(move || -> Result<bool> {
            for domain in DOMAINS {
                if domain != own && domain.holds(&paths, &actor, action_id)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
        .map_err(|_| {
            storage("the check was stopped before it had read every record the daemon keeps")
        })??;
        if spent_elsewhere {
            return Err(conflict());
        }
        Ok(Some(spending))
    }
}
