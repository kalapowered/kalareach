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
//! The door also keeps what every arrival under one identifier is doing from the moment it has the
//! mutation: it has not decided yet, it is carrying the action out, or it has been refused. A copy
//! that is refused for its window, and finds no claim for its action, asks the others which of them
//! may still carry the action out. That is a question of the arrivals that are running and of those
//! that have not decided, and the copy waits for the latter to decide, so it is neither refused
//! while a first attempt is about to claim, nor told that the outcome is not known because of
//! another copy that is refused as well.
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

/// What the arrivals under one identifier, for one mutation, are doing.
#[derive(Debug, Default)]
struct Arrivals {
    /// How many arrivals hold the identifier for the mutation.
    arrivals: usize,
    /// How many of them have neither started their effect nor been refused.
    undecided: usize,
    /// How many of them are carrying the action out.
    running: usize,
}

/// The arrivals at the door, and what changes in them.
#[derive(Debug, Default)]
struct Door {
    arrivals: Mutex<HashMap<(ActorId, ActionId, Digest256), Arrivals>>,
    /// Woken when an arrival decides, or ends.
    changed: tokio::sync::Notify,
    /// Where this host's own tests are told that a copy is waiting for an arrival to decide. Armed
    /// once, it fires once. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    a_copy_waits: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

/// Where an arrival stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// It has not started its effect and has not been refused.
    Undecided,
    /// It is carrying the action out.
    Running,
    /// It has been refused and carries nothing out.
    Refused,
}

/// An arrival at the door, from the moment the door has its mutation until the arrival has ended,
/// whatever it comes to.
#[must_use = "the arrival is forgotten when this is dropped"]
pub(super) struct Arrival {
    door: Arc<Door>,
    key: (ActorId, ActionId, Digest256),
    stage: Stage,
}

/// The identifiers being performed: each with the digest of the mutation it is performed for and
/// how many arrivals are performing it.
type Held = HashMap<(ActorId, ActionId), (Digest256, usize)>;

/// The identifiers this daemon is performing, each with the digest of the mutation it is performed
/// for and how many arrivals are performing it.
#[derive(Debug, Default)]
pub(super) struct Performing {
    held: Arc<Mutex<Held>>,
    door: Arc<Door>,
}

/// An identifier being performed, until the effect it was taken for has ended.
#[must_use = "the identifier is released when this is dropped"]
pub(super) struct Spending {
    held: Arc<Mutex<Held>>,
    key: (ActorId, ActionId),
}

impl Performing {
    /// Arms the signal that the next copy to wait for an arrival to decide gives. Returns the end
    /// that says it is waiting.
    #[cfg(feature = "testing")]
    pub(super) fn notify_when_a_copy_waits(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (waiting, told) = tokio::sync::oneshot::channel();
        *self
            .door
            .a_copy_waits
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(waiting);
        told
    }

    /// Records an arrival under the identifier for the mutation whose digest this is.
    fn arrive(&self, actor_id: &ActorId, action_id: ActionId, digest: Digest256) -> Arrival {
        let key = (actor_id.clone(), action_id, digest);
        {
            let mut arrivals = self
                .door
                .arrivals
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let entry = arrivals.entry(key.clone()).or_default();
            entry.arrivals += 1;
            entry.undecided += 1;
        }
        Arrival {
            door: Arc::clone(&self.door),
            key,
            stage: Stage::Undecided,
        }
    }

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

impl Arrival {
    /// Says that this arrival is going on to carry its action out. A copy that was refused for its
    /// window and found a claim open goes on to finish what the claim began, and is one that runs.
    pub(super) fn runs(&mut self) {
        let was_undecided = match self.stage {
            Stage::Running => return,
            Stage::Undecided => true,
            Stage::Refused => false,
        };
        {
            let mut arrivals = self
                .door
                .arrivals
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = arrivals.get_mut(&self.key) {
                if was_undecided {
                    entry.undecided -= 1;
                }
                entry.running += 1;
            }
        }
        self.stage = Stage::Running;
        self.door.changed.notify_waiters();
    }

    /// Says that this arrival is refused, waits until every other arrival under the identifier for
    /// the same mutation has decided, and whether one of them is carrying the action out.
    ///
    /// It is asked by a copy that its window refuses and that finds no claim for its action. An
    /// arrival that has not decided may be a first attempt about to write its claim, so the copy
    /// waits for it: refused while the first attempt goes on to run, it would have a refusal the
    /// host cannot stand behind, and told that the outcome is not known because of an arrival that
    /// is refused as well, it would be told what is not so. An arrival decides without waiting for
    /// anything this one holds, so the wait ends. It must be asked before the claim is read: asked
    /// after, it can find the arrival that ran gone, its claim written and settled in between.
    pub(super) async fn another_may_carry_it_out(&mut self) -> bool {
        if self.stage == Stage::Undecided {
            {
                let mut arrivals = self
                    .door
                    .arrivals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(entry) = arrivals.get_mut(&self.key) {
                    entry.undecided -= 1;
                }
            }
            self.stage = Stage::Refused;
            self.door.changed.notify_waiters();
        }
        loop {
            let changed = self.door.changed.notified();
            tokio::pin!(changed);
            // Registered before the arrivals are looked at, so a decision made between the look and
            // the wait is not missed.
            changed.as_mut().enable();
            {
                let arrivals = self
                    .door
                    .arrivals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let Some(entry) = arrivals.get(&self.key) else {
                    return false;
                };
                if entry.undecided == 0 {
                    let own = usize::from(self.stage == Stage::Running);
                    return entry.running > own;
                }
            }
            #[cfg(feature = "testing")]
            if let Some(waiting) = self
                .door
                .a_copy_waits
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                let _ = waiting.send(());
            }
            changed.await;
        }
    }
}

impl Drop for Arrival {
    fn drop(&mut self) {
        {
            let mut arrivals = self
                .door
                .arrivals
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = arrivals.get_mut(&self.key) {
                entry.arrivals -= 1;
                match self.stage {
                    Stage::Undecided => entry.undecided -= 1,
                    Stage::Running => entry.running -= 1,
                    Stage::Refused => {}
                }
                if entry.arrivals == 0 {
                    arrivals.remove(&self.key);
                }
            }
        }
        self.door.changed.notify_waiters();
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
    /// Records the arrival of a mutation at the local door, so that a copy that arrives on another
    /// connection while this one looks for a retained answer or reads the other stores knows that
    /// it is there: it may be the first attempt, about to write the claim of its action.
    ///
    /// Nothing is recorded for a method that keeps no record of its action here, or for a mutation
    /// whose digest cannot be made, which the first admission refuses.
    pub(super) fn arrive(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<Arrival> {
        Domain::of(method)?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        Some(
            self.identifiers_performing
                .arrive(actor_id, mutation.action_id, digest),
        )
    }

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
