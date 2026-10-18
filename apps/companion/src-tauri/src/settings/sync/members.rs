//! Who shares this person's settings: the devices that hold the collection's key, the ones a host
//! lists that could, and joining a collection another device shares.
//!
//! The rules about who may hold the key are `kr_client::sync::membership::SyncMembership`'s: a key
//! reaches a device only through a record an owner issued after confirming it, and only for a
//! device one of its hosts lists as paired and holding the right to manage the host. This module is
//! the companion's half of that:
//!
//! * **The hosts' device lists** are asked of every host this computer can ask ([`Hosts::device_lists`])
//!   and handed to the membership as what each host says of each device's keys, its right to manage
//!   the host and whether it was revoked. A host that revoked a device is how the membership learns
//!   to take that device out.
//! * **The owner's presence** is asked for through the platform's ceremony, with what it would do as
//!   its reason, before a device is added to the collection and before this computer joins one. The
//!   page names a device by an opaque reference and never holds a key. Taking a device out needs no
//!   ceremony: taking rights away asks for no new confirmation.
//! * **The page is shown** [`DevicesView`], made at the end of each step from the membership's own
//!   record, so showing it asks nobody anything.
//!
//! Every operation here takes the step settings sync holds, so the ceremony a person is at keeps the
//! next background step waiting rather than running under it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::pairing::owner::{CeremonyKind, CeremonyOutcome};
use kr_client::services::ManagedSyncService;
use kr_client::sync::membership::{
    CollectionRef, Device, DeviceDirectory, Ended, HostAnswers, HostDevice, HostReport, Outcome,
    SyncMembership,
};
use kr_protocol::scalars::AuthorisationKey;
use serde::Serialize;

use super::{Record, SettingsSync, installation_id_of, member_failure, now};
use crate::error::{CommandError, Result};
use crate::settings::Hosts;

/// How long the person is given at the ceremony.
const CONFIRM_WITHIN: Duration = Duration::from_secs(90);

/// How long what the hosts listed is believed by a background step. A step the person asked for
/// asks again.
const LISTS_FRESH: Duration = Duration::from_secs(60);

/// What the page is shown of who shares the settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DevicesView {
    /// Whether this computer can ask the person to confirm: without a ceremony it adds and joins
    /// nothing.
    pub can_confirm: bool,
    /// Whether this computer was taken out of the shared settings, so that joining them again waits
    /// for the person to confirm here.
    pub out: bool,
    /// Whether what the service holds is sealed under keys this computer has not been given, so
    /// that it waits for another device to seal it again.
    pub waiting: bool,
    /// The devices that hold the settings' key, this computer among them.
    pub members: Vec<Member>,
    /// The devices a host lists that could be given the key.
    pub candidates: Vec<Candidate>,
    /// The collections other devices share with this one, which it could join.
    pub offers: Vec<Offer>,
    /// What happened to changes the person asked for, until they dismiss it.
    pub outcomes: Vec<Happened>,
}

/// A device that holds the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Member {
    /// What a command names it by.
    pub reference: String,
    /// What it is called.
    pub name: String,
    /// Whether it is this computer.
    pub this_computer: bool,
    /// Whether a host still lists it as able to manage the host. One that no host does is taken
    /// out at the next step.
    pub vouched: bool,
}

/// A device that could be given the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// What a command names it by.
    pub reference: String,
    /// What it is called.
    pub name: String,
}

/// A collection another device shares with this one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Offer {
    /// What a command names it by.
    pub reference: String,
}

/// What became of a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Happened {
    /// Which change: `addition`, `removal` or `join`.
    pub what: &'static str,
    /// How it ended: `done`, `cancelled` or `refused`.
    pub ended: &'static str,
    /// The device, when there is one to name.
    pub name: Option<String>,
}

/// How much of the hosts' answer a step wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ask {
    /// None: a collection of one device has nobody to check.
    Never,
    /// What was listed a minute ago, if it was.
    Recent,
    /// A fresh list from every host.
    Now,
}

/// What this computer knows of the devices its hosts listed, shared by every membership it opens.
#[derive(Default)]
pub(super) struct Listed {
    names: Mutex<BTreeMap<AuthorisationKey, String>>,
    last: Mutex<Option<(Instant, HostAnswers)>>,
}

impl Listed {
    fn name_of(&self, device: &AuthorisationKey) -> Option<String> {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(device)
            .cloned()
    }
}

/// The membership's view of this computer's hosts.
pub(super) struct HostsDirectory {
    hosts: Arc<dyn Hosts>,
    listed: Arc<Listed>,
    ask: Ask,
}

impl std::fmt::Debug for HostsDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostsDirectory")
            .finish_non_exhaustive()
    }
}

impl HostsDirectory {
    pub(super) fn new(hosts: Arc<dyn Hosts>, listed: Arc<Listed>, ask: Ask) -> Self {
        Self { hosts, listed, ask }
    }
}

impl DeviceDirectory for HostsDirectory {
    fn answers(&self) -> kr_client::services::ServiceFuture<'_, Option<HostAnswers>> {
        Box::pin(async move {
            if self.ask == Ask::Never {
                return Ok(None);
            }
            if self.ask == Ask::Recent
                && let Some((at, answers)) = &*self
                    .listed
                    .last
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                && at.elapsed() < LISTS_FRESH
            {
                return Ok(Some(answers.clone()));
            }
            let lists = self.hosts.device_lists().await;
            if lists.is_empty() {
                return Ok(None);
            }
            let mut reports = Vec::new();
            let mut names = self
                .listed
                .names
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for list in &lists {
                let mut devices = Vec::new();
                for summary in &list.devices {
                    // A device whose four keys the host does not report yet is not one another
                    // device seals to: the pairing the owner approved is what binds a key to a
                    // device.
                    let Some(keys) = summary.keys.0 else { continue };
                    names.insert(keys.authorisation, summary.display_name.clone());
                    devices.push(HostDevice {
                        authorisation: keys.authorisation,
                        stored_envelope: keys.stored_envelope,
                        manages_host: summary.manages_host,
                        revoked: summary.revoked,
                    });
                }
                reports.push(HostReport { devices });
            }
            drop(names);
            let answers = HostAnswers { reports };
            *self
                .listed
                .last
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), answers.clone()));
            Ok(Some(answers))
        })
    }
}

impl SettingsSync {
    /// What the page is shown of who shares the settings.
    pub(super) fn devices_view(&self) -> DevicesView {
        let mut view = self
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        view.can_confirm = self.ceremony.kind() != CeremonyKind::None;
        view.waiting = self.waiting.load(std::sync::atomic::Ordering::Relaxed);
        view
    }

    /// Makes the cached view from the membership's own record. It asks nobody anything.
    pub(super) fn note_devices(&self, membership: &SyncMembership) {
        let name = |device: &Device| {
            self.listed
                .name_of(&device.authorisation)
                .unwrap_or_else(|| "another device".to_owned())
        };
        let Ok(Some(status)) = membership.members() else {
            let mut cached = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            cached.members.clear();
            cached.candidates.clear();
            cached.out = false;
            return;
        };
        let members = status
            .members
            .iter()
            .map(|member| Member {
                reference: installation_id_of(&member.device),
                name: if member.is_self {
                    "This computer".to_owned()
                } else {
                    name(&member.device)
                },
                this_computer: member.is_self,
                vouched: member.passes || member.is_self,
            })
            .collect();
        let candidates = membership
            .candidates()
            .unwrap_or_default()
            .iter()
            .map(|device| Candidate {
                reference: installation_id_of(device),
                name: name(device),
            })
            .collect();
        let outcomes = membership
            .outcomes()
            .unwrap_or_default()
            .iter()
            .map(|outcome| happened(outcome, &name))
            .collect();
        let mut cached = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        cached.members = members;
        cached.candidates = candidates;
        cached.outcomes = outcomes;
        cached.out = status.out;
        if !status.out {
            cached.offers.clear();
        }
    }

    /// The membership of this computer's collection, with the hosts asked for as much as `ask` says.
    pub(super) fn membership_asking(
        &self,
        service: &Arc<ManagedSyncService>,
        ask: Ask,
    ) -> Result<SyncMembership> {
        self.membership_with(
            service,
            Arc::new(HostsDirectory::new(
                Arc::clone(&self.hosts),
                Arc::clone(&self.listed),
                ask,
            )),
        )
    }

    /// How much of the hosts' answer a step needs, given what it was asked for: a collection of one
    /// device with nothing pending has nobody to check, so a background step asks no host.
    pub(super) fn ask_for(&self, service: &Arc<ManagedSyncService>, wanted: Ask) -> Result<Ask> {
        let held = self
            .membership_with(
                service,
                Arc::new(HostsDirectory::new(
                    Arc::clone(&self.hosts),
                    Arc::clone(&self.listed),
                    Ask::Never,
                )),
            )?
            .members()
            .map_err(member_failure)?;
        Ok(match held {
            Some(status)
                if status.members.len() > 1
                    || status.out
                    || !status.removals.is_empty()
                    || status.addition.is_some()
                    || status.candidate.is_some() =>
            {
                wanted
            }
            _ if wanted == Ask::Now => Ask::Now,
            _ => Ask::Never,
        })
    }

    /// Asks every host who it lists, brings this computer and the service to the same settings, and
    /// looks for a collection another device shares when this computer holds none.
    ///
    /// # Errors
    ///
    /// Returns what stopped it: a service that could not be reached, or a local record.
    pub async fn devices_refresh(&self) -> Result<()> {
        let outcome = self.devices_refresh_in_a_step().await;
        self.finished(&outcome);
        outcome
    }

    async fn devices_refresh_in_a_step(&self) -> Result<()> {
        let _step = self.step().await?;
        let held = self.record()?;
        let origin = match &held {
            Some(record) => record.origin()?,
            None => self.parts.service.origin().clone(),
        };
        let service = self.managed(&origin)?;
        let mut out = held.is_none();
        if let Some(mut record) = held {
            self.settle(&mut record, &service, Ask::Now).await?;
            out = self
                .devices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .out;
        }
        if out {
            self.look_for_offers(&service).await?;
        }
        Ok(())
    }

    /// The collections the service says name this installation, kept for the page to offer.
    async fn look_for_offers(&self, service: &Arc<ManagedSyncService>) -> Result<()> {
        let listed = service.memberships().await.map_err(CommandError::from)?;
        let held = self.membership_asking(service, Ask::Never)?;
        let current = held.members().map_err(member_failure)?;
        let mut offered: Vec<CollectionRef> = Vec::new();
        for entry in listed {
            // A collection this computer is in is not one to join.
            if current
                .as_ref()
                .is_some_and(|status| !status.out && status.collection == entry.collection)
            {
                continue;
            }
            offered.push(entry.collection);
        }
        let offers = offered
            .iter()
            .map(|collection| Offer {
                reference: collection.collection_id.to_string(),
            })
            .collect();
        *self.offered.lock().unwrap_or_else(PoisonError::into_inner) = offered;
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .offers = offers;
        self.told.tell();
        Ok(())
    }

    /// Gives the device `reference` names the settings' key, once the person confirms it here.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no host lists such a device, or the person did not confirm; and what
    /// stopped the step otherwise.
    pub async fn share(&self, reference: &str) -> Result<()> {
        let outcome = self.share_in_a_step(reference).await;
        self.finished(&outcome);
        outcome
    }

    async fn share_in_a_step(&self, reference: &str) -> Result<()> {
        let _step = self.step().await?;
        let mut record = self
            .record()?
            .ok_or_else(|| CommandError::refused("settings sync is not on"))?;
        let service = self.managed(&record.origin()?)?;
        let mut membership = self.membership_asking(&service, Ask::Now)?;
        membership.refresh().await.map_err(member_failure)?;
        let device = membership
            .candidates()
            .map_err(member_failure)?
            .into_iter()
            .find(|device| installation_id_of(device) == reference)
            .ok_or_else(|| CommandError::refused("no host lists that device any more"))?;
        let name = self
            .listed
            .name_of(&device.authorisation)
            .unwrap_or_else(|| "another device".to_owned());
        let plan = membership
            .plan_share(&device.authorisation, now())
            .map_err(member_failure)?;
        self.confirmed(
            &mut membership,
            &plan,
            &format!("Share your settings with {name}"),
        )
        .await?;
        let ended = membership.authorise(&plan, now()).map_err(member_failure)?;
        drop(membership);
        // The key moves on with the addition, and the new device reads only what is sealed under
        // the new one: carrying it out seals the settings again.
        self.settle(&mut record, &service, Ask::Now).await?;
        match ended {
            Ended::Refused => Err(CommandError::refused(
                "that device cannot be given the settings now: a host does not list it, or it is \
                 being taken out",
            )),
            Ended::Done | Ended::Cancelled => Ok(()),
        }
    }

    /// Takes the device `reference` names out of the shared settings.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no member is named so, and what stopped the step otherwise.
    pub async fn remove(&self, reference: &str) -> Result<()> {
        let outcome = self.remove_in_a_step(reference).await;
        self.finished(&outcome);
        outcome
    }

    async fn remove_in_a_step(&self, reference: &str) -> Result<()> {
        let _step = self.step().await?;
        let mut record = self
            .record()?
            .ok_or_else(|| CommandError::refused("settings sync is not on"))?;
        let service = self.managed(&record.origin()?)?;
        let mut membership = self.membership_asking(&service, Ask::Now)?;
        let device = membership
            .members()
            .map_err(member_failure)?
            .and_then(|status| {
                status
                    .members
                    .into_iter()
                    .find(|member| installation_id_of(&member.device) == reference)
            })
            .ok_or_else(|| CommandError::refused("that device does not share the settings"))?;
        membership
            .remove(&device.device.authorisation)
            .map_err(member_failure)?;
        drop(membership);
        self.settle(&mut record, &service, Ask::Now)
            .await
            .map(|_| ())
    }

    /// Joins the collection `reference` names, once the person confirms it here.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the offer is gone, this computer already shares settings, or the
    /// person did not confirm; and what stopped the step otherwise.
    pub async fn join(&self, reference: &str) -> Result<()> {
        let outcome = self.join_in_a_step(reference).await;
        self.finished(&outcome);
        outcome
    }

    async fn join_in_a_step(&self, reference: &str) -> Result<()> {
        let _step = self.step().await?;
        let held = self.record()?;
        let origin = match &held {
            Some(record) => record.origin()?,
            None => self.parts.service.origin().clone(),
        };
        let service = self.managed(&origin)?;
        // The offer is asked for again: it may be gone, and the one joined is the service's word.
        self.look_for_offers(&service).await?;
        let collection = self
            .offered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|collection| collection.collection_id.to_string() == reference)
            .copied()
            .ok_or_else(|| CommandError::refused("that offer is not there any more"))?;
        let mut membership = self.membership_asking(&service, Ask::Now)?;
        let plan = membership
            .plan_join(collection, now())
            .map_err(member_failure)?;
        self.confirmed(
            &mut membership,
            &plan,
            "Join the settings your other device shares",
        )
        .await?;
        membership
            .join(&plan, now())
            .await
            .map_err(member_failure)?;
        drop(membership);
        let mut record = Record {
            version: Record::VERSION,
            service_origin: origin.as_str().to_owned(),
            collection_id: collection.collection_id,
            started: false,
            sealed_epoch: 0,
        };
        self.keep(&record)?;
        self.settle(&mut record, &service, Ask::Now)
            .await
            .map(|_| ())
    }

    /// Asks the person to confirm `plan` through the platform's ceremony, with `reason` as what the
    /// dialog says, and withdraws the plan when they do not.
    async fn confirmed(
        &self,
        membership: &mut SyncMembership,
        plan: &kr_client::sync::membership::Plan,
        reason: &str,
    ) -> Result<()> {
        match self.ceremony.verify(reason, CONFIRM_WITHIN).await {
            CeremonyOutcome::Confirmed => Ok(()),
            CeremonyOutcome::NotConfirmed => {
                membership.cancel(plan);
                Err(CommandError::refused(
                    "it was not confirmed, so nothing was changed",
                ))
            }
            CeremonyOutcome::Unavailable => {
                membership.cancel(plan);
                Err(CommandError::unsupported(
                    "this computer has no way to ask you to confirm, so it adds and joins nothing",
                ))
            }
        }
    }

    /// Lets go of the outcomes the page has shown.
    ///
    /// # Errors
    ///
    /// Returns what stopped it: the membership could not be used.
    pub async fn dismiss_outcomes(&self) -> Result<()> {
        let _step = self.step().await?;
        let Some(record) = self.record()? else {
            return Ok(());
        };
        let service = self.managed(&record.origin()?)?;
        let mut membership = self.membership_asking(&service, Ask::Never)?;
        let shown = self
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .outcomes
            .len();
        membership
            .acknowledge_outcomes(shown)
            .map_err(member_failure)?;
        self.note_devices(&membership);
        self.told.tell();
        Ok(())
    }
}

/// An outcome, in the words the page keeps for it.
fn happened(outcome: &Outcome<Device>, name: &dyn Fn(&Device) -> String) -> Happened {
    let ended = |ended: &Ended| match ended {
        Ended::Done => "done",
        Ended::Cancelled => "cancelled",
        Ended::Refused => "refused",
    };
    match outcome {
        Outcome::Addition { device, ended: how } => Happened {
            what: "addition",
            ended: ended(how),
            name: Some(name(device)),
        },
        Outcome::Removal { device, ended: how } => Happened {
            what: "removal",
            ended: ended(how),
            name: Some(name(device)),
        },
        Outcome::Join { ended: how } => Happened {
            what: "join",
            ended: ended(how),
            name: None,
        },
    }
}
