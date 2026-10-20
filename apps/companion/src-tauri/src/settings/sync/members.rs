//! Who shares this person's settings: the devices that hold the collection's key, the ones a host
//! lists that could, and joining a collection another device shares.
//!
//! The rules about who may hold the key are `kr_client::sync::membership::SyncMembership`'s: a key
//! reaches a device only through a record an owner issued after confirming it, and only for a
//! device one of its hosts lists as paired and holding the right to manage the host. This module is
//! the companion's half of that:
//!
//! * **The hosts' device lists** are asked of every host this computer owns
//!   ([`Hosts::device_lists`]) and handed to the membership as what each host says of each device's
//!   keys, its right to manage the host and whether it was revoked. A host that revoked a device is
//!   how the membership learns to take that device out. A host that does not answer, or will not
//!   list its devices to this computer, says nothing about any device: the membership is told that
//!   one was silent. A device this computer's hosts vouched for before, and that no answering host
//!   mentions, is then not taken out, and the next key is wrapped to it as before; a device an
//!   answering host mentions is judged by what that host says. Silence accepts, opens and adds
//!   nothing: a record, a key or an addition still needs a host that answered to list the device. A
//!   device a host lists whose right to manage the host has run out with its grant is not one to
//!   share with.
//! * **The owner's presence** is asked for through the platform's ceremony, with what it would do
//!   as its reason, before a device is added to the collection and before this computer joins one.
//!   The page names a device by an opaque reference and never holds a key. Taking a device out
//!   needs no ceremony: taking rights away asks for no new confirmation.
//! * **The page is shown** [`DevicesView`], made at the end of each step from the membership's own
//!   record, so showing it asks nobody anything.
//!
//! Every operation here takes the step settings sync holds, so the ceremony a person is at keeps
//! the next background step waiting rather than running under it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::pairing::owner::{CeremonyKind, CeremonyOutcome};
use kr_client::services::ManagedSyncService;
use kr_client::sync::membership::{
    CollectionRef, Device, DeviceDirectory, Ended, HostAnswers, HostDevice, HostReport,
    MembershipError, Outcome, Refreshed, SyncMembership,
};
use kr_client::{ClientError, Shown};
use kr_protocol::error::ErrorCode;
use kr_protocol::pairing::DevicePlatform;
use kr_protocol::scalars::AuthorisationKey;
use kr_protocol::service::installation_id;
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
    /// The devices this computer took out when the person revoked them, that the hosts still list
    /// as unrevoked: the revoke may not have gone through. Sharing with one again is the person's
    /// choice, and is asked for as sharing with any device is, unless a request to revoke it may
    /// still be carried out.
    pub held_out: Vec<HeldOut>,
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
    /// Whether a host still lists it as able to manage the host, or none that answered mentions it
    /// while one did not answer or refused to list, and its hosts vouched for it before. One that
    /// is not is taken out at the next step.
    pub vouched: bool,
}

/// A device that could be given the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// What a command names it by.
    pub reference: String,
    /// What it is called.
    pub name: String,
    /// The key the device is known by, which decides whether a revoke for it is on record.
    #[serde(skip)]
    key: AuthorisationKey,
}

/// A device this computer took out when the person revoked it, that the hosts still list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HeldOut {
    /// What a command names it by.
    pub reference: String,
    /// What it is called.
    pub name: String,
    /// Whether a revoke for it is on record here, so that it is not offered: a request this
    /// computer published in a host's feed, which a host may carry out or may have carried out, or
    /// a revocation not yet taken in. What is not known is on record: a record this computer cannot
    /// read holds every device.
    pub waiting: bool,
    /// The key the device is known by, which decides whether a request is in force for it.
    #[serde(skip)]
    key: AuthorisationKey,
}

/// A collection another device shares with this one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Offer {
    /// What a command names it by.
    pub reference: String,
    /// The device the collection was started on, when a host lists it. It may be a device since
    /// taken out: it says which offer is which and nothing of who shares it now.
    pub name: Option<String>,
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

/// What the person is told when a device that was taken out when they revoked it is not shared
/// with, because the revoke may still be carried out.
fn revoke_waiting() -> CommandError {
    CommandError::refused(
        "a revoke for that device is on record here, so nothing was shared with it",
    )
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
    /// What each device is called, by the host that listed it first at the last full list.
    names: Mutex<BTreeMap<AuthorisationKey, String>>,
    /// The devices two hosts list with different stored-envelope keys: nothing is shared with one,
    /// because a key sealed to the wrong one of the two is a key given to whoever holds it.
    disputed: Mutex<BTreeSet<AuthorisationKey>>,
    /// The devices a host lists on a platform that has no ceremony to join with: a phone, or a
    /// Linux computer. Settings are not shared with one, because it could never join them.
    cannot_join: Mutex<BTreeSet<AuthorisationKey>>,
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

    /// The name of the device whose installation is `home`, when a host lists it.
    fn name_of_installation(&self, home: kr_protocol::ids::InstallationId) -> Option<String> {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(key, _)| installation_id(key) == home)
            .map(|(_, name)| name.clone())
    }

    fn cannot_join(&self, device: &AuthorisationKey) -> bool {
        self.cannot_join
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(device)
    }

    fn is_disputed(&self, device: &AuthorisationKey) -> bool {
        self.disputed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(device)
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
            let asked = self.hosts.device_lists().await;
            if asked.lists.is_empty() {
                // Hosts that refuse to list their devices to this computer, and no host that
                // listed, have answered, and what they say is that this computer cannot vouch for
                // anybody: it checks nobody, publishes nothing, and takes nobody out for it, which
                // is for the person to decide. No host that answered at all leaves check 3 unable
                // to run.
                if asked.refused {
                    // What the hosts listed a minute ago is not believed any more.
                    *self
                        .listed
                        .last
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = None;
                    return Err(ClientError::refusal(
                        ErrorCode::PermissionDenied,
                        Shown::said(
                            "the hosts that answered will not list their devices to this computer \
                             any more, so who may share your settings cannot be checked here",
                        ),
                    ));
                }
                return Ok(None);
            }
            let mut reports = Vec::new();
            let mut names = BTreeMap::new();
            let mut stored: BTreeMap<AuthorisationKey, BTreeSet<_>> = BTreeMap::new();
            let mut cannot_join = BTreeSet::new();
            for list in &asked.lists {
                let mut devices = Vec::new();
                for summary in &list.devices {
                    // A device whose four keys the host does not report yet is not one another
                    // device seals to: the pairing the owner approved is what binds a key to a
                    // device.
                    let Some(keys) = summary.keys.0 else { continue };
                    names
                        .entry(keys.authorisation)
                        .or_insert_with(|| summary.display_name.clone());
                    stored
                        .entry(keys.authorisation)
                        .or_default()
                        .insert(keys.stored_envelope);
                    if !matches!(
                        summary.platform,
                        DevicePlatform::Macos | DevicePlatform::Windows
                    ) {
                        cannot_join.insert(keys.authorisation);
                    }
                    devices.push(HostDevice {
                        authorisation: keys.authorisation,
                        stored_envelope: keys.stored_envelope,
                        // A grant that has run out manages nothing, whatever actions it listed.
                        manages_host: summary.manages_host && !summary.grant_expired,
                        revoked: summary.revoked,
                    });
                }
                reports.push(HostReport { devices });
            }
            *self
                .listed
                .names
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = names;
            *self
                .listed
                .cannot_join
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = cannot_join;
            *self
                .listed
                .disputed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = stored
                .into_iter()
                .filter(|(_, keys)| keys.len() > 1)
                .map(|(device, _)| device)
                .collect();
            // A host that refuses to list its devices to this computer says nothing of the devices
            // only it lists, as a host that did not answer says nothing: they are kept, and
            // nothing is accepted, opened or added on that host's word.
            let answers = HostAnswers {
                reports,
                silent: asked.silent || asked.refused,
            };
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
        // A request is recorded, or let go of, between two steps: what it says of a device is read
        // when the view is asked for, not when the step noted the devices.
        for held in &mut view.held_out {
            held.waiting = self.revoke_may_be_carried_out(&held.key);
        }
        // A device never shared with whose revoke is on record is kept out as one taken out is.
        let (kept_out, offered): (Vec<_>, Vec<_>) = std::mem::take(&mut view.candidates)
            .into_iter()
            .partition(|candidate| self.revoke_may_be_carried_out(&candidate.key));
        view.candidates = offered;
        view.held_out
            .extend(kept_out.into_iter().map(|candidate| HeldOut {
                reference: candidate.reference,
                name: candidate.name,
                waiting: true,
                key: candidate.key,
            }));
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
            cached.held_out.clear();
            cached.out = false;
            return;
        };
        let outcomes = membership
            .outcomes()
            .unwrap_or_default()
            .iter()
            .map(|outcome| happened(outcome, &name))
            .collect();
        if status.out {
            // A computer that was taken out has no devices to take out or to share with: what its
            // last record listed is not its to act on.
            let mut cached = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            cached.members.clear();
            cached.candidates.clear();
            cached.held_out.clear();
            cached.outcomes = outcomes;
            cached.out = true;
            return;
        }
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
            .filter(|device| {
                !self.listed.is_disputed(&device.authorisation)
                    && !self.listed.cannot_join(&device.authorisation)
            })
            .map(|device| Candidate {
                reference: installation_id_of(device),
                name: name(device),
                key: device.authorisation,
            })
            .collect();
        let held_out = membership
            .held_out()
            .unwrap_or_default()
            .iter()
            .filter(|device| {
                !self.listed.is_disputed(&device.authorisation)
                    && !self.listed.cannot_join(&device.authorisation)
            })
            .map(|device| HeldOut {
                reference: installation_id_of(device),
                name: name(device),
                waiting: false,
                key: device.authorisation,
            })
            .collect();
        let mut cached = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        cached.members = members;
        cached.candidates = candidates;
        cached.held_out = held_out;
        cached.outcomes = outcomes;
        cached.out = false;
        cached.offers.clear();
    }

    /// The membership of this computer's collection, with the hosts asked for as much as `ask`
    /// says.
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
        if !offered.is_empty() {
            // An offer is named for the device that shares it, as the hosts call it. What they
            // answer is for the names alone; nothing is decided on it here.
            let _ =
                HostsDirectory::new(Arc::clone(&self.hosts), Arc::clone(&self.listed), Ask::Now)
                    .answers()
                    .await;
        }
        let offers = offered
            .iter()
            .map(|collection| Offer {
                reference: collection.collection_id.to_string(),
                name: self.listed.name_of_installation(collection.home),
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
        // The hosts are asked, and what they answer is what the device is chosen from. A refresh
        // none of them answered leaves the answers of an earlier one in place, which are not what
        // a key is given on.
        Self::answered(membership.refresh().await.map_err(member_failure)?)?;
        let candidate = membership
            .candidates()
            .map_err(member_failure)?
            .into_iter()
            .find(|device| installation_id_of(device) == reference);
        // A device this computer took out when the person revoked it is shared with again only
        // when the person names it, here, and a revocation still on its way is not forgotten.
        let sharing_again = candidate.is_none();
        let device = match candidate {
            Some(device) if self.revoke_may_be_carried_out(&device.authorisation) => {
                return Err(revoke_waiting());
            }
            Some(device) => device,
            None => membership
                .held_out()
                .map_err(member_failure)?
                .into_iter()
                .find(|device| installation_id_of(device) == reference)
                .ok_or_else(|| CommandError::refused("no host lists that device any more"))
                .and_then(|device| {
                    if self.revoke_may_be_carried_out(&device.authorisation) {
                        Err(revoke_waiting())
                    } else {
                        Ok(device)
                    }
                })?,
        };
        if self.listed.is_disputed(&device.authorisation) {
            return Err(CommandError::refused(
                "your hosts do not agree on the keys of that device, so nothing is shared with it",
            ));
        }
        if self.listed.cannot_join(&device.authorisation) {
            return Err(CommandError::refused(
                "that device has no way to ask you to confirm yet, so it cannot join the \
                 settings; use a Mac or a Windows computer",
            ));
        }
        let name = self
            .listed
            .name_of(&device.authorisation)
            .unwrap_or_else(|| "another device".to_owned());
        let (plan, reason) = if sharing_again {
            (
                membership
                    .plan_share_again(&device.authorisation, now())
                    .map_err(member_failure)?,
                format!("Share your settings with {name} again"),
            )
        } else {
            (
                membership
                    .plan_share(&device.authorisation, now())
                    .map_err(member_failure)?,
                format!("Share your settings with {name}"),
            )
        };
        self.confirmed(&mut membership, &plan, &reason).await?;
        // The person took their time. A host may have revoked the device, or two hosts may now
        // disagree about its keys: the hosts are asked again, and the device must still be one they
        // list, alone. (Another member may have changed the collection meanwhile. The person
        // confirmed this device and not the collection around it, and an addition outlives a
        // change to the members, as it does between the plan and the record.)
        let again = match membership.refresh().await {
            Ok(refreshed) => Self::answered(refreshed),
            Err(error) => Err(member_failure(error)),
        };
        // A request may have been sent while the person was at the dialog.
        if self.revoke_may_be_carried_out(&device.authorisation) {
            membership.cancel(&plan);
            return Err(revoke_waiting());
        }
        let still = if sharing_again {
            membership
                .held_out()
                .is_ok_and(|held| held.contains(&device))
        } else {
            membership
                .candidates()
                .is_ok_and(|candidates| candidates.contains(&device))
        } && !self.listed.is_disputed(&device.authorisation);
        if again.is_err() || !still {
            membership.cancel(&plan);
            return Err(again.err().unwrap_or_else(|| {
                CommandError::refused(
                    "no host lists that device any more, or they disagree about its keys, so \
                     nothing was shared",
                )
            }));
        }
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

    /// Whether a refresh was answered by a host and recorded what it said.
    fn answered(refreshed: Refreshed) -> Result<()> {
        match refreshed {
            Refreshed::Recorded => Ok(()),
            Refreshed::NoHostAnswered => Err(CommandError::unavailable(
                "none of your hosts answered, so who may be given your settings could not be checked",
            )),
            _ => Err(CommandError::refused(
                "this computer is not sharing settings now: it was taken out, or holds none",
            )),
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

    /// Whether the page was shown a device taken out by a revoke.
    pub fn shows_held_out(&self) -> bool {
        !self
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .held_out
            .is_empty()
    }

    /// Whether a request of this computer's to revoke `device` may still be carried out: the
    /// revocation is not yet taken in here, or a request for it is recorded, whatever became of it
    /// ([`super::Requests`]).
    fn revoke_may_be_carried_out(&self, device: &AuthorisationKey) -> bool {
        !self.fence.holds_none_of(&[*device]) || self.requests.holds(device)
    }

    /// Takes devices whose revocation is known here out of the shared settings, as far as the hosts
    /// and the service allow.
    ///
    /// The devices are held before anything else is done (already, for a revocation this computer
    /// sent; here, from memory if the record cannot be written, for a device found revoked at a
    /// host): a step in hand may be waiting on the network and holds the membership meanwhile, so
    /// the membership takes them in under a step of its own, after it. One call for all the devices
    /// of one view makes one removal step. A call that is dropped, or fails, leaves them held, and
    /// the next step of any companion takes them in.
    ///
    /// Says whether none of the devices is held any longer, which is so when a step took them in.
    /// A computer that shares no settings has none to take them out of, and says no.
    ///
    /// # Errors
    ///
    /// Returns what stopped the step before it could try: its lock or the record of the collection
    /// could not be used, with the devices held all the same.
    pub async fn revocations_sent(&self, devices: &[AuthorisationKey]) -> Result<bool> {
        self.fence.raise_regardless(devices);
        let _step = self.step().await?;
        let Some(mut record) = self.record()? else {
            // A membership with no record of its collection is a start or a join that was
            // interrupted: the step that resumes it takes the devices in.
            if !kr_client::sync::membership::holds_membership(
                &self.directory.join(super::MEMBERSHIP),
            ) {
                self.fence.lift(devices)?;
            }
            return Ok(false);
        };
        let service = self.managed(&record.origin()?)?;
        if self
            .membership_asking(&service, Ask::Never)?
            .members()
            .map_err(member_failure)?
            .is_none()
        {
            self.fence.lift(devices)?;
            return Ok(false);
        }
        let settled = self
            .settle(&mut record, &service, Ask::Now)
            .await
            .map(|_| ());
        self.finished(&settled);
        Ok(self.fence.holds_none_of(devices))
    }

    /// Takes the revocations the fence holds into `membership`, under the step in hand, and says
    /// which it took in; the step lets the fence go of them after it reconciles. A computer with no
    /// collection has nothing to take them out of.
    pub(super) fn take_in_revocations(
        &self,
        membership: &mut SyncMembership,
    ) -> Result<Vec<AuthorisationKey>> {
        self.fence.keep_held();
        let devices = self.fence.pending()?;
        for device in &devices {
            match membership.feed_revocation(device) {
                Ok(()) | Err(MembershipError::NoMembership) => {}
                Err(error) => return Err(member_failure(error)),
            }
        }
        Ok(devices)
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
        let starter = self.listed.name_of_installation(collection.home);
        self.confirmed(
            &mut membership,
            &plan,
            &match starter {
                Some(name) => format!("Join the settings started on {name}"),
                None => "Join the settings your other devices share".to_owned(),
            },
        )
        .await?;
        membership
            .join(&plan, now())
            .await
            .map_err(member_failure)?;
        drop(membership);
        let mut record = Record::of(&origin, collection.collection_id);
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
