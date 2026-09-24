//! This computer as an owner device: the confirmations its hosts ask for, found and answered.
//!
//! A host this computer owns asks its owner devices to confirm sensitive actions: issuing an
//! invitation, adding a device, and the others section 10 lists. No event announces a challenge,
//! so the watcher keeps an authorised session to each owned host, through the host's own network
//! configuration, and reads `owner.confirmation.pending` every [`INTERVAL`]. The page is sent
//! descriptions ([`OwnerView`]) with an opaque reference each; it never receives a challenge, a
//! proof or a key. A review runs in native code: kr-client checks what the challenge shows against
//! what it would authorise, the platform's ceremony asks the person, and only then does native code
//! sign and complete it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::pairing::owner::{
    CannotCheck, Ceremony, CeremonyKind, Listed, OwnerConfirmations, ReviewOutcome, SessionChannel,
    Subject, reason,
};
use kr_client::pairing::paired::PairedHost;
use kr_protocol::ids::DeviceId;
use kr_protocol::pairing::{SensitiveAction, group_verification_value};
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::device::hosts::UNNAMED_HOST;
use crate::error::{CommandError, Result};

/// How often each owned host is asked what it wants confirmed.
pub const INTERVAL: Duration = Duration::from_secs(2);

/// How long connecting to an owned host may take before it counts as out of contact.
const CONNECT_WITHIN: Duration = Duration::from_secs(10);

/// What the page is shown of the confirmations this computer's hosts ask for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnerView {
    /// The ceremony this computer offers, which names the confirm button.
    pub ceremony: CeremonyKind,
    /// The requests, oldest first.
    pub requests: Vec<RequestView>,
}

/// One request, as the page lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestView {
    /// The opaque reference a review names it by. It is not the challenge's identifier.
    pub reference: String,
    /// The name of the host that asks.
    pub host_name: String,
    /// What it would do, in a few words.
    pub title: String,
    /// Everything it would authorise, in one line, as the platform's dialog shows it.
    pub detail: Option<String>,
    /// The value both devices show, grouped, for a device being added.
    pub value: Option<String>,
    /// When the host stops accepting an answer.
    pub expires_at_ms: u64,
    /// False when it cannot be checked, so it cannot be confirmed here.
    pub checkable: bool,
}

/// What the page sends to review one request: its reference, and nothing else.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    /// The reference the request was listed with.
    pub reference: String,
}

/// One request this computer is showing.
struct Entry {
    reference: String,
    host: DeviceId,
    view: RequestView,
    listed: Listed,
}

/// This computer's owner confirmations.
pub struct Owner {
    device: Arc<Device>,
    ceremony: Arc<dyn Ceremony>,
    sessions: tokio::sync::Mutex<BTreeMap<DeviceId, Arc<OwnerConfirmations>>>,
    entries: Mutex<Vec<Entry>>,
    changed: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Owner")
            .field("ceremony", &self.ceremony.kind())
            .field("requests", &lock(&self.entries).len())
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Owner {
    /// The confirmations of `device`'s owned hosts, answered through `ceremony`. `changed` is
    /// called whenever the list the page shows changes.
    #[must_use]
    pub fn new(
        device: Arc<Device>,
        ceremony: Arc<dyn Ceremony>,
        changed: impl Fn() + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            device,
            ceremony,
            sessions: tokio::sync::Mutex::new(BTreeMap::new()),
            entries: Mutex::new(Vec::new()),
            changed: Box::new(changed),
        })
    }

    /// Starts watching the owned hosts.
    pub fn start(self: &Arc<Self>) {
        let owner = Arc::downgrade(self);
        tauri::async_runtime::spawn(async move {
            loop {
                match owner.upgrade() {
                    Some(owner) => owner.cycle().await,
                    None => return,
                }
                tokio::time::sleep(INTERVAL).await;
            }
        });
    }

    /// What the page is shown.
    #[must_use]
    pub fn view(&self) -> OwnerView {
        OwnerView {
            ceremony: self.ceremony.kind(),
            requests: lock(&self.entries)
                .iter()
                .map(|entry| entry.view.clone())
                .collect(),
        }
    }

    /// Reviews the request `reference` names: checks it, asks the person through the platform's
    /// ceremony, and signs and completes it only when they confirm in time.
    ///
    /// # Errors
    ///
    /// Returns a refusal for a reference this computer is not showing.
    pub async fn review(self: &Arc<Self>, reference: &str) -> Result<ReviewOutcome> {
        let (host, listed) = {
            let entries = lock(&self.entries);
            let entry = entries
                .iter()
                .find(|entry| entry.reference == reference)
                .ok_or_else(|| CommandError::refused("that request is not waiting here"))?;
            (entry.host, entry.listed.clone())
        };
        let confirmations = self
            .sessions
            .lock()
            .await
            .get(&host)
            .cloned()
            .ok_or_else(|| CommandError::unavailable("the host is not in contact"))?;
        let outcome = confirmations.review(&listed, &*self.ceremony).await;
        self.cycle().await;
        Ok(outcome)
    }

    /// Asks every owned host once what it wants confirmed.
    async fn cycle(&self) {
        let owned = self.device.owner_hosts();
        for host in &owned {
            let listed = match self.confirmations(host).await {
                Some(confirmations) => confirmations.pending().await.ok(),
                None => None,
            };
            if listed.is_none() {
                self.sessions.lock().await.remove(&host.host_device_id);
            }
            self.device
                .set_contact(host.host_device_id, listed.is_some());
            self.show(host, listed.unwrap_or_default());
        }
        let before = lock(&self.entries).len();
        lock(&self.entries)
            .retain(|entry| owned.iter().any(|host| host.host_device_id == entry.host));
        if lock(&self.entries).len() != before {
            (self.changed)();
        }
    }

    /// The confirmations of `host`, over a session opened now if none is open.
    async fn confirmations(&self, host: &PairedHost) -> Option<Arc<OwnerConfirmations>> {
        let mut sessions = self.sessions.lock().await;
        if let Some(confirmations) = sessions.get(&host.host_device_id) {
            return Some(Arc::clone(confirmations));
        }
        let pairing = self.device.pairing();
        let identity = pairing.candidate.paired_identity(host.device_id);
        let session =
            tokio::time::timeout(CONNECT_WITHIN, pairing.link.connect_paired(host, &identity))
                .await
                .ok()?
                .ok()?;
        let channel = SessionChannel::open(Arc::new(session)).await.ok()?;
        let confirmations = Arc::new(OwnerConfirmations::new(
            host.clone(),
            self.device.identity().keys.authorisation.clone(),
            Arc::new(channel),
            Arc::clone(&pairing.clock),
        ));
        sessions.insert(host.host_device_id, Arc::clone(&confirmations));
        Some(confirmations)
    }

    /// Replaces what is shown for `host` with `listed`, keeping each request's reference.
    fn show(&self, host: &PairedHost, listed: Vec<Listed>) {
        let host_name = host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned());
        let now = self.device.pairing().clock.wall_clock_ms();
        let mut entries = lock(&self.entries);
        let before: Vec<(String, RequestView)> = entries
            .iter()
            .filter(|entry| entry.host == host.host_device_id)
            .map(|entry| (entry.reference.clone(), entry.view.clone()))
            .collect();
        let mut kept: Vec<Entry> = Vec::new();
        for listed in listed.into_iter().filter(|listed| !listed.answered) {
            let reference = entries
                .iter()
                .find(|entry| {
                    entry.host == host.host_device_id
                        && entry.listed.request.confirmation_id == listed.request.confirmation_id
                })
                .map_or_else(
                    || kr_ipc::new_uuid().to_string(),
                    |entry| entry.reference.clone(),
                );
            let view = describe(&reference, &host_name, &listed, now);
            kept.push(Entry {
                reference,
                host: host.host_device_id,
                view,
                listed,
            });
        }
        let after: Vec<(String, RequestView)> = kept
            .iter()
            .map(|entry| (entry.reference.clone(), entry.view.clone()))
            .collect();
        entries.retain(|entry| entry.host != host.host_device_id);
        entries.extend(kept);
        drop(entries);
        if before != after {
            (self.changed)();
        }
    }
}

/// What the page is shown of one listed request.
fn describe(reference: &str, host_name: &str, listed: &Listed, now_ms: u64) -> RequestView {
    let expires_at_ms = listed.request.expires_at_ms.get();
    let unchecked = |title: &str| RequestView {
        reference: reference.to_owned(),
        host_name: host_name.to_owned(),
        title: title.to_owned(),
        detail: None,
        value: None,
        expires_at_ms,
        checkable: false,
    };
    let Ok(subject) = &listed.subject else {
        return unchecked(title_of_unchecked(listed.subject.as_ref().err()));
    };
    let title = match subject {
        Subject::IssueInvitation { .. } => "Issue an invitation",
        Subject::ConfirmDevice { .. } => "Add a device",
        Subject::EstablishClock => "Trust this host's clock again",
        Subject::Described(described) => match described.action {
            SensitiveAction::EnlargeGrant => "Widen what devices may do",
            SensitiveAction::TrustRepositoryRoot => "Trust a plugin repository",
            SensitiveAction::GrantExecutableCapability => "Let a plugin use new capabilities",
            SensitiveAction::IssueInvitation => "Issue an invitation",
            SensitiveAction::ConfirmDevice => "Add a device",
            SensitiveAction::ChangeHostAuthority => "Change who manages the host",
        },
    };
    let Ok(line) = reason(subject, host_name, now_ms) else {
        return unchecked(title);
    };
    let value = match subject {
        Subject::ConfirmDevice { candidate, .. } => {
            Some(group_verification_value(&candidate.verification_value))
        }
        _ => None,
    };
    RequestView {
        reference: reference.to_owned(),
        host_name: host_name.to_owned(),
        title: title.to_owned(),
        detail: Some(sentence(&line)),
        value,
        expires_at_ms,
        checkable: true,
    }
}

/// The title of a request that could not be checked.
const fn title_of_unchecked(_why: Option<&CannotCheck>) -> &'static str {
    "A request that could not be checked"
}

/// `line` as a sentence: its first letter capital, ending with a full stop.
fn sentence(line: &str) -> String {
    let mut characters = line.chars();
    let mut sentence: String = characters
        .next()
        .map(|first| first.to_uppercase().chain(characters).collect())
        .unwrap_or_default();
    if !sentence.ends_with('.') {
        sentence.push('.');
    }
    sentence
}
