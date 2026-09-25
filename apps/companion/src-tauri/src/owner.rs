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
//!
//! No host holds up another. Each visit, from connecting to the answer, ends within
//! [`VISIT_WITHIN`], so a host that takes the connection and answers nothing is out of contact for
//! that cycle and nothing more; and the record of open sessions is never locked across a wait on
//! the network. A review holds the endpoint its host is reached through from the ceremony to the
//! answer, so the watcher's visit to another host on the same relay waits for it rather than
//! closing the connection the answer goes over.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::pairing::owner::{
    CannotCheck, Ceremony, CeremonyKind, Listed, OwnerConfirmations, ReviewOutcome, SessionChannel,
    Subject, reason, shows_value,
};
use kr_client::pairing::paired::PairedHost;
use kr_protocol::ids::{ConfirmationId, DeviceId};
use kr_protocol::pairing::{SensitiveAction, group_verification_value};
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::device::hosts::UNNAMED_HOST;
use crate::error::{CommandError, Result};

/// How often each owned host is asked what it wants confirmed.
pub const INTERVAL: Duration = Duration::from_secs(2);

/// How long one visit to an owned host may take, from connecting to its answer. A host that has
/// not answered by then is out of contact until the next cycle.
pub const VISIT_WITHIN: Duration = Duration::from_secs(10);

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
    /// Everything it would authorise, in one line, as the platform's dialog shows it, less the
    /// value, which has a place of its own.
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
    /// The open session to each owned host. It is looked up and changed under its lock, which is
    /// never held across a wait on the network.
    sessions: Mutex<BTreeMap<DeviceId, Arc<OwnerConfirmations>>>,
    entries: Mutex<Vec<Entry>>,
    /// The reference each challenge is shown by, with when it expires, kept for the challenge's
    /// whole life: a request that leaves the list while its host is out of contact comes back
    /// under the same reference, so what the page did with it, such as setting it aside, holds.
    references: Mutex<BTreeMap<ConfirmationId, (String, u64)>>,
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
            sessions: Mutex::new(BTreeMap::new()),
            entries: Mutex::new(Vec::new()),
            references: Mutex::new(BTreeMap::new()),
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
    /// Returns a refusal for a reference this computer is not showing, and an unavailable answer
    /// when its host cannot be reached in time.
    pub async fn review(self: &Arc<Self>, reference: &str) -> Result<ReviewOutcome> {
        let (host_id, listed) = {
            let entries = lock(&self.entries);
            let entry = entries
                .iter()
                .find(|entry| entry.reference == reference)
                .ok_or_else(|| CommandError::refused("that request is not waiting here"))?;
            (entry.host, entry.listed.clone())
        };
        let host = self
            .device
            .owner_hosts()
            .into_iter()
            .find(|owned| owned.host_device_id == host_id)
            .ok_or_else(|| CommandError::refused("that request is not waiting here"))?;
        let out_of_contact = || CommandError::unavailable("the host is not in contact");
        // From the ceremony to the answer, nothing this computer does for another host may close
        // the endpoint the answer goes over.
        let _held = tokio::time::timeout(
            VISIT_WITHIN,
            self.device.pairing().link.hold(&host.network_config),
        )
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .ok_or_else(out_of_contact)?;
        // A session that answers now, and the challenge as the host holds it now: one the host
        // no longer holds open cannot be confirmed any more.
        let (confirmations, holding) = self.reach(&host).await.ok_or_else(out_of_contact)?;
        let outcome = match holding
            .iter()
            .find(|held| held.request.confirmation_id == listed.request.confirmation_id)
        {
            Some(current) => confirmations.review(current, &*self.ceremony).await,
            None => ReviewOutcome::Expired,
        };
        self.refresh(&host).await;
        Ok(outcome)
    }

    /// Asks every owned host once what it wants confirmed, one after another.
    async fn cycle(&self) {
        let owned = self.device.owner_hosts();
        for host in &owned {
            self.refresh(host).await;
        }
        let owns = |host: &DeviceId| owned.iter().any(|owned| owned.host_device_id == *host);
        lock(&self.sessions).retain(|host, _| owns(host));
        let before = lock(&self.entries).len();
        lock(&self.entries).retain(|entry| owns(&entry.host));
        if lock(&self.entries).len() != before {
            (self.changed)();
        }
    }

    /// Asks `host` what it wants confirmed, and shows its answer, or that it is out of contact.
    async fn refresh(&self, host: &PairedHost) {
        let listed = self.visit(host).await;
        self.device
            .set_contact(host.host_device_id, listed.is_some());
        self.show(host, listed.unwrap_or_default());
    }

    /// One visit to `host`: what it holds open, or `None` when it could not be reached and asked
    /// in time.
    async fn visit(&self, host: &PairedHost) -> Option<Vec<Listed>> {
        self.reach(host).await.map(|(_, listed)| listed)
    }

    /// A session to `host` that answers now, and what the host holds open, found within
    /// [`VISIT_WITHIN`]: the open session is asked first, and one that no longer answers is let go
    /// for a fresh one.
    async fn reach(&self, host: &PairedHost) -> Option<(Arc<OwnerConfirmations>, Vec<Listed>)> {
        let deadline = tokio::time::Instant::now() + VISIT_WITHIN;
        if let Some(open) = self.session(host.host_device_id) {
            match tokio::time::timeout_at(deadline, open.pending()).await {
                Ok(Ok(listed)) => return Some((open, listed)),
                _ => self.forget(host.host_device_id, &open),
            }
        }
        let opened = tokio::time::timeout_at(deadline, self.open(host))
            .await
            .ok()??;
        let listed = tokio::time::timeout_at(deadline, opened.pending())
            .await
            .ok()?
            .ok()?;
        self.keep(host.host_device_id, &opened);
        Some((opened, listed))
    }

    /// A session to `host`, opened now: connected as the device this computer is there, through
    /// the host's own network configuration, and aimed at the host's environment.
    async fn open(&self, host: &PairedHost) -> Option<Arc<OwnerConfirmations>> {
        let pairing = self.device.pairing();
        let identity = pairing.candidate.paired_identity(host.device_id);
        let session = pairing.link.connect_paired(host, &identity).await.ok()?;
        let channel = SessionChannel::open(Arc::new(session)).await.ok()?;
        Some(Arc::new(OwnerConfirmations::new(
            host.clone(),
            self.device.identity().keys.authorisation.clone(),
            Arc::new(channel),
            Arc::clone(&pairing.clock),
        )))
    }

    /// The open session to `host`, if there is one.
    fn session(&self, host: DeviceId) -> Option<Arc<OwnerConfirmations>> {
        lock(&self.sessions).get(&host).cloned()
    }

    /// Keeps `opened` as the open session to `host`.
    fn keep(&self, host: DeviceId, opened: &Arc<OwnerConfirmations>) {
        lock(&self.sessions).insert(host, Arc::clone(opened));
    }

    /// Lets go of `stale`, the session to `host` that stopped answering, unless another has
    /// replaced it meanwhile.
    fn forget(&self, host: DeviceId, stale: &Arc<OwnerConfirmations>) {
        let mut sessions = lock(&self.sessions);
        if sessions
            .get(&host)
            .is_some_and(|open| Arc::ptr_eq(open, stale))
        {
            sessions.remove(&host);
        }
    }

    /// Replaces what is shown for `host` with `listed`, each request under its own reference.
    fn show(&self, host: &PairedHost, listed: Vec<Listed>) {
        let host_name = host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned());
        let now = self.device.pairing().clock.wall_clock_ms();
        let mut references = lock(&self.references);
        references.retain(|_, (_, expires_at_ms)| *expires_at_ms > now);
        let mut entries = lock(&self.entries);
        let before: Vec<(String, RequestView)> = entries
            .iter()
            .filter(|entry| entry.host == host.host_device_id)
            .map(|entry| (entry.reference.clone(), entry.view.clone()))
            .collect();
        let mut kept: Vec<Entry> = Vec::new();
        for listed in listed.into_iter().filter(|listed| !listed.answered) {
            let reference = references
                .entry(listed.request.confirmation_id)
                .or_insert_with(|| {
                    (
                        kr_ipc::new_uuid().to_string(),
                        listed.request.expires_at_ms.get(),
                    )
                })
                .0
                .clone();
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
        drop(references);
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
    // The value has a place of its own, where a screen reader spells it out, so the line beside it
    // leaves it out rather than say it a second time, unspelled.
    let line = value
        .as_deref()
        .and_then(|value| line.strip_suffix(&format!(" {}", shows_value(value))))
        .unwrap_or(&line);
    RequestView {
        reference: reference.to_owned(),
        host_name: host_name.to_owned(),
        title: title.to_owned(),
        detail: Some(sentence(line)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::invitation::PairCandidateView;
    use kr_protocol::pairing::{DeviceName, DevicePlatform, OwnerConfirmationRequest};
    use kr_protocol::scalars::{Digest256, Nonce256, Nullable, TimestampMs, Uuid};

    const NOW: u64 = 1_790_000_000_000;

    /// A device being added, as a host this computer owns lists it.
    fn a_device_being_added() -> Listed {
        let keys = DeviceKeys::generate().expect("keys").public_keys();
        let proposed_grant = kr_pairing::grants::personal_owner_grant();
        Listed {
            request: OwnerConfirmationRequest {
                confirmation_id: ConfirmationId::new(Uuid::from_bytes([1; 16])),
                action: SensitiveAction::ConfirmDevice,
                action_digest: Digest256::from_bytes([2; 32]),
                destination_keys: Nullable::some(keys),
                destination_rights: proposed_grant.actions.clone(),
                host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
                host_endpoint_id: keys.transport,
                nonce: Nonce256::from_bytes([4; 32]),
                expires_at_ms: TimestampMs::new(NOW + 110_000),
            },
            subject: Ok(Subject::ConfirmDevice {
                candidate: PairCandidateView {
                    device_name: DeviceName::new("Pixel 8").expect("a name"),
                    platform: DevicePlatform::Android,
                    keys,
                    verification_value: "f3c146fd".to_owned(),
                },
                proposed_grant,
            }),
            answered: false,
        }
    }

    /// KR-REQ-10.06: a device being added is shown with its value in a place of its own, where the
    /// page spells it out, and the line beside it leaves the value out rather than say it a second
    /// time, unspelled. The platform's dialog is given the whole line, value included.
    #[test]
    fn a_device_being_added_shows_its_value_once() {
        let listed = a_device_being_added();
        let view = describe("a reference", "studio", &listed, NOW);
        assert_eq!(view.value.as_deref(), Some("f3c1 46fd"));
        let detail = view.detail.expect("a request this computer checked");
        assert!(!detail.contains("f3c1"), "{detail}");
        assert!(
            detail.starts_with("Confirm adding Pixel 8 (Android) to studio, which may"),
            "{detail}"
        );
        assert!(detail.ends_with('.'), "{detail}");
        let Ok(subject) = &listed.subject else {
            panic!("checked");
        };
        assert!(
            reason(subject, "studio", NOW)
                .expect("a line")
                .ends_with("It shows f3c1 46fd."),
            "the dialog's line keeps the value"
        );
    }
}
