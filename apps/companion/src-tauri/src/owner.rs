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
    Subject, is_plain_text, reason, shows_value,
};
use kr_client::pairing::paired::PairedHost;
use kr_protocol::confirmation::{CatalogueTrustPlan, NATIVE_BRIDGE_NOTICE, PluginInstallPlan};
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
    /// What the request names beyond the sentence, one fact to a line, exactly as the host
    /// described it and as the confirmation covers it.
    pub facts: Vec<Fact>,
    /// What this host says in its own words about what the request would place, where it would
    /// place code that runs outside the plugin sandbox.
    pub notice: Option<String>,
    /// What the publisher says in its own words about what the release does. The page quotes it
    /// apart from the host's own words, so it is never read as the host's.
    pub statement: Option<String>,
    /// When the host stops accepting an answer.
    pub expires_at_ms: u64,
    /// False when it cannot be checked, so it cannot be confirmed here.
    pub checkable: bool,
}

/// One fact a request names: what it is, and its exact value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fact {
    /// What the value is, in a few words.
    pub label: String,
    /// The value, as the confirmation covers it.
    pub value: String,
    /// True for a value read character by character, an address, a hash or a list of identifiers,
    /// which the page sets in a monospace face and breaks anywhere; false for words.
    pub code: bool,
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
        // A challenge's reference outlives its host's visits until the challenge expires, and no
        // longer, whether or not any host is left to visit.
        let now = self.device.pairing().clock.wall_clock_ms();
        lock(&self.references).retain(|_, (_, expires_at_ms)| *expires_at_ms > now);
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
        facts: Vec::new(),
        notice: None,
        statement: None,
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
        Subject::CatalogueAdd(_) => "Trust a plugin repository",
        Subject::PluginInstall(_) => "Install a plugin",
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
    // What a request names beyond its sentence is shown as the host wrote it or not at all: text
    // this page could not show exactly makes the request one that is not confirmed here.
    let Some(particulars) = particulars(subject) else {
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
        facts: particulars.facts,
        notice: particulars.notice,
        statement: particulars.statement,
        expires_at_ms,
        checkable: true,
    }
}

/// What a request names beyond the sentence the platform's dialog says.
struct Particulars {
    facts: Vec<Fact>,
    notice: Option<String>,
    statement: Option<String>,
}

/// The facts, the host's notice and the publisher's statement for an enrolment or an installation,
/// and nothing for any other request. `None` when a word the host or the publisher wrote could
/// not be shown exactly as it was written.
fn particulars(subject: &Subject) -> Option<Particulars> {
    match subject {
        Subject::CatalogueAdd(plan) => Some(Particulars {
            facts: enrolment_facts(plan)?,
            notice: None,
            statement: None,
        }),
        Subject::PluginInstall(plan) => {
            let bridge = plan.grant_statement.is_some()
                || plan.grant.contains(&"native_bridge.install".to_owned());
            Some(Particulars {
                facts: installation_facts(plan)?,
                notice: bridge.then(|| NATIVE_BRIDGE_NOTICE.to_owned()),
                statement: match &plan.grant_statement {
                    Some(words) => Some(plain(words, STATEMENT_CHARS)?),
                    None => None,
                },
            })
        }
        _ => Some(Particulars {
            facts: Vec::new(),
            notice: None,
            statement: None,
        }),
    }
}

/// The longest publisher statement a manifest may carry, and so the longest this page shows whole.
const STATEMENT_CHARS: usize = 1000;

/// The longest address, name or identifier this page shows whole.
const FIELD_CHARS: usize = 2048;

/// `text` as written when it is one plain line of at most `limit` characters, and `None` otherwise.
fn plain(text: &str, limit: usize) -> Option<String> {
    (!text.is_empty() && text.chars().count() <= limit && is_plain_text(text))
        .then(|| text.to_owned())
}

/// A list of names, in the order the host sent them, as one line.
fn names(list: impl IntoIterator<Item = impl AsRef<str>>) -> Option<String> {
    let mut words = Vec::new();
    for word in list {
        words.push(plain(word.as_ref(), FIELD_CHARS)?);
    }
    Some(words.join(", "))
}

/// A hash as eight groups of eight characters, which a person reads and compares by group.
fn grouped(hash: &str) -> Option<String> {
    let hash = plain(hash, FIELD_CHARS)?;
    Some(
        hash.as_bytes()
            .chunks(8)
            .map(|group| String::from_utf8_lossy(group).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// A fact whose value is words.
fn words(label: &str, value: String) -> Fact {
    Fact {
        label: label.to_owned(),
        value,
        code: false,
    }
}

/// A fact whose value is read character by character.
fn exact(label: &str, value: String) -> Fact {
    Fact {
        label: label.to_owned(),
        value,
        code: true,
    }
}

/// A count with its thousands separated.
fn count(number: u64) -> String {
    let digits = number.to_string();
    let mut grouped = String::new();
    for (position, digit) in digits.chars().enumerate() {
        if position > 0 && (digits.len() - position).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// A size in the largest binary unit that holds it exactly, and in bytes where none does.
fn size(bytes: u64) -> String {
    for (unit, name) in [(1u64 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")] {
        if bytes >= unit && bytes.is_multiple_of(unit) {
            return format!("{} {name}", bytes / unit);
        }
    }
    format!("{} bytes", count(bytes))
}

fn enrolment_facts(plan: &CatalogueTrustPlan) -> Option<Vec<Fact>> {
    use kr_protocol::catalogue::CatalogueKind;
    let kind = match plan.kind {
        CatalogueKind::Official => "The official repository",
        CatalogueKind::Vendor => "A vendor's repository",
        CatalogueKind::Community => "A community repository",
        CatalogueKind::Local => "A folder on the host",
        CatalogueKind::Mirror => "A mirror of another repository",
    };
    let budgets = &plan.budgets;
    let beyond = if plan.ceiling.is_empty() {
        "Nothing".to_owned()
    } else {
        names(plan.ceiling.iter())?
    };
    Some(vec![
        words("Name", plain(&plan.catalogue_id, FIELD_CHARS)?),
        words("Kind", kind.to_owned()),
        exact("Metadata at", plain(&plan.metadata_url, FIELD_CHARS)?),
        exact("Targets at", plain(&plan.targets_url, FIELD_CHARS)?),
        exact("Root", grouped(&plan.root_digest)?),
        exact("Root keys", names(plan.root_key_ids.iter())?),
        Fact {
            label: "Beyond the default".to_owned(),
            value: beyond,
            code: !plan.ceiling.is_empty(),
        },
        words(
            "Metadata",
            format!(
                "Up to {} and {} entries",
                size(budgets.metadata_bytes.get()),
                count(budgets.metadata_entries.get())
            ),
        ),
        words(
            "Metadata kept",
            format!(
                "{} generation{}, up to {}",
                count(budgets.retained_generations.get()),
                if budgets.retained_generations.get() == 1 {
                    ""
                } else {
                    "s"
                },
                size(budgets.retained_metadata_bytes.get())
            ),
        ),
        words(
            "Package cache",
            format!("Up to {}", size(budgets.payload_cache_bytes.get())),
        ),
        words(
            "Offline copy",
            if budgets.full_offline_mirror {
                "The whole generation is kept".to_owned()
            } else {
                "Not kept".to_owned()
            },
        ),
    ])
}

fn installation_facts(plan: &PluginInstallPlan) -> Option<Vec<Fact>> {
    let granted = if plan.grant.is_empty() {
        "Nothing beyond what the repository allows".to_owned()
    } else {
        names(plan.grant.iter())?
    };
    Some(vec![
        exact(
            "Plugin",
            format!(
                "{} {}",
                plain(plan.plugin_id.as_str(), FIELD_CHARS)?,
                plain(&plan.version, FIELD_CHARS)?
            ),
        ),
        words("From", plain(&plan.catalogue_id, FIELD_CHARS)?),
        exact("Package hash", grouped(&plan.package_digest)?),
        Fact {
            label: "Granted".to_owned(),
            value: granted,
            code: !plan.grant.is_empty(),
        },
        if plan.ceiling.is_empty() {
            words("Allowed by the repository", "Nothing".to_owned())
        } else {
            exact("Allowed by the repository", names(plan.ceiling.iter())?)
        },
    ])
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
    use kr_protocol::confirmation::{CatalogueTrustPlan, PluginInstallPlan};
    use kr_protocol::invitation::PairCandidateView;
    use kr_protocol::pairing::{DeviceName, DevicePlatform, OwnerConfirmationRequest};
    use kr_protocol::scalars::{CanonicalSet, Digest256, Nonce256, Nullable, TimestampMs, Uuid};

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

    /// A request for `subject` as a host this computer owns lists it.
    fn listed_subject(subject: Subject, action: SensitiveAction) -> Listed {
        let mut listed = a_device_being_added();
        listed.request.action = action;
        listed.request.destination_keys = Nullable::null();
        listed.request.destination_rights = CanonicalSet::new();
        listed.subject = Ok(subject);
        listed
    }

    fn enrolment() -> CatalogueTrustPlan {
        use kr_protocol::catalogue::{CatalogueAddParams, CatalogueBudgets, CatalogueKind};
        use kr_protocol::scalars::U64;
        CatalogueTrustPlan::of_request(
            &CatalogueAddParams {
                environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([8; 16])),
                catalogue_id: "community".to_owned(),
                kind: CatalogueKind::Community,
                metadata_url: "https://repo.example/metadata/".to_owned(),
                targets_url: "https://repo.example/targets/".to_owned(),
                root: "cm9vdA==".to_owned(),
                budgets: CatalogueBudgets {
                    metadata_bytes: U64::new(67_108_864),
                    metadata_entries: U64::new(100_000),
                    retained_generations: U64::new(2),
                    retained_metadata_bytes: U64::new(268_435_456),
                    payload_cache_bytes: U64::new(2_147_483_648),
                    full_offline_mirror: false,
                },
                ceiling: vec!["terminal.stream".to_owned()],
                owner_confirmation: Nullable::null(),
            },
            "1a2b3c4d".repeat(8),
            ["key-one".to_owned(), "key-two".to_owned()]
                .into_iter()
                .collect(),
        )
    }

    const PUBLISHER: &str =
        "Adds one registration file in Claude Code's directory, which Claude Code starts.";

    fn installation() -> PluginInstallPlan {
        PluginInstallPlan {
            environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([8; 16])),
            catalogue_id: "community".to_owned(),
            ceiling: ["metadata.match".to_owned()].into_iter().collect(),
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code")
                .expect("a plugin identifier"),
            version: "0.3.0".to_owned(),
            package_digest: "e5f60718".repeat(8),
            grant: [
                "approval.respond".to_owned(),
                "native_bridge.install".to_owned(),
            ]
            .into_iter()
            .collect(),
            grant_statement: Some(PUBLISHER.to_owned()),
        }
    }

    fn fact(label: &str, value: &str, code: bool) -> Fact {
        Fact {
            label: label.to_owned(),
            value: value.to_owned(),
            code,
        }
    }

    /// KR-REQ-11.42: a repository whose root an owner is asked to trust is listed with the sentence
    /// the platform's dialog will say and, one fact to a line, everything the confirmation covers:
    /// where its metadata and targets are, its whole root and the keys it names, its limits and
    /// what its packages may hold. Nothing else is placed beside it.
    #[test]
    fn an_enrolment_is_listed_with_everything_its_confirmation_covers() {
        let listed = listed_subject(
            Subject::CatalogueAdd(enrolment()),
            SensitiveAction::TrustRepositoryRoot,
        );
        let view = describe("a reference", "studio", &listed, NOW);
        assert!(view.checkable);
        assert_eq!(view.title, "Trust a plugin repository");
        assert_eq!(
            view.detail.as_deref(),
            Some(
                "Trust the plugin repository community on studio, served from repo.example: its \
                 root starts 1a2b 3c4d, and its packages may hold 1 capability beyond the \
                 default."
            )
        );
        let group = "1a2b3c4d";
        let root = [group; 8].join(" ");
        assert_eq!(
            view.facts,
            vec![
                fact("Name", "community", false),
                fact("Kind", "A community repository", false),
                fact("Metadata at", "https://repo.example/metadata/", true),
                fact("Targets at", "https://repo.example/targets/", true),
                fact("Root", &root, true),
                fact("Root keys", "key-one, key-two", true),
                fact("Beyond the default", "terminal.stream", true),
                fact("Metadata", "Up to 64 MiB and 100,000 entries", false),
                fact("Metadata kept", "2 generations, up to 256 MiB", false),
                fact("Package cache", "Up to 2 GiB", false),
                fact("Offline copy", "Not kept", false),
            ]
        );
        assert_eq!(view.notice, None);
        assert_eq!(view.statement, None);
        assert_eq!(view.value, None);
    }

    /// KR-REQ-11.42: an installation of a release with a native bridge carries the host's own
    /// notice, that the bridge runs in the application's directory with its permissions outside
    /// the plugin sandbox, and the publisher's statement apart from it: the two are never one
    /// text. The controls are an installation with no bridge, which has neither, and a repository
    /// that names no capability beyond the default.
    #[test]
    fn an_installation_with_a_native_bridge_shows_the_hosts_notice_apart_from_the_publishers_words()
    {
        let listed = listed_subject(
            Subject::PluginInstall(installation()),
            SensitiveAction::GrantExecutableCapability,
        );
        let view = describe("a reference", "studio", &listed, NOW);
        assert!(view.checkable);
        assert_eq!(view.title, "Install a plugin");
        assert_eq!(
            view.facts,
            vec![
                fact("Plugin", "kalareach/claude-code 0.3.0", true),
                fact("From", "community", false),
                fact("Package hash", &["e5f60718"; 8].join(" "), true),
                fact("Granted", "approval.respond, native_bridge.install", true),
                fact("Allowed by the repository", "metadata.match", true),
            ]
        );
        assert_eq!(
            view.notice.as_deref(),
            Some(kr_protocol::confirmation::NATIVE_BRIDGE_NOTICE)
        );
        assert_eq!(view.statement.as_deref(), Some(PUBLISHER));
        assert!(
            !view
                .notice
                .as_deref()
                .unwrap_or_default()
                .contains(PUBLISHER),
            "the host's words never carry the publisher's"
        );
        assert!(
            view.detail.as_deref().is_some_and(
                |line| line.contains("a native bridge that runs outside the plugin sandbox")
            ),
            "{:?}",
            view.detail
        );

        let plain = PluginInstallPlan {
            grant: CanonicalSet::new(),
            grant_statement: None,
            ..installation()
        };
        let view = describe(
            "a reference",
            "studio",
            &listed_subject(
                Subject::PluginInstall(plain),
                SensitiveAction::GrantExecutableCapability,
            ),
            NOW,
        );
        assert_eq!(view.notice, None);
        assert_eq!(view.statement, None);
        assert!(
            view.facts.contains(&fact(
                "Granted",
                "Nothing beyond what the repository allows",
                false
            )),
            "{:?}",
            view.facts
        );
    }

    /// KR-REQ-11.42: what a host or a publisher wrote is shown as it was written or not at all. A
    /// statement, a name or an address with a line break, a control character or a character that
    /// reorders text makes the request one this computer cannot check, so it cannot be confirmed
    /// here, and no part of it is placed on the page. The control is the same request without it.
    #[test]
    fn text_that_cannot_be_shown_as_written_makes_a_request_one_that_cannot_be_checked() {
        for bad in [
            "two\nlines",
            "reordered \u{202E}text",
            "tab\there",
            "bell\u{7}",
            "zero\u{200B}width",
        ] {
            let hostile_statement = PluginInstallPlan {
                grant_statement: Some(bad.to_owned()),
                ..installation()
            };
            let view = describe(
                "a reference",
                "studio",
                &listed_subject(
                    Subject::PluginInstall(hostile_statement),
                    SensitiveAction::GrantExecutableCapability,
                ),
                NOW,
            );
            assert!(!view.checkable, "{bad:?}");
            assert!(view.facts.is_empty() && view.statement.is_none() && view.notice.is_none());
            let hostile_name = CatalogueTrustPlan {
                catalogue_id: bad.to_owned(),
                ..enrolment()
            };
            let view = describe(
                "a reference",
                "studio",
                &listed_subject(
                    Subject::CatalogueAdd(hostile_name),
                    SensitiveAction::TrustRepositoryRoot,
                ),
                NOW,
            );
            assert!(!view.checkable, "{bad:?}");
            assert!(view.facts.is_empty());
        }
        let ordinary = describe(
            "a reference",
            "studio",
            &listed_subject(
                Subject::PluginInstall(installation()),
                SensitiveAction::GrantExecutableCapability,
            ),
            NOW,
        );
        assert!(ordinary.checkable);
    }

    /// A count of one is worded as one, and a repository that allows nothing by itself says so
    /// rather than leaving a line empty.
    #[test]
    fn a_single_generation_and_an_empty_allowance_are_worded_as_they_are() {
        let mut one = enrolment();
        one.budgets.retained_generations = kr_protocol::scalars::U64::new(1);
        one.budgets.retained_metadata_bytes = kr_protocol::scalars::U64::new(1_500_000);
        let view = describe(
            "a reference",
            "studio",
            &listed_subject(
                Subject::CatalogueAdd(one),
                SensitiveAction::TrustRepositoryRoot,
            ),
            NOW,
        );
        assert!(
            view.facts.contains(&fact(
                "Metadata kept",
                "1 generation, up to 1,500,000 bytes",
                false
            )),
            "{:?}",
            view.facts
        );
        let nothing = PluginInstallPlan {
            ceiling: CanonicalSet::new(),
            ..installation()
        };
        let view = describe(
            "a reference",
            "studio",
            &listed_subject(
                Subject::PluginInstall(nothing),
                SensitiveAction::GrantExecutableCapability,
            ),
            NOW,
        );
        assert!(
            view.facts
                .contains(&fact("Allowed by the repository", "Nothing", false)),
            "{:?}",
            view.facts
        );
    }

    /// A request that names nothing beyond its sentence, a device being added, has no facts, no
    /// notice and no statement.
    #[test]
    fn a_device_being_added_carries_no_facts_notice_or_statement() {
        let view = describe("a reference", "studio", &a_device_being_added(), NOW);
        assert!(view.facts.is_empty());
        assert_eq!((view.notice, view.statement), (None, None));
    }
}
