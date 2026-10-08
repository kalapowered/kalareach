//! The bearer this host delivers under, and renewing it.
//!
//! Section 16 gives the host two of the four `Services` push methods: `push.sender.renew` and
//! `push.sender.revoke`, both proven by the **host** key over a fresh gateway nonce. The other
//! two, registering a token and issuing a sender authorisation, are the installation's and reach
//! the gateway from the device; the credential they produce arrives here through the paired
//! encrypted channel (`device.push.register`).
//!
//! Renewal is [`super::sender`]'s: this store holds what the host delivers under and asks the
//! renewal it was given to replace a credential, and a store with no renewal says so rather than
//! answering with the credential it already has.
//!
//! # Where the secret lives
//!
//! In memory, in [`HeldCredentials`], and in the host's secret store when the store was given one
//! ([`HeldCredentials::persisted`], which is what a daemon builds): a bearer lasts thirty days and
//! the host renews it with no phone awake, so a restart must find the one it had. It is never
//! written to the delivery journal, never logged and never put in an error message: what the
//! journal holds is the `sender_record_id`, which names the authorisation and proves nothing.
//!
//! Every change of what is held, a registration, a renewal and a removal, goes through one lock
//! that also covers the secret store's item, so the store and memory cannot disagree about whether
//! an authorisation is still held: a removal that comes while a renewal is waiting on the gateway
//! stays a removal.
//!
//! A renewed bearer the store would not take is held in memory all the same, because the gateway
//! has already retired the one before it, and is written again at the next opportunity
//! ([`HeldCredentials::flush`]): the gateway renews a credential again for an hour after a
//! renewal, to cover an answer that was lost, and after that only in the last week of its life,
//! so a bearer that reached memory and no further would be lost by a restart.
//!
//! # Which bearer is the latest
//!
//! The gateway keeps one bearer for an authorisation, and what changes it is a renewal and an
//! issue by the device's installation; each stamps the credential it mints with the gateway's own
//! clock. The host learns of a renewal from the gateway's answer and of an issue from the device,
//! which hands the bearer over after the gateway has confirmed it, so two answers can be in flight
//! at once and arrive in either order, and the order they arrive in says nothing of the order the
//! gateway made them in. So whichever of two credentials for one authorisation was issued later
//! is the one kept: a registration leaves a newer renewal in place, and a renewal that comes back
//! late leaves a newer registration in place. The issue time a device hands over is the device's
//! word, and a device that lies about it can keep a retired bearer for its own destination and
//! nothing else; a credential issued in the future is refused before it reaches this store.
//!
//! # Asking again after a refusal
//!
//! A renewal the gateway refuses or does not answer is asked for again after a wait that doubles
//! with each refusal ([`renewal_backoff_ms`]), for as long as the credential held has not expired.
//! A credential's expiry is the device's word, and one that says it is due when the gateway holds
//! a longer life is refused at every ask: asked at every question tick, that costs the gateway's
//! allowance for the host twenty-four requests an hour for as long as the credential lasts. A
//! credential past its expiry is asked about at every attempt, because nothing presents it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use super::{Clock as _, SystemClock};
use kr_delivery::push::SenderCredentials;
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::push::PushDeliveryCredential;

use super::secrets::{DestinationSecrets, StoredCredential};

/// How long after a refused renewal the gateway is asked again: five minutes, doubling with each
/// refusal in a row, to at most an hour. A credential whose expiry is wrong is then asked about at
/// most twice an hour.
fn renewal_backoff_ms(refusals: u32) -> u64 {
    const FIRST_MS: u64 = 5 * 60 * 1000;
    const LONGEST_MS: u64 = 60 * 60 * 1000;
    FIRST_MS
        .saturating_mul(1_u64 << refusals.min(16))
        .min(LONGEST_MS)
}

/// When the gateway may be asked to renew one authorisation again.
#[derive(Clone, Copy, Debug)]
struct Wait {
    refusals: u32,
    until_steady_ms: u64,
}

/// What the last refused renewal said, in this host's own words, and when it may be asked again.
#[derive(Clone, Debug)]
struct Refusal {
    wait: Wait,
    said: String,
}

/// The clocks the waits are counted on: one that only moves forward, and the host's time of day,
/// which says whether a credential has expired.
#[derive(Clone)]
struct Clocks {
    steady: Arc<dyn Fn() -> u64 + Send + Sync>,
    wall: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl Default for Clocks {
    fn default() -> Self {
        Self {
            steady: Arc::new(|| SystemClock.steady_ms()),
            wall: Arc::new(|| SystemClock.now_ms()),
        }
    }
}

impl std::fmt::Debug for Clocks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Clocks")
    }
}

impl HeldCredentials {
    /// Builds an empty store whose waits are counted on clocks a test moves.
    #[cfg(test)]
    fn counting_on(
        steady: Arc<dyn Fn() -> u64 + Send + Sync>,
        wall: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            clocks: Clocks { steady, wall },
            ..Self::default()
        }
    }
}

/// How a held credential is replaced by a fresh one.
pub trait CredentialRenewal: std::fmt::Debug + Send + Sync {
    /// Renews one credential at the gateway that issued it.
    ///
    /// # Errors
    ///
    /// Returns why no renewal happened: a gateway that refused, one nobody reached, or an answer
    /// this host would not hold. The credential already held is untouched either way.
    fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String>;
}

/// What this host holds for each authorisation it delivers under.
///
/// The map is the whole of it: a credential is a bearer with an expiry, and a host that lost one
/// renews rather than asking for the same one again.
#[derive(Debug, Default)]
pub struct HeldCredentials {
    held: Mutex<BTreeMap<PushSenderRecordId, PushDeliveryCredential>>,
    renewal: RwLock<Option<Arc<dyn CredentialRenewal>>>,
    /// One renewal at a time. The delivery loop and the question loop can both find a credential
    /// that needs renewing, and two renewals of one authorisation are two new bearers of which the
    /// gateway keeps only the later: the store must never hold the earlier one afterwards.
    renewing: Mutex<()>,
    /// Where each credential is also kept, when it is kept anywhere but memory.
    vault: Option<DestinationSecrets>,
    /// Held across every change of what is held and of the vault's item for it.
    changing: Mutex<()>,
    /// The authorisations whose held credential the vault does not have yet.
    unsaved: Mutex<BTreeSet<PushSenderRecordId>>,
    /// When each authorisation whose renewal was refused may be asked about again.
    waits: Mutex<BTreeMap<PushSenderRecordId, Refusal>>,
    /// The clocks the waits are counted on.
    clocks: Clocks,
}

impl HeldCredentials {
    /// Builds an empty store with no way to renew yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an empty store that keeps every credential it holds in `vault` as well.
    #[must_use]
    pub fn persisted(vault: DestinationSecrets) -> Self {
        Self {
            vault: Some(vault),
            ..Self::default()
        }
    }

    /// Records the credential one authorisation produced, in memory only.
    ///
    /// This is how a daemon takes back at its start what the vault kept, and how a test installs a
    /// credential. A credential this host has just been given goes through [`Self::keep`].
    pub fn hold(&self, credential: PushDeliveryCredential) {
        if let Ok(mut held) = self.held.lock() {
            held.insert(credential.sender_record_id, credential);
        }
    }

    /// Takes back from the vault the credential one authorisation was kept under, at a start.
    ///
    /// Expired credentials come back too: renewal needs the authorisation, the gateway it names
    /// and this host's key, and section 16 renews after expiry. An item this build cannot read,
    /// such as one a later build wrote, is removed and reported: a destination with no credential
    /// is delivered to once its device registers again, and a daemon that stopped for it would
    /// deliver to nobody. An item the vault will not give up is reported and not loaded, and the
    /// start goes on: it only takes room, and nothing renews it. Returns whether a credential was
    /// held.
    ///
    /// # Errors
    ///
    /// Returns why the vault could not be read.
    pub fn load(&self, sender_record_id: PushSenderRecordId) -> Result<bool, String> {
        let Some(vault) = &self.vault else {
            return Ok(false);
        };
        match vault
            .push_credential(sender_record_id)
            .map_err(|error| error.to_string())?
        {
            StoredCredential::Absent => Ok(false),
            StoredCredential::Unreadable => {
                eprintln!(
                    "kr-controller: a stored delivery credential is not one this build writes \
                     and is not used; its device registers again to be delivered to"
                );
                Self::let_go_of(vault, sender_record_id);
                Ok(false)
            }
            StoredCredential::Held(credential)
                if credential.sender_record_id != sender_record_id =>
            {
                eprintln!(
                    "kr-controller: a stored delivery credential is another authorisation's and \
                     is not used; its device registers again to be delivered to"
                );
                Self::let_go_of(vault, sender_record_id);
                Ok(false)
            }
            StoredCredential::Held(credential) => {
                self.hold(credential);
                Ok(true)
            }
        }
    }

    /// Removes one authorisation's item from the vault at a start, and says so when it will not go.
    fn let_go_of(vault: &DestinationSecrets, sender_record_id: PushSenderRecordId) {
        if let Err(error) = vault.remove_push_credential(sender_record_id) {
            eprintln!(
                "kr-controller: a stored delivery credential could not be removed from the secret \
                 store: {error}"
            );
        }
    }

    /// Lets a refused renewal be asked for again: the refusal was about a credential no longer
    /// held. Called with `changing` held.
    fn clear_wait(&self, sender_record_id: PushSenderRecordId) {
        if let Ok(mut waits) = self.waits.lock() {
            waits.remove(&sender_record_id);
        }
    }

    /// Keeps the credential one authorisation was given: in the vault first, then in memory.
    ///
    /// A credential issued earlier than the one held is not kept: a renewal that finished while
    /// the gateway was confirming this one is newer, and replacing it would put back a bearer the
    /// renewal retired. See the module's note on which bearer is the latest.
    ///
    /// # Errors
    ///
    /// Returns why the credential was not kept, and then what was held is as it was.
    pub fn keep(&self, credential: PushDeliveryCredential) -> Result<(), String> {
        let _changing = self
            .changing
            .lock()
            .map_err(|_| "an earlier change of the held credentials failed part way".to_owned())?;
        let held = self.current(credential.sender_record_id);
        if held
            .as_ref()
            .is_some_and(|held| held.issued_at_ms > credential.issued_at_ms)
        {
            return Ok(());
        }
        if let Some(vault) = &self.vault {
            vault
                .put_push_credential(&credential)
                .map_err(|error| error.to_string())?;
        }
        if let Ok(mut unsaved) = self.unsaved.lock() {
            unsaved.remove(&credential.sender_record_id);
        }
        // A bearer the gateway has not seen refused is asked about afresh: the refusal of a
        // renewal is about the record, and a new bearer opens the hour after an issue in which
        // the gateway renews again.
        if held.is_none_or(|held| held.secret != credential.secret) {
            self.clear_wait(credential.sender_record_id);
        }
        self.hold(credential);
        Ok(())
    }

    /// Forgets one authorisation's credential, which is what unpairing does: from memory and from
    /// the vault.
    ///
    /// # Errors
    ///
    /// Returns why the vault would not give it up. Memory has let go of it all the same, so
    /// nothing more is delivered under it.
    pub fn forget(&self, sender_record_id: PushSenderRecordId) -> Result<(), String> {
        let _changing = self
            .changing
            .lock()
            .map_err(|_| "an earlier change of the held credentials failed part way".to_owned())?;
        if let Ok(mut held) = self.held.lock() {
            held.remove(&sender_record_id);
        }
        if let Ok(mut unsaved) = self.unsaved.lock() {
            unsaved.remove(&sender_record_id);
        }
        self.clear_wait(sender_record_id);
        match &self.vault {
            Some(vault) => vault
                .remove_push_credential(sender_record_id)
                .map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }

    /// The credential held for one authorisation, if any, without renewing it.
    #[must_use]
    pub fn held(&self, sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        self.current(sender_record_id)
    }

    /// Gives this store the renewal it replaces credentials through.
    ///
    /// Attached with the transport, because a renewal is a call to a gateway and a host with no
    /// transport cannot make one.
    pub fn attach_renewal(&self, renewal: Arc<dyn CredentialRenewal>) {
        if let Ok(mut attached) = self.renewal.write() {
            *attached = Some(renewal);
        }
    }

    /// Writes to the vault every held credential it does not have yet, and returns how many it
    /// could not.
    ///
    /// A renewed bearer the vault would not take stays in memory, where deliveries use it, and is
    /// written here on the next question tick.
    pub fn flush(&self) -> usize {
        let Some(vault) = &self.vault else {
            return 0;
        };
        let Ok(_changing) = self.changing.lock() else {
            return 0;
        };
        let pending: Vec<PushSenderRecordId> = self
            .unsaved
            .lock()
            .map(|unsaved| unsaved.iter().copied().collect())
            .unwrap_or_default();
        let mut failed = 0;
        for id in pending {
            let written = match self.current(id) {
                Some(credential) => vault.put_push_credential(&credential).is_ok(),
                // Forgotten since: nothing to keep.
                None => true,
            };
            if written {
                if let Ok(mut unsaved) = self.unsaved.lock() {
                    unsaved.remove(&id);
                }
            } else {
                failed += 1;
            }
        }
        failed
    }

    /// Renews every held credential inside section 16's renewal window, and returns how many it
    /// renewed.
    ///
    /// Renewing ahead of need is what makes renewal work while the phone is asleep: the host
    /// proves possession of its own key and needs nobody else awake, and a credential nothing
    /// delivered under for a week is still current when the next notification comes. A renewal
    /// that fails leaves the credential where it was, to be tried again.
    pub fn renew_due(&self, now_ms: u64) -> usize {
        self.flush();
        let due: Vec<PushDeliveryCredential> = self
            .held
            .lock()
            .map(|held| {
                held.values()
                    .filter(|credential| kr_delivery::push::needs_renewal(credential, now_ms))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        due.iter()
            .filter(|credential| self.renew(credential).is_ok())
            .count()
    }
}

impl SenderCredentials for HeldCredentials {
    fn current(&self, sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        self.held
            .lock()
            .ok()
            .and_then(|held| held.get(&sender_record_id).cloned())
    }

    fn renew(&self, held: &PushDeliveryCredential) -> kr_delivery::Result<PushDeliveryCredential> {
        let _one_at_a_time = self.renewing.lock().map_err(|_| {
            kr_delivery::DeliveryError::Source(
                "an earlier renewal failed part way and left its lock poisoned".to_owned(),
            )
        })?;
        // Compared under the lock, with the credential the caller holds: a renewal that finished
        // at any moment since the caller read `held`, including while this one waited for its
        // turn, has already replaced it. Renewing again would retire a bearer another caller may
        // be presenting now.
        let current = self.current(held.sender_record_id).ok_or_else(|| {
            kr_delivery::DeliveryError::Source(
                "this host holds no credential for that authorisation, so there is nothing to \
                 renew"
                    .to_owned(),
            )
        })?;
        if current.secret != held.secret {
            return Ok(current);
        }
        let refused_before = self.refusals_so_far(&current)?;
        // Answering with the credential already held would say a renewal happened when none did,
        // and the caller would present the same refused bearer again under the impression that it
        // had been replaced.
        let renewal = self
            .renewal
            .read()
            .ok()
            .and_then(|attached| attached.clone())
            .ok_or_else(|| {
                kr_delivery::DeliveryError::Source(
                    "this host has no transport to renew a credential through".to_owned(),
                )
            })?;
        let renewed = match renewal.renew(&current) {
            Ok(renewed) => renewed,
            Err(error) => {
                self.refused(&current, refused_before, &error);
                return Err(kr_delivery::DeliveryError::Source(error));
            }
        };
        // Replaced only while the authorisation is still held. A removal that came while the
        // gateway was answering stays a removal, and the renewed bearer is dropped here: the
        // gateway has a bearer this host will not use, and the authorisation it belongs to is
        // being revoked. A credential a device handed over and the gateway confirmed while this
        // waited is kept when the gateway issued it later than this renewal, and this answer is
        // that one. Otherwise the answer is the gateway's latest bearer.
        let _changing = self.changing.lock().map_err(|_| {
            kr_delivery::DeliveryError::Source(
                "an earlier change of the held credentials failed part way".to_owned(),
            )
        })?;
        let Some(newest) = self.current(renewed.sender_record_id) else {
            return Err(kr_delivery::DeliveryError::Source(
                "the authorisation was removed while it was being renewed".to_owned(),
            ));
        };
        if newest.issued_at_ms > renewed.issued_at_ms {
            return Ok(newest);
        }
        // The vault first, then memory. A write the vault refuses is retried at the next
        // question tick ([`Self::flush`]); the bearer is held meanwhile, because the gateway has
        // retired the one before it.
        if let Some(vault) = &self.vault {
            if let Err(error) = vault.put_push_credential(&renewed) {
                eprintln!(
                    "kr-controller: a renewed delivery credential could not be kept yet: {error}"
                );
                if let Ok(mut unsaved) = self.unsaved.lock() {
                    unsaved.insert(renewed.sender_record_id);
                }
            } else if let Ok(mut unsaved) = self.unsaved.lock() {
                unsaved.remove(&renewed.sender_record_id);
            }
        }
        self.clear_wait(renewed.sender_record_id);
        self.hold(renewed.clone());
        Ok(renewed)
    }
}

impl HeldCredentials {
    /// How many renewals of the credential held were refused in a row, or why none is asked for
    /// now: the gateway is not asked while a refusal's wait lasts, unless the credential has
    /// expired, which nothing presents until it is renewed.
    fn refusals_so_far(
        &self,
        held: &PushDeliveryCredential,
    ) -> Result<u32, kr_delivery::DeliveryError> {
        let waits = self.waits.lock().map_err(|_| {
            kr_delivery::DeliveryError::Source(
                "an earlier renewal failed part way and left its lock poisoned".to_owned(),
            )
        })?;
        let Some(last) = waits.get(&held.sender_record_id) else {
            return Ok(0);
        };
        let steady_ms = (self.clocks.steady)();
        let expired = (self.clocks.wall)() >= held.expires_at_ms.get();
        match last.wait.until_steady_ms.checked_sub(steady_ms) {
            Some(remaining) if remaining > 0 && !expired => {
                Err(kr_delivery::DeliveryError::Source(format!(
                    "{}; this host asks again in {} seconds",
                    last.said,
                    remaining.div_ceil(1000)
                )))
            }
            _ => Ok(last.wait.refusals),
        }
    }

    /// Records a refused renewal of `refused`, the credential it was asked for: the next ask waits
    /// longer than the last. Nothing is recorded when the credential held is no longer that one,
    /// because the refusal is then about a bearer the host has let go of.
    fn refused(&self, refused: &PushDeliveryCredential, refusals_before: u32, said: &str) {
        let Ok(_changing) = self.changing.lock() else {
            return;
        };
        if self
            .current(refused.sender_record_id)
            .is_none_or(|held| held.secret != refused.secret)
        {
            return;
        }
        if let Ok(mut waits) = self.waits.lock() {
            waits.insert(
                refused.sender_record_id,
                Refusal {
                    wait: Wait {
                        refusals: refusals_before.saturating_add(1),
                        until_steady_ms: (self.clocks.steady)()
                            .saturating_add(renewal_backoff_ms(refusals_before)),
                    },
                    said: said.to_owned(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::{InstallationId, PushSenderRevision};
    use kr_protocol::scalars::{SecretBytes32, TimestampMs, Uuid};
    use kr_protocol::service::GatewayOrigin;

    use super::*;

    const NOW: u64 = 1_700_000_000_000;
    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn credential(record: u8, secret: u8, expires_at_ms: u64) -> PushDeliveryCredential {
        PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(expires_at_ms),
            gateway_origin: GatewayOrigin::new("https://reach.invalid").expect("an origin"),
            installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
            issued_at_ms: TimestampMs::new(expires_at_ms - 29 * DAY),
            revision: PushSenderRevision::new(1),
            secret: SecretBytes32::from_bytes([secret; 32]),
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([record; 16])),
        }
    }

    /// Renews every credential into a new secret, and counts what it was asked.
    #[derive(Debug, Default)]
    struct Renewing {
        asked: Mutex<Vec<PushSenderRecordId>>,
    }

    impl CredentialRenewal for Renewing {
        fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push(held.sender_record_id);
            Ok(PushDeliveryCredential {
                secret: SecretBytes32::from_bytes([0xee; 32]),
                expires_at_ms: TimestampMs::new(NOW + 30 * DAY),
                ..held.clone()
            })
        }
    }

    #[test]
    fn a_store_with_no_renewal_says_so_and_keeps_what_it_holds() {
        let credentials = HeldCredentials::new();
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let refused = credentials
            .renew(&held)
            .expect_err("nothing to renew through");
        assert!(refused.to_string().contains("no transport"), "{refused}");
        assert_eq!(credentials.current(held.sender_record_id), Some(held));
        assert!(
            credentials.renew(&credential(4, 9, NOW + 2 * DAY)).is_err(),
            "and a credential it does not hold is not renewed"
        );
    }

    #[test]
    fn a_renewal_replaces_the_credential_it_renewed() {
        let credentials = HeldCredentials::new();
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        credentials.attach_renewal(Arc::new(Renewing::default()));
        let renewed = credentials.renew(&held).expect("a renewal");
        assert_ne!(renewed.secret, held.secret);
        assert_eq!(
            credentials.current(held.sender_record_id),
            Some(renewed),
            "what is presented next is the renewed bearer"
        );
    }

    #[test]
    fn only_credentials_inside_the_renewal_window_are_renewed_ahead_of_need() {
        let credentials = HeldCredentials::new();
        credentials.hold(credential(3, 9, NOW + 2 * DAY));
        credentials.hold(credential(4, 9, NOW + 20 * DAY));
        let renewal = Arc::new(Renewing::default());
        credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
        assert_eq!(credentials.renew_due(NOW), 1);
        assert_eq!(
            *renewal.asked.lock().expect("not poisoned"),
            vec![PushSenderRecordId::new(Uuid::from_bytes([3; 16]))],
            "twenty days from expiry is outside section 16's seven-day window"
        );
    }

    /// Renews slowly and counts, which is how two callers are made to overlap.
    #[derive(Debug, Default)]
    struct SlowRenewal {
        renewed: Mutex<u32>,
    }

    impl CredentialRenewal for SlowRenewal {
        fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let mut renewed = self.renewed.lock().expect("not poisoned");
            *renewed += 1;
            Ok(PushDeliveryCredential {
                secret: SecretBytes32::from_bytes([u8::try_from(*renewed).unwrap_or(0xff); 32]),
                ..held.clone()
            })
        }
    }

    /// Two callers that find one credential due at once get one renewal between them: the second
    /// waits for the first and takes what it produced, rather than retiring it with a second one.
    #[test]
    fn two_callers_renewing_one_credential_at_once_share_one_renewal() {
        let credentials = Arc::new(HeldCredentials::new());
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let renewal = Arc::new(SlowRenewal::default());
        credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
        let callers: Vec<_> = (0..2)
            .map(|_| {
                let credentials = Arc::clone(&credentials);
                let held = held.clone();
                std::thread::spawn(move || credentials.renew(&held))
            })
            .collect();
        let renewed: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().expect("a caller").expect("a renewal"))
            .collect();
        assert_eq!(*renewal.renewed.lock().expect("not poisoned"), 1);
        assert_eq!(
            renewed[0], renewed[1],
            "both hold the one bearer the gateway kept"
        );
    }

    /// A caller that read the credential before another caller renewed it, and asks only once
    /// that renewal has finished, is given that renewal rather than a second one.
    #[test]
    fn a_renewal_asked_for_after_another_caller_renewed_is_that_renewal() {
        let credentials = HeldCredentials::new();
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let renewal = Arc::new(Renewing::default());
        credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
        // The first caller reads the credential, finds it due, and is held up.
        let first_read = credentials
            .current(held.sender_record_id)
            .expect("a credential");
        // The second caller renews it, start to finish.
        let second = credentials.renew(&held).expect("a renewal");
        // The first caller now asks, with the credential it read.
        let first = credentials.renew(&first_read).expect("an answer");
        assert_eq!(
            first, second,
            "it is given the renewal that already happened"
        );
        assert_eq!(
            renewal.asked.lock().expect("not poisoned").len(),
            1,
            "and nothing was renewed twice"
        );
    }

    /// A store that takes writes, deletions and reads only when it is let.
    #[derive(Debug, Default)]
    struct Flaky {
        inner: kr_crypto::store::MemoryStore,
        refusing: std::sync::atomic::AtomicBool,
        refusing_deletes: std::sync::atomic::AtomicBool,
        unreadable: std::sync::atomic::AtomicBool,
    }

    impl kr_crypto::store::SecretStore for Flaky {
        fn set(&self, name: &kr_crypto::store::SecretName, secret: &[u8]) -> kr_crypto::Result<()> {
            if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store refuses".to_owned(),
                });
            }
            self.inner.set(name, secret)
        }

        fn get(
            &self,
            name: &kr_crypto::store::SecretName,
        ) -> kr_crypto::Result<Option<kr_crypto::secret::SecretVec>> {
            if self.unreadable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store cannot be read".to_owned(),
                });
            }
            self.inner.get(name)
        }

        fn delete(&self, name: &kr_crypto::store::SecretName) -> kr_crypto::Result<()> {
            if self
                .refusing_deletes
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store refuses to delete".to_owned(),
                });
            }
            self.inner.delete(name)
        }

        fn describe(&self) -> String {
            "a flaky store".to_owned()
        }
    }

    /// A renewed bearer the store would not take is held and used, because the gateway has retired
    /// the one before it, and is written when the store takes writes again, so a restart finds it.
    #[test]
    fn a_renewed_bearer_the_vault_would_not_take_is_written_when_it_can_be() {
        let store = Arc::new(Flaky::default());
        let vault = DestinationSecrets::new(
            Arc::clone(&store) as Arc<dyn kr_crypto::store::SecretStore>,
            kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])),
        );
        let credentials = HeldCredentials::persisted(vault.clone());
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.keep(held.clone()).expect("kept");
        credentials.attach_renewal(Arc::new(Renewing::default()));
        store
            .refusing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let renewed = credentials.renew(&held).expect("a renewal");
        assert_eq!(
            credentials.held(held.sender_record_id),
            Some(renewed.clone())
        );
        let stored = |vault: &DestinationSecrets| match vault
            .push_credential(held.sender_record_id)
            .expect("a read")
        {
            StoredCredential::Held(credential) => credential,
            other => panic!("kept: {other:?}"),
        };
        assert_eq!(
            stored(&vault),
            held,
            "the vault still has the earlier bearer"
        );
        assert_eq!(credentials.flush(), 1, "and the write is still refused");

        store
            .refusing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(credentials.flush(), 0);
        assert_eq!(stored(&vault), renewed, "the vault has what is held");
    }

    /// Answers a renewal only once it is let: with a credential the gateway issued at the time
    /// given, or with a refusal.
    #[derive(Debug)]
    struct Gated {
        started: std::sync::mpsc::SyncSender<()>,
        go: Mutex<std::sync::mpsc::Receiver<()>>,
        answer: Result<u64, String>,
    }

    impl Gated {
        /// A renewal held at the gateway, with the sending ends the test lets it go by.
        fn new(
            answer: Result<u64, String>,
        ) -> (
            Arc<Self>,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::SyncSender<()>,
        ) {
            let (started_tx, started) = std::sync::mpsc::sync_channel(1);
            let (go_tx, go) = std::sync::mpsc::sync_channel(1);
            let gate = Arc::new(Self {
                started: started_tx,
                go: Mutex::new(go),
                answer,
            });
            (gate, started, go_tx)
        }
    }

    impl CredentialRenewal for Gated {
        fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
            self.started.send(()).expect("the test is listening");
            self.go
                .lock()
                .expect("not poisoned")
                .recv()
                .expect("the test lets it go");
            self.answer
                .clone()
                .map(|issued_at_ms| PushDeliveryCredential {
                    secret: SecretBytes32::from_bytes([0xee; 32]),
                    issued_at_ms: TimestampMs::new(issued_at_ms),
                    ..held.clone()
                })
        }
    }

    /// A removal that comes while the gateway is answering a renewal stays a removal.
    #[test]
    fn a_removal_during_a_renewal_stays_a_removal() {
        let credentials = Arc::new(HeldCredentials::new());
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.keep(held.clone()).expect("kept");
        let (gate, started, go) = Gated::new(Ok(held.issued_at_ms.get() + 1));
        credentials.attach_renewal(gate);
        let renewing = {
            let credentials = Arc::clone(&credentials);
            let held = held.clone();
            std::thread::spawn(move || credentials.renew(&held))
        };
        started.recv().expect("the renewal is on its way");
        credentials
            .forget(held.sender_record_id)
            .expect("forgotten");
        go.send(()).expect("let it go");
        assert!(renewing.join().expect("a caller").is_err());
        assert!(credentials.held(held.sender_record_id).is_none());
    }

    /// Whichever of two credentials for one authorisation the gateway issued later is kept,
    /// whichever order the host hears of them in. A renewal that was asked for first and answers
    /// last, after the device handed over a bearer the gateway issued after it, gives that bearer
    /// back; and a registration that is kept while a renewal is on its way gives way to the
    /// renewal if the renewal is the later issue.
    #[test]
    fn the_credential_issued_later_is_kept_whichever_the_host_hears_of_last() {
        let id = PushSenderRecordId::new(Uuid::from_bytes([3; 16]));
        let held = credential(3, 9, NOW + 2 * DAY);
        let issued = held.issued_at_ms.get();
        let handed_over = |secret: u8, at: u64| PushDeliveryCredential {
            issued_at_ms: TimestampMs::new(at),
            ..credential(3, secret, NOW + 2 * DAY)
        };

        // The renewal is the earlier issue: the device's bearer, handed over while it was on its
        // way, is the one that works.
        let credentials = Arc::new(HeldCredentials::new());
        credentials.hold(held.clone());
        let (gate, started, go) = Gated::new(Ok(issued + 10));
        credentials.attach_renewal(gate);
        let renewing = {
            let credentials = Arc::clone(&credentials);
            let held = held.clone();
            std::thread::spawn(move || credentials.renew(&held))
        };
        started.recv().expect("the renewal is on its way");
        let theirs = handed_over(7, issued + 20);
        credentials.keep(theirs.clone()).expect("kept");
        go.send(()).expect("let it go");
        let answered = renewing.join().expect("a caller").expect("an answer");
        assert_eq!(
            answered, theirs,
            "the caller is given the bearer that works"
        );
        assert_eq!(credentials.held(id), Some(theirs));

        // The renewal is the later issue: it is kept over the bearer handed over while it was on
        // its way, which it retired.
        let credentials = Arc::new(HeldCredentials::new());
        credentials.hold(held.clone());
        let (gate, started, go) = Gated::new(Ok(issued + 30));
        credentials.attach_renewal(gate);
        let renewing = {
            let credentials = Arc::clone(&credentials);
            let held = held.clone();
            std::thread::spawn(move || credentials.renew(&held))
        };
        started.recv().expect("the renewal is on its way");
        credentials.keep(handed_over(7, issued + 20)).expect("kept");
        go.send(()).expect("let it go");
        let answered = renewing.join().expect("a caller").expect("an answer");
        assert_eq!(answered.issued_at_ms.get(), issued + 30);
        assert_eq!(credentials.held(id), Some(answered));

        // And a registration that comes after a renewal that is already kept gives way to it.
        let later = credentials.held(id).expect("held");
        credentials
            .keep(handed_over(8, issued + 5))
            .expect("not kept, and not an error");
        assert_eq!(credentials.held(id), Some(later));
    }

    /// An item at start that this build cannot read, or that is another authorisation's, is
    /// removed and reported, and the daemon starts: a destination with no credential delivers
    /// once its device registers again, and a daemon that stopped for the item would deliver to
    /// nobody.
    #[test]
    fn a_stored_item_this_build_cannot_use_is_removed_at_start() {
        let vault = DestinationSecrets::new(
            Arc::new(kr_crypto::store::MemoryStore::new()),
            kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])),
        );
        let credentials = HeldCredentials::persisted(vault.clone());
        let id = PushSenderRecordId::new(Uuid::from_bytes([3; 16]));
        // A later build's item: it names a field this build does not know.
        vault.put_raw_push_item(id, br#"{"a_field_a_later_build_wrote":1}"#);
        assert!(matches!(
            vault.push_credential(id).expect("a read"),
            StoredCredential::Unreadable
        ));
        assert!(!credentials.load(id).expect("the start goes on"));
        assert!(matches!(
            vault.push_credential(id).expect("a read"),
            StoredCredential::Absent
        ));

        // Another authorisation's credential kept under this one's name.
        let other = credential(4, 9, NOW + 2 * DAY);
        vault.put_push_credential(&other).expect("a write");
        vault.put_raw_push_item(id, &serde_json::to_vec(&other).expect("an item"));
        assert!(!credentials.load(id).expect("the start goes on"));
        assert!(credentials.held(id).is_none());
        assert!(matches!(
            vault.push_credential(id).expect("a read"),
            StoredCredential::Absent
        ));
    }

    /// An item at start that cannot be used and that the store will not give up is reported and
    /// not loaded, and the start goes on: the item only wastes room, and a daemon that stopped for
    /// it would deliver to nobody. A store that cannot be read at all is another matter, and the
    /// start stops for it.
    #[test]
    fn a_store_that_refuses_a_deletion_does_not_stop_the_start_but_one_that_cannot_be_read_does() {
        let store = Arc::new(Flaky::default());
        let vault = DestinationSecrets::new(
            Arc::clone(&store) as Arc<dyn kr_crypto::store::SecretStore>,
            kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])),
        );
        let credentials = HeldCredentials::persisted(vault.clone());
        let id = PushSenderRecordId::new(Uuid::from_bytes([3; 16]));
        vault.put_raw_push_item(id, br#"{"a_field_a_later_build_wrote":1}"#);
        store
            .refusing_deletes
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            !credentials
                .load(id)
                .expect("a refused deletion is reported and the start goes on"),
            "and nothing is loaded from it"
        );
        assert!(credentials.held(id).is_none());
        assert!(matches!(
            vault.push_credential(id).expect("a read"),
            StoredCredential::Unreadable
        ));

        // Another authorisation's credential kept under this one's name, which it also would not
        // give up.
        let other = credential(4, 9, NOW + 2 * DAY);
        vault.put_raw_push_item(id, &serde_json::to_vec(&other).expect("an item"));
        assert!(!credentials.load(id).expect("the start goes on"));
        assert!(credentials.held(id).is_none());

        // The control: a store that cannot be read stops the start, and a store that can give the
        // item up does.
        store
            .unreadable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(credentials.load(id).is_err());
        store
            .unreadable
            .store(false, std::sync::atomic::Ordering::SeqCst);
        store
            .refusing_deletes
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!credentials.load(id).expect("the start goes on"));
        assert!(matches!(
            vault.push_credential(id).expect("a read"),
            StoredCredential::Absent
        ));
    }

    /// The same at the daemon's start as a whole: an authorisation the host owes a revocation for
    /// is forgotten first, and a store that will not delete its item leaves the item and the debt,
    /// not a daemon that does not start.
    #[test]
    fn a_start_goes_on_when_the_store_will_not_give_up_what_a_debt_names() {
        let store = Arc::new(Flaky::default());
        let vault = DestinationSecrets::new(
            Arc::clone(&store) as Arc<dyn kr_crypto::store::SecretStore>,
            kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])),
        );
        let directory = tempfile::tempdir().expect("a directory");
        let delivery = crate::push::DeliveryModule::open_at(
            &directory.path().join("delivery.sqlite3"),
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
            vault.clone(),
        )
        .expect("a delivery module");
        let owed = credential(3, 9, NOW + 2 * DAY);
        vault.put_push_credential(&owed).expect("a write");
        delivery
            .with(|producer| {
                producer
                    .journal_mut()
                    .owe_revocation(owed.sender_record_id, "https://reach.invalid", NOW)
                    .expect("a debt");
                Ok(())
            })
            .expect("the debt is written");
        store
            .refusing_deletes
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let credentials = HeldCredentials::persisted(vault.clone());
        let loaded =
            crate::push::load_held_credentials(&delivery, &credentials).expect("the start goes on");
        assert_eq!(loaded, 0);
        assert!(
            credentials.held(owed.sender_record_id).is_none(),
            "an authorisation being revoked is not loaded"
        );
        assert!(
            matches!(
                vault
                    .push_credential(owed.sender_record_id)
                    .expect("a read"),
                StoredCredential::Held(_)
            ),
            "and the item is still there for the sweep to delete"
        );
    }

    /// Refuses every renewal, and counts the asks.
    #[derive(Debug, Default)]
    struct Refusing {
        asked: Mutex<u32>,
    }

    impl CredentialRenewal for Refusing {
        fn renew(&self, _held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
            *self.asked.lock().expect("not poisoned") += 1;
            Err("the gateway refused the renewal (403, FORBIDDEN)".to_owned())
        }
    }

    /// A credential whose expiry says it is due and that the gateway will not renew, because the
    /// expiry is the device's word, is asked about once, and again only after a wait that grows to
    /// an hour. Asked at every question tick it would cost the gateway's allowance twenty-four
    /// requests an hour for as long as the credential lasts.
    #[test]
    fn a_refused_renewal_is_not_asked_for_again_until_its_wait_is_over() {
        const MINUTE: u64 = 60 * 1000;
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
        let credentials = HeldCredentials::counting_on(
            {
                let clock = Arc::clone(&clock);
                Arc::new(move || clock.load(std::sync::atomic::Ordering::SeqCst))
            },
            Arc::new(|| NOW),
        );
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let gateway = Arc::new(Refusing::default());
        credentials.attach_renewal(Arc::clone(&gateway) as Arc<dyn CredentialRenewal>);
        let asked = || *gateway.asked.lock().expect("not poisoned");
        let advance = |by: u64| clock.fetch_add(by, std::sync::atomic::Ordering::SeqCst);

        for tick in 0..3 {
            assert_eq!(credentials.renew_due(NOW), 0, "tick {tick}");
        }
        assert_eq!(asked(), 1, "three ticks, one question to the gateway");

        // A delivery that needs the credential is held back the same way, and says why.
        let refused = credentials
            .renew(&held)
            .expect_err("it was refused a moment ago");
        assert!(refused.to_string().contains("asks again"), "{refused}");
        assert_eq!(asked(), 1);

        // The wait doubles with each refusal and stops growing at an hour.
        let mut asks = 1;
        for wait in [5, 10, 20, 40, 60, 60] {
            advance(wait * MINUTE - 1);
            assert_eq!(credentials.renew_due(NOW), 0);
            assert_eq!(asked(), asks, "not before {wait} minutes");
            advance(1);
            assert_eq!(credentials.renew_due(NOW), 0);
            asks += 1;
            assert_eq!(asked(), asks, "and at {wait} minutes");
        }
    }

    /// A credential past its expiry is asked about at every attempt, wait or no wait: nothing
    /// presents it, so nothing is lost by asking, and the wait would hold back every notification.
    #[test]
    fn an_expired_credential_is_renewed_whatever_the_last_refusal_said() {
        let credentials = HeldCredentials::counting_on(Arc::new(|| 1_000_000), Arc::new(|| NOW));
        let held = credential(3, 9, NOW - 1_000);
        credentials.hold(held.clone());
        let gateway = Arc::new(Refusing::default());
        credentials.attach_renewal(Arc::clone(&gateway) as Arc<dyn CredentialRenewal>);
        for _ in 0..3 {
            credentials.renew(&held).expect_err("refused");
        }
        assert_eq!(*gateway.asked.lock().expect("not poisoned"), 3);
    }

    /// The wait reads the clock once, so a clock that moves between the check and the message
    /// cannot make the time left a negative number. A clock that moves three minutes every time
    /// it is read crosses the end of a five-minute wait between any two reads.
    #[test]
    fn the_time_left_of_a_wait_is_read_from_one_reading_of_the_clock() {
        let reads = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let credentials = HeldCredentials::counting_on(
            {
                let reads = Arc::clone(&reads);
                Arc::new(move || 180_000 * reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
            },
            Arc::new(|| NOW),
        );
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let gateway = Arc::new(Refusing::default());
        credentials.attach_renewal(Arc::clone(&gateway) as Arc<dyn CredentialRenewal>);
        // The refusal reads the clock at 0 and sets a wait that ends at five minutes.
        credentials.renew(&held).expect_err("refused");
        // Asked again at three minutes: two minutes to wait, and one reading to say so.
        let waiting = credentials
            .renew(&held)
            .expect_err("still waiting")
            .to_string();
        assert!(waiting.contains("in 120 seconds"), "{waiting}");
        assert_eq!(*gateway.asked.lock().expect("not poisoned"), 1);
    }

    /// A credential the device hands over for an authorisation is asked about afresh: the refusal
    /// was about the one that was held. The same bearer handed over again is not a new one.
    #[test]
    fn a_new_bearer_is_renewed_without_waiting_for_the_last_refusal() {
        let credentials = HeldCredentials::counting_on(Arc::new(|| 1_000_000), Arc::new(|| NOW));
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let gateway = Arc::new(Refusing::default());
        credentials.attach_renewal(Arc::clone(&gateway) as Arc<dyn CredentialRenewal>);
        assert_eq!(credentials.renew_due(NOW), 0);
        credentials.keep(held.clone()).expect("the same bearer");
        assert_eq!(credentials.renew_due(NOW), 0);
        assert_eq!(
            *gateway.asked.lock().expect("not poisoned"),
            1,
            "the same bearer again leaves the wait"
        );
        let handed_over = credential(3, 7, NOW + 2 * DAY);
        credentials.keep(handed_over).expect("a new bearer");
        assert_eq!(credentials.renew_due(NOW), 0);
        assert_eq!(*gateway.asked.lock().expect("not poisoned"), 2);
    }

    /// A refusal that comes back after the credential it was about has been replaced is not held
    /// against the replacement.
    #[test]
    fn a_late_refusal_is_not_held_against_the_credential_that_replaced_it() {
        let credentials = Arc::new(HeldCredentials::counting_on(
            Arc::new(|| 1_000_000),
            Arc::new(|| NOW),
        ));
        let held = credential(3, 9, NOW + 2 * DAY);
        credentials.hold(held.clone());
        let (gate, started, go) = Gated::new(Err("the gateway refused the renewal".to_owned()));
        credentials.attach_renewal(gate);
        let renewing = {
            let credentials = Arc::clone(&credentials);
            let held = held.clone();
            std::thread::spawn(move || credentials.renew(&held))
        };
        started.recv().expect("the renewal is on its way");
        let replacement = credential(3, 7, NOW + 2 * DAY);
        credentials.keep(replacement.clone()).expect("kept");
        go.send(()).expect("let it go");
        renewing.join().expect("a caller").expect_err("refused");

        let again = Arc::new(Refusing::default());
        credentials.attach_renewal(Arc::clone(&again) as Arc<dyn CredentialRenewal>);
        credentials
            .renew(&replacement)
            .expect_err("refused by the second gateway");
        assert_eq!(
            *again.asked.lock().expect("not poisoned"),
            1,
            "the replacement was asked about at once"
        );
    }
}
