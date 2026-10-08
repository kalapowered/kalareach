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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use kr_delivery::push::SenderCredentials;
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::push::PushDeliveryCredential;

use super::secrets::{DestinationSecrets, StoredCredential};

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
    /// deliver to nobody. Returns whether a credential was held.
    ///
    /// # Errors
    ///
    /// Returns why the vault could not be read or written.
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
                     and was removed; its device registers again to be delivered to"
                );
                vault
                    .remove_push_credential(sender_record_id)
                    .map_err(|error| error.to_string())?;
                Ok(false)
            }
            StoredCredential::Held(credential)
                if credential.sender_record_id != sender_record_id =>
            {
                eprintln!(
                    "kr-controller: a stored delivery credential is another authorisation's and \
                     was removed; its device registers again to be delivered to"
                );
                vault
                    .remove_push_credential(sender_record_id)
                    .map_err(|error| error.to_string())?;
                Ok(false)
            }
            StoredCredential::Held(credential) => {
                self.hold(credential);
                Ok(true)
            }
        }
    }

    /// Keeps the credential one authorisation was given: in the vault first, then in memory.
    ///
    /// Whether it is the gateway's latest is not decided here: a bearer the gateway has retired is
    /// refused when it is asked about ([`super::runtime::DeliveryRuntime::confirm`]), and the
    /// revision a credential carries is the device's word.
    ///
    /// # Errors
    ///
    /// Returns why the credential was not kept, and then what was held is as it was.
    pub fn keep(&self, credential: PushDeliveryCredential) -> Result<(), String> {
        let _changing = self
            .changing
            .lock()
            .map_err(|_| "an earlier change of the held credentials failed part way".to_owned())?;
        if let Some(vault) = &self.vault {
            vault
                .put_push_credential(&credential)
                .map_err(|error| error.to_string())?;
        }
        if let Ok(mut unsaved) = self.unsaved.lock() {
            unsaved.remove(&credential.sender_record_id);
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
        let renewed = renewal
            .renew(&current)
            .map_err(kr_delivery::DeliveryError::Source)?;
        // Replaced only while the authorisation is still held. A removal that came while the
        // gateway was answering stays a removal, and the renewed bearer is dropped here: the
        // gateway has a bearer this host will not use, and the authorisation it belongs to is
        // being revoked. Otherwise the answer is the gateway's latest bearer, whatever was kept
        // while it was coming.
        let _changing = self.changing.lock().map_err(|_| {
            kr_delivery::DeliveryError::Source(
                "an earlier change of the held credentials failed part way".to_owned(),
            )
        })?;
        if self.current(renewed.sender_record_id).is_none() {
            return Err(kr_delivery::DeliveryError::Source(
                "the authorisation was removed while it was being renewed".to_owned(),
            ));
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
        self.hold(renewed.clone());
        Ok(renewed)
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

    /// A store that takes writes only when it is let.
    #[derive(Debug, Default)]
    struct Flaky {
        inner: kr_crypto::store::MemoryStore,
        refusing: std::sync::atomic::AtomicBool,
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
            self.inner.get(name)
        }

        fn delete(&self, name: &kr_crypto::store::SecretName) -> kr_crypto::Result<()> {
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

    /// Answers a renewal only once it is let.
    #[derive(Debug)]
    struct Gated {
        started: std::sync::mpsc::SyncSender<()>,
        go: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl CredentialRenewal for Gated {
        fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
            self.started.send(()).expect("the test is listening");
            self.go
                .lock()
                .expect("not poisoned")
                .recv()
                .expect("the test lets it go");
            Ok(PushDeliveryCredential {
                secret: SecretBytes32::from_bytes([0xee; 32]),
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
        let (started_tx, started) = std::sync::mpsc::sync_channel(1);
        let (go_tx, go) = std::sync::mpsc::sync_channel(1);
        credentials.attach_renewal(Arc::new(Gated {
            started: started_tx,
            go: Mutex::new(go),
        }));
        let renewing = {
            let credentials = Arc::clone(&credentials);
            let held = held.clone();
            std::thread::spawn(move || credentials.renew(&held))
        };
        started.recv().expect("the renewal is on its way");
        credentials
            .forget(held.sender_record_id)
            .expect("forgotten");
        go_tx.send(()).expect("let it go");
        assert!(renewing.join().expect("a caller").is_err());
        assert!(credentials.held(held.sender_record_id).is_none());
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
}
