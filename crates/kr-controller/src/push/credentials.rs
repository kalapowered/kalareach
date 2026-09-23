//! The bearer this host delivers under, and renewing it.
//!
//! Section 16 gives the host two of the four `Services` push methods: `push.sender.renew` and
//! `push.sender.revoke`, both proven by the **host** key over a fresh gateway nonce. The other
//! two, registering a token and issuing a sender authorisation, are the installation's and reach
//! the gateway from the device; the credential they produce arrives here through the paired
//! encrypted channel.
//!
//! Renewal is [`super::sender`]'s: this store holds what the host delivers under and asks the
//! renewal it was given to replace a credential, and a store with no renewal says so rather than
//! answering with the credential it already has.
//!
//! # Where the secret lives
//!
//! In memory, in [`HeldCredentials`], and nowhere else. It is never written to the delivery
//! journal, never logged and never put in an error message: what the journal holds is the
//! `sender_record_id`, which names the authorisation and proves nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use kr_delivery::push::SenderCredentials;
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::push::PushDeliveryCredential;

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
}

impl HeldCredentials {
    /// Builds an empty store with no way to renew yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the credential one authorisation produced.
    pub fn hold(&self, credential: PushDeliveryCredential) {
        if let Ok(mut held) = self.held.lock() {
            held.insert(credential.sender_record_id, credential);
        }
    }

    /// Forgets one authorisation's credential, which is what unpairing does.
    pub fn forget(&self, sender_record_id: PushSenderRecordId) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(&sender_record_id);
        }
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

    /// Renews every held credential inside section 16's renewal window, and returns how many it
    /// renewed.
    ///
    /// Renewing ahead of need is what makes renewal work while the phone is asleep: the host
    /// proves possession of its own key and needs nobody else awake, and a credential nothing
    /// delivered under for a week is still current when the next notification comes. A renewal
    /// that fails leaves the credential where it was, to be tried again.
    pub fn renew_due(&self, now_ms: u64) -> usize {
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
}
