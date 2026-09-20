//! The content-bearing outbox privacy mode reaches.
//!
//! T-040 built the contract and the two worked examples over this crate's kind of store. This is
//! the real one: a queue that holds built notifications and composed external messages, and sends
//! them somewhere this host cannot recall them from.
//!
//! Section 24, in the order it states them:
//!
//! 1. **Fence** the content-bearing outbox *at once*. [`DeliveryJournal::due`] answers with
//!    nothing while the fence is up, so the stop is in the read every sender makes rather than in
//!    a flag each of them remembers to check.
//! 2. **Cancel** what was admitted and never dispatched. It has not left, so it is taken back and
//!    its bytes go with it.
//! 3. **Remove** the retained local content: the built request bodies and the encrypted objects a
//!    preview's excess detail moved into. The records of what happened stay, because a host that
//!    forgot its own attempts could not tell a person what the device did not see.
//! 4. **Reconcile** before completion is reported. [`DeliveryOutbox::outstanding`] counts what was
//!    on the wire and what has an unknown outcome, and privacy mode is not complete while either
//!    is above nought.
//!
//! And the part section 24 is most specific about: *already uploaded archives and notifications
//! and copies held by authorised viewers are not retroactively erased. Show those retained
//! artifacts and offer an explicit separately authorised deletion action.* [`DeliveryOutbox::
//! exported`] is that list. Every entry says it is not deletable by this host, because it is not:
//! a notification a provider queued is on a device, and an external message is in somebody else's
//! service.

use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
};

use crate::journal::DeliveryJournal;

/// The delivery outbox, as privacy mode sees it.
///
/// It borrows the journal rather than owning it, which is T-040's own shape: the caller holds the
/// subsystems and drives them, so the one that reports its own cleanup is still reachable after
/// the enabling that started it.
#[derive(Debug)]
pub struct DeliveryOutbox<'a> {
    journal: &'a mut DeliveryJournal,
    now_ms: u64,
    failure: Option<String>,
}

impl<'a> DeliveryOutbox<'a> {
    /// Builds the hook over one environment's delivery journal.
    ///
    /// `now_ms` is what a cancellation receipt is stamped with. A generation is not a time, and a
    /// receipt stamped with one would say a cancellation happened in 1970.
    #[must_use]
    pub fn over(journal: &'a mut DeliveryJournal, now_ms: u64) -> Self {
        Self {
            journal,
            now_ms,
            failure: None,
        }
    }

    /// Returns why a step could not finish, when one could not.
    ///
    /// A failure here keeps [`PrivacySubsystem::outstanding`] above nought, so cleanup does not
    /// report complete over content it did not manage to remove.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    fn record(&mut self, what: &str, error: &crate::DeliveryError) {
        self.failure = Some(format!("{what}: {error}"));
    }
}

impl PrivacySubsystem for DeliveryOutbox<'_> {
    fn name(&self) -> &'static str {
        "delivery"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        match self.journal.fence(generation.get()) {
            Ok((queues, items)) => Fenced { queues, items },
            Err(error) => {
                // A fence this host could not record is a fence it is not in. Saying so is what
                // stops privacy mode reporting that the queue was stopped.
                self.record("the delivery outbox could not be fenced", &error);
                Fenced::default()
            }
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        match self.journal.cancel_undispatched(self.now_ms) {
            Ok((undispatched, in_flight)) => Cancelled {
                undispatched,
                in_flight,
            },
            Err(error) => {
                self.record("admitted deliveries could not be taken back", &error);
                Cancelled::default()
            }
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        match self.journal.remove_retained() {
            Ok((bytes, records)) => Removed { bytes, records },
            Err(error) => {
                self.record("queued content could not be removed", &error);
                Removed::default()
            }
        }
    }

    fn outstanding(&self) -> u64 {
        let queued = self.journal.outstanding().unwrap_or(1);
        queued.saturating_add(u64::from(self.failure.is_some()))
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![
            KeptExplicitly {
                what: "the delivery journal's own records: which event, which destination, which \
                       attempt and what became of it",
                why: "section 16 has the host retain every request and report suppression \
                      locally, and a host that forgot its attempts could not tell a person what \
                      the device did not see",
            },
            KeptExplicitly {
                what: "each destination's spent rate allowance",
                why: "the burst and sustained limits are per destination and survive a restart; \
                      forgetting them would be a way to buy twenty more notifications",
            },
        ]
    }

    fn exported(&self) -> Vec<Exported> {
        self.journal
            .exported()
            .unwrap_or_default()
            .into_iter()
            .map(|exported| Exported {
                kind: exported.kind,
                reference: exported.reference,
                left_at_ms: exported.left_at_ms,
                deletable: exported.deletable,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{
        DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
        ExternalDestination, Idempotency,
    };
    use crate::journal::{
        DeliveryRecord, DeliveryState, EventKey, EventSource, TakenEvent, Transition,
    };
    use kr_protocol::ids::NotificationId;
    use kr_protocol::scalars::{TimestampMs, Uuid};
    use kr_worker::privacy::{Completion, PrivacyMode};

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn consumer() -> String {
        EventSource::WorkerOutbox.consumer("session-1")
    }

    /// The one external destination these tests send to.
    fn hook() -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new("hook").expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Unsupported,
            }),
            rule: Some(DeliveryRule {
                name: "on failure".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    /// Claims one delivery the way a pass does, so the record is really on the wire.
    fn claim(journal: &mut DeliveryJournal, byte: u8, now_ms: u64) {
        assert!(
            matches!(
                journal
                    .claim(NotificationId::new(uuid(byte)), now_ms)
                    .expect("a claim"),
                crate::journal::Claim::Taken(_)
            ),
            "the delivery was claimable"
        );
    }

    fn journal_with_work() -> DeliveryJournal {
        let mut journal = DeliveryJournal::in_memory().expect("a journal");
        journal
            .register_consumer(&consumer(), 1)
            .expect("registration");
        journal
            .configure_destination(&hook())
            .expect("a destination");
        for byte in 1..=3u8 {
            journal
                .take_events(
                    &consumer(),
                    &[TakenEvent {
                        key: EventKey::outbox(&uuid(byte)),
                        source_cursor: u64::from(byte),
                        session_id: None,
                        recorded_at_ms: TimestampMs::new(1_000),
                        notice: Vec::new(),
                    }],
                    u64::from(byte),
                )
                .expect("a page");
            journal
                .admit(&DeliveryRecord {
                    notification_id: NotificationId::new(uuid(byte + 10)),
                    event: EventKey::outbox(&uuid(byte)),
                    destination_id: DestinationId::new("hook").expect("an identifier"),
                    state: DeliveryState::Admitted,
                    privacy_generation: 0,
                    destination_digest: hook().binding_digest(),
                    authority_digest: String::new(),
                    content: Some(vec![b'x'; 100]),
                    payload_bytes: 100,
                    expires_at_ms: TimestampMs::new(1_000_000),
                    admitted_at_ms: TimestampMs::new(1_000),
                    attempts: 0,
                    suppression: None,
                    detail: None,
                    dispatched: false,
                })
                .expect("admitted");
        }
        journal
    }

    #[test]
    fn enabling_privacy_fences_cancels_and_removes_in_that_order() {
        let mut journal = journal_with_work();
        let mut mode = PrivacyMode::new();
        let generation = mode.open_generation(TimestampMs::new(2_000));
        let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let enabling = mode.apply(&mut [&mut outbox], TimestampMs::new(2_000));
        assert_eq!(generation.get(), 1);
        let fenced = enabling
            .fenced
            .iter()
            .find(|(name, _)| *name == "delivery")
            .expect("the delivery outbox reported its fence");
        assert_eq!(fenced.1.queues, 1);
        assert_eq!(fenced.1.items, 3);
        let cancelled = enabling
            .cancelled
            .iter()
            .find(|(name, _)| *name == "delivery")
            .expect("it reported its cancellation");
        assert_eq!(cancelled.1.undispatched, 3);
        assert_eq!(cancelled.1.in_flight, 0);
        assert!(outbox.failure().is_none());
        assert!(
            journal.due(50_000, 10).expect("a read").is_empty(),
            "nothing is offered to a sender after the fence"
        );
        for record in journal.deliveries().expect("a read") {
            assert_eq!(record.state, DeliveryState::Cancelled);
            assert_eq!(record.content, None, "the bytes are gone");
        }
    }

    /// A record something has already dispatched is not "undispatched", whatever its state says
    /// about retrying. Cancelling it would claim this host took back something it cannot reach.
    #[test]
    fn a_record_that_has_left_is_reconciled_rather_than_cancelled() {
        let mut journal = journal_with_work();
        // One of the three has been out to the destination and is waiting to be asked about
        // again: the destination answered, so the message has left this host.
        claim(&mut journal, 11, 1_500);
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::Retrying,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(1_600)),
                next_attempt_at_ms: Some(TimestampMs::new(5_000)),
                detail: Some("the destination is holding it".to_owned()),
                suppression: None,
                keep_content: true,
                left_this_host: true,
            })
            .expect("a transition");

        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(2_000));
        let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let enabling = mode.apply(&mut [&mut outbox], TimestampMs::new(2_000));
        let cancelled = enabling
            .cancelled
            .iter()
            .find(|(name, _)| *name == "delivery")
            .expect("it reported its cancellation");
        assert_eq!(
            cancelled.1.undispatched, 2,
            "only what never left is taken back"
        );
        assert_eq!(
            cancelled.1.in_flight, 1,
            "what has left is counted rather than claimed back"
        );
        assert_eq!(
            journal
                .delivery(NotificationId::new(uuid(11)))
                .expect("a read")
                .expect("the record")
                .state,
            DeliveryState::OutcomeUnknown,
            "it is left in a state a reconciliation can still resolve"
        );
        assert!(matches!(
            PrivacyMode::reconcile(&[&DeliveryOutbox::over(&mut journal, 2_000)]),
            Completion::Reconciling { .. }
        ));
    }

    #[test]
    fn cleanup_is_not_complete_while_a_send_is_in_flight() {
        let mut journal = journal_with_work();
        claim(&mut journal, 11, 1_500);
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(2_000));
        let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let enabling = mode.apply(&mut [&mut outbox], TimestampMs::new(2_000));
        assert_eq!(enabling.in_flight(), 1);
        assert!(matches!(
            PrivacyMode::reconcile(&[&outbox]),
            Completion::Reconciling { .. }
        ));

        // The send settles, and only then is the cleanup complete.
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::Accepted,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(2_500)),
                next_attempt_at_ms: None,
                detail: Some("queued".to_owned()),
                suppression: None,
                keep_content: false,
                left_this_host: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert_eq!(PrivacyMode::reconcile(&[&outbox]), Completion::Complete);
    }

    #[test]
    fn an_unknown_outcome_keeps_the_cleanup_reconciling() {
        let mut journal = journal_with_work();
        claim(&mut journal, 11, 1_500);
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::OutcomeUnknown,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(1_600)),
                next_attempt_at_ms: None,
                detail: Some("nobody knows".to_owned()),
                suppression: None,
                keep_content: false,
                left_this_host: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert!(matches!(
            PrivacyMode::reconcile(&[&outbox]),
            Completion::Reconciling { .. }
        ));
    }

    #[test]
    fn what_has_already_left_is_shown_rather_than_claimed_to_be_erased() {
        let mut journal = journal_with_work();
        claim(&mut journal, 11, 1_500);
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::Accepted,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(1_600)),
                next_attempt_at_ms: None,
                detail: Some("the destination took it".to_owned()),
                suppression: None,
                keep_content: false,
                left_this_host: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let exported = outbox.exported();
        assert_eq!(exported.len(), 1);
        assert!(exported[0].kind.contains("webhook"));
        assert!(
            !exported[0].deletable,
            "this host holds no way to recall a message another service has"
        );
    }

    #[test]
    fn what_is_kept_is_named_rather_than_quietly_retained() {
        let mut journal = journal_with_work();
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let kept = outbox.kept();
        assert_eq!(kept.len(), 2);
        assert!(
            kept.iter()
                .any(|kept| kept.what.contains("delivery journal"))
        );
        assert!(kept.iter().any(|kept| kept.what.contains("rate allowance")));
    }

    #[test]
    fn a_journal_that_cannot_answer_is_outstanding_rather_than_finished() {
        // A closed store cannot be asked, and the honest answer to "is your cleanup finished" from
        // something that cannot look is no.
        let mut journal = journal_with_work();
        let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
        outbox.failure = Some("the store could not be written".to_owned());
        assert!(outbox.outstanding() > 0);
        assert!(matches!(
            PrivacyMode::reconcile(&[&outbox]),
            Completion::Reconciling { .. }
        ));
    }
}
