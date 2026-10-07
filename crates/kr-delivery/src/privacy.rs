//! The content-bearing outbox privacy mode reaches.
//!
//! The privacy generation contract has two worked examples over this crate's kind of store. This
//! is the real one: a queue that holds built notifications and composed external messages, and
//! sends them somewhere this host cannot recall them from.
//!
//! Section 24, in the order it states them:
//!
//! 1. **Fence** the content-bearing outbox *at once*. [`DeliveryJournal::due`] answers with
//!    nothing from a generation before the fence's, so the stop is in the read every sender makes
//!    rather than in a flag each of them remembers to check. The one thing admitted under the
//!    fence is an alert with no content, which belongs to the fence's own generation.
//! 2. **Cancel** what was admitted and never dispatched. It has not left, so it is taken back and
//!    its bytes go with it.
//! 3. **Remove** the retained local content: the built request bodies and the encrypted objects a
//!    preview's excess detail moved into. The records of what happened stay, because a host that
//!    forgot its own attempts could not tell a person what the device did not see.
//! 4. **Reconcile** before completion is reported. [`DeliveryOutbox::outstanding`] counts the
//!    sends on the wire, whose answers are still coming, and privacy mode is not complete while
//!    any is. A notification whose outcome nobody knows is not waited for: under the fence
//!    nothing asks the gateway what became of one from before it, so the wait would never end. It
//!    is a copy that may have left, shown in the exported list with its local content gone.
//!
//! And the part section 24 is most specific about: *already uploaded archives and notifications
//! and copies held by authorised viewers are not retroactively erased. Show those retained
//! artifacts and offer an explicit separately authorised deletion action.* [`DeliveryOutbox::
//! exported`] is that list. Every entry says it is not deletable by this host, because it is not:
//! a notification a provider queued is on a device, and an external message is in somebody else's
//! service.

use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
    Unavailable,
};

use crate::journal::DeliveryJournal;

/// The delivery outbox, as privacy mode sees it.
///
/// It borrows the journal rather than owning it, which is the privacy contract's own shape: the
/// caller holds the subsystems and drives them, so the one that reports its own cleanup is still
/// reachable after the enabling that started it. It keeps no memory of a failed step: each step
/// answers with the journal's reason, and the caller keeps it until the step succeeds.
#[derive(Debug)]
pub struct DeliveryOutbox<'a> {
    journal: &'a mut DeliveryJournal,
    now_ms: u64,
}

impl<'a> DeliveryOutbox<'a> {
    /// Builds the hook over one environment's delivery journal.
    ///
    /// `now_ms` is what a cancellation receipt is stamped with. A generation is not a time, and a
    /// receipt stamped with one would say a cancellation happened in 1970.
    #[must_use]
    pub fn over(journal: &'a mut DeliveryJournal, now_ms: u64) -> Self {
        Self { journal, now_ms }
    }
}

/// Says what a step could not do, with the journal's own reason.
fn unavailable(what: &str, error: &crate::DeliveryError) -> Unavailable {
    Unavailable::new(format!("{what}: {error}"))
}

impl DeliveryOutbox<'_> {
    /// Returns how many sends are on the wire: claimed by a pass and not yet answered.
    ///
    /// Those are the only deliveries whose answer is still coming. One settled as an unknown
    /// outcome, or marked as the uncertainty an external message leaves, has left this host and
    /// has no answer to wait for. An alert privacy mode let through while it is on is neither
    /// content captured before the boundary nor cleanup of it, so it is not counted: privacy
    /// mode can be turned off while one is on the wire.
    fn on_the_wire(&self) -> Result<u64, Unavailable> {
        self.journal.on_the_wire().map_err(|error| {
            unavailable(
                "the delivery journal cannot say what is on the wire",
                &error,
            )
        })
    }
}

impl PrivacySubsystem for DeliveryOutbox<'_> {
    fn name(&self) -> &'static str {
        "delivery"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Result<Fenced, Unavailable> {
        // A fence this host could not record is a fence it is not in, and the answer says so
        // rather than reporting that the queue was stopped.
        self.journal
            .fence(generation.get())
            .map(|(queues, items)| Fenced { queues, items })
            .map_err(|error| unavailable("the delivery outbox could not be fenced", &error))
    }

    fn cancel_undispatched(
        &mut self,
        _generation: PrivacyGeneration,
    ) -> Result<Cancelled, Unavailable> {
        let (undispatched, _left) = self
            .journal
            .cancel_undispatched(self.now_ms)
            .map_err(|error| unavailable("admitted deliveries could not be taken back", &error))?;
        // What is in flight is what reconciliation waits for, and nothing else: what had left
        // earlier is now an uncertain copy, shown rather than waited for.
        Ok(Cancelled {
            undispatched,
            in_flight: self.on_the_wire()?,
        })
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Result<Removed, Unavailable> {
        self.journal
            .remove_retained()
            .map(|(bytes, records)| Removed { bytes, records })
            .map_err(|error| unavailable("queued content could not be removed", &error))
    }

    fn outstanding(&self) -> Result<u64, Unavailable> {
        self.on_the_wire()
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

    fn exported(&self) -> Result<Vec<Exported>, Unavailable> {
        let copies = self.journal.exported().map_err(|error| {
            unavailable(
                "the delivery journal cannot list what has left this host",
                &error,
            )
        })?;
        Ok(copies
            .into_iter()
            .map(|exported| Exported {
                kind: exported.kind,
                reference: exported.reference,
                left_at_ms: exported.left_at_ms,
                deletable: exported.deletable,
            })
            .collect())
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
        EventSource::Attention.consumer("session-1")
    }

    /// The one external destination these tests send to.
    fn hook() -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new("hook").expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Unsupported,
                credential: None,
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

    /// A paired device, whose unresolved deliveries a receipt can still account for.
    fn phone() -> DestinationRecord {
        let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
        DestinationRecord {
            id: DestinationId::new("phone").expect("an identifier"),
            destination: crate::destination::Destination::Push(Box::new(
                crate::destination::PushDestination {
                    installation_id: kr_protocol::ids::InstallationId::new(uuid(41)),
                    sender_record_id: kr_protocol::ids::PushSenderRecordId::new(uuid(42)),
                    preview_keys: crate::destination::PreviewKeys::only(*device.public(), 1),
                    previews_enabled: true,
                    mailbox_key: None,
                },
            )),
            rule: Some(crate::destination::DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    fn journal_with_work() -> DeliveryJournal {
        let mut journal = DeliveryJournal::in_memory().expect("a journal");
        fill(&mut journal);
        journal
    }

    /// A journal on the internal disk, so a second connection can reach its store.
    fn journal_on_disk_with_work(
        directory: &tempfile::TempDir,
    ) -> (DeliveryJournal, std::path::PathBuf) {
        let path = directory.path().join("delivery.sqlite3");
        let mut journal = DeliveryJournal::open(&path).expect("a journal");
        fill(&mut journal);
        (journal, path)
    }

    /// Three deliveries admitted to the webhook and never dispatched.
    fn fill(journal: &mut DeliveryJournal) {
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
                        key: EventKey::announcement(None, "an-item", u64::from(byte)),
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
                    event: EventKey::announcement(None, "an-item", u64::from(byte)),
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
        assert!(enabling.is_finished());
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
                next: crate::push::NextAction::None,
                detail: Some("the destination is holding it".to_owned()),
                suppression: None,
                left_this_host: true,
                reported_by_destination: false,
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
            cancelled.1.in_flight, 0,
            "nothing is on the wire: what left earlier is an uncertain copy, not a send to wait for"
        );
        assert_eq!(
            journal
                .delivery(NotificationId::new(uuid(11)))
                .expect("a read")
                .expect("the record")
                .state,
            // A webhook has no receipt to read, so what it leaves behind is the uncertainty
            // itself rather than a question nothing can answer.
            DeliveryState::DuplicateUncertain,
            "it is marked as having left rather than taken back"
        );
        let exported = DeliveryOutbox::over(&mut journal, 2_000)
            .exported()
            .expect("a list");
        assert_eq!(exported.len(), 1, "it is shown as a retained artifact");
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
                next: crate::push::NextAction::None,
                detail: Some("queued".to_owned()),
                suppression: None,
                left_this_host: false,
                reported_by_destination: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert_eq!(PrivacyMode::reconcile(&[&outbox]), Completion::Complete);
    }

    /// Admits one notification to the paired device, and returns its identifier.
    fn admit_to_the_phone(journal: &mut DeliveryJournal, byte: u8) -> NotificationId {
        let phone = phone();
        journal
            .configure_destination(&phone)
            .expect("a destination");
        journal
            .take_events(
                &consumer(),
                &[TakenEvent {
                    key: EventKey::announcement(None, "an-item", u64::from(byte)),
                    source_cursor: u64::from(byte),
                    session_id: None,
                    recorded_at_ms: TimestampMs::new(1_000),
                    notice: Vec::new(),
                }],
                u64::from(byte),
            )
            .expect("a page");
        let notification_id = NotificationId::new(uuid(byte + 20));
        journal
            .admit(&DeliveryRecord {
                notification_id,
                event: EventKey::announcement(None, "an-item", u64::from(byte)),
                destination_id: phone.id.clone(),
                state: DeliveryState::Admitted,
                privacy_generation: 0,
                destination_digest: phone.binding_digest(),
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
        notification_id
    }

    /// A notification whose outcome nobody knows has left this host, and privacy mode's fence
    /// stops anything asking the gateway what became of it: a fenced sweep asks nothing, and a
    /// record of an earlier generation is never asked about afterwards. Waiting for it would never
    /// end, so it is a copy that may have left, shown as a retained artifact with its local content
    /// gone, and cleanup does not wait for it. A send on the wire is different: its answer is still
    /// coming, and cleanup waits for that.
    #[test]
    fn an_unknown_outcome_is_a_retained_artifact_and_only_a_send_on_the_wire_is_waited_for() {
        let mut journal = journal_with_work();
        let unknown = admit_to_the_phone(&mut journal, 9);
        claim(&mut journal, 9 + 20, 1_500);
        journal
            .record_attempt(&Transition {
                notification_id: unknown,
                attempt: 1,
                state: DeliveryState::OutcomeUnknown,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(1_600)),
                next_attempt_at_ms: None,
                next: crate::push::NextAction::None,
                detail: Some("nobody knows".to_owned()),
                suppression: None,
                left_this_host: false,
                reported_by_destination: false,
            })
            .expect("a transition");
        // And one send is on the wire when privacy mode is enabled.
        claim(&mut journal, 11, 1_700);

        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(2_000));
        let enabling = {
            let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
            mode.apply(&mut [&mut outbox], TimestampMs::new(2_000))
        };
        assert_eq!(
            enabling.in_flight(),
            1,
            "only the send on the wire is in flight"
        );
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert_eq!(
            PrivacyMode::reconcile(&[&outbox]),
            Completion::Reconciling {
                outstanding: vec![("delivery", 1)]
            }
        );
        let exported = outbox.exported().expect("a list");
        assert!(
            exported
                .iter()
                .any(|copy| copy.kind == "notification" && !copy.deletable),
            "the unknown outcome is shown: {exported:?}"
        );
        let record = journal
            .delivery(unknown)
            .expect("a read")
            .expect("the record");
        assert_eq!(
            record.state,
            DeliveryState::OutcomeUnknown,
            "its outcome is kept as it was"
        );
        assert_eq!(record.content, None, "its local content is gone");

        // The send's answer arrives, and only then is the cleanup complete.
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::Accepted,
                started_at_ms: TimestampMs::new(1_700),
                settled_at_ms: Some(TimestampMs::new(2_500)),
                next_attempt_at_ms: None,
                next: crate::push::NextAction::None,
                detail: Some("queued".to_owned()),
                suppression: None,
                left_this_host: false,
                reported_by_destination: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert_eq!(PrivacyMode::reconcile(&[&outbox]), Completion::Complete);
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
                next: crate::push::NextAction::None,
                detail: Some("the destination took it".to_owned()),
                suppression: None,
                left_this_host: false,
                reported_by_destination: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let exported = outbox.exported().expect("a list");
        assert_eq!(exported.len(), 1);
        assert!(exported[0].kind.contains("webhook"));
        assert!(
            !exported[0].deletable,
            "this host holds no way to recall a message another service has"
        );
    }

    #[test]
    fn a_confirmed_duplicate_delivery_is_shown_as_a_retained_artifact() {
        let mut journal = journal_with_work();
        claim(&mut journal, 11, 1_500);
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(11)),
                attempt: 1,
                state: DeliveryState::Duplicate,
                started_at_ms: TimestampMs::new(1_500),
                settled_at_ms: Some(TimestampMs::new(1_600)),
                next_attempt_at_ms: None,
                next: crate::push::NextAction::None,
                detail: Some("the destination had already seen this".to_owned()),
                suppression: None,
                left_this_host: true,
                reported_by_destination: false,
            })
            .expect("a transition");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let exported = outbox.exported().expect("a list");
        assert_eq!(exported.len(), 1);
        assert!(exported[0].kind.contains("webhook"));
        assert!(exported[0].reference.contains("duplicate"));
        assert!(!exported[0].deletable);
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
        assert!(
            !kept.iter().any(|kept| kept.what.contains("request bytes")),
            "a settled delivery keeps no request: what resolves an unknown outcome is a question \
             about its identifier"
        );
    }

    #[test]
    fn a_journal_that_cannot_answer_is_unavailable_rather_than_finished() {
        // A store that cannot be read cannot say whether a send is still on the wire, and the
        // honest answer to "is your cleanup finished" from something that cannot look is neither
        // yes nor a count: it is that this subsystem cannot say, and why.
        let directory = tempfile::tempdir().expect("a directory");
        let (mut journal, path) = journal_on_disk_with_work(&directory);
        let other = rusqlite::Connection::open(&path).expect("the same store");
        other
            .execute_batch("ALTER TABLE delivery_notifications RENAME TO delivery_hidden")
            .expect("the records go out of reach");

        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        let reason = outbox
            .outstanding()
            .expect_err("a journal that cannot be read cannot say what is outstanding");
        assert!(reason.reason().contains("cannot say"), "{reason}");
        assert!(
            outbox.exported().is_err(),
            "nor can it list what has left, and it does not answer with an empty list"
        );
        let Completion::Unavailable { unavailable, .. } = PrivacyMode::reconcile(&[&outbox]) else {
            panic!("a subsystem that cannot answer is not reconciling and not complete");
        };
        assert_eq!(unavailable.len(), 1);
        assert_eq!(unavailable[0].0, "delivery");

        // Once the store can be read again, the same question has an answer.
        other
            .execute_batch("ALTER TABLE delivery_hidden RENAME TO delivery_notifications")
            .expect("the records come back");
        let outbox = DeliveryOutbox::over(&mut journal, 2_000);
        assert_eq!(PrivacyMode::reconcile(&[&outbox]), Completion::Complete);
    }

    /// A fence the store refused stops this subsystem at that step, with the store's reason, and
    /// nothing behind it runs. A new hook over the same journal then takes it through every step,
    /// which is how a caller that kept the failure retries it.
    #[test]
    fn a_refused_fence_is_retried_by_a_new_hook_at_the_same_generation() {
        let directory = tempfile::tempdir().expect("a directory");
        let (mut journal, path) = journal_on_disk_with_work(&directory);
        let other = rusqlite::Connection::open(&path).expect("the same store");
        other
            .execute_batch(
                "CREATE TRIGGER refuse_the_fence BEFORE UPDATE ON delivery_privacy
                 BEGIN SELECT RAISE(ABORT, 'this store refused the fence'); END;",
            )
            .expect("the store will refuse the fence");
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(2_000));

        let enabling = {
            let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
            mode.apply(&mut [&mut outbox], TimestampMs::new(2_000))
        };
        let unfinished = enabling
            .unfinished("delivery")
            .expect("the fence was refused");
        assert_eq!(unfinished.step, kr_worker::privacy::Step::Fence);
        assert!(
            unfinished
                .unavailable
                .reason()
                .contains("refused the fence"),
            "{}",
            unfinished.unavailable
        );
        assert!(
            enabling.cancelled.is_empty(),
            "nothing is cancelled behind a fence that failed"
        );
        assert!(!journal.is_fenced().expect("a read"));
        assert!(
            journal
                .deliveries()
                .expect("a read")
                .iter()
                .all(|record| record.state == DeliveryState::Admitted),
            "the admitted work was not taken back behind a fence that did not go up"
        );

        // The store accepts writes again, and a fresh hook takes it through every step.
        other
            .execute_batch("DROP TRIGGER refuse_the_fence")
            .expect("the store accepts the fence");
        let enabling = {
            let mut outbox = DeliveryOutbox::over(&mut journal, 2_000);
            mode.apply(&mut [&mut outbox], TimestampMs::new(2_000))
        };
        assert!(enabling.is_finished());
        assert!(journal.is_fenced().expect("a read"));
        for record in journal.deliveries().expect("a read") {
            assert_eq!(record.state, DeliveryState::Cancelled);
            assert_eq!(record.content, None);
        }
    }
}
