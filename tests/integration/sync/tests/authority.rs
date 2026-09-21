//! The revocation feed acknowledgement, against a deployment.
//!
//! Section 10 divides remote revocation between a remote owner, a target host and a durable feed,
//! and every rule below is about that division. The owner publishes a signed request that carries
//! no revision. The host validates the owner's authority, issues its own ordered revision and
//! acknowledges what it applied. The feed keeps the record until the host is finished with it, and
//! nothing else ends its retention. The announcement that tells a device something changed is only
//! an announcement.
//!
//! The service half runs in the deployment and the host half is
//! [`kr_controller::grants::feed::AuthorityFeed`], so each leg drives both: what the deployment
//! answered, and what the host's own record does with it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.46 | `kr_req_10_46_a_published_request_is_retained_until_every_host_has_finished_with_it`, `kr_req_10_46_an_acknowledgement_outside_the_revision_that_applied_it_is_refused`, `kr_req_10_46_a_revision_that_does_not_follow_the_accepted_one_is_rejected`, `kr_req_10_46_a_synchronisation_is_owed_from_the_connection_until_one_happens`, `kr_req_10_46_an_unreachable_feed_is_stale_and_still_shows_the_last_acknowledgement`, and `kr_req_10_46_an_announcement_is_only_an_announcement` |
//!
//! The dispatch barrier itself is section 9's, and a host reports it through the completion in its
//! acknowledgement; what this file proves about it is that a barrier which has not held leaves the
//! record outstanding.

use std::sync::Arc;

use kr_client::services::authority::{
    AuthorityFeedClient, FeedAnnouncement, RejectionReason, announcement_expiry,
};
use kr_controller::grants::feed::{AuthorityFeed, FeedRefusal};
use kr_crypto::envelope::seal_envelope;
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_pairing::grants::{issue_authority_revision, sign_revocation_request};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvelopeId, GrantId, RevocationRequestId};
use kr_protocol::mailbox::{EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType};
use kr_protocol::pairing::{
    AuthorityRevisionRecord, KeyPurpose, RevocationAcknowledgement, RevocationCompletion,
    RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::{Bytes, CanonicalSet, KeyId, Nullable, TimestampMs};
use kr_sync_integration::{Deployment, RunKey, fresh_uuid, now_ms, proved, unreachable_origin};

/// One run's feed: a host that owns it, and a remote owner that publishes to it.
///
/// Both keys are made for the leg, so the feed a leg reaches is a feed that did not exist before it
/// and belongs to nobody else.
struct Feed {
    deployment: Deployment,
    owner: Arc<RunKey>,
    host: Arc<RunKey>,
    owner_client: AuthorityFeedClient,
    host_client: AuthorityFeedClient,
}

impl Feed {
    /// The feed this leg runs against, or nothing when this run was given no deployment.
    fn open() -> Option<Self> {
        let deployment = Deployment::from_environment()?;
        let owner = RunKey::installation();
        let host = RunKey::host();
        Some(Self {
            owner_client: deployment.authority_feed(&owner),
            host_client: deployment.authority_feed(&host),
            deployment,
            owner,
            host,
        })
    }

    /// The feed's address: the identifier of the host's own authorisation key.
    fn address(&self) -> KeyId {
        self.host.key_id()
    }

    /// A signed revocation request from this owner to this host, with a fresh identity.
    fn revocation(&self) -> RevocationRequest {
        sign_revocation_request(
            self.owner.pair(),
            RevocationRequestId::new(fresh_uuid()),
            self.owner.device_id(),
            self.host.device_id(),
            RevocationTarget::Grants {
                grant_ids: [GrantId::new(fresh_uuid())]
                    .into_iter()
                    .collect::<CanonicalSet<_>>(),
            },
            TimestampMs::new(now_ms()),
        )
        .expect("a signed revocation request")
    }

    /// The host's next revision, applying `applied`.
    fn revision(
        &self,
        previous: AuthorityRevision,
        applied: &[RevocationRequestId],
    ) -> AuthorityRevisionRecord {
        issue_authority_revision(
            self.host.pair(),
            self.host.device_id(),
            previous,
            applied.iter().copied().collect::<CanonicalSet<_>>(),
            TimestampMs::new(now_ms()),
        )
        .expect("a signed authority revision")
    }

    /// The host's acknowledgement of one request under one revision.
    fn acknowledgement(
        &self,
        request_id: RevocationRequestId,
        revision: AuthorityRevision,
        completion: RevocationCompletion,
    ) -> RevocationAcknowledgement {
        RevocationAcknowledgement {
            request_id,
            host_device_id: self.host.device_id(),
            authority_revision: revision,
            completion,
            acknowledged_at_ms: TimestampMs::new(now_ms()),
        }
    }

    /// Removes this host from the feed, which ends the retention of everything addressed to it.
    ///
    /// It is how a leg gives back what it took: the records it published are dropped and the feed
    /// keeps a removed host and nothing else.
    async fn finish(&self) {
        let state = self
            .host_client
            .remove(self.address())
            .await
            .expect("the host removes itself");
        assert!(state.summary.removed, "the feed reports the host removed");
        assert_eq!(
            state.summary.outstanding.get(),
            0,
            "a removal ends the retention of what the host had not applied"
        );
    }
}

#[tokio::test]
async fn kr_req_10_46_a_published_request_is_retained_until_every_host_has_finished_with_it() {
    let Some(feed) = Feed::open() else { return };
    let published = feed.revocation();

    let state = feed
        .owner_client
        .publish(feed.address(), &published, None)
        .await
        .expect("the feed stored the owner's request");
    assert_eq!(state.summary.outstanding.get(), 1);

    // The host reads its own feed and finds the request waiting for it.
    let seen = feed
        .host_client
        .read(feed.address(), None, false)
        .await
        .expect("the host reads its feed");
    assert!(
        seen.is_outstanding(published.request_id),
        "a published request is outstanding until the host is finished with it"
    );
    assert_eq!(
        seen.record(published.request_id)
            .expect("the record")
            .request,
        published,
        "the feed serves back the request the owner signed"
    );

    // The host's own record: one revision, allocated by the host and by nobody else.
    let mut record = AuthorityFeed::new(feed.host.device_id(), AuthorityRevision::new(0));
    let second_host = DeviceId::new(fresh_uuid());
    record.enrol(feed.owner.device_id());
    record.enrol(second_host);
    let revision = record.next_revision();
    assert_eq!(
        record
            .apply(published.clone(), revision, now_ms())
            .expect("the host applies it"),
        revision
    );

    let issued = feed.revision(AuthorityRevision::new(0), &[published.request_id]);
    assert_eq!(issued.authority_revision, revision);
    feed.host_client
        .revise(&issued, None)
        .await
        .expect("the host issues its revision");

    // An acknowledgement whose barrier has not held is progress rather than completion, so the
    // record stays outstanding.
    let pending = feed.acknowledgement(
        published.request_id,
        revision,
        RevocationCompletion::Pending {
            pending_workers: kr_protocol::scalars::U64::new(1),
        },
    );
    let state = feed
        .host_client
        .acknowledge(&pending, None)
        .await
        .expect("the host reports progress");
    assert_eq!(
        state.summary.outstanding.get(),
        1,
        "a pending dispatch barrier is not a completion"
    );

    let complete = feed.acknowledgement(
        published.request_id,
        revision,
        RevocationCompletion::Complete,
    );
    let state = feed
        .host_client
        .acknowledge(&complete, None)
        .await
        .expect("the host acknowledges it");
    assert_eq!(state.summary.outstanding.get(), 0);
    assert_eq!(
        state
            .summary
            .last_acknowledgement
            .as_ref()
            .expect("the last acknowledgement")
            .authority_revision,
        revision,
        "the device list shows the host's last acknowledgement"
    );

    // The host's own record keeps it while an enrolled host has not answered for it.
    assert!(!record.acknowledge(published.request_id, feed.owner.device_id()));
    assert_eq!(
        record.retained().len(),
        1,
        "a record is retained while a second enrolled host has not acknowledged it"
    );
    assert!(record.acknowledge(published.request_id, second_host));
    assert!(
        record.retained().is_empty(),
        "every enrolled host has acknowledged it"
    );
    assert_eq!(
        record.last_acknowledgement(second_host),
        Some(revision),
        "the device list shows each host's last acknowledgement"
    );

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "a published revocation is retained until the host acknowledges its barrier as complete, and the host's record keeps it while another enrolled host has not answered",
    );
}

#[tokio::test]
async fn kr_req_10_46_an_acknowledgement_outside_the_revision_that_applied_it_is_refused() {
    let Some(feed) = Feed::open() else { return };
    let published = feed.revocation();
    feed.owner_client
        .publish(feed.address(), &published, None)
        .await
        .expect("the feed stored the owner's request");

    // A revision this host never issued.
    let invented = feed.acknowledgement(
        published.request_id,
        AuthorityRevision::new(9),
        RevocationCompletion::Complete,
    );
    let refused = feed
        .host_client
        .acknowledge(&invented, None)
        .await
        .expect_err("that revision was never issued");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    assert!(
        refused.to_string().contains("has issued"),
        "the feed says the revision is not one this host issued: {refused}"
    );

    // A revision this host did issue, for something else.
    let elsewhere = RevocationRequestId::new(fresh_uuid());
    let issued = feed.revision(AuthorityRevision::new(0), &[elsewhere]);
    feed.host_client
        .revise(&issued, None)
        .await
        .expect("the host issues its revision");
    let misapplied = feed.acknowledgement(
        published.request_id,
        issued.authority_revision,
        RevocationCompletion::Complete,
    );
    let refused = feed
        .host_client
        .acknowledge(&misapplied, None)
        .await
        .expect_err("that revision applied something else");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    assert!(
        refused.to_string().contains("applied that request"),
        "the feed says the revision did not apply this request: {refused}"
    );

    // The record is still waiting, because neither refusal ended anything.
    let seen = feed
        .host_client
        .read(feed.address(), None, false)
        .await
        .expect("the host reads its feed");
    assert!(seen.is_outstanding(published.request_id));

    // What does end it without an acknowledgement: the host saying it will not apply it.
    let state = feed
        .host_client
        .reject(published.request_id, RejectionReason::NoOwnerAuthority)
        .await
        .expect("the host refuses it");
    assert_eq!(state.summary.outstanding.get(), 0);

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "an acknowledgement is refused unless it names a revision this host issued and that revision applied the request",
    );
}

#[tokio::test]
async fn kr_req_10_46_a_revision_that_does_not_follow_the_accepted_one_is_rejected() {
    let Some(feed) = Feed::open() else { return };

    // The host's own record rejects a revision at or below the one it has accepted, whatever its
    // signature says. Each host persists its latest accepted revision, so a replayed feed entry
    // cannot put authority back.
    let mut record = AuthorityFeed::new(feed.host.device_id(), AuthorityRevision::new(5));
    let stale = feed.revision(AuthorityRevision::new(3), &[]);
    assert_eq!(stale.authority_revision, AuthorityRevision::new(4));
    assert_eq!(
        record.accept(&stale),
        Err(FeedRefusal::OutOfOrder {
            accepted: AuthorityRevision::new(5),
            offered: AuthorityRevision::new(4),
        })
    );
    let following = feed.revision(AuthorityRevision::new(5), &[]);
    record.accept(&following).expect("it follows what was held");
    assert_eq!(record.accepted_revision(), AuthorityRevision::new(6));

    // And a device cannot assign itself a host revision at all: what an owner publishes carries
    // none, and only a host key may submit one.
    let refused = feed
        .owner_client
        .revise(&following, None)
        .await
        .expect_err("an owner does not issue a host's revisions");
    assert!(
        refused.to_string().contains("only the host"),
        "an installation credential cannot carry a host's revision: {refused}"
    );

    // The feed holds the same order. A revision that does not follow the one it holds is refused.
    let first = feed.revision(AuthorityRevision::new(0), &[]);
    feed.host_client
        .revise(&first, None)
        .await
        .expect("the first revision follows nothing");
    let gap = feed.revision(AuthorityRevision::new(4), &[]);
    let refused = feed
        .host_client
        .revise(&gap, None)
        .await
        .expect_err("that revision leaves a gap");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(
        refused
            .to_string()
            .contains("follows the revision this feed holds"),
        "the feed keeps the host's own order: {refused}"
    );

    // Nor may a revision already issued be replaced by another under the same number.
    let rewritten = feed.revision(
        AuthorityRevision::new(0),
        &[RevocationRequestId::new(fresh_uuid())],
    );
    assert_eq!(rewritten.authority_revision, first.authority_revision);
    let refused = feed
        .host_client
        .revise(&rewritten, None)
        .await
        .expect_err("that revision already stands");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);

    // Submitting the revision that stands, again, is the same revision rather than a second one.
    let state = feed
        .host_client
        .revise(&first, None)
        .await
        .expect("the revision that stands");
    assert_eq!(
        state.summary.authority_revision,
        Nullable(Some(first.authority_revision))
    );

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "a revision is the host's own and follows the one already held: the record rejects an older one and the feed refuses a gap, a rewrite and an owner's attempt",
    );
}

#[tokio::test]
async fn kr_req_10_46_a_synchronisation_is_owed_from_the_connection_until_one_happens() {
    let Some(feed) = Feed::open() else { return };

    // A host that has just connected owes a synchronisation, before any remote access it might
    // affect.
    let mut record = AuthorityFeed::new(feed.host.device_id(), AuthorityRevision::new(0));
    assert!(record.synchronisation_owed());
    assert!(record.status().stale);

    // A feed that could not be reached does not satisfy it.
    let elsewhere = Deployment::at(unreachable_origin());
    let unreachable = elsewhere.authority_feed(&feed.host);
    let failure = unreachable
        .read(feed.address(), None, true)
        .await
        .expect_err("nothing answers there");
    assert_eq!(failure.code(), ErrorCode::UpstreamUnavailable);
    record.unreachable();
    assert!(
        record.synchronisation_owed(),
        "an attempt that reached nothing is not a synchronisation"
    );

    // An actual one does.
    let at = now_ms();
    let state = feed
        .host_client
        .read(feed.address(), None, true)
        .await
        .expect("the host reads its feed");
    record.synchronised(at);
    assert!(!record.synchronisation_owed());
    assert!(!record.status().stale);
    assert_eq!(
        u64::from(state.summary.poll_interval_seconds) * 1000,
        record.next_poll_due_ms().expect("a poll is due") - at,
        "the host polls at the interval the feed states while it is online"
    );

    // And a connection that was replaced owes one again.
    record.reconnected();
    assert!(record.synchronisation_owed());
    assert!(record.status().stale);

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "a synchronisation is owed from the moment a connection is established and only an actual synchronisation satisfies it",
    );
}

#[tokio::test]
async fn kr_req_10_46_an_unreachable_feed_is_stale_and_still_shows_the_last_acknowledgement() {
    let Some(feed) = Feed::open() else { return };
    let published = feed.revocation();
    feed.owner_client
        .publish(feed.address(), &published, None)
        .await
        .expect("the feed stored the owner's request");

    let mut record = AuthorityFeed::new(feed.host.device_id(), AuthorityRevision::new(0));
    record.enrol(feed.owner.device_id());
    let revision = record.next_revision();
    record
        .apply(published.clone(), revision, now_ms())
        .expect("the host applies it");
    feed.host_client
        .revise(
            &feed.revision(AuthorityRevision::new(0), &[published.request_id]),
            None,
        )
        .await
        .expect("the host issues its revision");
    let state = feed
        .host_client
        .acknowledge(
            &feed.acknowledgement(
                published.request_id,
                revision,
                RevocationCompletion::Complete,
            ),
            None,
        )
        .await
        .expect("the host acknowledges it");
    assert!(state.summary.acknowledged_at.as_ref().is_some());
    record.acknowledge(published.request_id, feed.owner.device_id());
    record.synchronised(now_ms());
    let current = record.status();
    assert!(!current.stale);

    // Then the feed cannot be reached. The status goes stale and stays stale; it is never reported
    // as current because nothing contradicted it.
    let elsewhere = Deployment::at(unreachable_origin());
    let failure = elsewhere
        .authority_feed(&feed.host)
        .read(feed.address(), None, true)
        .await
        .expect_err("nothing answers there");
    assert_eq!(failure.code(), ErrorCode::UpstreamUnavailable);
    record.unreachable();

    let stale = record.status();
    assert!(stale.stale, "an unavailable feed shows stale status");
    assert_eq!(
        stale.last_synchronised_at_ms, current.last_synchronised_at_ms,
        "the last successful synchronisation is still what it was"
    );
    assert_eq!(
        record.last_acknowledgement(feed.owner.device_id()),
        Some(revision),
        "the device list still shows the last acknowledgement"
    );
    assert_eq!(stale.accepted_revision, revision);

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "an unreachable feed leaves the status stale with the last acknowledgement and the last synchronisation still visible",
    );
}

#[tokio::test]
async fn kr_req_10_46_an_announcement_is_only_an_announcement() {
    let Some(feed) = Feed::open() else { return };
    let published = feed.revocation();

    // The owner seals an announcement for the host's mailbox. It says the feed changed and carries
    // nothing about what changed.
    let host_mailbox = StoredEnvelopeKeyPair::generate().expect("the host's stored-envelope key");
    let owner_envelopes =
        StoredEnvelopeKeyPair::generate().expect("the owner's stored-envelope key");
    let sealed_at = now_ms();
    let plaintext = EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id: EnvelopeId::new(fresh_uuid()),
        sender_key_id: owner_envelopes.key_id(),
        recipient_key_id: kr_crypto::keys::key_id(
            KeyPurpose::StoredEnvelope,
            host_mailbox.public().as_bytes(),
        ),
        payload_type: MailboxPayloadType::AuthorityFeedChange,
        created_at_ms: TimestampMs::new(sealed_at),
        expires_at_ms: announcement_expiry(sealed_at),
        grant_id: Nullable(None),
        environment_id: Nullable(None),
        session_id: Nullable(None),
        session_epoch: Nullable(None),
        thread_id: Nullable(None),
        payload: Bytes::new(b"the feed changed".to_vec()),
    };
    let announcement = FeedAnnouncement {
        recipient_key: *host_mailbox.public(),
        envelope: seal_envelope(&owner_envelopes, host_mailbox.public(), &plaintext)
            .expect("a sealed announcement"),
    };

    let state = feed
        .owner_client
        .publish(feed.address(), &published, Some(&announcement))
        .await
        .expect("the feed stored the owner's request");
    assert_eq!(
        state
            .announced
            .as_ref()
            .expect("the feed says what became of the announcement")
            .mailbox,
        kr_client::services::AnnouncementPlacement::Stored
    );

    // The host never reads that mailbox. It learns the revocation from the feed, which is where the
    // record lives: the announcement is a nudge and the feed is the record.
    let seen = feed
        .host_client
        .read(feed.address(), None, false)
        .await
        .expect("the host reads its feed");
    assert!(
        seen.is_outstanding(published.request_id),
        "a host that never saw the announcement still learns the revocation from the feed"
    );

    feed.finish().await;
    proved(
        "authority feed",
        &feed.deployment,
        "an announcement is placed in a mailbox and carries nothing of the record, and a host that never reads it still learns the revocation from the feed",
    );
}
