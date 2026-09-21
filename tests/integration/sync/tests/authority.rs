//! The revocation feed acknowledgement, against a deployment.
//!
//! Section 10 divides remote revocation between a remote owner, a target host and a durable feed,
//! and every rule below is about that division. The owner publishes a signed request that carries
//! no revision. The host validates current owner authority, issues its own ordered revision and
//! acknowledges what it applied. The feed keeps the record until the host is finished with it, and
//! nothing else ends its retention. The announcement that tells a device something changed is only
//! an announcement.
//!
//! The service half runs in the deployment and the host half is
//! [`kr_controller::grants::feed::AuthorityFeed`], so a leg drives both: what the deployment
//! answered, and what the host's own record does with it. Owner authority is the host's own to
//! check — the service holds no device records and could not — so a leg that applies anything
//! validates it first, the way a host does.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.46 | `kr_req_10_46_a_published_request_is_retained_until_every_host_has_finished_with_it`, `kr_req_10_46_a_request_from_a_key_this_host_holds_no_owner_record_for_is_never_applied`, `kr_req_10_46_an_acknowledgement_outside_the_revision_that_applied_it_is_refused`, `kr_req_10_46_a_revision_that_does_not_follow_the_accepted_one_is_rejected`, `kr_req_10_46_a_synchronisation_is_owed_from_the_connection_until_one_happens`, `kr_req_10_46_an_unreachable_feed_is_stale_and_still_shows_the_last_acknowledgement`, and `kr_req_10_46_an_announcement_is_only_an_announcement` |
//!
//! The dispatch barrier itself is section 9's, and a host reports it through the completion in its
//! acknowledgement; what this file proves about it is that a barrier which has not held leaves the
//! record outstanding.

use std::future::Future;
use std::sync::Arc;

use kr_client::services::authority::{
    AUTHORITY_SYNC_PATH, AuthorityFeedClient, FeedAnnouncement, MAX_AUTHORITY_REQUEST_BYTES,
    RejectionReason, announcement_expiry,
};
use kr_client::services::http::ExchangePhase;
use kr_client::services::signed::SignedService;
use kr_controller::grants::feed::{AuthorityFeed, FeedRefusal};
use kr_crypto::envelope::seal_envelope;
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_pairing::grants::{
    issue_authority_revision, sign_revocation_request, verify_revocation_request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvelopeId, GrantId, RevocationRequestId};
use kr_protocol::mailbox::{EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    AuthorityRevisionRecord, KeyPurpose, RevocationAcknowledgement, RevocationCompletion,
    RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::{AuthorisationKey, Bytes, CanonicalSet, KeyId, Nullable, TimestampMs};
use kr_sync_integration::{Deployment, RunKey, SilentService, fresh_uuid, now_ms, proved};

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

    /// The host's own record, at the revision it starts from.
    fn record(&self) -> AuthorityFeed {
        AuthorityFeed::new(self.host.device_id(), AuthorityRevision::new(0))
    }

    /// The owner keys this host holds records for, which is what owner authority means to it.
    fn owners(&self) -> Vec<AuthorisationKey> {
        vec![*self.owner.pair().public()]
    }

    /// A signed revocation request from this owner to this host, with a fresh identity.
    fn revocation(&self) -> RevocationRequest {
        self.revocation_from(&self.owner)
    }

    /// The same, from whichever device holds the key.
    fn revocation_from(&self, who: &Arc<RunKey>) -> RevocationRequest {
        sign_revocation_request(
            who.pair(),
            RevocationRequestId::new(fresh_uuid()),
            who.device_id(),
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

    /// What the host checks before it applies anything: current owner authority.
    ///
    /// The service cannot do this. It holds no device records and no grant chain, so all it can
    /// establish is that the publisher holds the key the request names. Whether that key is an
    /// owner's is the host's own record, which is what this stands for.
    fn owner_authority(&self, request: &RevocationRequest) -> Result<(), String> {
        let owners = self.owners();
        let held = owners.iter().find(|key| {
            kr_crypto::keys::key_id(KeyPurpose::Authorisation, key.as_bytes())
                == request.issuer_key_id
        });
        let Some(key) = held else {
            return Err("this host holds no owner record for the key that published it".to_owned());
        };
        verify_revocation_request(request, self.host.device_id(), key)
            .map_err(|error| error.to_string())
    }

    /// The whole of what a host does with a record it read from the feed.
    ///
    /// One path for every request, whoever published it: validate current owner authority, and
    /// apply it under a revision this host allocates only when that validation passed. A request
    /// that fails it reaches neither the record nor the revision, and the same call is what proves
    /// that, because an accepted request and a refused one go through exactly this.
    fn apply_if_authorised(
        &self,
        record: &mut AuthorityFeed,
        request: &RevocationRequest,
        now_ms: u64,
    ) -> Result<AuthorityRevision, String> {
        self.owner_authority(request)?;
        record
            .apply(request.clone(), record.next_revision(), now_ms)
            .map_err(|refusal| format!("{refusal:?}"))
    }

    /// Removes this host from the feed, which ends the retention of everything addressed to it.
    ///
    /// It is how a leg gives back what it took: the records addressed to this host are dropped and
    /// the feed keeps a removed host, the revisions that host issued and the nonces it has not yet
    /// forgotten.
    async fn remove_host(&self) -> kr_client::Result<kr_client::services::AuthorityFeedState> {
        self.host_client.remove(self.address()).await
    }
}

/// Runs one leg and gives back what it took, whether the leg passed or failed.
///
/// The leg's work runs as a task of its own, so a failed assertion ends that task rather than this
/// one: the host is removed from the feed either way and the failure is raised again afterwards. A
/// leg that panicked without removing it would leave an outstanding record on the deployment for
/// ever, because the only key that could remove it is the one this run discards.
async fn leg<Body, Work>(body: Body)
where
    Body: FnOnce(Arc<Feed>) -> Work + Send + 'static,
    Work: Future<Output = String> + Send + 'static,
{
    let Some(feed) = Feed::open() else { return };
    let feed = Arc::new(feed);

    let outcome = tokio::spawn(body(Arc::clone(&feed))).await;
    let removed = feed.remove_host().await;

    match outcome {
        Ok(what) => {
            let state = removed.expect("the host removes itself");
            assert!(state.summary.removed, "the feed reports the host removed");
            assert_eq!(
                state.summary.outstanding.get(),
                0,
                "a removal ends the retention of what the host had not applied"
            );
            proved("authority feed", &feed.deployment, &what);
        }
        Err(failed) => {
            if let Err(error) = removed {
                eprintln!("this leg could not give back what it took: {error}");
            }
            std::panic::resume_unwind(failed.into_panic());
        }
    }
}

/// KR-REQ-10.46: a revocation record is retained until every affected enrolled host has
/// acknowledged it or is explicitly removed, and a pending dispatch barrier is not an
/// acknowledgement.
#[tokio::test]
async fn kr_req_10_46_a_published_request_is_retained_until_every_host_has_finished_with_it() {
    leg(|feed| async move {
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
        let record = seen.record(published.request_id).expect("the record");
        assert_eq!(
            record.request, published,
            "the feed serves back the request the owner signed"
        );
        assert_eq!(
            record.published_by,
            *feed.owner.pair().public(),
            "the feed names the key that published it"
        );

        // The host validates current owner authority on what it read, and only then applies it
        // under a revision it allocates itself.
        let mut held = feed.record();
        let second_host = DeviceId::new(fresh_uuid());
        held.enrol(feed.owner.device_id());
        held.enrol(second_host);
        let revision = feed
            .apply_if_authorised(&mut held, &record.request, now_ms())
            .expect("the owner this host holds a record for signed it");
        assert_eq!(revision, AuthorityRevision::new(1));
        assert_eq!(held.accepted_revision(), revision);

        let issued = feed.revision(AuthorityRevision::new(0), &[published.request_id]);
        assert_eq!(issued.authority_revision, revision);
        feed.host_client
            .revise(&issued, None)
            .await
            .expect("the host issues its revision");

        // An acknowledgement whose barrier has not held is progress rather than completion, so the
        // record stays outstanding and a later reader still finds it.
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
        let still_there = feed
            .host_client
            .read(feed.address(), None, false)
            .await
            .expect("the host reads its feed again");
        assert!(
            still_there.is_outstanding(published.request_id),
            "the record is still retained after a pending acknowledgement"
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
        assert!(!held.acknowledge(published.request_id, feed.owner.device_id()));
        assert_eq!(
            held.retained().len(),
            1,
            "a record is retained while a second enrolled host has not acknowledged it"
        );
        assert!(held.acknowledge(published.request_id, second_host));
        assert!(
            held.retained().is_empty(),
            "every enrolled host has acknowledged it"
        );
        assert_eq!(
            held.last_acknowledgement(second_host),
            Some(revision),
            "the device list shows each host's last acknowledgement"
        );

        "a published revocation is retained until the host acknowledges its barrier as complete, and the host's record keeps it while another enrolled host has not answered".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: the target host validates current owner authority, and a request whose issuer
/// holds none is retired rather than applied.
#[tokio::test]
async fn kr_req_10_46_a_request_from_a_key_this_host_holds_no_owner_record_for_is_never_applied() {
    leg(|feed| async move {
        // A device with a key of its own, which the service admits as a publisher because it holds
        // the key its request names. What it does not hold is owner authority on this host.
        let stranger = RunKey::installation();
        let published = feed.revocation_from(&stranger);
        feed.deployment
            .authority_feed(&stranger)
            .publish(feed.address(), &published, None)
            .await
            .expect("the service stores what the key that signed it published");

        // And one from the owner this host does hold a record for, published to the same feed, so
        // that both go through the host's one path and the difference between them is the
        // validation and nothing else.
        let authorised = feed.revocation();
        feed.owner_client
            .publish(feed.address(), &authorised, None)
            .await
            .expect("the feed stored the owner's request");

        let seen = feed
            .host_client
            .read(feed.address(), None, false)
            .await
            .expect("the host reads its feed");
        let stranger_record = seen.record(published.request_id).expect("the record");
        let owner_record = seen.record(authorised.request_id).expect("the record");

        // One path, twice. The stranger's request reaches neither the record nor the revision; the
        // owner's does, and the revision it is applied under is the one the host allocated next.
        let mut held = feed.record();
        let refused = feed
            .apply_if_authorised(&mut held, &stranger_record.request, now_ms())
            .expect_err("this host holds no owner record for that key");
        assert!(refused.contains("no owner record"), "{refused}");
        assert_eq!(
            held.accepted_revision(),
            AuthorityRevision::new(0),
            "a request that failed validation allocates no revision"
        );
        assert!(held.applied().is_empty(), "and reaches no record");

        let revision = feed
            .apply_if_authorised(&mut held, &owner_record.request, now_ms())
            .expect("the owner this host holds a record for signed it");
        assert_eq!(revision, AuthorityRevision::new(1));
        assert_eq!(held.applied().len(), 1);
        assert_eq!(
            held.applied()[0].request.request_id,
            authorised.request_id,
            "the one that passed validation is the one that was applied"
        );

        // So the stranger's record is retired with the reason its publisher reads, and the owner's
        // is acknowledged under the revision the host issued for it.
        let state = feed
            .host_client
            .reject(published.request_id, RejectionReason::NoOwnerAuthority)
            .await
            .expect("the host refuses it");
        assert_eq!(state.summary.outstanding.get(), 1, "the owner's is still there");
        let issued = feed.revision(AuthorityRevision::new(0), &[authorised.request_id]);
        assert_eq!(issued.authority_revision, revision);
        feed.host_client
            .revise(&issued, None)
            .await
            .expect("the host issues its revision");
        let state = feed
            .host_client
            .acknowledge(
                &feed.acknowledgement(authorised.request_id, revision, RevocationCompletion::Complete),
                None,
            )
            .await
            .expect("the host acknowledges the one it applied");
        assert_eq!(state.summary.outstanding.get(), 0);

        // And the refused one cannot be acknowledged afterwards, whatever revision names it: a
        // completion cannot stand beside a refusal. The revision below is issued for this probe
        // alone, and the host's own record allocated nothing for that request.
        let probe = feed.revision(revision, &[published.request_id]);
        feed.host_client
            .revise(&probe, None)
            .await
            .expect("the host issues its next revision");
        let refused = feed
            .host_client
            .acknowledge(
                &feed.acknowledgement(
                    published.request_id,
                    probe.authority_revision,
                    RevocationCompletion::Complete,
                ),
                None,
            )
            .await
            .expect_err("that request was refused rather than applied");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);

        "one path validates every request a host reads: the one published by a key it holds no owner record for reaches neither its record nor its revision and is retired, and the owner's is applied and acknowledged".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: an acknowledgement names the revision the host issued for that request, and the
/// service refuses one that does not.
#[tokio::test]
async fn kr_req_10_46_an_acknowledgement_outside_the_revision_that_applied_it_is_refused() {
    leg(|feed| async move {
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

        "an acknowledgement is refused unless it names a revision this host issued and that revision applied the request, and a refusal ends nothing".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: a host is the sole issuer of its ordered authority revisions, and it rejects one
/// at or below the revision it has accepted, whether it is running or has come back from the
/// snapshot it writes down. What the snapshot is written to and read from is the controller's own
/// store and is not exercised here.
#[tokio::test]
async fn kr_req_10_46_a_revision_that_does_not_follow_the_accepted_one_is_rejected() {
    leg(|feed| async move {
        // The host's own record rejects a revision at or below the one it has accepted, whatever
        // its signature says, so a replayed feed entry cannot put authority back.
        let mut held = AuthorityFeed::new(feed.host.device_id(), AuthorityRevision::new(5));
        let stale = feed.revision(AuthorityRevision::new(3), &[]);
        assert_eq!(stale.authority_revision, AuthorityRevision::new(4));
        assert_eq!(
            held.accept(&stale),
            Err(FeedRefusal::OutOfOrder {
                accepted: AuthorityRevision::new(5),
                offered: AuthorityRevision::new(4),
            })
        );
        let mut equal = feed.revision(AuthorityRevision::new(4), &[]);
        equal.previous_revision = AuthorityRevision::new(4);
        assert_eq!(equal.authority_revision, AuthorityRevision::new(5));
        assert_eq!(
            held.accept(&equal),
            Err(FeedRefusal::OutOfOrder {
                accepted: AuthorityRevision::new(5),
                offered: AuthorityRevision::new(5),
            }),
            "the revision it already holds is not a later one"
        );
        let following = feed.revision(AuthorityRevision::new(5), &[]);
        held.accept(&following).expect("it follows what was held");
        assert_eq!(held.accepted_revision(), AuthorityRevision::new(6));

        // And what it accepted is what its snapshot carries: a record rebuilt from one holds the
        // same revision and refuses that revision again, and it owes a synchronisation because what
        // it knew before it stopped is not evidence about the feed now. Writing that snapshot down
        // and reading it back is the controller's own store, which this leg does not reach.
        let mut restarted = AuthorityFeed::restore(&held.snapshot());
        assert_eq!(restarted.accepted_revision(), AuthorityRevision::new(6));
        assert!(restarted.synchronisation_owed());
        assert!(restarted.status().stale);
        assert_eq!(
            restarted.accept(&following),
            Err(FeedRefusal::OutOfOrder {
                accepted: AuthorityRevision::new(6),
                offered: AuthorityRevision::new(6),
            }),
            "the revision it came back holding is not one it accepts again"
        );

        // An owner's client will not carry a host's revision at all, so nothing is sent.
        let never_sent = feed
            .owner_client
            .revise(&following, None)
            .await
            .expect_err("an owner does not issue a host's revisions");
        assert!(
            never_sent.to_string().contains("only the host"),
            "an installation credential does not carry a host's revision: {never_sent}"
        );

        // And the deployment says the same to a signed request that does carry one, which is what
        // makes the rule the service's rather than this client's.
        let body = serde_json::json!({ "revise": { "revision": following } });
        let refused = SignedService::new(
            feed.deployment.origin().clone(),
            feed.deployment.transport(),
            Arc::clone(&feed.owner) as Arc<_>,
        )
        .call(
            AUTHORITY_SYNC_PATH,
            Method::AuthoritySync,
            &body,
            MAX_AUTHORITY_REQUEST_BYTES,
        )
        .await
        .expect_err("only the host issues its own revisions");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert!(
            refused
                .to_string()
                .contains("Only the host issues its own revisions."),
            "{refused}"
        );

        // The feed holds the same order. A revision that does not follow the one it holds is
        // refused.
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

        // Submitting the revision that stands, again, is the same revision rather than a second
        // one.
        let state = feed
            .host_client
            .revise(&first, None)
            .await
            .expect("the revision that stands");
        assert_eq!(
            state.summary.authority_revision,
            Nullable(Some(first.authority_revision))
        );

        "a revision is the host's own and follows the one already held: the record rejects an older revision and the one it already holds, a record restored from its snapshot keeps the revision it accepted and refuses that revision again, and the deployment refuses an owner's revision, a gap and a rewrite".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: a host's record reports a synchronisation owed from the moment a connection is
/// established until one has happened, and counts the next poll from the interval the feed states.
/// Holding affected remote access back until it is not owed, and polling at that interval, are what
/// a caller does with those two answers; what is proved here is the answers.
#[tokio::test]
async fn kr_req_10_46_a_synchronisation_is_owed_from_the_connection_until_one_happens() {
    leg(|feed| async move {
        // A host that has just connected owes a synchronisation, before any remote access it might
        // affect.
        let mut held = feed.record();
        assert!(held.synchronisation_owed());
        assert!(held.status().stale);

        // A feed that answered nothing does not satisfy it. The service the leg calls holds its own
        // port and closes every connection it accepts, so the exchange ends at the socket.
        let silent = SilentService::start().await;
        let failure = silent
            .deployment()
            .authority_feed(&feed.host)
            .read(feed.address(), None, true)
            .await
            .expect_err("nothing answers there");
        assert_eq!(
            failure.code(),
            ErrorCode::OutcomeUnknown,
            "a request that was written and not answered is an unknown outcome"
        );
        assert_eq!(
            ExchangePhase::of(&failure),
            Some(ExchangePhase::Request),
            "the exchange ended with the request on its way"
        );
        held.unreachable();
        assert!(
            held.synchronisation_owed(),
            "an attempt that reached nothing is not a synchronisation"
        );

        // An actual one does.
        let at = now_ms();
        let state = feed
            .host_client
            .read(feed.address(), None, true)
            .await
            .expect("the host reads its feed");
        held.synchronised(at);
        assert!(!held.synchronisation_owed());
        assert!(!held.status().stale);
        assert_eq!(
            u64::from(state.summary.poll_interval_seconds) * 1000,
            held.next_poll_due_ms().expect("a poll is due") - at,
            "the host polls at the interval the feed states while it is online"
        );

        // And a connection that was replaced owes one again.
        held.reconnected();
        assert!(held.synchronisation_owed());
        assert!(held.status().stale);

        "the record reports a synchronisation owed from the moment a connection is established, keeps reporting it after an attempt that was not answered, stops once a read succeeded, counts the next poll from the interval the feed states, and owes one again when the connection is replaced".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: an unavailable feed shows stale revocation status, and the device list still shows
/// the last acknowledgement.
#[tokio::test]
async fn kr_req_10_46_an_unreachable_feed_is_stale_and_still_shows_the_last_acknowledgement() {
    leg(|feed| async move {
        let published = feed.revocation();
        feed.owner_client
            .publish(feed.address(), &published, None)
            .await
            .expect("the feed stored the owner's request");

        // Read back from the feed and put through the host's one path, as every other leg does:
        // what a host applies is what the feed served it, validated here and nowhere else.
        let seen = feed
            .host_client
            .read(feed.address(), None, false)
            .await
            .expect("the host reads its feed");
        let record = seen.record(published.request_id).expect("the record");
        let mut held = feed.record();
        held.enrol(feed.owner.device_id());
        let revision = feed
            .apply_if_authorised(&mut held, &record.request, now_ms())
            .expect("the owner this host holds a record for signed it");
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
        held.acknowledge(published.request_id, feed.owner.device_id());
        held.synchronised(now_ms());
        let current = held.status();
        assert!(!current.stale);

        // Then the feed cannot be reached. The status goes stale and stays stale; it is never
        // reported as current because nothing contradicted it.
        let silent = SilentService::start().await;
        let failure = silent
            .deployment()
            .authority_feed(&feed.host)
            .read(feed.address(), None, true)
            .await
            .expect_err("nothing answers there");
        assert_eq!(failure.code(), ErrorCode::OutcomeUnknown);
        held.unreachable();

        let stale = held.status();
        assert!(stale.stale, "an unavailable feed shows stale status");
        assert_eq!(
            stale.last_synchronised_at_ms, current.last_synchronised_at_ms,
            "the last successful synchronisation is still what it was"
        );
        assert_eq!(
            held.last_acknowledgement(feed.owner.device_id()),
            Some(revision),
            "the device list still shows the last acknowledgement"
        );
        assert_eq!(stale.accepted_revision, revision);

        "an unreachable feed leaves the status stale with the last acknowledgement and the last synchronisation still visible".to_owned()
    })
    .await;
}

/// KR-REQ-10.46: push and short-lived mailbox entries only announce feed changes, so a host that
/// never sees the announcement still learns the revocation from the feed.
#[tokio::test]
async fn kr_req_10_46_an_announcement_is_only_an_announcement() {
    leg(|feed| async move {
        let published = feed.revocation();

        // The owner seals an announcement for the host's mailbox. It says the feed changed and
        // carries nothing about what changed.
        let host_mailbox =
            StoredEnvelopeKeyPair::generate().expect("the host's stored-envelope key");
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

        // The host never reads that mailbox. It learns the revocation from the feed, which is where
        // the record lives, validates the owner's authority and applies it: the announcement is a
        // nudge and the feed is the record.
        let seen = feed
            .host_client
            .read(feed.address(), None, false)
            .await
            .expect("the host reads its feed");
        assert!(
            seen.is_outstanding(published.request_id),
            "a host that never saw the announcement still learns the revocation from the feed"
        );
        let record = seen.record(published.request_id).expect("the record");
        let mut held = feed.record();
        let revision = feed
            .apply_if_authorised(&mut held, &record.request, now_ms())
            .expect("the host applies what it learned from the feed");
        assert_eq!(held.accepted_revision(), revision);

        "an announcement is placed in a mailbox and carries nothing of the record, and a host that never reads it still learns the revocation from the feed and applies it".to_owned()
    })
    .await;
}
