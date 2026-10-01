//! What a delivery rule's grant lets its recipient see, answered from this host's own records.
//!
//! Section 19 intersects a notification's content with the recipient's own authority, and the
//! recipient's authority is the grant the destination's rule names, intersected with this host's
//! current policy the way every other use of a grant is. So this answers from the grants this host
//! holds, as they stand at the moment of asking, and from the policy in force at that moment: a
//! grant revoked, expired, never redeemed, issued under an authority revision this host has not
//! reached, or for another environment admits nothing; so does one the policy will not honour - an
//! organisation grant whose recipient this host cannot attribute to a member with a current lease,
//! a personal grant on a host that is exclusively organisation-managed, a grant used past the
//! bounded offline-validity policy - and so does one whose rights, after that intersection and the
//! host's configured ceiling, include nothing a notification can ask for.
//!
//! A grant lives in one of two places: the grant store, for a grant this host issued or shared, and
//! a paired device's own record, for the grant its pairing committed, where its revocation and its
//! expiry are written. Both are asked, the store first, and both decide the way a device's own
//! request does.
//!
//! A paired device's destination asks too. Its content is sealed to the device's own key, and that
//! says who can read it, not whether the device's grant admits it. The destination is named by the
//! device's identifier and its rule names a grant, and the grant has to be the device's own: a rule
//! that names another device's grant, or a device that is no longer paired, admits nothing.

use std::sync::{Arc, Mutex};

use kr_delivery::destination::{DeliveryRule, DestinationRecord};
use kr_delivery::producer::{RecipientAuthority, RecipientScope};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{DeviceId, EnvironmentId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_worker::history_filter::ViewerScope;

use crate::grants::{AccessRequest, GrantRecord, HostPolicy};
use crate::service::net::devices::DeviceRecord;
use crate::service::net::lifetimes::{Anchored, GrantLifetimes};
use crate::sharing::SharingService;

/// The grants this host holds, under its current policy and configuration, as a delivery rule's
/// recipient authority.
pub struct GrantedRecipients {
    sharing: Arc<SharingService>,
    policy: Arc<Mutex<HostPolicy>>,
    environment_id: EnvironmentId,
    /// Every grant's anchor in this boot, with the clocks a grant and a membership lease are both
    /// decided on, and the directory of paired devices a pairing grant is read from.
    lifetimes: Arc<GrantLifetimes>,
    /// The rights this host's configuration allows, which narrows every grant as it narrows a
    /// paired device's every request. None where nothing sets one.
    ceiling: Option<Arc<Mutex<Option<CanonicalSet<ActionRight>>>>>,
    /// Where this host's own tests stop a question once the grant's standing has been read and
    /// before the policy's lock is taken. Compiled away in every shipped build.
    #[cfg(test)]
    before_the_policy_lock: crate::attention::Pause,
}

impl std::fmt::Debug for GrantedRecipients {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantedRecipients")
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

/// What a rule's grant stands on.
enum Standing {
    /// A grant in the grant store.
    Stored(GrantRecord),
    /// The grant a paired device's pairing committed, with the device's record.
    Paired(DeviceRecord),
}

impl Standing {
    fn grant(&self) -> &Grant {
        match self {
            Self::Stored(record) => &record.grant,
            Self::Paired(device) => &device.grant,
        }
    }

    /// When the grant began, in UTC milliseconds, or none while it has not been redeemed.
    fn started_at_ms(&self) -> Option<u64> {
        match self {
            Self::Stored(record) => record.activated_at_ms,
            Self::Paired(device) => Some(device.paired_at_ms.get()),
        }
    }
}

impl GrantedRecipients {
    /// Answers from `sharing`'s grants and the devices `lifetimes` holds, under `policy`, for the
    /// sessions of one environment, with each grant's own bound and a membership lease decided on
    /// the clocks of `lifetimes`, the daemon's.
    #[must_use]
    pub fn new(
        sharing: Arc<SharingService>,
        policy: Arc<Mutex<HostPolicy>>,
        environment_id: EnvironmentId,
        lifetimes: Arc<GrantLifetimes>,
    ) -> Self {
        Self {
            sharing,
            policy,
            environment_id,
            lifetimes,
            ceiling: None,
            #[cfg(test)]
            before_the_policy_lock: crate::attention::Pause::default(),
        }
    }

    /// Narrows every grant by the rights ceiling this host's configuration holds in `ceiling`,
    /// read at each question, as the daemon narrows a paired device's every request.
    #[must_use]
    pub fn with_ceiling(mut self, ceiling: Arc<Mutex<Option<CanonicalSet<ActionRight>>>>) -> Self {
        self.ceiling = Some(ceiling);
        self
    }

    /// The lifetimes this answers on, and through them the directory of paired devices it reads.
    #[must_use]
    pub const fn lifetimes(&self) -> &Arc<GrantLifetimes> {
        &self.lifetimes
    }

    /// Answers on clocks of the caller's choosing, with anchors of its own, which is how a test
    /// holds a grant's expiry still: `continuous`, the clock a grant's anchor and a membership
    /// lease's continuous deadline are compared on, and `clock`, the wall clock.
    ///
    /// # Panics
    ///
    /// Panics when the in-memory records the anchors are kept in cannot be opened, or this boot
    /// cannot be identified.
    #[must_use]
    pub fn at(
        sharing: Arc<SharingService>,
        policy: Arc<Mutex<HostPolicy>>,
        environment_id: EnvironmentId,
        continuous: Arc<dyn kr_transport::clock::ContinuousClock>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        let floor = Arc::clone(
            policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .utc_floor(),
        );
        let lifetimes = Arc::new(GrantLifetimes::new(
            Arc::new(
                crate::service::net::devices::DeviceDirectory::in_memory()
                    .expect("an in-memory device directory"),
            ),
            continuous,
            Arc::new(kr_ipc::clock::SystemSharedClock),
            kr_ipc::identity::boot_identity().expect("this boot's identity"),
            crate::service::WallClock::from_fn(clock),
            floor,
        ));
        Self::new(sharing, policy, environment_id, lifetimes)
    }

    /// Finds what one grant stands on, in whichever store holds it.
    ///
    /// A store this host cannot read is a grant this host cannot show, and a grant it cannot show
    /// admits nothing.
    fn standing(&self, grant_id: GrantId) -> Option<Standing> {
        match self.sharing.grants().record(grant_id) {
            Ok(Some(record)) => return Some(Standing::Stored(record)),
            Ok(None) => {}
            Err(_) => return None,
        }
        self.lifetimes
            .devices()
            .devices()
            .ok()?
            .into_iter()
            .find(|device| device.grant.grant_id == grant_id)
            .map(Standing::Paired)
    }

    /// Reads the standing of the same grant again, once the policy's lock is held, so that what a
    /// revocation completed while this waited for the lock is found.
    fn still_standing(&self, standing: &Standing) -> bool {
        match standing {
            Standing::Stored(record) => self
                .sharing
                .grants()
                .record(record.grant.grant_id)
                .ok()
                .flatten()
                .is_some_and(|fresh| fresh.revoked_at_ms.is_none() && fresh.is_active()),
            Standing::Paired(device) => self
                .lifetimes
                .devices()
                .record_for_device(device.device_id)
                .ok()
                .flatten()
                .is_some_and(|fresh| fresh.is_paired()),
        }
    }

    /// The scope a grant gives its recipient now, decided as a device's own request is, on both
    /// clocks, under the policy and the configured ceiling.
    fn scope_of(&self, standing: &Standing) -> Option<RecipientScope> {
        let grant = standing.grant();
        let started_at_ms = standing.started_at_ms()?;
        // Revoked, expired, or a proposal nobody has redeemed: neither admits anything, and no
        // clock decides any of them.
        let anchored = match standing {
            Standing::Stored(record) => {
                if record.revoked_at_ms.is_some() || !record.is_active() {
                    return None;
                }
                // The grant's anchor in this boot, taken the first time anything asks and read back
                // after that, so what follows reads no store. An end already on record reads as
                // over. An expiring grant this host cannot anchor, or whose end it cannot write
                // down, admits nothing.
                self.lifetimes.stored(self.sharing.grants(), record).ok()?
            }
            Standing::Paired(device) => {
                if !device.is_paired() {
                    return None;
                }
                self.lifetimes.paired(device).ok()?
            }
        };
        // What the configuration allows, read before the policy's lock is taken, as a device's
        // request reads it.
        let ceiling = self.ceiling.as_ref().and_then(|ceiling| {
            ceiling
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        });
        #[cfg(test)]
        self.before_the_policy_lock.wait();
        // The policy as it stands now, decided under its lock and after every read of a store
        // above. A copy taken earlier could hold a lease its cell no longer states, and the rights
        // a decision takes have to be those of the lease whose time it loads.
        let policy = self.policy.lock().ok()?;
        if !self.still_standing(standing) {
            return None;
        }
        // Both clocks, read once the lock is held, so a bound that ran out while this waited for it
        // is found, and everything below is decided at these readings. UTC is read through this
        // host's floor, which the reading raises, so a clock wound back after this message does not
        // revive the grant for the next one.
        let now_ms = self.lifetimes.settled_utc_now();
        let continuous_now = self.lifetimes.continuous_now();
        // The grant's own bound, on both of its clocks. An end found here is written down as every
        // end this host finds is: as the grant's tombstone, once the policy's lock is let go, since a
        // later boot reads the tombstone before it derives anything; and, when UTC found it, as the
        // floor it was found at, which is written under the lock like every write of the policy.
        let expired_in_utc = !grant.expiry.is_valid_at(now_ms);
        if expired_in_utc || !anchored.holds_at(continuous_now) {
            if expired_in_utc {
                self.sharing.grants().record_floor(&policy);
            }
            drop(policy);
            if anchored != Anchored::Over {
                match standing {
                    Standing::Stored(_) => {
                        self.lifetimes.owe_stored_expiry(grant.grant_id);
                        self.lifetimes.settle_stored(self.sharing.grants());
                    }
                    // Asking where a paired device's grant stands writes down an end it finds.
                    Standing::Paired(device) => {
                        let _ = self.lifetimes.paired_standing(device);
                    }
                }
            }
            return None;
        }
        if grant.authority_revision.get() > policy.authority_revision().get()
            || !grant.environment_selector.admits(self.environment_id)
        {
            return None;
        }
        // Nothing that reads this host's clock is decided while this boot's clock continuity is
        // lost: an organisation's lease and a bounded offline validity are bounds that can pass, as
        // the grant's own expiry is, and nothing proves where any of them stands until the owner
        // establishes the clock.
        if policy.utc_floor().continuity_lost()
            && policy.stands_on_the_clock(grant, ActorIngress::PairedDevice)
        {
            return None;
        }
        // The configured ceiling narrows the grant before the policy is applied to it, as it does
        // for a device's request.
        let narrowed = match &ceiling {
            Some(ceiling) => Grant {
                actions: grant
                    .actions
                    .iter()
                    .copied()
                    .filter(|right| ceiling.contains(right))
                    .collect(),
                ..grant.clone()
            },
            None => grant.clone(),
        };
        // Content leaving this host for a recipient elsewhere is remote use of the grant, so it is
        // intersected the way a paired device's request is. An organisation grant answers to the
        // lease of the member its recipient device is bound to, on both clocks; a message carries
        // no account of its own that could name another.
        let effective = match policy.intersect(
            &narrowed,
            &AccessRequest {
                method: Method::SessionRead,
                ingress: ActorIngress::PairedDevice,
                environment_id: self.environment_id,
                session_id: None,
                claims_geometry: false,
                own_subject: None,
                now_ms,
                continuous_now,
            },
            now_ms,
        ) {
            Ok(effective) => effective,
            Err(refusal) => {
                // A lapse the clock decided, a lease or the offline bound run out, is written down
                // as the floor it was found at, as every such lapse is.
                if refusal.is_clock_decided() {
                    self.sharing.grants().record_floor(&policy);
                }
                return None;
            }
        };
        // The offline bound the intersection loaded is held to its continuous end as well, as a
        // device's request is: a wall clock wound back does not hold it open. Run out there, the
        // time it has spent is written down before this refuses.
        if self
            .lifetimes
            .offline_bound_ended(effective.offline.as_ref(), continuous_now, &policy)
        {
            return None;
        }
        drop(policy);
        // A grant that keeps none of the rights a notification can ask for admits nothing.
        if ![
            ActionRight::SessionView,
            ActionRight::AutomationManage,
            ActionRight::HostManage,
        ]
        .iter()
        .any(|right| effective.rights.contains(right))
        {
            return None;
        }
        Some(RecipientScope {
            viewer: ViewerScope::from_grant(&narrowed),
            sessions: narrowed.session_selector.clone(),
            rights: effective.rights,
            grant_id: narrowed.grant_id,
            recipient: narrowed.recipient_device_id,
            // Earlier history is opt-in: a grant reaches what was first seen at or after its own
            // history cursor, or at or after its own start when it has none.
            history_from_ms: narrowed
                .history
                .lower_bound_ms
                .as_ref()
                .map_or(started_at_ms, |cursor| cursor.get()),
        })
    }
}

impl RecipientAuthority for GrantedRecipients {
    /// Every lapse a clock decides here is written down where it is found, before the answer, as a
    /// paired device's and a workflow's are, so a clock wound back before a restart or a reboot
    /// cannot bring back what was refused: the end of the grant's own bound as its tombstone; a
    /// lapse found in UTC, the grant's own or a bound of the policy, as the floor it was found at;
    /// and the offline bound's end on the continuous clock as the time the bound has spent. A write
    /// that fails stays owed, and the host's next decision or its record task writes it.
    fn scope_for(&self, rule: &DeliveryRule) -> Option<RecipientScope> {
        let standing = self.standing(rule.grant_id?)?;
        self.scope_of(&standing)
    }

    /// The device is the one its destination is named by, and the grant its rule names is the
    /// device's own, by the device it was issued to; a grant in the grant store that was issued to
    /// a device is still only as good as that device's own pairing, so the device has to be
    /// paired.
    fn device_scope(&self, destination: &DestinationRecord) -> Option<RecipientScope> {
        let device_id: DeviceId = destination.id.as_str().parse().ok()?;
        let standing = self.standing(destination.rule.as_ref()?.grant_id?)?;
        if standing.grant().recipient_device_id != device_id {
            return None;
        }
        if matches!(standing, Standing::Stored(_))
            && !self
                .lifetimes
                .devices()
                .record_for_device(device_id)
                .ok()
                .flatten()
                .is_some_and(|device| device.is_paired())
        {
            return None;
        }
        self.scope_of(&standing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::GrantRecord;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId, SessionId};
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    const NOW: u64 = 1_700_000_000_000;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::new(uuid(7))
    }

    fn host() -> DeviceId {
        DeviceId::new(uuid(1))
    }

    fn grant(byte: u8, sessions: SessionSelector, actions: &[ActionRight]) -> Grant {
        Grant {
            grant_id: GrantId::new(uuid(byte)),
            parent_grant_id: Nullable::null(),
            issuer_device_id: host(),
            recipient_device_id: DeviceId::new(uuid(2)),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::These {
                environment_ids: [environment()].into_iter().collect(),
            },
            session_selector: sessions,
            actions: actions.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    fn issued(sharing: &SharingService, grant: Grant, activated: bool) {
        sharing
            .grants()
            .issue(
                &GrantRecord {
                    grant,
                    session_id: None,
                    issued_at_ms: NOW - 1_000,
                    activated_at_ms: activated.then_some(NOW - 500),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the grant is written");
    }

    fn rule(grant: Option<u8>) -> DeliveryRule {
        DeliveryRule {
            name: "on a failed command".to_owned(),
            grant_id: grant.map(|byte| GrantId::new(uuid(byte))),
        }
    }

    fn personal() -> Arc<Mutex<HostPolicy>> {
        Arc::new(Mutex::new(HostPolicy::personal(AuthorityRevision::new(1))))
    }

    fn recipients(sharing: &Arc<SharingService>) -> GrantedRecipients {
        GrantedRecipients::at(
            Arc::clone(sharing),
            personal(),
            environment(),
            Arc::new(kr_transport::clock::ManualClock::new()),
            || NOW,
        )
    }

    /// A grant that runs out while its question waits for the policy's lock admits nothing: both of
    /// its deadlines are read again once the lock is held, on UTC and on the continuous clock alike,
    /// and the end is written down as its tombstone. The control: with the clocks left where they
    /// were, the question admits its recipient and nothing is written.
    #[test]
    fn a_grant_that_runs_out_while_its_question_waits_for_the_lock_admits_nothing() {
        use std::sync::atomic::{AtomicU64, Ordering};

        for runs_out in [None, Some("in UTC"), Some("on the continuous clock")] {
            let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
            let mut expiring = grant(13, SessionSelector::Any, &[ActionRight::SessionView]);
            expiring.expiry = GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(NOW + 1_000),
            };
            issued(&sharing, expiring, true);
            let wall = Arc::new(AtomicU64::new(NOW));
            let continuous = kr_transport::clock::ManualClock::new();
            let recipients = Arc::new(GrantedRecipients::at(
                Arc::clone(&sharing),
                personal(),
                environment(),
                Arc::new(continuous.clone()),
                {
                    let wall = Arc::clone(&wall);
                    move || wall.load(Ordering::SeqCst)
                },
            ));
            let (arrived, go) = recipients.before_the_policy_lock.arm();
            let asking = {
                let recipients = Arc::clone(&recipients);
                std::thread::spawn(move || recipients.scope_for(&rule(Some(13))))
            };
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the question read the grant's standing and reached the lock");
            match runs_out {
                Some("in UTC") => wall.store(NOW + 1_000, Ordering::SeqCst),
                Some(_) => continuous.advance(std::time::Duration::from_millis(1_000)),
                None => {}
            }
            go.send(()).expect("the question waits");
            let scope = asking.join().expect("the question ends");
            assert_eq!(
                scope.is_some(),
                runs_out.is_none(),
                "run out {}",
                runs_out.unwrap_or("nowhere")
            );
            // An end found there is written down as the grant's tombstone, so a host that holds
            // no anchor for the grant, as after a reboot, finds it ended too.
            let tombstone = sharing
                .grants()
                .grant_expired_at(GrantId::new(uuid(13)))
                .expect("the store reads");
            assert_eq!(tombstone.is_some(), runs_out.is_some());
            let afresh = GrantedRecipients::at(
                Arc::clone(&sharing),
                personal(),
                environment(),
                Arc::new(kr_transport::clock::ManualClock::new()),
                move || NOW,
            );
            assert_eq!(
                afresh.scope_for(&rule(Some(13))).is_some(),
                runs_out.is_none(),
                "and a host with no anchor for it answers as the record says"
            );
        }
    }

    /// A grant whose expiry UTC has passed admits nothing, and the end is written down as every end
    /// this host finds is: as the grant's tombstone, and as the floor it was found at. So a host
    /// that holds no anchor for the grant and whose wall clock reads before the expiry, as after a
    /// reboot with the clock wound back, finds it ended too. Alike when the question is the first
    /// in this boot and when an earlier one anchored the grant. The control: with UTC short of the
    /// expiry, the question admits its recipient and nothing is written.
    #[test]
    fn a_grant_run_out_in_utc_is_written_down_with_the_floor_it_was_found_at() {
        use std::sync::atomic::{AtomicU64, Ordering};

        for (run_out, anchored_before) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let case = format!("run out {run_out}, anchored before {anchored_before}");
            let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
            let mut expiring = grant(15, SessionSelector::Any, &[ActionRight::SessionView]);
            expiring.expiry = GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(NOW + 1_000),
            };
            issued(&sharing, expiring, true);
            let policy = personal();
            let wall = Arc::new(AtomicU64::new(NOW));
            let recipients = GrantedRecipients::at(
                Arc::clone(&sharing),
                Arc::clone(&policy),
                environment(),
                Arc::new(kr_transport::clock::ManualClock::new()),
                {
                    let wall = Arc::clone(&wall);
                    move || wall.load(Ordering::SeqCst)
                },
            );
            if anchored_before {
                assert!(
                    recipients.scope_for(&rule(Some(15))).is_some(),
                    "in force when first asked: {case}"
                );
            }
            if run_out {
                wall.store(NOW + 1_000, Ordering::SeqCst);
            }
            assert_eq!(
                recipients.scope_for(&rule(Some(15))).is_some(),
                !run_out,
                "{case}"
            );
            let tombstone = sharing
                .grants()
                .grant_expired_at(GrantId::new(uuid(15)))
                .expect("the store reads");
            assert_eq!(tombstone.is_some(), run_out, "the tombstone: {case}");
            let floor = Arc::clone(policy.lock().expect("not poisoned").utc_floor());
            assert_eq!(
                floor.written() >= NOW + 1_000,
                run_out,
                "the floor the end was found at is written down: {case}"
            );
            assert!(!floor.is_owed(), "and nothing is left owed: {case}");
            let afresh = GrantedRecipients::at(
                Arc::clone(&sharing),
                personal(),
                environment(),
                Arc::new(kr_transport::clock::ManualClock::new()),
                move || NOW,
            );
            assert_eq!(
                afresh.scope_for(&rule(Some(15))).is_some(),
                !run_out,
                "a host with no anchor for it and its clock wound back: {case}"
            );
        }
    }

    /// A message under a personal grant whose offline bound has run out admits nothing: in UTC, and
    /// then the floor it was found at is written down, so a clock wound back before a restart
    /// cannot revive the bound; and on the continuous clock, whatever UTC says. The control: inside
    /// the bound it admits, and no floor is written.
    #[test]
    fn a_lapsed_offline_bound_admits_nothing_and_its_utc_lapse_writes_the_floor_down() {
        use std::sync::atomic::{AtomicU64, Ordering};

        for lapsed in [None, Some("in UTC"), Some("on the continuous clock")] {
            let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
            issued(
                &sharing,
                grant(14, SessionSelector::Any, &[ActionRight::SessionView]),
                true,
            );
            let policy = personal();
            let wall = Arc::new(AtomicU64::new(NOW));
            let continuous = kr_transport::clock::ManualClock::new();
            let recipients = GrantedRecipients::at(
                Arc::clone(&sharing),
                Arc::clone(&policy),
                environment(),
                Arc::new(continuous.clone()),
                {
                    let wall = Arc::clone(&wall);
                    move || wall.load(Ordering::SeqCst)
                },
            );
            {
                // A bound of a minute, synchronised now, published as a daemon publishes it, with
                // its continuous end a minute out.
                let mut held = policy.lock().expect("not poisoned");
                held.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                    maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60_000),
                    last_synchronised_at_ms: Nullable::some(
                        kr_protocol::scalars::TimestampMs::new(NOW),
                    ),
                }));
                held.offline_cell().publish(
                    crate::grants::policy::BoundIdentity::Offline {
                        synchronised_at_ms: Some(NOW),
                    },
                    kr_transport::clock::ContinuousClock::now(&continuous)
                        .checked_add(std::time::Duration::from_secs(60)),
                    Some(NOW + 60_001),
                    false,
                    false,
                );
            }
            match lapsed {
                Some("in UTC") => wall.store(NOW + 60_001, Ordering::SeqCst),
                Some(_) => continuous.advance(std::time::Duration::from_secs(61)),
                None => {}
            }
            let scope = recipients.scope_for(&rule(Some(14)));
            assert_eq!(scope.is_some(), lapsed.is_none(), "lapsed {lapsed:?}");
            let floor = Arc::clone(policy.lock().expect("not poisoned").utc_floor());
            assert_eq!(
                floor.written() >= NOW + 60_001,
                lapsed == Some("in UTC"),
                "only a lapse found in UTC writes the floor down, at the reading it was found at"
            );
            assert!(!floor.is_owed(), "and nothing is left owed");
        }
    }

    #[test]
    fn a_redeemed_grant_answers_with_its_own_session_selector() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        let scope = recipients(&sharing)
            .scope_for(&rule(Some(10)))
            .expect("the grant is in force");
        assert_eq!(
            scope.sessions,
            SessionSelector::Any,
            "a grant over every session covers the ones created after it, so it is not a list"
        );
        let named = SessionSelector::These {
            session_ids: [SessionId::new(uuid(30))].into_iter().collect(),
        };
        issued(
            &sharing,
            grant(11, named.clone(), &[ActionRight::SessionView]),
            true,
        );
        assert_eq!(
            recipients(&sharing)
                .scope_for(&rule(Some(11)))
                .expect("the grant is in force")
                .sessions,
            named
        );
    }

    /// While this boot's clock continuity is lost, a rule whose grant stands on the clock admits
    /// nothing, however it stands on it: a grant that never expires under a bounded offline
    /// validity is one. A grant that reads no clock still admits its recipient.
    #[test]
    fn a_lost_clock_continuity_admits_nothing_that_reads_the_clock() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        issued(
            &sharing,
            grant(12, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        let policy = personal();
        let recipients = GrantedRecipients::at(
            Arc::clone(&sharing),
            Arc::clone(&policy),
            environment(),
            Arc::new(kr_transport::clock::ManualClock::new()),
            || NOW,
        );
        policy
            .lock()
            .expect("not poisoned")
            .utc_floor()
            .lose_continuity();
        assert!(
            recipients.scope_for(&rule(Some(12))).is_some(),
            "a grant that reads no clock is untouched"
        );
        {
            // Chosen and published, as a daemon publishes a policy it has written down.
            let mut held = policy.lock().expect("not poisoned");
            let before = held.clone();
            held.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(
                    NOW,
                )),
            }));
            held.publish_unanchored(&before);
        }
        assert!(
            recipients.scope_for(&rule(Some(12))).is_none(),
            "a bounded offline validity reads the clock"
        );
        // The control: once the owner establishes the clock, the rule admits its recipient again.
        policy
            .lock()
            .expect("not poisoned")
            .utc_floor()
            .establish_continuity();
        assert!(recipients.scope_for(&rule(Some(12))).is_some());
    }

    #[test]
    fn a_grant_that_is_not_in_force_or_does_not_view_sessions_admits_nothing() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        // Never redeemed: a proposal authorises nothing.
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            false,
        );
        // In force, and it does not let its holder view a session.
        issued(
            &sharing,
            grant(11, SessionSelector::Any, &[ActionRight::FilesRead]),
            true,
        );
        // Issued for another environment.
        let mut elsewhere = grant(12, SessionSelector::Any, &[ActionRight::SessionView]);
        elsewhere.environment_selector = EnvironmentSelector::These {
            environment_ids: [EnvironmentId::new(uuid(8))].into_iter().collect(),
        };
        issued(&sharing, elsewhere, true);
        // In force, and then revoked.
        issued(
            &sharing,
            grant(13, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        sharing
            .grants()
            .revoke(GrantId::new(uuid(13)), NOW - 100, || Ok(()))
            .expect("the revocation is written");

        let recipients = recipients(&sharing);
        for byte in [10, 11, 12, 13, 14] {
            assert_eq!(
                recipients.scope_for(&rule(Some(byte))),
                None,
                "grant {byte} admits nothing"
            );
        }
        assert_eq!(
            recipients.scope_for(&rule(None)),
            None,
            "nor does a rule that names no grant"
        );
    }

    /// The grant is intersected with the policy as it stands at the moment of asking: a policy
    /// that stops honouring the grant after the message was admitted stops the message.
    #[test]
    fn a_grant_the_host_policy_no_longer_honours_admits_nothing() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        let policy = personal();
        let recipients = GrantedRecipients::at(
            Arc::clone(&sharing),
            Arc::clone(&policy),
            environment(),
            Arc::new(kr_transport::clock::ManualClock::new()),
            || NOW,
        );
        assert!(recipients.scope_for(&rule(Some(10))).is_some());

        // The host becomes exclusively organisation-managed: personal authority stops with the
        // organisation's, and an external recipient is nobody this host can attribute a lease to.
        policy
            .lock()
            .expect("the policy is not poisoned")
            .set_exclusively_managed(true);
        assert_eq!(recipients.scope_for(&rule(Some(10))), None);
    }

    /// An organisation grant answers only to the lease of the member its recipient device is bound
    /// to. On a host that is not enrolled in the organisation, and so binds nobody in it, the grant
    /// admits nothing rather than being answered by somebody else's lease.
    #[test]
    fn an_organisation_grant_admits_nothing_for_a_recipient_no_lease_answers_for() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        let mut organisational = grant(10, SessionSelector::Any, &[ActionRight::SessionView]);
        organisational.organisation = Nullable::some(kr_protocol::grant::OrganisationRequirement {
            organisation_id: kr_protocol::ids::OrganisationId::new(uuid(40)),
            policy_revision: AuthorityRevision::new(1),
        });
        issued(&sharing, organisational, true);
        assert_eq!(recipients(&sharing).scope_for(&rule(Some(10))), None);
    }
}
