//! The wait a restored policy puts on every remote grant, until the person at this machine ends it.
//!
//! The record of the restore is a store of its own ([`crate::grants::restored`]); this is the
//! daemon's half. The wait is the policy's flag and a bit of the word every remote grant reads,
//! raised and lowered together ([`Controller::put_a_feed_refusal`]). One lock covers a change of the
//! wait and of the record: the first finding that the feed is ahead raises both, the confirmation
//! lowers both, and the order of the two is the order they take it in, so a confirmation that
//! passed its check cannot remove the record a finding has just relied on.
//!
//! The lock is taken before the registry's guard, in the order restored, registry, policy, table.

use kr_protocol::envelope::ParamsValue;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::organisation::HostPolicyConfirmResult;

use super::Controller;
use crate::authority::AdmittedMutation;
use crate::error::{ControllerError, Result};
use crate::grants::RemoteRefusal;
use crate::grants::restored::{self, Found, Kept};

/// What a person who finds the host refusing remote access for a restored policy does.
const WAITS_REMEDY: &str = "Read what this host holds with `kr organisation list`, and end what \
     you do not want in force with `kr organisation withdraw`, `kr device revoke` and `kr share \
     revoke`, which need no confirmation and work while this stands. Then run `kr host policy \
     --confirm` at this machine. Until then no remote device is served, owner devices \
     included, and the person at this machine is not refused. The policy is the restored one: \
     confirming changes none of it. A host that reads an authority feed and has not reached it \
     since it started cannot tell whether it is behind it, so confirm once it has. A \
     confirmation made earlier ends the wait, and the host then serves remote devices from the \
     registry as restored, a device that an owner revoked through the feed after the copy \
     among them, until the first pass that reads the feed finds the host behind and raises the \
     wait again. Ending exclusive organisation management takes an owner device's \
     confirmation, which this wait refuses, or the terminal's when no owner device is left \
     whose grant could confirm, which the wait does not change. A host that is exclusively \
     organisation-managed cannot withdraw its last enrolment until exclusive management has \
     ended, so on such a host end it first where the terminal can, and otherwise confirm \
     first.";

/// As [`WAITS_REMEDY`], for a record of the restore that cannot be read.
const UNREADABLE_REMEDY: &str = "Read what this host holds with `kr organisation list`, and end \
     what you do not want in force with `kr organisation withdraw`, `kr device revoke` and `kr \
     share revoke`, which need no confirmation and work while this stands. Then run `kr host \
     policy --confirm` at this machine, which removes the record that cannot be read. Until \
     then no remote device is served, owner devices included, and `kr host update` to a \
     release that lists the record's store is refused when the update check cannot read the \
     record either. A host that reads an authority feed and has not reached it since it \
     started cannot tell whether it is behind it, so confirm once it has. A confirmation made \
     earlier ends the wait, and the host then serves remote devices from the registry as \
     restored, a device that an owner revoked through the feed after the copy among them, \
     until the first pass that reads the feed finds the host behind and raises the wait \
     again. Ending exclusive organisation management takes an owner device's confirmation, \
     which this wait refuses, or the terminal's when no owner device is left whose grant could \
     confirm, which the wait does not change. A host that is exclusively \
     organisation-managed cannot withdraw its last enrolment until exclusive management has \
     ended, so on such a host end it first where the terminal can, and otherwise confirm \
     first.";

impl Controller {
    /// What a start does about the record of a restore: reads it, decides whether the host waits,
    /// and keeps the record of the row it holds when it has to. Returns whether the host waits.
    ///
    /// `held` is the row this host holds, none when the registry has no policy row and the mirror
    /// holds none either. `mirror_unreadable` says the mirror was there and could not be read.
    ///
    /// # Errors
    ///
    /// Returns an error when the mirror cannot be read and the record naming the row read cannot
    /// be written: the start stops there, since going on would replace the mirror and lose the
    /// only evidence of what it held.
    pub(super) fn wait_for_a_restored_policy(
        kept: &mut Kept,
        held: Option<&crate::grants::StoredPolicy>,
        mirror_unreadable: bool,
        now_ms: u64,
    ) -> Result<bool> {
        let found = restored::read(kept.file());
        let Some(held) = held else {
            // A record of a restore describes a row, and there is none to describe.
            if !matches!(found, Found::Missing)
                && let Err(error) = kept.lift()
            {
                eprintln!(
                    "kr-controller: could not remove the record of a restored policy that \
                     describes no policy: {error}"
                );
            }
            return Ok(false);
        };
        let subject = restored::subject_of(held);
        if mirror_unreadable {
            // The mirror is what a restored registry would have been compared with. Its record
            // comes first, then the start replaces the mirror with a copy of the row it holds.
            if let Found::Record(record) = found {
                kept.adopt(record);
            }
            kept.ensure(subject, now_ms)?;
            eprintln!(
                "kr-controller: the copy of this host's policy could not be read, so a registry \
                 put back to an earlier state could not be noticed; the host waits for the \
                 person at this machine to confirm the policy it holds"
            );
            return Ok(true);
        }
        match found {
            Found::Missing => Ok(false),
            Found::Unreadable(why) => {
                eprintln!(
                    "kr-controller: the record that this host's policy was found restored cannot \
                     be read, so the host waits for the person at this machine to confirm the \
                     policy it holds: {why}"
                );
                Ok(true)
            }
            Found::Record(record) => {
                let stale = record.subject != subject;
                kept.adopt(record);
                if stale {
                    eprintln!(
                        "kr-controller: the policy this host holds is not the one it found \
                         restored, and nobody has confirmed it, so the host waits for the person \
                         at this machine"
                    );
                    if let Err(error) = kept.ensure(subject, now_ms) {
                        eprintln!(
                            "kr-controller: could not write the record of the policy this host \
                             holds: {error}"
                        );
                    }
                }
                Ok(true)
            }
        }
    }

    /// Whether this host waits for the person at this machine to confirm the policy it holds.
    #[must_use]
    pub fn restored_policy_waits(&self) -> bool {
        self.policy().restored_policy_waits()
    }

    /// Writes down that the policy this host holds was found restored, and raises the wait.
    ///
    /// Called when the feed is first found ahead of the registry, before anything is carried out
    /// again and before the registry is raised: once it has moved, the comparison finds nothing.
    /// A record already durable for this row costs no write. Nothing is raised until the record is
    /// durable, and the wait it raises stays when the host has caught up.
    ///
    /// # Errors
    ///
    /// Returns the write's error. The pass stops, nothing is carried out and the registry does not
    /// move, so the next pass finds the feed ahead again and writes again.
    pub(crate) async fn find_the_policy_restored(&self) -> Result<()> {
        let mut kept = self.restored_policy.lock().await;
        kept.ensure(
            restored::subject_of(&self.policy().snapshot()),
            self.wall_now_ms(),
        )?;
        self.move_a_feed_refusal(
            RemoteRefusal::RESTORED_POLICY_WAITS,
            true,
            crate::grants::HostPolicy::restored_policy_waits,
            crate::grants::HostPolicy::set_restored_policy_waits,
        )
        .await;
        Ok(())
    }

    /// Makes sure the record names the row this host holds now, as the catch-up begins: carrying
    /// out the feed's withdrawals again can unbind a member device and so change the row.
    ///
    /// # Errors
    ///
    /// Returns the write's error; the catch-up does not begin.
    pub(crate) async fn keep_the_record_of_the_policy_held(&self) -> Result<()> {
        let mut kept = self.restored_policy.lock().await;
        if !self.policy().restored_policy_waits() {
            return Ok(());
        }
        kept.ensure(
            restored::subject_of(&self.policy().snapshot()),
            self.wall_now_ms(),
        )
    }

    /// `host.policy.confirm`: the person at this machine confirms the policy this host holds,
    /// which ends the wait. Nothing about the policy changes.
    ///
    /// The admission the call was accepted under is asked again where the record is removed, under
    /// the record's lock and the registry's guard, in the order every service takes them: the call
    /// can wait for the lock behind a finding, which waits for the writes to the pairing records
    /// that were under way, and the registration or the deadline can lapse meanwhile.
    ///
    /// # Errors
    ///
    /// Returns a refusal while the host is still catching up with its feed, since the policy is
    /// not yet the one it will hold, the way the admission lapsed when it did, and an error when
    /// the record cannot be removed: the wait stands then.
    pub(super) async fn confirm_the_restored_policy(
        &self,
        carried: AdmittedMutation,
    ) -> Result<ParamsValue> {
        let lifted = {
            let mut kept = self.restored_policy.lock().await;
            if self.policy().behind_its_feed() {
                return Err(ControllerError::PermissionDenied {
                    detail: "this host is still catching up with its authority feed, so the \
                             policy it holds is not yet the one it will hold; confirm it once \
                             the host has caught up"
                        .to_owned(),
                });
            } else if !self.policy().restored_policy_waits() {
                false
            } else {
                {
                    let registry = self.registry.lock().await;
                    self.check_admission(&registry, &carried)?;
                    kept.lift()?;
                }
                self.move_a_feed_refusal(
                    RemoteRefusal::RESTORED_POLICY_WAITS,
                    false,
                    crate::grants::HostPolicy::restored_policy_waits,
                    crate::grants::HostPolicy::set_restored_policy_waits,
                )
                .await;
                true
            }
        };
        if lifted {
            eprintln!(
                "kr-controller: the person at this machine confirmed the policy this host holds, \
                 which it had found restored from an earlier state"
            );
        }
        ParamsValue::from_typed(&HostPolicyConfirmResult { lifted })
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// What the doctor says of a restored policy that waits for the person at this machine, none
    /// when nothing waits. It reads the record when it is asked, and not through the lock the
    /// changes take, so a host that no longer reads a feed says it all the same.
    pub(super) fn restored_policy_check(&self) -> Option<DoctorCheck> {
        use kr_protocol::hostinfo::export::Sentence;

        let policy = self.policy();
        if !policy.restored_policy_waits() {
            return None;
        }
        let record = restored::read(&restored::file_beside(&self.paths().registry_database()));
        let snapshot = policy.snapshot();
        let mut detail = Sentence::new().stated(
            "this host found the policy it holds restored from an earlier state, and refuses \
             every grant but the owner's at this machine until the person at this machine has \
             confirmed it; it holds ",
        );
        detail = detail
            .number(snapshot.enrolments.len() as u64)
            .stated(" organisation enrolments, exclusive organisation management is ")
            .stated(if snapshot.exclusively_managed {
                "on"
            } else {
                "off"
            });
        detail = match snapshot.offline.0 {
            Some(offline) => detail
                .stated(", and personal remote access is bounded to ")
                .number(offline.maximum_offline_ms.get())
                .stated(" milliseconds without a synchronisation"),
            None => detail.stated(", and personal remote access is not bounded"),
        };
        let unreadable = matches!(record, Found::Unreadable(_));
        if unreadable {
            detail = detail.stated("; the record of the restore cannot be read");
        }
        Some(DoctorCheck::new(
            "restored-policy",
            "The policy this host holds was not found restored",
            DoctorStatus::Warning,
            detail,
            Some(if unreadable {
                UNREADABLE_REMEDY
            } else {
                WAITS_REMEDY
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::StoredPolicy;
    use crate::grants::restored::Record;
    use kr_protocol::ids::AuthorityRevision;
    use kr_protocol::scalars::{Digest256, Nullable, TimestampMs};

    fn row() -> StoredPolicy {
        StoredPolicy {
            accepted_floor: AuthorityRevision::new(3),
            utc_floor_ms: TimestampMs::new(10),
            exclusively_managed: false,
            offline: Nullable::null(),
            enrolments: Vec::new(),
            lease_records: Vec::new(),
        }
    }

    fn a_kept() -> (tempfile::TempDir, Kept) {
        let directory = tempfile::tempdir().expect("a directory");
        let file = restored::file_beside(&directory.path().join("registry.sqlite"));
        (directory, Kept::new(file))
    }

    /// A client at this machine, registered at the revision in force, and the admission of a call
    /// it makes that runs out at `deadline`, or a minute from now when none is given.
    fn admitted(
        controller: &Controller,
        deadline: Option<kr_transport::clock::ContinuousInstant>,
    ) -> (kr_protocol::ids::ConnectionId, AdmittedMutation) {
        let revision = controller.policy().authority_revision();
        let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
        let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        controller.admitted_table().insert(
            connection_id,
            crate::service::AdmittedConnection::local(
                actor,
                revision,
                kr_protocol::local::LocalClientKind::Cli,
            ),
        );
        let carried = AdmittedMutation {
            connection_id,
            admitted_revision: revision,
            deadline: deadline.or_else(|| {
                controller
                    .clock
                    .now()
                    .checked_add(std::time::Duration::from_secs(60))
            }),
        };
        (connection_id, carried)
    }

    /// A mirror that cannot be read is a wait, and the record naming the row comes first. A record
    /// that cannot be written stops the start, so the mirror is not replaced and the only evidence
    /// of what it held is not lost.
    #[test]
    fn an_unreadable_mirror_is_a_wait_once_the_record_is_written_and_a_start_that_cannot_write_it_stops()
     {
        let (_directory, mut kept) = a_kept();
        let waits =
            Controller::wait_for_a_restored_policy(&mut kept, Some(&row()), true, 77).expect("ok");
        assert!(waits, "the host waits");
        assert_eq!(
            restored::read(kept.file()),
            Found::Record(Record::of(
                restored::subject_of(&row()),
                TimestampMs::new(77)
            )),
            "and the record naming the row is on disk"
        );

        let (_directory, mut obstructed) = a_kept();
        std::fs::create_dir(obstructed.file()).expect("an obstacle");
        let stopped =
            Controller::wait_for_a_restored_policy(&mut obstructed, Some(&row()), true, 77);
        assert!(
            stopped.is_err(),
            "a start that cannot write the record stops: {stopped:?}"
        );
    }

    /// Each thing a start can find at the file's place, with a mirror that reads.
    #[test]
    fn a_start_waits_for_a_record_it_finds_and_for_nothing_else() {
        let (_directory, mut kept) = a_kept();
        assert!(
            !Controller::wait_for_a_restored_policy(&mut kept, Some(&row()), false, 5).expect("ok"),
            "no record: today's behaviour"
        );
        restored::write(
            kept.file(),
            &Record::of(Digest256::from_bytes([4; 32]), TimestampMs::new(2)),
        )
        .expect("a record");
        assert!(
            Controller::wait_for_a_restored_policy(&mut kept, Some(&row()), false, 5).expect("ok"),
            "a record naming another row"
        );
        assert_eq!(
            restored::read(kept.file()),
            Found::Record(Record::of(
                restored::subject_of(&row()),
                TimestampMs::new(2)
            )),
            "is rewritten to name the row held, and keeps the moment it was found"
        );
        std::fs::write(kept.file(), b"junk").expect("junk");
        assert!(
            Controller::wait_for_a_restored_policy(&mut kept, Some(&row()), false, 5).expect("ok"),
            "a record that cannot be read"
        );
        assert!(kept.file().is_file(), "is left where it is");
        assert!(
            !Controller::wait_for_a_restored_policy(&mut kept, None, false, 5).expect("ok"),
            "a record that describes no policy waits for nothing"
        );
        assert_eq!(
            restored::read(kept.file()),
            Found::Missing,
            "and is removed"
        );
    }

    /// A finding and a confirmation take the one lock, so a confirmation that passed its check
    /// cannot remove the record a finding has just relied on, and the other way round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_finding_and_a_confirmation_wait_for_each_other() {
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        controller
            .find_the_policy_restored()
            .await
            .expect("the finding is written down");
        assert!(controller.restored_policy_waits());

        let held = controller.restored_policy.lock().await;
        let (_, carried) = admitted(&controller, None);
        let mut confirmation = std::pin::pin!(controller.confirm_the_restored_policy(carried));
        let mut finding = std::pin::pin!(controller.find_the_policy_restored());
        let pending = |name: &'static str, polled: std::task::Poll<()>| {
            assert!(polled.is_pending(), "{name} waits for the lock");
        };
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        pending(
            "the confirmation",
            std::future::Future::poll(confirmation.as_mut(), &mut cx).map(|_| ()),
        );
        pending(
            "the finding",
            std::future::Future::poll(finding.as_mut(), &mut cx).map(|_| ()),
        );
        drop(held);

        // Whichever takes the lock first, they leave the wait and the record in step.
        let (confirmed, found) = tokio::join!(confirmation, finding);
        confirmed.expect("the confirmation is answered");
        found.expect("the finding is written down");
        let record = restored::read(&restored::file_beside(
            &controller.paths().registry_database(),
        ));
        assert_eq!(
            controller.restored_policy_waits(),
            matches!(record, Found::Record(_)),
            "a wait stands exactly when its record does"
        );
    }
    /// The confirmation is refused while the host is still catching up with its feed, since the
    /// policy it holds is not yet the one it will hold, and lifts the wait once it has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_confirmation_is_refused_while_the_host_is_behind_its_feed() {
        use crate::grants::HostPolicy;
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let (_, carried) = admitted(&controller, None);
        controller
            .move_a_feed_refusal(
                RemoteRefusal::BEHIND_ITS_FEED,
                true,
                HostPolicy::behind_its_feed,
                HostPolicy::set_behind_its_feed,
            )
            .await;
        let refused = controller.confirm_the_restored_policy(carried).await;
        assert!(
            matches!(&refused, Err(ControllerError::PermissionDenied { detail }) if detail.contains("catching up")),
            "a host that knows it is behind its feed but has not yet written the record is still \
             catching up, and nothing waited yet to be lifted: {refused:?}"
        );
        controller
            .move_a_feed_refusal(
                RemoteRefusal::BEHIND_ITS_FEED,
                false,
                HostPolicy::behind_its_feed,
                HostPolicy::set_behind_its_feed,
            )
            .await;

        controller
            .find_the_policy_restored()
            .await
            .expect("the finding is written down");
        controller
            .move_a_feed_refusal(
                RemoteRefusal::BEHIND_ITS_FEED,
                true,
                HostPolicy::behind_its_feed,
                HostPolicy::set_behind_its_feed,
            )
            .await;
        let refused = controller.confirm_the_restored_policy(carried).await;
        assert!(
            matches!(&refused, Err(ControllerError::PermissionDenied { detail }) if detail.contains("catching up")),
            "{refused:?}"
        );
        assert!(
            controller.restored_policy_waits(),
            "and the wait stands, with its record"
        );
        assert!(matches!(
            restored::read(&restored::file_beside(
                &controller.paths().registry_database()
            )),
            Found::Record(_)
        ));

        controller
            .move_a_feed_refusal(
                RemoteRefusal::BEHIND_ITS_FEED,
                false,
                HostPolicy::behind_its_feed,
                HostPolicy::set_behind_its_feed,
            )
            .await;
        let confirmed: HostPolicyConfirmResult = controller
            .confirm_the_restored_policy(carried)
            .await
            .expect("the host has caught up")
            .to_typed()
            .expect("an answer");
        assert!(confirmed.lifted);
        assert!(!controller.restored_policy_waits());
    }

    /// A confirmation can wait for the record's lock behind a finding, which waits for the writes
    /// to the pairing records that were under way. The registration or the deadline it was
    /// accepted under can lapse meanwhile, and then it removes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confirmation_whose_admission_lapses_while_it_waits_for_the_record_removes_nothing() {
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        controller
            .find_the_policy_restored()
            .await
            .expect("the finding is written down");
        let record = || {
            restored::read(&restored::file_beside(
                &controller.paths().registry_database(),
            ))
        };
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);

        // The registration is withdrawn while the call waits for the lock.
        let (connection, carried) = admitted(&controller, None);
        let held = controller.restored_policy.lock().await;
        let mut confirmation = std::pin::pin!(controller.confirm_the_restored_policy(carried));
        assert!(
            std::future::Future::poll(confirmation.as_mut(), &mut cx).is_pending(),
            "the call waits for the lock"
        );
        controller.admitted_table().remove(&connection);
        drop(held);
        let refused = confirmation.await;
        assert!(
            matches!(&refused, Err(ControllerError::PermissionDenied { .. })),
            "a registration withdrawn while the call waited: {refused:?}"
        );
        assert!(controller.restored_policy_waits(), "the wait stands");
        assert!(matches!(record(), Found::Record(_)), "with its record");

        // The deadline passes while the call waits for the lock.
        let (_, carried) = admitted(&controller, Some(controller.clock.now()));
        let held = controller.restored_policy.lock().await;
        let mut confirmation = std::pin::pin!(controller.confirm_the_restored_policy(carried));
        assert!(std::future::Future::poll(confirmation.as_mut(), &mut cx).is_pending());
        drop(held);
        let refused = confirmation.await;
        assert!(
            matches!(&refused, Err(ControllerError::WindowExpired { .. })),
            "a deadline that passed while the call waited: {refused:?}"
        );
        assert!(controller.restored_policy_waits(), "the wait stands");
        assert!(matches!(record(), Found::Record(_)), "with its record");

        // The control: an admission that stands lifts it.
        let (_, carried) = admitted(&controller, None);
        let confirmed: HostPolicyConfirmResult = controller
            .confirm_the_restored_policy(carried)
            .await
            .expect("an admission that stands")
            .to_typed()
            .expect("an answer");
        assert!(confirmed.lifted);
        assert_eq!(record(), Found::Missing);
    }
}
