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
use crate::grants::restored::{self, Found, Kept, Owed, Target};

/// What a host that reads an authority feed owes a confirmation, said once for both remedies.
macro_rules! feed_note {
    () => {
        "A host that reads an authority feed refuses the confirmation until a scan of this run has \
         read the feed through and carried out, or settled, every record it holds, so that a \
         device an owner revoked through the feed since the copy is not served by a confirmation \
         made earlier; this check says when that is still owed, and the host asks its feed again \
         by itself. Where a request waits for this host to decide who may manage it, because its \
         clock lost its continuity, reboot the machine, which ends that, so that the host judges \
         the request again. A host that cannot reach its feed is confirmed by taking \
         `authority.origin` out of the configuration document and starting the daemon again, once \
         no device or share this host's list names is live, at this cost: the host then reads no \
         feed, so it serves every device an owner revoked through the feed since the copy that \
         the list does not name until the person has revoked it at this machine, and learns no \
         remote revocation while it reads none; revoke those devices at this machine first. "
    };
}

/// The owner's other ways to end a restored policy's refusals, said once for both remedies.
macro_rules! exclusive_note {
    () => {
        "Ending exclusive organisation management takes an owner device's confirmation, which \
         this wait refuses, or the terminal's when no owner device is left whose grant could \
         confirm, which the wait does not change. A host that is exclusively \
         organisation-managed cannot withdraw its last enrolment until exclusive management has \
         ended, so on such a host end it first where the terminal can, and otherwise confirm \
         first."
    };
}

/// What a person who finds the host refusing remote access for a restored policy does.
const WAITS_REMEDY: &str = concat!(
    "Read what this host holds with `kr organisation list`, and end what you do not want in \
     force with `kr organisation withdraw`, `kr device revoke` and `kr share revoke`, which need \
     no confirmation and work while this stands. Then run `kr host policy --confirm` at this \
     machine. Until then no remote device is served, owner devices included, and the person at \
     this machine is not refused. The policy is the restored one: confirming changes none of it. ",
    feed_note!(),
    exclusive_note!()
);

/// As [`WAITS_REMEDY`], for a record of the restore that cannot be read.
const UNREADABLE_REMEDY: &str = concat!(
    "Read what this host holds with `kr organisation list`, and end what you do not want in \
     force with `kr organisation withdraw`, `kr device revoke` and `kr share revoke`, which need \
     no confirmation and work while this stands. Then run `kr host policy --confirm` at this \
     machine, which removes the record that cannot be read. Until then no remote device is \
     served, owner devices included, and `kr host update` to a release that lists the record's \
     store is refused when the update check cannot read the record either. ",
    feed_note!(),
    exclusive_note!()
);

/// As [`WAITS_REMEDY`], for a list that names every live owner device: revoking them all would leave
/// no way to pair another, so the way that keeps one goes through the record's file.
const OWNER_ROUTE_REMEDY: &str = concat!(
    "The devices and shares this check names are every owner device of this host and what else \
     the authority feed's requests name. Revoke every other one at this machine with `kr device \
     revoke` and `kr share revoke`, which need no confirmation and work while this stands. Do not \
     revoke the last owner device: pairing waits for an owner device's confirmation, which this \
     wait refuses, and the terminal confirms nothing on an owned host. To keep it, stop the \
     daemon; remove the file `restored-policy.cbor` beside the registry database in this host's \
     state directory (the refusal of `kr host policy --confirm` names its full path), after \
     which this host waits for nothing and checks nothing else on its list; start the daemon; \
     pair a new owner device with the kept owner device's confirmation; and revoke the kept owner \
     device if it must go. If a withdrawal this host cannot verify also refuses remote grants, \
     take `authority.origin` out of the configuration document before the daemon starts and set \
     it back after the new owner device is paired. ",
    feed_note!(),
    exclusive_note!()
);

/// How many devices a refusal or the doctor names.
const MOST_NAMED: usize = 8;

/// What a confirmation still waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owing {
    /// No scan of this run has read the feed through and written what it owes.
    AScanThrough,
    /// Devices or grants the requests the feed holds name are live here.
    Targets(OwedNow),
}

/// The targets a restored policy's wait owes that are live now.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OwedNow {
    /// The live targets, sorted.
    named: Vec<Target>,
    /// Whether the list reached its cap or the scan met more than it holds: more may be owed than
    /// `named` says.
    full: bool,
    /// Whether every live owner device of this host is among them (named, or by its pairing
    /// grant), so that revoking what is named would leave no way to pair another owner device.
    every_owner: bool,
}

/// Names a target in a refusal.
fn named(target: &Target) -> String {
    match target {
        Target::Device(device) => format!("device {device}"),
        Target::Grant(grant) => format!("share {grant}"),
    }
}

/// The steps that keep an owner device when the list names every live owner device. `file` is the
/// record of the restore, which the person removes by hand.
fn the_way_that_keeps_an_owner(file: &std::path::Path) -> String {
    format!(
        "these are every owner device of this host, so revoking all of them would leave no way to \
         pair another owner device (pairing waits for an owner device's confirmation, which this \
         wait refuses): revoke every other device and share named above; stop the daemon; remove \
         the record of the restore by hand, the file {}, after which this host waits for \
         nothing and checks nothing else on its list; start the daemon; pair a new owner device \
         with the kept owner device's confirmation; revoke the kept owner device if it must go. If \
         `kr doctor` also says that a withdrawal this host cannot verify refuses remote grants, \
         take `authority.origin` out of the configuration document before the daemon starts, and \
         set it back after the new owner device is paired",
        file.display()
    )
}

/// The words of the refusal of a confirmation while the wait owes something.
fn the_refusal_while_the_wait_is_owed(owing: &Owing, file: &std::path::Path) -> String {
    let cost = "taking `authority.origin` out of the configuration document and starting the \
                daemon again confirms a host that cannot reach its feed once no device or share \
                its list names is live, at this cost: the host then reads no feed, so it serves \
                every device an owner revoked through the feed since the copy that the list does \
                not name until the person has revoked it at this machine with `kr device \
                revoke`, and it learns no remote revocation while it reads none; revoke those \
                devices first";
    match owing {
        Owing::AScanThrough => format!(
            "this host reads an authority feed, and no scan of this run has read it through and \
             carried out what it holds, so a device an owner revoked through the feed since the \
             copy may be live in the registry and would be served once the wait ends; ask again \
             when `kr doctor` no longer says that a confirmation is refused until a scan has, for \
             the host asks its feed again by itself; {cost}"
        ),
        Owing::Targets(owed) => {
            let names = owed
                .named
                .iter()
                .take(MOST_NAMED)
                .map(named)
                .collect::<Vec<_>>()
                .join(", ");
            let more = owed.named.len().saturating_sub(MOST_NAMED);
            let more = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            let mut said = format!(
                "this host owes {names}{more}: requests its authority feed holds name them, this \
                 host has not carried those out or set them aside on what a restore cannot \
                 change, and they are live in the registry, so ending the wait would serve them \
                 again; revoke each at this machine, with `kr device revoke` for a device and \
                 `kr share revoke` for a share, which need no confirmation and work while the \
                 wait stands, and confirm again"
            );
            if owed.full {
                said.push_str(
                    "; the list this host keeps is full, so more may be owed than it names: once \
                     these are revoked it asks its feed again by itself and finds the rest",
                );
            }
            if owed.every_owner {
                said.push_str("; ");
                said.push_str(&the_way_that_keeps_an_owner(file));
            }
            said
        }
    }
}

/// What a write to the list of what a restored policy's wait owes came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwedWrite {
    /// The list stands as the change makes it, written or already so. `full` says that the cap
    /// kept an entry out.
    Kept {
        /// Whether the cap kept an entry out.
        full: bool,
    },
    /// No wait stands: nothing is written, so a scan that ends after a confirmation cannot bring
    /// the wait back at the next start.
    NotWaiting,
    /// The record could not be read at the start and is not written over: what the run owes stays
    /// in memory, where a confirmation reads it.
    NoRecord,
}

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

    /// Changes the list of what the wait owes: adds the targets of `origin`'s requests that `add`
    /// names, takes out those `clear` names, and drops every entry that is no longer live, in one
    /// write through the durable gate. The record's lock is taken here, so a write and a
    /// confirmation wait for each other, and nothing is written once no wait stands.
    ///
    /// # Errors
    ///
    /// Returns the write's error. The list is then as it was and the caller owes the targets from
    /// memory.
    pub async fn keep_what_is_owed(
        &self,
        origin: &str,
        add: &[Target],
        clear: &[Target],
    ) -> Result<OwedWrite> {
        self.keep_the_list(origin, add, clear, || self.target_liveness())
            .await
    }

    /// [`Self::keep_what_is_owed`] with the test of liveness made when the lock is held, so the
    /// registry is read after the wait for the lock and not before it.
    async fn keep_the_list<L: Fn(&Target) -> bool>(
        &self,
        origin: &str,
        add: &[Target],
        clear: &[Target],
        liveness: impl FnOnce() -> L,
    ) -> Result<OwedWrite> {
        let mut kept = self.restored_policy.lock().await;
        if !self.policy().restored_policy_waits() {
            return Ok(OwedWrite::NotWaiting);
        }
        if kept.known().is_none() {
            return Ok(OwedWrite::NoRecord);
        }
        let change = restored::Change {
            origin: restored::origin_digest(origin),
            add,
            clear,
        };
        let full = kept.keep(&change, liveness())?;
        Ok(OwedWrite::Kept { full })
    }

    /// Lowers the most the list of what is owed holds, for a suite that fills it.
    #[cfg(feature = "testing")]
    pub async fn limit_the_owed_list_to(&self, most: usize) {
        self.restored_policy.lock().await.limit_the_list_to(most);
    }

    /// The test of whether a target is live, made from the registry as it stands when this is
    /// called. A device is live while the directory holds it unrevoked; a grant, while an
    /// unrevoked device holds it as its pairing grant or the grant store holds it unrevoked. A
    /// registry that cannot be read shows every target live, and a target the registry does not
    /// hold is not live now.
    pub fn target_liveness(&self) -> impl Fn(&Target) -> bool + '_ {
        let held = self.devices.devices();
        move |target| {
            let Ok(held) = &held else {
                return true;
            };
            match target {
                Target::Device(id) => held
                    .iter()
                    .any(|record| record.device_id == *id && record.revoked_at_ms.is_none()),
                Target::Grant(id) => {
                    held.iter().any(|record| {
                        record.grant.grant_id == *id && record.revoked_at_ms.is_none()
                    }) || match self.sharing.grants().record(*id) {
                        Ok(record) => record.is_some_and(|record| record.revoked_at_ms.is_none()),
                        Err(_) => true,
                    }
                }
            }
        }
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
    /// not yet the one it will hold, and while a host that reads a feed has had no scan in this run
    /// that read it through and carried out, or settled, every record it holds: a registry
    /// restored from an earlier state serves the devices an owner revoked through the feed after
    /// the copy until a scan carries that out again, and a confirmation would end the refusal that
    /// holds them back. It returns the way the admission lapsed when it did, and an error when the
    /// record cannot be removed: the wait stands then.
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
            } else if let Some(owing) = self.what_the_confirmation_waits_for(
                kept.known().map_or(&[], |known| known.owed.as_slice()),
                kept.most(),
            ) {
                return Err(ControllerError::PermissionDenied {
                    detail: the_refusal_while_the_wait_is_owed(&owing, kept.file()),
                });
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

    /// What a confirmation still waits for, given the list the record holds: the devices and
    /// grants the wait owes that are live now, from the record and from what the scan in hand owes
    /// and has not written; else, on a host that reads a feed that has not removed it, a scan of
    /// this run that reads the feed through. None when nothing is owed.
    fn what_the_confirmation_waits_for(&self, held: &[Owed], most: usize) -> Option<Owing> {
        if let Some(owed) = self.what_is_owed_now(held, most) {
            return Some(Owing::Targets(owed));
        }
        let feed = self.feed_runtime()?;
        (!feed.has_read_the_feed_through()).then_some(Owing::AScanThrough)
    }

    /// The targets the wait owes that are live now.
    fn what_is_owed_now(&self, held: &[Owed], most: usize) -> Option<OwedNow> {
        let (in_memory, full_in_memory) = self
            .feed_runtime()
            .map_or((Vec::new(), false), |feed| feed.what_the_scan_owes());
        let live = self.target_liveness();
        let mut targets: Vec<Target> = held
            .iter()
            .map(|entry| entry.target)
            .chain(in_memory)
            .collect();
        targets.sort();
        targets.dedup();
        targets.retain(|target| live(target));
        if targets.is_empty() {
            return None;
        }
        let owners: Vec<(kr_protocol::ids::DeviceId, kr_protocol::ids::GrantId)> = self
            .devices
            .devices()
            .map(|devices| {
                devices
                    .into_iter()
                    .filter(|record| {
                        record.is_paired()
                            && record.revoked_at_ms.is_none()
                            && record
                                .grant
                                .actions
                                .contains(&kr_protocol::rights::ActionRight::HostManage)
                    })
                    .map(|record| (record.device_id, record.grant.grant_id))
                    .collect()
            })
            .unwrap_or_default();
        let every_owner = !owners.is_empty()
            && owners.iter().all(|(device, grant)| {
                targets.contains(&Target::Device(*device))
                    || targets.contains(&Target::Grant(*grant))
            });
        Some(OwedNow {
            named: targets,
            full: full_in_memory || held.len() >= most,
            every_owner,
        })
    }

    /// A feed that removed this host is read no more, so a pass that found the registry behind it
    /// and stopped before the catch-up leaves that refusal up for good. The wait for the policy
    /// found restored refuses the same grants and is ended by the person at this machine, so it
    /// takes the refusal's place. Says whether it did.
    pub(crate) async fn end_a_catch_up_that_a_removed_feed_leaves(&self) -> bool {
        let _kept = self.restored_policy.lock().await;
        if !(self.policy().behind_its_feed() && self.policy().restored_policy_waits()) {
            return false;
        }
        self.move_a_feed_refusal(
            RemoteRefusal::BEHIND_ITS_FEED,
            false,
            crate::grants::HostPolicy::behind_its_feed,
            crate::grants::HostPolicy::set_behind_its_feed,
        )
        .await;
        true
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
        let held: &[Owed] = match &record {
            Found::Record(record) => &record.owed,
            _ => &[],
        };
        let owing = self.what_the_confirmation_waits_for(held, restored::MOST_OWED);
        let every_owner = matches!(&owing, Some(Owing::Targets(owed)) if owed.every_owner);
        detail = match owing {
            None => detail,
            Some(Owing::AScanThrough) => detail.stated(
                "; a confirmation is refused until a scan of this run has read this host's \
                 authority feed through and carried out what it holds, and none has yet",
            ),
            Some(Owing::Targets(owed)) => {
                let detail = owed.named.iter().take(MOST_NAMED).fold(
                    detail.stated(
                        "; a confirmation is refused while a device or share that requests the \
                         authority feed holds name is live here, and this host owes it",
                    ),
                    |detail, target| match target {
                        Target::Device(device) => detail.stated("; device ").identifier(device),
                        Target::Grant(grant) => detail
                            .stated("; share ")
                            .identifier(&kr_protocol::ids::DeviceId::new(grant.get())),
                    },
                );
                let detail = match owed.named.len().saturating_sub(MOST_NAMED) {
                    0 => detail,
                    beyond => detail
                        .stated("; ")
                        .number(beyond as u64)
                        .stated(" more are not listed"),
                };
                let detail = if owed.full {
                    detail.stated("; the list this host keeps is full, so more may be owed")
                } else {
                    detail
                };
                if owed.every_owner {
                    detail
                        .stated(
                            "; these are every owner device of this host, so revoking all of them \
                         would leave no way to pair another: see the steps that keep one, \
                         which end by removing the file of the record of the restore, named ",
                        )
                        .path(&restored::file_beside(&self.paths().registry_database()))
                } else {
                    detail
                }
            }
        };
        Some(DoctorCheck::new(
            "restored-policy",
            "The policy this host holds was not found restored",
            DoctorStatus::Warning,
            detail,
            Some(if unreadable {
                UNREADABLE_REMEDY
            } else if every_owner {
                OWNER_ROUTE_REMEDY
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
        controller.admitted_write().insert(
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
    fn a_device(byte: u8) -> Target {
        Target::Device(kr_protocol::ids::DeviceId::new(
            kr_protocol::scalars::Uuid::from_bytes([byte; 16]),
        ))
    }

    /// A list write, like a finding, takes the record's lock, and writes only while a wait stands:
    /// a scan that ends after the confirmation cannot write a record that would make the next
    /// start wait again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_list_write_after_a_lift_writes_nothing() {
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let file = restored::file_beside(&controller.paths().registry_database());
        assert_eq!(
            controller
                .keep_the_list("feed", &[a_device(1)], &[], || |_: &Target| true)
                .await
                .expect("answered"),
            OwedWrite::NotWaiting,
            "no wait stands, so there is nothing to write into"
        );
        assert_eq!(restored::read(&file), Found::Missing);

        controller
            .find_the_policy_restored()
            .await
            .expect("the finding is written down");
        assert_eq!(
            controller
                .keep_the_list("feed", &[a_device(1)], &[], || |_: &Target| true)
                .await
                .expect("answered"),
            OwedWrite::Kept { full: false }
        );
        let Found::Record(held) = restored::read(&file) else {
            panic!("the record is there");
        };
        assert_eq!(held.owed.len(), 1);

        let (_, carried) = admitted(&controller, None);
        let confirmed: HostPolicyConfirmResult = controller
            .confirm_the_restored_policy(carried)
            .await
            .expect("answered")
            .to_typed()
            .expect("an answer");
        assert!(confirmed.lifted);
        assert_eq!(
            controller
                .keep_the_list("feed", &[a_device(2)], &[], || |_: &Target| true)
                .await
                .expect("answered"),
            OwedWrite::NotWaiting,
            "a scan that ends after the confirmation writes nothing"
        );
        assert_eq!(restored::read(&file), Found::Missing);
    }

    /// A list write and a confirmation take the one lock, so a confirmation that passed its check
    /// does not remove a record a write has just changed, and the other way round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_list_write_and_a_confirmation_wait_for_each_other() {
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        controller
            .find_the_policy_restored()
            .await
            .expect("the finding is written down");
        let held = controller.restored_policy.lock().await;
        let (_, carried) = admitted(&controller, None);
        let mut confirmation = std::pin::pin!(controller.confirm_the_restored_policy(carried));
        let named = [a_device(1)];
        let mut writing =
            std::pin::pin!(controller.keep_the_list("feed", &named, &[], || |_: &Target| true));
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(
            std::future::Future::poll(confirmation.as_mut(), &mut cx).is_pending(),
            "the confirmation waits for the lock"
        );
        assert!(
            std::future::Future::poll(writing.as_mut(), &mut cx).is_pending(),
            "the write waits for the lock"
        );
        drop(held);
        let (confirmed, written) = tokio::join!(confirmation, writing);
        confirmed.expect("the confirmation is answered");
        let written = written.expect("the write is answered");
        let record = restored::read(&restored::file_beside(
            &controller.paths().registry_database(),
        ));
        assert_eq!(
            controller.restored_policy_waits(),
            matches!(record, Found::Record(_)),
            "a wait stands exactly when its record does"
        );
        match (written, record) {
            (OwedWrite::NotWaiting, Found::Missing) => {}
            (OwedWrite::Kept { .. }, Found::Missing) => {}
            (_, other) => panic!("the write and the confirmation left {other:?}"),
        }
    }

    /// A registry that cannot be read shows every target live, so a list is never shortened by a
    /// fault; a target it does not hold is not live.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_registry_that_cannot_be_read_shows_every_target_live() {
        use crate::service::a_floor_owed_its_record::daemon;

        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        assert!(
            !controller.target_liveness()(&a_device(1)),
            "the registry holds no such device"
        );
        rusqlite::Connection::open(controller.paths().registry_database())
            .expect("the registry opens")
            .execute_batch("DROP TABLE network_devices;")
            .expect("the table is gone");
        assert!(
            controller.target_liveness()(&a_device(1)),
            "a read that fails counts the target as live"
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
        controller.admitted_withdraw().remove(&connection);
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
