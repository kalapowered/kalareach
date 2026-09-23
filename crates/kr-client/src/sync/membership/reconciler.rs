//! The reconciler: its rows, one step at a time, one durable write per step.
//!
//! Every operation takes the membership file's lock, reads the facts, decides from them alone
//! (with the host answers they hold and the keys the store holds), asks the service what the row
//! needs, and makes at most one durable write: the file, or one key into the store. So a crash
//! between two operations is a crash between two writes, and a restart resumes where the file
//! says. What is not in the file is what a crash may lose: the send that follows a dispatch mark,
//! and an answer that arrived and was not yet taken.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::scalars::{TimestampMs, Uuid};

use super::environment::{Environment, MarkOf, MemberOf, RecordOf};
use super::facts::{Candidate, Change, Ended, Facts, Kinds, Outcome, Rule, View, weakened};
use super::{
    CollectionRef, KeyRecords, MembershipError, RecordAt, Refreshed, RekeyAnswer, RekeyFence,
    RekeyStatus, Settlement, Step,
};

/// The facts, and the mark of the key the store holds for each epoch it holds one for.
pub(crate) type Held<E> = (Facts<<E as Environment>::Kinds>, BTreeMap<u64, MarkOf<E>>);

/// How a dispatched candidate settles, before the write that records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Settle {
    /// The service applied it at this revision.
    Applied(u64),
    /// The service refused it, naming its own revision.
    Refused(u64),
    /// The service fenced it and says it never ran.
    Fenced,
    /// The fence cannot say it never ran: its receipt has expired.
    Unknown,
}

/// One device's reconciler over one environment.
pub(crate) struct Reconciler<E: Environment> {
    /// What it runs against.
    pub(crate) env: E,
    /// The candidate this process marked dispatched and has not sent yet. A crash loses it, and a
    /// dispatched candidate nobody here is sending is settled by status and fence, never sent.
    pub(crate) sending: Option<Uuid>,
    /// The answer to the one send, when it arrived and was not yet taken.
    pub(crate) inbox: Option<(Uuid, RekeyAnswer)>,
    /// Outcomes a weakened rule keeps where a crash loses them. Always empty otherwise.
    pub(crate) volatile_outcomes: Vec<Outcome<MemberOf<E>>>,
}

impl<E: Environment> Reconciler<E> {
    /// A reconciler with nothing in flight.
    pub(crate) const fn new(env: E) -> Self {
        Self {
            env,
            sending: None,
            inbox: None,
            volatile_outcomes: Vec::new(),
        }
    }

    /// Reads the facts and runs the load check. Facts that no sequence of writes produces are
    /// replaced by this device being out of the collection, with a join awaiting the owner.
    pub(crate) fn load(&self) -> Result<Option<Facts<E::Kinds>>, MembershipError> {
        let Some(mut facts) = self.env.load()? else {
            return Ok(None);
        };
        let me = self.env.me();
        let mut consistent = facts.check(&me).is_ok();
        if consistent && facts.head > 0 {
            // Check 2 again over the window: a file that was changed behind this device's back
            // does not become a chain it accepts.
            let links = facts.records.windows(2);
            consistent = links.into_iter().all(|pair| match pair {
                [previous, next] => self.env.follows(previous, next),
                _ => true,
            });
        }
        if !consistent {
            facts = facts.refused();
            self.write(&facts)?;
        }
        Ok(Some(facts))
    }

    /// Replaces the file. A weakened rule keeps new outcomes where a crash loses them instead.
    fn write(&self, facts: &Facts<E::Kinds>) -> Result<(), MembershipError> {
        self.env.replace(facts)
    }

    /// Writes the facts after a transition that may have ended changes.
    fn commit(
        &mut self,
        before: usize,
        mut facts: Facts<E::Kinds>,
    ) -> Result<Facts<E::Kinds>, MembershipError> {
        if weakened(Rule::VolatileReports) && facts.outcomes.len() > before {
            self.volatile_outcomes
                .extend(facts.outcomes.drain(before..));
        }
        self.write(&facts)?;
        Ok(facts)
    }

    /// The marks of the keys the store holds, by epoch, for every epoch this device opened a
    /// record of since its join.
    fn held(&self, facts: &Facts<E::Kinds>) -> Result<BTreeMap<u64, MarkOf<E>>, MembershipError> {
        let mut held = BTreeMap::new();
        for epoch in facts.epochs() {
            if let Some(key) = self.env.held_key(&facts.collection, epoch)? {
                held.insert(epoch, self.env.mark(&key));
            }
        }
        Ok(held)
    }

    /// The first record's facts: this device starts a collection, and its own first record is
    /// its first candidate.
    pub(crate) fn start(
        &mut self,
        collection: CollectionRef,
        now: TimestampMs,
    ) -> Result<(), MembershipError> {
        let _guard = self.env.lock()?;
        if let Some(facts) = self.load()?
            && !facts.out
        {
            return Err(MembershipError::AlreadyMember);
        }
        let me = self.env.me();
        let key = self.env.draw_key(0, 0, &[me])?;
        let record = self.env.issue(&collection, None, 0, &[me], &key, now)?;
        let request = self.env.fresh_request()?;
        let facts = Facts::genesis(collection, record, request, Default::default());
        self.sending = None;
        self.inbox = None;
        self.write(&facts)
    }

    /// One step: the first row that applies.
    pub(crate) async fn step(&mut self, now: TimestampMs) -> Result<Step, MembershipError> {
        let _guard = self.env.lock()?;
        let Some(facts) = self.load()? else {
            return Ok(Step::Nothing);
        };
        let held = self.held(&facts)?;
        if facts.out {
            // The collection's keys go after the write that recorded leaving, never before it.
            if held.is_empty() {
                return Ok(Step::Nothing);
            }
            for epoch in held.keys() {
                self.env.forget_key(&facts.collection, *epoch)?;
            }
            return Ok(Step::ForgotKeys);
        }
        // Row 1, and the send that follows a dispatch mark.
        if let Some(candidate) = &facts.candidate
            && let Some(signed_at) = candidate.dispatched
        {
            if self.sending == Some(candidate.request) {
                return self.send(&facts, signed_at).await;
            }
            return self.settle(facts, signed_at).await;
        }
        self.sending = None;
        let me = self.env.me();
        let view = View {
            facts: &facts,
            me,
            held: &held,
        };
        // Row 2.
        if view.left_out() {
            let before = facts.outcomes.len();
            let mut next = facts.clone();
            next.leave();
            self.inbox = None;
            self.commit(before, next)?;
            return Ok(Step::Left);
        }
        // Row 4.
        if let Some(record) = view.newest_accepted() {
            let epoch = <E::Kinds as Kinds>::epoch(record);
            let revision = <E::Kinds as Kinds>::revision(record);
            if !held.contains_key(&epoch) {
                let key = self.env.open_key(record)?;
                self.env.store_key(&facts.collection, epoch, &key)?;
                return Ok(Step::Stored { epoch });
            }
            let mut next = facts.clone();
            next.install(revision);
            self.write(&next)?;
            return Ok(Step::Installed { revision });
        }
        if facts.installed == 0 && facts.join > 1 {
            // A joining device that accepts no record from its join record on is out again, as
            // row 2 leaves: whatever the host answers asked of it meanwhile ends as refused.
            let before = facts.outcomes.len();
            let mut next = facts.clone();
            next.leave();
            next.outcomes.push(Outcome::Join {
                ended: Ended::Refused,
            });
            self.commit(before, next)?;
            return Ok(Step::JoinRefused);
        }
        // Row 5.
        if facts.candidate.is_none()
            && facts.installed != 0
            && (facts.installed == facts.head || weakened(Rule::DoneByBothRecords))
        {
            let done = view.done();
            if !done.is_empty() {
                let before = facts.outcomes.len();
                let mut next = facts.clone();
                for change in done {
                    next.end(change, Ended::Done);
                }
                self.commit(before, next)?;
                return Ok(Step::Done);
            }
        }
        // Rows 6 and 7.
        if let Some(candidate) = &facts.candidate {
            let mut next = facts.clone();
            if view.still_wanted(candidate) {
                let request = candidate.request;
                if let Some(standing) = &mut next.candidate {
                    standing.dispatched = Some(now);
                }
                self.write(&next)?;
                self.sending = Some(request);
                return Ok(Step::Dispatched);
            }
            next.candidate = None;
            self.write(&next)?;
            return Ok(Step::Dropped);
        }
        // Row 8.
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        if let Some(addition) = next.addition
            && !(addition == me || <E::Kinds as Kinds>::passes(&next.answers, &addition))
        {
            next.end(Change::Addition(addition), Ended::Refused);
        }
        let built = {
            let view = View {
                facts: &next,
                me,
                held: &held,
            };
            if view.needs_candidate() {
                Some(self.build(&view, now)?)
            } else {
                None
            }
        };
        let is_built = built.is_some();
        if let Some(candidate) = built {
            next.candidate = Some(candidate);
        }
        if next != facts {
            self.commit(before, next)?;
            return Ok(Step::Built { built: is_built });
        }
        // Row 5's wait: a change the installed head carries out waits only for a fetch.
        if !facts.unfetched.is_empty() {
            return Ok(Step::FetchNeeded);
        }
        Ok(Step::Nothing)
    }

    /// Row 8's candidate: on the head, from the installed record's members.
    fn build(
        &self,
        view: &View<'_, E::Kinds>,
        now: TimestampMs,
    ) -> Result<Candidate<RecordOf<E>>, MembershipError> {
        let desired = view.desired();
        let members: Vec<MemberOf<E>> = desired.members.iter().copied().collect();
        let key = if desired.same_epoch {
            self.env
                .held_key(&view.facts.collection, desired.epoch)?
                .ok_or(MembershipError::KeyMissing {
                    epoch: desired.epoch,
                })?
        } else {
            self.env.draw_key(desired.epoch, desired.base, &members)?
        };
        let base = view.facts.record(desired.base);
        let record = self.env.issue(
            &view.facts.collection,
            base,
            desired.epoch,
            &members,
            &key,
            now,
        )?;
        Ok(Candidate {
            record,
            request: self.env.fresh_request()?,
            dispatched: None,
        })
    }

    /// The one send of a dispatched candidate, by the process that marked it.
    async fn send(
        &mut self,
        facts: &Facts<E::Kinds>,
        signed_at: TimestampMs,
    ) -> Result<Step, MembershipError> {
        self.sending = None;
        let Some(candidate) = &facts.candidate else {
            return Ok(Step::Nothing);
        };
        match self
            .env
            .rekey(
                &facts.collection,
                candidate.request,
                signed_at,
                &candidate.record,
            )
            .await
        {
            Ok(answer) => {
                self.inbox = Some((candidate.request, answer));
                Ok(Step::Sent { answered: true })
            }
            // An answer that did not arrive is settled by row 1, never by a second send.
            Err(_) => Ok(Step::Sent { answered: false }),
        }
    }

    /// Row 1: a dispatched candidate is settled by its answer, or by status and then fence, or,
    /// when the fence cannot say it never ran, by the record after its base.
    async fn settle(
        &mut self,
        facts: Facts<E::Kinds>,
        signed_at: TimestampMs,
    ) -> Result<Step, MembershipError> {
        let Some(candidate) = facts.candidate.clone() else {
            return Ok(Step::Nothing);
        };
        let request = candidate.request;
        let answer = match self.inbox.take() {
            Some((id, answer)) if id == request => Some(answer),
            _ => None,
        };
        let settle = if let Some(answer) = answer {
            match answer {
                RekeyAnswer::Applied { revision } => Settle::Applied(revision),
                RekeyAnswer::Refused { revision } => Settle::Refused(revision),
            }
        } else {
            if weakened(Rule::ResendAfterRestart) {
                return self.send(&facts, signed_at).await;
            }
            match self.env.rekey_status(&facts.collection, request).await? {
                RekeyStatus::Applied { revision } => Settle::Applied(revision),
                RekeyStatus::Refused { revision } => Settle::Refused(revision),
                RekeyStatus::Fenced { never_ran: true } => Settle::Fenced,
                RekeyStatus::Fenced { never_ran: false } => Settle::Unknown,
                RekeyStatus::Unknown => {
                    match self
                        .env
                        .rekey_fence(&facts.collection, request, signed_at, signed_at)
                        .await?
                    {
                        RekeyFence::Applied { revision } => Settle::Applied(revision),
                        RekeyFence::Refused { revision } => Settle::Refused(revision),
                        RekeyFence::Fenced { never_ran: true } => Settle::Fenced,
                        RekeyFence::Fenced { never_ran: false } => Settle::Unknown,
                    }
                }
            }
        };
        let me = self.env.me();
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        next.candidate = None;
        let settlement = match settle {
            Settle::Applied(revision) => {
                if !weakened(Rule::SettleKeepsHead) {
                    self.take_applied(&mut next, &candidate.record, revision)?;
                    next.record_answers(&me, false);
                }
                Settlement::Applied { revision }
            }
            Settle::Refused(revision) => Settlement::Refused { revision },
            Settle::Fenced => Settlement::Fenced,
            Settle::Unknown => {
                // Records are kept for the collection's life, so the record after the base is
                // final: the candidate's, when it applied, or the one that took its place, which
                // the fence now stops it from ever replacing.
                let base = <E::Kinds as Kinds>::revision(&candidate.record) - 1;
                let read = match self.env.record_at(&facts.collection, base + 1).await? {
                    RecordAt::Record(record) => Some(record),
                    // A first record that never applied leaves no collection behind it.
                    RecordAt::Missing | RecordAt::Absent if base == 0 => None,
                    RecordAt::Missing => None,
                    RecordAt::Absent => {
                        next.leave();
                        self.commit(before, next)?;
                        return Ok(Step::Left);
                    }
                };
                let revision = read.as_ref().map(<E::Kinds as Kinds>::revision);
                if let Some(record) = read {
                    if <E::Kinds as Kinds>::revision(&record) != base + 1 {
                        return Err(MembershipError::BrokenChain);
                    }
                    if !weakened(Rule::ReadNotRecorded) {
                        if base + 1 > next.head {
                            if !self.links(&next, &record) {
                                next.leave();
                                self.commit(before, next)?;
                                return Ok(Step::Left);
                            }
                            let mark = self.env.mark_of(&record);
                            next.push(record, mark);
                        }
                        if !weakened(Rule::ReadSkipsAnswers) {
                            next.record_answers(&me, false);
                        }
                    }
                }
                Settlement::ReadAfterBase { revision }
            }
        };
        self.commit(before, next)?;
        Ok(Step::Settled(settlement))
    }

    /// An applied candidate: the head becomes the later of its record and the head held.
    fn take_applied(
        &self,
        facts: &mut Facts<E::Kinds>,
        record: &RecordOf<E>,
        revision: u64,
    ) -> Result<(), MembershipError> {
        if weakened(Rule::SettleWithoutMax) && revision < facts.head {
            facts.truncate(revision);
            return Ok(());
        }
        if revision <= facts.head {
            return Ok(());
        }
        if revision != facts.head + 1 || <E::Kinds as Kinds>::revision(record) != revision {
            return Err(MembershipError::BrokenChain);
        }
        let mark = self.env.mark_of(record);
        facts.push(record.clone(), mark);
        Ok(())
    }

    /// Check 2 for a record that would become the head.
    fn links(&self, facts: &Facts<E::Kinds>, record: &RecordOf<E>) -> bool {
        match facts.head_record() {
            Some(head) => self.env.follows(head, record),
            None => self.env.first(&facts.collection, record),
        }
    }

    /// A refresh: the host answers and the records after the head, recorded in one write with
    /// the removals the answers require. A refresh no host answers writes nothing.
    pub(crate) async fn refresh(&mut self) -> Result<Refreshed, MembershipError> {
        let _guard = self.env.lock()?;
        let Some(facts) = self.load()? else {
            return Ok(Refreshed::NoMembership);
        };
        if facts.out {
            return Ok(Refreshed::Out);
        }
        let Some(fresh) = self.env.answers().await? else {
            return Ok(Refreshed::NoHostAnswered);
        };
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        match self
            .env
            .records_after(&facts.collection, facts.head)
            .await?
        {
            // Before its first record applies, a collection this device starts does not exist
            // at the service yet, which is no answer about this device's membership.
            KeyRecords::Absent if facts.head == 0 => {}
            KeyRecords::Absent => {
                next.leave();
                self.commit(before, next)?;
                return Ok(Refreshed::Left);
            }
            KeyRecords::Records(records) => {
                for record in records {
                    let expected = next.head + 1;
                    if <E::Kinds as Kinds>::revision(&record) != expected
                        || !self.links(&next, &record)
                    {
                        // An answer, not a failed fetch: a chain this device cannot follow from
                        // the revision it holds. It accepts nothing and waits for a rejoin.
                        let mut left = facts.clone();
                        left.leave();
                        self.commit(before, left)?;
                        return Ok(Refreshed::BrokenChain);
                    }
                    let mark = self.env.mark_of(&record);
                    next.push(record, mark);
                }
            }
        }
        next.answers = <E::Kinds as Kinds>::refreshed(&next.answers, fresh);
        next.unfetched.clear();
        next.record_answers(&self.env.me(), true);
        if next != facts {
            self.commit(before, next)?;
        }
        Ok(Refreshed::Recorded)
    }

    /// The owner removes a device on this member's screen. A member never removes itself.
    pub(crate) fn remove(&mut self, member: MemberOf<E>) -> Result<(), MembershipError> {
        let _guard = self.env.lock()?;
        let facts = self.member_facts()?;
        if member == self.env.me() {
            return Err(MembershipError::CannotRemoveSelf);
        }
        if facts.removals.contains(&member) {
            return Ok(());
        }
        let listed = facts
            .installed_record()
            .is_some_and(|record| <E::Kinds as Kinds>::lists(record, &member))
            || facts
                .head_record()
                .is_some_and(|record| <E::Kinds as Kinds>::lists(record, &member))
            || facts.addition == Some(member);
        if !listed {
            return Err(MembershipError::NotAMember);
        }
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        if next.addition == Some(member) {
            next.end(Change::Addition(member), Ended::Cancelled);
        }
        next.begin(Change::Removal(member), false);
        self.commit(before, next)?;
        Ok(())
    }

    /// The owner confirmed an addition. An addition of a device whose removal is pending, or
    /// beside another pending addition, is refused and reported (I3).
    pub(crate) fn add(&mut self, member: MemberOf<E>) -> Result<Ended, MembershipError> {
        let _guard = self.env.lock()?;
        let facts = self.member_facts()?;
        if facts
            .installed_record()
            .is_some_and(|record| <E::Kinds as Kinds>::lists(record, &member))
        {
            return Err(MembershipError::AlreadyListed);
        }
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        if next.removals.contains(&member) || next.addition.is_some() {
            next.outcomes.push(Outcome::Addition {
                device: member,
                ended: Ended::Refused,
            });
            self.commit(before, next)?;
            return Ok(Ended::Refused);
        }
        next.begin(Change::Addition(member), false);
        self.commit(before, next)?;
        Ok(Ended::Done)
    }

    /// A revocation this device verified from an authority feed, recorded when it arrives with
    /// the removals it requires, without waiting for a host.
    pub(crate) fn feed_revocation(
        &mut self,
        revocation: <E::Kinds as Kinds>::Revocation,
    ) -> Result<(), MembershipError> {
        let _guard = self.env.lock()?;
        let facts = self.load()?.ok_or(MembershipError::NoMembership)?;
        if weakened(Rule::FeedWaitsForRefresh) {
            return Ok(());
        }
        let before = facts.outcomes.len();
        let mut next = facts.clone();
        <E::Kinds as Kinds>::revoke(&mut next.answers, revocation);
        if !next.out {
            next.record_answers(&self.env.me(), false);
        }
        if next != facts {
            self.commit(before, next)?;
        }
        Ok(())
    }

    /// The owner confirmed a join on this device: the newest record that lists it becomes the
    /// join record, checked as a new member, and the host answers are recorded with the removals
    /// they require before anything is installed.
    pub(crate) async fn join(&mut self, collection: CollectionRef) -> Result<(), MembershipError> {
        let _guard = self.env.lock()?;
        let previous = self.load()?;
        if let Some(facts) = &previous {
            if !facts.out {
                return Err(MembershipError::AlreadyMember);
            }
            // The keys of the membership that ended go before the one that starts.
            for epoch in self.held(facts)?.keys() {
                self.env.forget_key(&facts.collection, *epoch)?;
            }
        }
        let fresh = self
            .env
            .answers()
            .await?
            .ok_or(MembershipError::NoHostAnswered)?;
        let KeyRecords::Records(chain) = self.env.records_after(&collection, 0).await? else {
            return Err(MembershipError::NotListed);
        };
        let Some(first) = chain.first() else {
            return Err(MembershipError::NotListed);
        };
        if <E::Kinds as Kinds>::revision(first) != 1 || !self.env.first(&collection, first) {
            return Err(MembershipError::BrokenChain);
        }
        for pair in chain.windows(2) {
            if let [before, after] = pair
                && (<E::Kinds as Kinds>::revision(after)
                    != <E::Kinds as Kinds>::revision(before) + 1
                    || !self.env.follows(before, after))
            {
                return Err(MembershipError::BrokenChain);
            }
        }
        let me = self.env.me();
        let newest = chain.last().ok_or(MembershipError::NotListed)?;
        if !<E::Kinds as Kinds>::lists(newest, &me) {
            return Err(MembershipError::NotListed);
        }
        let epoch = <E::Kinds as Kinds>::epoch(newest);
        let opener = chain
            .iter()
            .find(|record| <E::Kinds as Kinds>::epoch(record) == epoch)
            .and_then(<E::Kinds as Kinds>::issuer)
            .ok_or(MembershipError::BrokenChain)?;
        let revision = <E::Kinds as Kinds>::revision(newest);
        let outcomes = previous
            .as_ref()
            .map(|facts| facts.outcomes.clone())
            .unwrap_or_default();
        let answers = previous
            .as_ref()
            .map(|facts| <E::Kinds as Kinds>::refreshed(&facts.answers, fresh.clone()))
            .unwrap_or(fresh);
        let mut facts = Facts {
            format: super::facts::MembershipFormat::V1,
            collection,
            join: revision,
            installed: 0,
            head: revision,
            records: vec![newest.clone()],
            openers: vec![super::facts::Opener {
                epoch,
                issuer: opener,
            }],
            opened: BTreeSet::new(),
            answers,
            removals: BTreeSet::new(),
            addition: None,
            candidate: None,
            out: false,
            outcomes,
            unfetched: BTreeSet::new(),
        };
        if let Some(mark) = self.env.mark_of(newest) {
            facts.opened.insert(super::facts::Opened {
                revision,
                epoch,
                mark,
            });
        }
        let before = facts.outcomes.len();
        if !weakened(Rule::JoinSkipsAnswers) {
            facts.record_answers(&me, true);
        }
        self.sending = None;
        self.inbox = None;
        self.commit(before, facts)?;
        Ok(())
    }

    /// The screen showed the first `shown` outcomes, which may now be cleared.
    pub(crate) fn acknowledge(&mut self, shown: usize) -> Result<(), MembershipError> {
        let _guard = self.env.lock()?;
        let facts = self.load()?.ok_or(MembershipError::NoMembership)?;
        let mut next = facts.clone();
        next.outcomes.drain(..shown.min(next.outcomes.len()));
        if next != facts {
            self.write(&next)?;
        }
        Ok(())
    }

    /// The facts, with the keys the store holds, for a caller that only reads.
    pub(crate) fn read(&self) -> Result<Option<Held<E>>, MembershipError> {
        let _guard = self.env.lock()?;
        let Some(facts) = self.load()? else {
            return Ok(None);
        };
        let held = self.held(&facts)?;
        Ok(Some((facts, held)))
    }

    /// The facts of a member with an installed record, or why there are none.
    fn member_facts(&self) -> Result<Facts<E::Kinds>, MembershipError> {
        let facts = self.load()?.ok_or(MembershipError::NoMembership)?;
        if facts.out {
            return Err(MembershipError::Out);
        }
        if facts.installed == 0 {
            return Err(MembershipError::NotInstalled);
        }
        Ok(facts)
    }
}
