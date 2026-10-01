//! Putting the configuration document into force, and what is in force.

use std::sync::Arc;

use kr_protocol::action::RevocationBarrier;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};

use crate::error::{ControllerError, Result};

use super::Controller;
use super::barrier::Reach;
use super::capabilities::DESKTOP_REREAD_INTERVAL;

impl Controller {
    /// The session number admission enforces now, which a new workflow chain's created-session
    /// ceiling does not exceed.
    pub(crate) fn sessions_in_force(&self) -> u64 {
        self.sessions_in_force
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Reads this environment's configuration.
    ///
    /// One reader, so the value a check reports and the value the host acts on cannot be two
    /// different readings of the same document.
    #[must_use]
    pub fn configuration(&self) -> kr_worker::config::Resolver {
        crate::config::open(&self.paths)
    }

    /// The ordinary preferences the last acceptance put in force.
    pub(super) fn in_force(&self) -> crate::config::InForce {
        self.in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns what this host's configuration currently resolves to.
    ///
    /// The document is put into force first and the report is built from that same reading, so a
    /// value a person is shown is the value this host is acting on rather than a second reading of
    /// a file that may since have moved. A document edited outside this daemon therefore takes
    /// effect - ceiling, fence and capability invalidation alike - the next time anything asks
    /// this question, rather than at the next restart.
    pub async fn effective_configuration(&self) -> kr_protocol::hostinfo::EffectiveConfiguration {
        let accepted = self.accept_configuration().await;
        self.report_configuration(&accepted).await
    }

    /// Builds the effective-value report from one accepted configuration.
    pub(super) async fn report_configuration(
        &self,
        accepted: &crate::config::Accepted,
    ) -> kr_protocol::hostinfo::EffectiveConfiguration {
        crate::config::effective(
            accepted,
            self.hard_limits(),
            crate::desktop::default_profile(&self.desktop().await.0),
        )
    }

    /// Puts the configuration document on disk into force, and returns what is in force.
    ///
    /// The one ordered path, and the whole of the ordering is this lock: it is taken *before* the
    /// document is read, so an edit applying its own effects and a reader accepting what it found
    /// cannot interleave, and whichever of them runs last is the one that read the document that
    /// is actually on disk. The effects are derived from what moved since the last acceptance
    /// rather than from the request that caused it, which is what makes a document edited in a
    /// text editor owe exactly what the same edit made through this daemon owes; and they are
    /// applied on every acceptance rather than only when the revision number moved, because a
    /// document edited by hand can change what it says without changing what it calls itself.
    ///
    /// Nothing here returns an error. A failure is what the returned value carries, because the
    /// report is built from it and a report that quietly dropped the failure would describe a
    /// document this host is not acting on.
    pub(super) async fn accept_configuration(&self) -> crate::config::Accepted {
        let mut state = self.accepted_configuration.lock().await;
        let resolver = self.configuration();
        let mut owed = kr_protocol::hostinfo::configuration::owed(
            state.document.as_ref(),
            resolver.loaded().document.as_ref(),
        );
        // The ordinary preferences take effect by being read, so this reading is what the things
        // that act on them read until the next acceptance replaces it. It is written whatever the
        // effects below do: a sleep policy is in force because the document says it, not because
        // a registry write succeeded.
        *self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            crate::config::InForce::of(&resolver);
        // The owner's settings for descriptions apply at once, with no fence to raise: the host
        // takes them at its next turn, and a reading that changed nothing changes nothing there.
        if let Some(host) = self.descriptions.host() {
            let settings = self.description_settings();
            host.settings(Some(settings.enabled), Some(settings.on_battery));
        }
        // The enrolment budgets the catalogue acts on, by the session number's rule: this reading
        // decides them when it loaded a document, and leaves them as they are when it did not.
        let mut budget_failure = None;
        let budgets = match crate::config::catalogue::budgets_in_force(&resolver) {
            Some(budgets) => match self.catalogue.put_budgets_in_force(budgets).await {
                // Package limits that moved raised the admission revision with them, in one step:
                // every worker is sent a round.
                Ok(moved) => {
                    if moved {
                        self.admissions_due();
                    }
                    crate::config::EnforcedBudgets {
                        value: budgets,
                        from_document: true,
                    }
                }
                // Budgets whose package limits moved do not move when the revision cannot be
                // raised for them: the acceptance reports that, and the next one tries again,
                // since the budgets in force still differ from this document's.
                Err(error) => {
                    budget_failure = Some(
                        Sentence::new()
                            .stated(
                                "the enrolment budgets did not change, because the admission \
                                 revision their package limits move could not be written: ",
                            )
                            .withheld(ContentClass::Message, &error.message),
                    );
                    crate::config::EnforcedBudgets {
                        value: self.catalogue.budgets_in_force(),
                        from_document: false,
                    }
                }
            },
            None => crate::config::EnforcedBudgets {
                value: self.catalogue.budgets_in_force(),
                from_document: false,
            },
        };
        // The disable policy the catalogue enforces, by the budgets' rule: this reading decides it
        // when it loaded a document, whether the document names one or leaves the default, and
        // leaves it as it is when it did not. It is recorded with the admission revision it moves,
        // so a change sends every worker a round; one that cannot be recorded changes nothing.
        let mut policy_failure = None;
        let disable_policy = match crate::config::catalogue::disable_policy_in_force(&resolver) {
            Some(policy) => match self.catalogue.put_disable_policy_in_force(policy).await {
                Ok(moved) => {
                    if moved {
                        self.admissions_due();
                    }
                    crate::config::EnforcedDisablePolicy {
                        value: Some(policy),
                        from_document: true,
                    }
                }
                Err(error) => {
                    policy_failure = Some(
                        Sentence::new()
                            .stated(
                                "the disable policy did not change, because it could not be \
                                 recorded with the admission revision it moves: ",
                            )
                            .withheld(ContentClass::Message, &error.message),
                    );
                    crate::config::EnforcedDisablePolicy {
                        value: self.held_disable_policy(&mut policy_failure).await,
                        from_document: false,
                    }
                }
            },
            None => crate::config::EnforcedDisablePolicy {
                value: self.held_disable_policy(&mut policy_failure).await,
                from_document: false,
            },
        };
        // The rights ceiling a paired device's request is decided against, from this reading when
        // it produced a document and as it was when it did not. Before the fence below, so a
        // narrower ceiling decides every request from here on while the work admitted under the
        // wider one is fenced; a reading that decided nothing lifts nothing.
        //
        // A ceiling that moves is a restrictive change: its debt is written before the ceiling
        // moves, and published once it has. A ceiling whose debt cannot be written does not move:
        // the acceptance reports that, and is attempted again by the next one, since the record of
        // what this environment accepted advances only once every effect landed.
        let mut ceiling_debt = None;
        let mut ceiling_failure = None;
        let (rights, ceiling_moved, ceiling_barrier) = {
            let mut held = self
                .rights_ceiling
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let decided = resolver.loaded().document.as_ref();
            let mut moved = false;
            if let Some(document) = decided {
                let configured = crate::config::ceilings::configured_rights(&document.ceilings);
                moved = *held != configured;
                if moved {
                    match self.owe_debt("a change of the rights ceiling", Reach::Host) {
                        Ok(debt) => {
                            ceiling_debt = Some(debt);
                            *held = configured;
                            self.advance_authority_epoch();
                        }
                        Err(error) => {
                            moved = false;
                            ceiling_failure = Some(
                                Sentence::new()
                                    .stated(
                                        "the rights ceiling did not change, because the fence its \
                                         change owes could not be written down: ",
                                    )
                                    .withheld(ContentClass::Message, &error.to_string()),
                            );
                        }
                    }
                }
            }
            // Covered by the barrier below, which this acceptance raises once the ceiling has
            // moved, whatever else it does first.
            let own = ceiling_debt.map(|debt| self.publish_debts(&[(debt, Reach::Host)]));
            (
                crate::config::EnforcedRights {
                    ceiling: held.clone(),
                    // A ceiling kept because its change could not be written down is not the one
                    // this document names.
                    from_document: decided.is_some() && ceiling_failure.is_none(),
                },
                moved,
                own,
            )
        };
        // The fence answers for the ceiling in force as well as for the document last accepted.
        // The two part when an acceptance put its ceiling in force and an effect after it failed:
        // the document stays the one before, while devices are served under the new ceiling. A
        // later document that matches the old one then moves nothing against it, and it still
        // withdraws what the ceiling in force allowed, so the work admitted under that ceiling is
        // fenced like any other.
        //
        // And a fence an earlier reading owed and could not raise is owed until one is raised.
        // Nothing else settles it: once the ceiling it answered for is in force, no reading moves
        // anything, and a reading that let the debt go would leave the work admitted under the
        // withdrawn ceiling admitted.
        // A fence this acceptance owes for its own change: its ceiling moved, or the document it
        // reads withdrew something the ceiling in force already matched. A ceiling that could not
        // move withdrew nothing, so it owes none. A debt an earlier barrier left published is
        // raised too, and its own debt is never created for it: if another barrier captures that
        // debt first, this one captures nothing and reports the barrier as it stands.
        let owes_own = (owed.fences_dispatch || ceiling_moved) && ceiling_failure.is_none();
        let owed_elsewhere = !self.debts().published.is_empty();
        owed.fences_dispatch = owes_own || owed_elsewhere;
        let fence_now = owed.fences_dispatch;
        let (sessions, mut failure) = self.apply_session_limit(&resolver, &state).await;
        for problem in [ceiling_failure, budget_failure, policy_failure]
            .into_iter()
            .flatten()
        {
            failure = Some(match failure {
                Some(earlier) => earlier.stated("; ").sentence(&problem),
                None => problem,
            });
        }
        if sessions.from_document {
            // Recorded the moment the registry took it, separately from everything below. A later
            // effect that fails does not put this number back, and a state that said it had would
            // make the next report describe a ceiling admission is no longer enforcing.
            state.sessions = sessions.value;
            self.sessions_in_force
                .store(sessions.value, std::sync::atomic::Ordering::SeqCst);
        }
        // The durable fact, read before anything acts on it. The flag this process used to keep
        // decided nothing that survived it.
        let (owed_before, mut unreadable) = self.fence_owed().await;
        let mut barrier = None;
        if fence_now {
            // Attempted whatever else failed, because the values above are already in force: the
            // narrower ceiling decides every request from here on, and the work admitted under the
            // one it replaced is dispatchable until the revision advances. An effect that failed
            // earlier is a reason to fence rather than a reason to skip it.
            //
            // Before anything is told the ceiling moved. Work admitted under the ceiling this
            // document withdrew has to stop being dispatchable first, whoever wrote the document.
            // The revision advance writes the worker debt with it, so the fence is recorded as
            // owed before the announcement travels and before any effect below runs. A fence owed
            // with no debt of this acceptance's own, for a document whose ceiling the one in force
            // already matched, is raised under a debt held in memory.
            let own = match ceiling_barrier {
                Some(own) => own,
                None if owes_own => {
                    self.publish_debts(&[(crate::grants::store::DebtId::fresh(), Reach::Host)])
                }
                None => self.publish_debts(&[]),
            };
            match self.barrier(own).await {
                Ok(raised) => {
                    barrier = Some(raised);
                }
                Err(error) => {
                    // The debt stays published, so every admission and forward is refused before
                    // the report is read: work admitted under the ceiling this document withdrew is
                    // still dispatchable until the revision advances, and the revision is exactly
                    // what did not advance. It is left to the debt pass, which is woken for it.
                    let fenced = Sentence::new()
                        .stated("dispatch could not be fenced: ")
                        .withheld(ContentClass::Message, &error.to_string());
                    // Beside whatever failed before it rather than instead of it. Both are
                    // effects this document owed, and a report that named one of them would send
                    // a person to fix half of what is wrong.
                    failure = Some(match failure {
                        Some(earlier) => earlier.stated("; ").sentence(&fenced),
                        None => fenced,
                    });
                }
            }
        }
        if failure.is_none() && !owed.fences_dispatch && owed_before.is_some() {
            // A fence this environment raised earlier that a worker had not acknowledged. The debt
            // is this host's, not the document's: the document has not moved since, so nothing
            // above would raise it again, and a change asked for a second time would otherwise be
            // told it was done. Announcing again is how a worker that has since answered, or since
            // ended, settles it, and it advances no revision.
            match self.announce_authority_revision().await {
                Ok(reported) => barrier = Some(reported),
                Err(error) => {
                    failure = Some(
                        Sentence::new()
                            .stated("the outstanding fence could not be checked: ")
                            .withheld(ContentClass::Message, &error.to_string()),
                    );
                }
            }
        }
        if failure.is_none()
            && owed
                .invalidated
                .contains(&kr_protocol::desktop::CapabilityInvalidation::WorkerProfile)
            && let Err(error) = self.invalidate_profile_evidence(&resolver).await
        {
            failure = Some(
                Sentence::new()
                    .stated(
                        "the capability evidence taken under the old profile could not be \
                         replaced: ",
                    )
                    .withheld(ContentClass::Message, &error.to_string()),
            );
        }
        let effects_applied = failure.is_none();
        // A reading that produced no document decided nothing, so there is nothing to record. An
        // absent or unusable file leaves what was in force in force, which is the rule `owed`
        // follows on the way in; replacing the accepted document with nothing would break it on
        // the way out, because the next usable document would then be compared against empty
        // defaults and a ceiling removed while the file could not be read would be lifted without
        // a fence.
        let decided = resolver.loaded().document.is_some();
        if effects_applied && decided {
            // Recorded once every effect has landed, so a failed acceptance is retried by the
            // next one instead of being remembered as done. What this records is which document
            // was accepted; the fence debt is not here, because a value this process holds cannot
            // outlive it and only a worker answering settles one.
            state.revision = resolver.revision();
            state.document = resolver.loaded().document.clone();
            // And durably, because the next daemon has to be able to tell a document this host
            // acted on from one it never reached. It is the same record in the registry row that
            // holds the fence debt, written in the opposite order: the debt before the effects,
            // because it says what is still owed, and this after them, because it says what is
            // done.
            let accepted = crate::registry::AcceptedConfiguration {
                revision: state.revision,
                document: crate::config::recorded(state.document.as_ref()),
            };
            if let Err(error) = self
                .registry
                .lock()
                .await
                .record_accepted_configuration(&accepted)
            {
                failure = Some(
                    Sentence::new()
                        .stated(
                            "this host applied the document and could not record that it had, so \
                             it will apply it again when it next starts: ",
                        )
                        .withheld(ContentClass::Message, &error.to_string()),
                );
            }
        }
        drop(state);
        // Read back after the effects rather than derived from them. A fence raised above is owed
        // whatever happened afterwards, and one raised by an earlier daemon is owed although
        // nothing in this process raised it.
        let (fence_owed, unreadable_now) = self.fence_owed().await;
        unreadable = unreadable.or(unreadable_now);
        if failure.is_none() {
            failure = unreadable;
        }
        crate::config::Accepted {
            resolver,
            sessions,
            budgets,
            disable_policy,
            owed,
            barrier,
            fence_owed,
            effects_applied,
            not_in_force: failure,
            rights,
        }
    }

    /// The disable policy already in force, for a reading that decided none, or `None` with the
    /// reason added to `failure` where the policy this host holds cannot be read: an unreadable
    /// policy is never reported as the default.
    async fn held_disable_policy(
        &self,
        failure: &mut Option<Sentence>,
    ) -> Option<kr_protocol::admission::RevocationPolicy> {
        match self.catalogue.disable_policy_in_force().await {
            Ok(policy) => Some(policy),
            Err(error) => {
                let problem = Sentence::new()
                    .stated("the disable policy this host holds could not be read: ")
                    .withheld(ContentClass::Message, &error.message);
                *failure = Some(match failure.take() {
                    Some(earlier) => earlier.stated("; ").sentence(&problem),
                    None => problem,
                });
                None
            }
        }
    }

    /// Puts the document's session ceiling where admission reads it, and returns what is in force.
    ///
    /// A document this host can read decides the number admission enforces, whether it names one
    /// or leaves it to the product default: both are things the document says. A document that is
    /// absent, one this build cannot read and one whose write failed decide nothing, and then the
    /// number admission already enforces stays exactly as it is and is what the report prints: a
    /// restriction the owner accepted must not be lifted because a later build could not read the
    /// file it was in, and it must not be *reported* as lifted either.
    async fn apply_session_limit(
        &self,
        resolver: &kr_worker::config::Resolver,
        state: &crate::config::AcceptedState,
    ) -> (crate::config::Enforced, Option<Sentence>) {
        let retained = crate::config::Enforced {
            value: state.sessions,
            from_document: false,
        };
        let Some(limit) = crate::config::session_limit_in_force(resolver, self.hard_limits())
        else {
            return (retained, None);
        };
        match self.registry.lock().await.set_session_limit(limit) {
            Ok(()) => (
                crate::config::Enforced {
                    value: limit,
                    from_document: true,
                },
                None,
            ),
            Err(error) => (
                retained,
                Some(
                    Sentence::new()
                        .stated("this host still admits ")
                        .number(state.sessions)
                        .stated(
                            " sessions, because the number this document asks for could not be \
                             recorded: ",
                        )
                        .withheld(ContentClass::Message, &error.to_string()),
                ),
            ),
        }
    }

    /// Replaces the capability evidence taken under a profile this host no longer creates sessions
    /// in.
    ///
    /// Nothing migrates a worker: a running session keeps the profile it was created in, and the
    /// new value applies to sessions created afterwards. What is replaced is the evidence, because
    /// evidence about a profile this host has stopped using is no longer about this host.
    ///
    /// # Errors
    ///
    /// Returns an error when the replacement evidence could not be recorded. Reporting success
    /// would publish records under a revision that no longer describes them, which is the one
    /// thing a revision exists to prevent.
    async fn invalidate_profile_evidence(
        &self,
        resolver: &kr_worker::config::Resolver,
    ) -> Result<()> {
        // Taken from the configuration this acceptance read, so the evidence is replaced under
        // the profile the report describes rather than under whatever is on disk a moment later.
        *self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            crate::config::InForce::of(resolver);
        let mut reading = self.desktop.lock().await;
        reading.read_at = std::time::Instant::now()
            .checked_sub(DESKTOP_REREAD_INTERVAL)
            .unwrap_or_else(std::time::Instant::now);
        drop(reading);
        self.capability_report().await?;
        Ok(())
    }

    /// Applies one validated configuration edit and does what the change owes.
    ///
    /// A change that affects authority fences dispatch *before* this returns, which is section
    /// 26's "changes affecting authority fence dispatch before acknowledgement": the caller is
    /// told the change is in force only once work admitted under the old authority can no longer
    /// be dispatched. Nothing migrates a worker: a running session keeps the profile it was
    /// created in, and the evidence taken under the old one is invalidated rather than reused.
    ///
    /// # Errors
    ///
    /// Returns an error when the edit is refused, when an effect could not be applied, or when a
    /// worker has not yet acknowledged the fence the change raised.
    pub async fn apply_configuration(
        self: &Arc<Self>,
        change: &kr_protocol::hostinfo::configuration::Change,
    ) -> Result<crate::config::Applied> {
        let edit = crate::config::apply(&self.paths, change, self.hard_limits())?;
        // Inside the edit lock, and through the one path every other revision takes: what this
        // daemon does with a document it wrote is what it does with a document somebody else
        // wrote. Holding the lock across it is what keeps the effects and the write together, so
        // a slower older edit cannot put its number back after a newer one has landed.
        let accepted = self.accept_configuration().await;
        let applied = crate::config::Applied {
            revision: edit.revision,
            effect: edit.effect,
            invalidated: accepted.owed.invalidated.clone(),
            fences_dispatch: accepted.owed.fences_dispatch,
            authority_revision: accepted
                .barrier
                .as_ref()
                .map(|barrier| barrier.authority_revision),
            barrier_holds: accepted
                .barrier
                .as_ref()
                .is_none_or(RevocationBarrier::holds),
            pending_workers: accepted
                .barrier
                .as_ref()
                .map_or(0, |barrier| barrier.pending().len() as u64),
        };
        // The durable debt, not the barrier this call happens to hold. A fence an earlier daemon
        // raised and no worker answered is owed by this environment, and a caller told its change
        // is in force would be told something that is not yet true of that worker.
        let outstanding = accepted.fence_outstanding();
        let not_in_force = accepted.not_in_force.clone();
        drop(accepted);
        drop(edit);
        if let Some(problem) = not_in_force {
            return Err(ControllerError::Configuration(format!(
                "revision {} is written and is not in force: {problem}",
                applied.revision
            )));
        }
        if let Some(outstanding) = outstanding {
            // Section 26 says a change affecting authority fences dispatch *before* it is
            // acknowledged. A worker that has not acknowledged its fence still holds work admitted
            // under the authority this change withdrew, so the revision is recorded and the caller
            // is told what is outstanding rather than told it is done.
            return Err(ControllerError::Configuration(format!(
                "revision {} is written and dispatch is fenced: {outstanding}; the change is in \
                 force for dispatch once they answer",
                applied.revision
            )));
        }
        Ok(applied)
    }

    /// The resource limits a configured ceiling is intersected with on this machine.
    ///
    /// This host does not measure its own headroom, so nothing is established and an owner's
    /// configured number applies. The value is here rather than at each call site so the day it is
    /// measured there is one place to answer from.
    #[must_use]
    pub const fn hard_limits(&self) -> crate::config::HardLimits {
        crate::config::HardLimits {
            sessions_per_environment: None,
        }
    }
}
