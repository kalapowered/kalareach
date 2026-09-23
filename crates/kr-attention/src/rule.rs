//! The rule set, its escalation policies and its de-duplication window.
//!
//! Section 25 names eight rules, gives them stable identifiers and fixes the de-duplication window
//! at sixty seconds; its automation paragraph, with section 17's workflow limits, adds a ninth for
//! a workflow or a causal chain its own limits paused. [`RULES`] is that table, one entry per
//! identifier, and [`rule`] is the only way to reach an entry, so a rule's policy cannot be decided
//! twice in two places.
//!
//! # What escalation is, and what it is not
//!
//! Escalation raises what an item is asking for while it stays unattended, and then keeps asking at
//! a fixed interval. It is a property of the notification, not of the inbox: an item is in the
//! inbox from the moment it is raised, whatever level it stands at, and quiet hours never take one
//! out. A step that has already been passed is never taken again, so a restart cannot walk an item
//! up the ladder a second time.

use kr_protocol::attention::{AttentionLevel, AttentionRule, DEDUPLICATION_WINDOW_MS};

/// One step of an escalation ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscalationStep {
    /// How long after the item was first raised this step is taken, in milliseconds.
    pub after_ms: u64,
    /// What the item asks for from then on.
    pub level: AttentionLevel,
}

/// One rule of the attention rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The stable identifier.
    pub id: AttentionRule,
    /// What the item asks for when it is first raised.
    pub initial: AttentionLevel,
    /// The ladder it climbs while nobody attends to it, in ascending order of `after_ms`.
    pub steps: &'static [EscalationStep],
    /// How often an unattended item is announced again once the ladder is finished.
    ///
    /// `None` means it is announced once. A command that failed is history: repeating it would
    /// add nothing, because nothing is waiting on the person.
    pub repeat_ms: Option<u64>,
    /// How long a repeat of the same condition is folded into the item rather than announced.
    pub dedup_window_ms: u64,
    /// Whether the host itself observed the condition.
    ///
    /// False only for an application notice, which any process writing to the terminal can emit.
    pub trusted: bool,
    /// Whether the inbox's own bound may let go of one of these.
    ///
    /// False for anything somebody or something is still waiting on: an unanswered approval, an
    /// unanswered request, an adapter that is still down, a host still out of contact. Those are
    /// outstanding conditions rather than a record of one, and section 25 keeps an outstanding
    /// approval in the inbox. What the bound lets go of is the rest: a command that has already
    /// exited, a turn already waiting, a notice an application printed.
    pub droppable: bool,
}

const fn step(after_ms: u64, level: AttentionLevel) -> EscalationStep {
    EscalationStep { after_ms, level }
}

/// How long an unanswered approval or input request waits before it is announced again.
pub const REMINDER_INTERVAL_MS: u64 = 300_000;

/// How long an adapter stays failed before the failure becomes urgent.
pub const ADAPTER_ESCALATION_MS: u64 = 300_000;

/// How long contact stays lost before it becomes urgent.
pub const HOST_CONTACT_ESCALATION_MS: u64 = 60_000;

/// The rule set of section 25, one entry per stable identifier.
pub static RULES: &[Rule] = &[
    // A pending approval is the one thing in the set that is holding work up on purpose, and
    // section 25 calls it urgent where it calls nothing else urgent. It starts there, and keeps
    // asking, because the agent is waiting.
    Rule {
        id: AttentionRule::PendingApproval,
        initial: AttentionLevel::Urgent,
        steps: &[],
        repeat_ms: Some(REMINDER_INTERVAL_MS),
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
    // A verified pending request is worth telling the person about at once. What it is not yet is
    // an interruption: that is the idle reminder's job, five minutes later, and having one rule
    // start where the other takes over is why they are two rules rather than one with a ladder.
    Rule {
        id: AttentionRule::PendingInput,
        initial: AttentionLevel::Notable,
        steps: &[],
        repeat_ms: None,
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
    Rule {
        id: AttentionRule::InputIdleReminder,
        initial: AttentionLevel::Urgent,
        steps: &[],
        repeat_ms: Some(REMINDER_INTERVAL_MS),
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
    // History. Nothing is waiting on the person, so it is announced once and stays in the inbox.
    Rule {
        id: AttentionRule::CommandFailed,
        initial: AttentionLevel::Notable,
        steps: &[],
        repeat_ms: None,
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: true,
    },
    Rule {
        id: AttentionRule::ReviewReady,
        initial: AttentionLevel::Notable,
        steps: &[],
        repeat_ms: None,
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: true,
    },
    // A capability that has gone is worth knowing about immediately and worth interrupting for
    // once it is clear it is not coming back on its own.
    Rule {
        id: AttentionRule::AdapterFailed,
        initial: AttentionLevel::Notable,
        steps: &[step(ADAPTER_ESCALATION_MS, AttentionLevel::Urgent)],
        repeat_ms: Some(REMINDER_INTERVAL_MS),
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
    Rule {
        id: AttentionRule::HostContactLost,
        initial: AttentionLevel::Notable,
        steps: &[step(HOST_CONTACT_ESCALATION_MS, AttentionLevel::Urgent)],
        repeat_ms: Some(REMINDER_INTERVAL_MS),
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
    // Untrusted, and deliberately at the bottom of the set. An application that wants attention
    // can ask for it; it cannot award itself any.
    Rule {
        id: AttentionRule::ApplicationNotice,
        initial: AttentionLevel::Informational,
        steps: &[],
        repeat_ms: None,
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: false,
        droppable: true,
    },
    // A workflow or a causal chain stopped by one of its own limits. Something the person has to
    // decide - enable the revision again, or re-arm the chain - so it is notable, and it is the
    // host's own record of its own journal, so it is trusted. It does not climb: a paused workflow
    // is not getting worse by waiting. And it is not the bound's to let go of, because it stands
    // until the revision is enabled again; a chain has no ending record yet, and its item stands
    // until the person has seen it.
    Rule {
        id: AttentionRule::AutomationPaused,
        initial: AttentionLevel::Notable,
        steps: &[],
        repeat_ms: None,
        dedup_window_ms: DEDUPLICATION_WINDOW_MS,
        trusted: true,
        droppable: false,
    },
];

/// Returns the rule with this identifier.
///
/// # Panics
///
/// Never. [`RULES`] holds one entry per [`AttentionRule`] and the test below proves it, so the
/// lookup cannot miss.
#[must_use]
pub fn rule(id: AttentionRule) -> &'static Rule {
    RULES
        .iter()
        .find(|rule| rule.id == id)
        .expect("every attention rule has exactly one entry")
}

impl Rule {
    /// Returns the level this rule asks for once `elapsed_ms` have passed since the item was
    /// raised, and how many steps of the ladder that is.
    #[must_use]
    pub fn level_after(&self, elapsed_ms: u64) -> (AttentionLevel, usize) {
        let mut level = self.initial;
        let mut taken = 0;
        for step in self.steps {
            if elapsed_ms >= step.after_ms {
                level = step.level;
                taken += 1;
            }
        }
        (level, taken)
    }

    /// Returns how long after the item was raised the next unclimbed step is due.
    #[must_use]
    pub fn next_step_after(&self, taken: usize) -> Option<u64> {
        self.steps.get(taken).map(|step| step.after_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_set_covers_every_identifier_exactly_once() {
        assert_eq!(RULES.len(), AttentionRule::ALL.len());
        for id in AttentionRule::ALL {
            let found: Vec<_> = RULES.iter().filter(|rule| rule.id == *id).collect();
            assert_eq!(found.len(), 1, "{id} has exactly one rule");
            assert_eq!(rule(*id).id, *id);
        }
    }

    #[test]
    fn every_rule_de_duplicates_over_the_sixty_second_window() {
        for rule in RULES {
            assert_eq!(
                rule.dedup_window_ms, 60_000,
                "{} keeps section 25's window",
                rule.id
            );
        }
    }

    #[test]
    fn nothing_anybody_is_waiting_on_is_one_the_bound_may_let_go_of() {
        for rule in RULES {
            let waiting = matches!(
                rule.id,
                AttentionRule::PendingApproval
                    | AttentionRule::PendingInput
                    | AttentionRule::InputIdleReminder
                    | AttentionRule::AdapterFailed
                    | AttentionRule::HostContactLost
                    | AttentionRule::AutomationPaused
            );
            assert_eq!(
                rule.droppable, !waiting,
                "{} says whether the inbox's bound may let go of it",
                rule.id
            );
        }
    }

    #[test]
    fn only_the_application_notice_rule_is_untrusted() {
        for rule in RULES {
            assert_eq!(
                rule.trusted,
                rule.id != AttentionRule::ApplicationNotice,
                "{} states whether the host observed it",
                rule.id
            );
        }
    }

    #[test]
    fn an_untrusted_rule_never_reaches_an_urgent_level() {
        let notice = rule(AttentionRule::ApplicationNotice);
        let (level, taken) = notice.level_after(u64::MAX);
        assert_eq!(level, AttentionLevel::Informational);
        assert_eq!(taken, 0);
        assert_eq!(notice.repeat_ms, None);
    }

    #[test]
    fn a_ladder_is_climbed_one_step_at_a_time_and_never_twice() {
        let adapter = rule(AttentionRule::AdapterFailed);
        assert_eq!(
            adapter.level_after(0),
            (AttentionLevel::Notable, 0),
            "a fresh failure is notable"
        );
        assert_eq!(
            adapter.level_after(ADAPTER_ESCALATION_MS - 1),
            (AttentionLevel::Notable, 0)
        );
        assert_eq!(
            adapter.level_after(ADAPTER_ESCALATION_MS),
            (AttentionLevel::Urgent, 1)
        );
        assert_eq!(adapter.next_step_after(0), Some(ADAPTER_ESCALATION_MS));
        assert_eq!(adapter.next_step_after(1), None);
    }

    #[test]
    fn the_idle_reminder_counts_the_interval_section_twenty_five_fixes() {
        assert_eq!(kr_protocol::attention::IDLE_REMINDER_MS, 300_000);
        assert_eq!(
            rule(AttentionRule::InputIdleReminder).initial,
            AttentionLevel::Urgent
        );
    }
}
