//! The worker's half of the default context: what a session's worker holds that section 15 ¶12
//! puts into a voice call's context, the last twenty semantic messages and the decisions waiting
//! on a person.
//!
//! This daemon reads them from the worker over its own link, with the worker's existing reads
//! (`agent.instances`, `question.read` and `agent.snapshot`), and nothing else: not its output, its
//! screen, its files, its environment or its attachments, which the default leaves out. What it
//! reads comes here as items, each placed at the moment it was produced, and goes into the same
//! snapshot as the daemon's own half. The shared filter, the cap, the secret patterns and the
//! counts of what was kept out or replaced are applied to both halves at one place after that, so
//! nothing here decides what a device may see.
//!
//! # Privacy mode
//!
//! While privacy mode is on nothing of this half is read. After it is turned off again only what
//! was produced after it last changed is carried: a worker of an earlier release keeps its history
//! through the change, and what such a worker holds of the interval before it is not for a call.
//!
//! # What a decision is
//!
//! A question a verified source asked, and an approval a decoder gave meaning to, each while it can
//! still be answered. A decision that was created before the grant's history bound stays outside
//! it, though section 10 would admit a current decision the grant names: this is the narrower
//! reading, and a voice grant names none.

use kr_protocol::agent::AgentSnapshotEntry;
use kr_protocol::gateway::{PendingKind, PendingResource};
use kr_protocol::question::Question;
use kr_voice::seams::{ContextItem, WithheldRun};

/// The most parts of one agent's history a read follows. A history is at most 4,096 entries, and a
/// part carries as many as a control frame holds, so this is far more than a history needs; a read
/// that passes it is given up rather than followed on.
pub const MAX_HISTORY_PARTS: usize = 64;

/// The reason given when privacy mode is on.
pub const PRIVACY_ON: &str = "privacy mode is on, so none of the session's worker was read";

/// The reason given for what was produced before privacy mode last changed.
pub const BEFORE_PRIVACY_CHANGE: &str = "produced before privacy mode last changed";

/// What the daemon read of one session's worker for the default context.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerHalf {
    /// The decisions waiting on a person, newest last.
    pub decisions: Vec<ContextItem>,
    /// The semantic messages of the session's agents, oldest first.
    pub messages: Vec<ContextItem>,
    /// What could not be read, and why, so that a gap is visible rather than silent.
    pub unavailable: Vec<WithheldRun>,
}

impl WorkerHalf {
    /// A half that was not read, for `reason`.
    #[must_use]
    pub fn not_read(reason: &str) -> Self {
        Self {
            unavailable: vec![WithheldRun {
                reason: reason.to_owned(),
                count: 0,
            }],
            ..Self::default()
        }
    }

    /// Records a part that could not be read. The count is nought: how many items it held is not
    /// known, and a count of nothing would say it held none.
    pub fn could_not_read(&mut self, what: &str) {
        self.unavailable.push(WithheldRun {
            reason: format!("{what} could not be read"),
            count: 0,
        });
    }

    /// Keeps only what was produced after `boundary_ms`, the moment privacy mode last changed, and
    /// says how many items that kept out.
    #[must_use]
    pub fn after(mut self, boundary_ms: Option<u64>) -> Self {
        let Some(boundary) = boundary_ms else {
            return self;
        };
        let mut kept_out = 0u64;
        for items in [&mut self.decisions, &mut self.messages] {
            let before = items.len();
            items.retain(|item| item.produced_at_ms > boundary);
            kept_out += (before - items.len()) as u64;
        }
        if kept_out > 0 {
            self.unavailable.push(WithheldRun {
                reason: BEFORE_PRIVACY_CHANGE.to_owned(),
                count: kept_out,
            });
        }
        self
    }
}

/// One semantic entry as a message: what kind of event it was and what it said, at the moment it
/// was observed. A text the worker cut says so.
#[must_use]
pub fn message(entry: &AgentSnapshotEntry) -> ContextItem {
    let mut text = format!("{}: {}", entry.kind, entry.text);
    if entry.omitted_text_bytes.get() > 0 {
        text.push_str(" (text cut)");
    }
    ContextItem::new(text, entry.observed_at.get())
}

/// The messages of several agents as one run, oldest first. Entries observed at one moment stay in
/// the order the agents are given in.
#[must_use]
pub fn messages(agents: Vec<Vec<AgentSnapshotEntry>>) -> Vec<ContextItem> {
    let mut all: Vec<ContextItem> = agents.iter().flatten().map(message).collect();
    all.sort_by_key(|item| item.produced_at_ms);
    all
}

/// A question as a decision waiting on a person, when it still can be answered.
#[must_use]
pub fn question(question: &Question) -> Option<ContextItem> {
    if question.state.is_resolved() {
        return None;
    }
    let mut text = format!("question: {}", question.question);
    if !question.context.is_empty() {
        text.push_str(&format!(" ({})", question.context));
    }
    Some(ContextItem::new(text, question.created_at_ms.get()))
}

/// An approval request as a decision waiting on a person, when it still can be decided. The
/// request's own bytes are not read: they can hold anything the agent was asked to do it with.
#[must_use]
pub fn approval(resource: &PendingResource) -> Option<ContextItem> {
    if resource.kind != PendingKind::Approval || resource.state.is_terminal() {
        return None;
    }
    let verified = if resource.interpretation_verified {
        "verified"
    } else {
        "not verified"
    };
    Some(ContextItem::new(
        format!("approval: {} ({verified})", resource.method.as_str()),
        resource.recorded_at.get(),
    ))
}

/// The decisions as one run, the newest last.
#[must_use]
pub fn decisions(mut items: Vec<ContextItem>) -> Vec<ContextItem> {
    items.sort_by_key(|item| item.produced_at_ms);
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::AgentBindingRevision;
    use kr_protocol::scalars::{Nullable, TimestampMs, U64};

    fn entry(node: u64, text: &str, at: u64, omitted: u64) -> AgentSnapshotEntry {
        AgentSnapshotEntry {
            node: U64::new(node),
            kind: "message".to_owned(),
            text: text.to_owned(),
            omitted_text_bytes: U64::new(omitted),
            observed_at: TimestampMs::new(at),
            binding_revision: AgentBindingRevision::new(1),
            turn_id: Nullable::null(),
        }
    }

    /// Two agents' entries are one run, oldest first, and entries at one moment keep the order the
    /// agents were given in.
    #[test]
    fn the_messages_of_several_agents_are_one_run_oldest_first() {
        let run = messages(vec![
            vec![entry(1, "a1", 10, 0), entry(2, "a2", 30, 0)],
            vec![entry(1, "b1", 10, 0), entry(2, "b2", 20, 0)],
        ]);
        let texts: Vec<&str> = run.iter().map(|item| item.text.as_str()).collect();
        assert_eq!(
            texts,
            ["message: a1", "message: b1", "message: b2", "message: a2"]
        );
    }

    /// A text the worker cut is carried as cut.
    #[test]
    fn a_text_the_worker_cut_says_so() {
        assert_eq!(message(&entry(1, "start", 1, 0)).text, "message: start");
        assert_eq!(
            message(&entry(1, "start", 1, 9)).text,
            "message: start (text cut)"
        );
    }

    /// What was produced at or before the moment privacy mode last changed is kept out and counted.
    #[test]
    fn what_was_produced_before_privacy_mode_last_changed_is_kept_out_and_counted() {
        let half = WorkerHalf {
            decisions: vec![ContextItem::new("d", 50)],
            messages: vec![ContextItem::new("m1", 100), ContextItem::new("m2", 101)],
            unavailable: Vec::new(),
        };
        let kept = half.clone().after(Some(100));
        assert_eq!(kept.messages, vec![ContextItem::new("m2", 101)]);
        assert!(kept.decisions.is_empty());
        assert_eq!(
            kept.unavailable,
            vec![WithheldRun {
                reason: BEFORE_PRIVACY_CHANGE.to_owned(),
                count: 2
            }]
        );
        assert_eq!(half.clone().after(None), half, "no change to be after");
    }
}
