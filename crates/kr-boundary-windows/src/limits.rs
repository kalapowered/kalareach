//! The counts the broker keeps before it does any work for a request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::frame::invocation::RefusedKind;
use crate::refusal::Refusal;

/// The most invocations one account has running at once.
pub const MAX_INVOCATIONS_PER_CLIENT: usize = 2;
/// The most invocations the computer has running at once, whoever asked.
pub const MAX_INVOCATIONS_PER_MACHINE: usize = 4;
/// How long one invocation may run before the broker ends it.
pub const INVOCATION_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// The rule that refuses a request when its account has the most invocations running.
pub const RULE_PER_CLIENT: &str = "limit-per-client";
/// The rule that refuses a request when the computer has the most invocations running.
pub const RULE_PER_MACHINE: &str = "limit-per-machine";

/// What a person reads when the account has the most invocations running.
// text: PER_CLIENT_WORDS
pub const PER_CLIENT_WORDS: &str = "this account already has the most repository operations the broker runs at once; wait for one to finish";
/// What a person reads when the computer has the most invocations running.
// text: PER_MACHINE_WORDS
pub const PER_MACHINE_WORDS: &str = "the broker already runs the most repository operations it allows on this computer; try again when one has finished";

/// The invocations that are running, by account.
#[derive(Debug, Default)]
pub struct InvocationCounts {
    live: Mutex<HashMap<String, usize>>,
}

/// One invocation's place, given back when the value is dropped.
#[derive(Debug)]
pub struct Permit {
    counts: Arc<InvocationCounts>,
    client: String,
}

impl InvocationCounts {
    /// An empty count.
    #[must_use]
    pub fn new() -> Arc<InvocationCounts> {
        Arc::new(InvocationCounts::default())
    }

    /// Takes a place for an invocation of the account.
    ///
    /// # Errors
    ///
    /// Refuses with the kind `limit` when the account or the computer has no place left.
    pub fn admit(self: &Arc<InvocationCounts>, client: &str) -> Result<Permit, Refusal> {
        let mut live = match self.live.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // The account's own limit is told first: it is the one the person can act on.
        if live.get(client).copied().unwrap_or(0) >= MAX_INVOCATIONS_PER_CLIENT {
            return Err(Refusal::new(
                RefusedKind::Limit,
                RULE_PER_CLIENT,
                PER_CLIENT_WORDS,
            ));
        }
        if live.values().sum::<usize>() >= MAX_INVOCATIONS_PER_MACHINE {
            return Err(Refusal::new(
                RefusedKind::Limit,
                RULE_PER_MACHINE,
                PER_MACHINE_WORDS,
            ));
        }
        *live.entry(client.to_owned()).or_insert(0) += 1;
        Ok(Permit {
            counts: Arc::clone(self),
            client: client.to_owned(),
        })
    }

    /// How many places are taken.
    #[must_use]
    pub fn in_use(&self) -> usize {
        let live = match self.live.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        live.values().sum()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut live = match self.counts.live.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(count) = live.get_mut(&self.client) {
            *count -= 1;
            if *count == 0 {
                live.remove(&self.client);
            }
        }
    }
}
