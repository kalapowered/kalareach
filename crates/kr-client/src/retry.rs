//! What a client does with a failure, and what it tells the person.
//!
//! Section 23 states the rule in four sentences: only idempotent reads, transfer chunks and
//! requests whose receipt proves no dispatch may retry automatically; `OUTCOME_UNKNOWN` is not
//! retryable; `RESYNC_REQUIRED` requests a new snapshot; authentication and schema failures require
//! a configuration or software change. The user interface translates the codes into direct actions
//! without displaying raw protocol internals by default.
//!
//! This module is that rule as a table. [`entry`] gives every code one step and one plain-language
//! action, in a single exhaustive match, so a code added to the protocol stops the build here
//! rather than reaching a client as an unclassified failure. [`Attempts`] applies the table to one
//! request: it combines the code's step with the request's [`RequestClass`], the delay the host
//! asked for or the bounded jittered backoff, and an attempt budget.
//!
//! # Two conditions, both required
//!
//! An automatic retry needs the *code* to permit one, which means its
//! [`kr_protocol::error::RetryCategory`] is `Transient`, and the *request* to be one of the three
//! classes the specification names. Neither
//! alone is enough. A transient failure of a mutation is not retried, because the library cannot
//! know whether the host dispatched it; and an idempotent read that failed with
//! `PERMISSION_DENIED` is not retried, because sending it again cannot change the answer.
//!
//! # What the library never decides
//!
//! `OUTCOME_UNKNOWN` never yields a retry, whatever the class asks for. The action it names is to
//! ask the host what became of that action identifier. Section 9 forbids dispatching the identifier
//! again, and inventing a new one would submit the same intent twice.

use std::time::Duration;

use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_transport::reconnect::Backoff;

/// The shortest delay the policy draws when nothing told it how long to wait.
///
/// It bounds the backoff this module produces, not a delay a host or a service stated: a refuser
/// that named a figure knows when its condition passes, and its figure is honoured as it came.
/// [`MAX_AUTOMATIC_DELAY`] is what bounds how long a *call* waits, whichever the delay came from.
pub const RETRY_BACKOFF_MIN: Duration = Duration::from_millis(100);

/// The longest delay the policy draws when nothing told it how long to wait, before jitter.
pub const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// How many times the library sends the same request again before it hands the decision back.
///
/// The bound exists because an automatic retry happens inside a call the caller is waiting on. A
/// library that retried until it succeeded would turn a host that is refusing everything into a
/// call that never returns, and the caller would have nothing to show for the wait.
pub const MAX_AUTOMATIC_RETRIES: u32 = 3;

/// The longest *one* delay may be before the library hands the decision back instead of waiting.
///
/// A managed service may legitimately ask for a delay of minutes. Honouring it inside a call would
/// hold the caller for minutes with no way to change its mind, so a longer delay is reported as a
/// repeat the caller schedules rather than performed as a retry the caller cannot see.
///
/// It bounds each delay and not their sum. [`MAX_AUTOMATIC_RETRIES`] delays of this length add up,
/// so the longest a call waits on the policy's account is the two multiplied together, and the
/// requests themselves take whatever they take.
pub const MAX_AUTOMATIC_DELAY: Duration = Duration::from_secs(10);

/// Which class a request belongs to, which decides whether an automatic retry is legal at all.
///
/// Section 23 names three classes and no others. [`Self::Dispatchable`] is everything else: a
/// request that may already have taken effect, where sending it again could perform the intent
/// twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RequestClass {
    /// An idempotent read, as the method registry marks it.
    IdempotentRead,
    /// One chunk of a transfer, addressed by index and verified by its own digest.
    TransferChunk,
    /// A request whose receipt proves it was never dispatched.
    ReceiptProvesNoDispatch,
    /// Anything else. Every mutation is here until its receipt says otherwise.
    Dispatchable,
}

impl RequestClass {
    /// The three classes section 23 permits an automatic retry for.
    pub const AUTOMATIC: [Self; 3] = [
        Self::IdempotentRead,
        Self::TransferChunk,
        Self::ReceiptProvesNoDispatch,
    ];

    /// Every class, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::IdempotentRead,
        Self::TransferChunk,
        Self::ReceiptProvesNoDispatch,
        Self::Dispatchable,
    ];

    /// Returns true when a request of this class may be sent again without the caller deciding.
    #[must_use]
    pub const fn permits_automatic_retry(self) -> bool {
        match self {
            Self::IdempotentRead | Self::TransferChunk | Self::ReceiptProvesNoDispatch => true,
            Self::Dispatchable => false,
        }
    }

    /// Returns a stable name for logs and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdempotentRead => "idempotent_read",
            Self::TransferChunk => "transfer_chunk",
            Self::ReceiptProvesNoDispatch => "receipt_proves_no_dispatch",
            Self::Dispatchable => "dispatchable",
        }
    }
}

/// The direct action a user interface offers for a failure.
///
/// Section 23: the interface translates a code into a direct action and does not display raw
/// protocol internals by default. This is that translation, and it is deliberately small: a person
/// has a handful of things they can actually do, and a client that showed forty-eight of them
/// would be showing the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UserAction {
    /// Pair this device with the host again.
    PairAgain,
    /// Sign in to the managed account.
    SignIn,
    /// Update this client or the host: the two builds do not agree on the contract.
    Update,
    /// Wait. The condition passes on its own.
    Wait,
    /// Refresh: this view has fallen behind what the host holds.
    Resync,
    /// Check what became of the action before doing anything else.
    CheckTheOutcome,
    /// Change a setting on this device or on the host.
    FixConfiguration,
    /// Nothing remedial. The interface reports what the host said and the person carries on.
    Nothing,
}

impl UserAction {
    /// Every action, in declaration order.
    pub const ALL: [Self; 8] = [
        Self::PairAgain,
        Self::SignIn,
        Self::Update,
        Self::Wait,
        Self::Resync,
        Self::CheckTheOutcome,
        Self::FixConfiguration,
        Self::Nothing,
    ];

    /// Returns a stable key, so a client can carry its own translation of each action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PairAgain => "pair_again",
            Self::SignIn => "sign_in",
            Self::Update => "update",
            Self::Wait => "wait",
            Self::Resync => "resync",
            Self::CheckTheOutcome => "check_the_outcome",
            Self::FixConfiguration => "fix_configuration",
            Self::Nothing => "nothing",
        }
    }

    /// Returns the plain-language action, for a client with no translation of its own.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PairAgain => "Pair this device with the host again.",
            Self::SignIn => "Sign in to your account.",
            Self::Update => "Update this app or the host: their versions do not agree.",
            Self::Wait => "Wait a moment and try again.",
            Self::Resync => "Refresh: this view has fallen behind.",
            Self::CheckTheOutcome => "Check whether this went through before trying it again.",
            Self::FixConfiguration => "Change a setting on this device or on the host.",
            Self::Nothing => "",
        }
    }
}

/// What the specification prescribes for one code, before a request's class is considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Step {
    /// A transient condition. An eligible request may be sent again after a delay.
    Transient,
    /// The condition passes at a time the host knows. Honour its delay, or the bounded backoff.
    Wait,
    /// Take a new snapshot and resume from the cursor it returns.
    NewSnapshot,
    /// Ask the host what became of the action. Its identifier is never dispatched again.
    QueryOutcome,
    /// The request as sent cannot succeed. Something outside it has to change first.
    Stop,
}

/// One row of the policy table: what to do about a code, and what to tell the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// What the specification prescribes.
    pub step: Step,
    /// The direct action a user interface offers.
    pub action: UserAction,
}

/// What the library does with the request that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// The library sends the same request again after this delay, and the caller sees only the
    /// final answer.
    Retry {
        /// How long to wait first.
        delay: Duration,
    },
    /// The same request may be sent again, but not before this delay, and not by the library.
    ///
    /// This is what a host's retry-after becomes when the caller owns the decision: the allowance
    /// that is spent, the service with no capacity, and the transient condition whose attempt
    /// budget is used up.
    RepeatNoSoonerThan {
        /// The earliest the same request may be sent again.
        delay: Duration,
    },
    /// Take a new snapshot of the stream and resume from the cursor it returns.
    NewSnapshot,
    /// Ask the host what became of this action. Never dispatch its identifier again.
    QueryOutcome,
    /// The request as sent cannot succeed.
    Stop,
}

/// What the policy decided about one failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The code this decision is about.
    pub code: ErrorCode,
    /// The retry category the protocol assigns to that code.
    pub category: RetryCategory,
    /// The class of the request that failed.
    pub class: RequestClass,
    /// What happens to the request.
    pub recovery: Recovery,
    /// What a user interface offers the person.
    pub action: UserAction,
}

impl Decision {
    /// Returns true when the library sends this request again by itself.
    #[must_use]
    pub const fn retries_automatically(&self) -> bool {
        matches!(self.recovery, Recovery::Retry { .. })
    }

    /// Returns the delay a retry or a repeat waits, when there is one.
    #[must_use]
    pub const fn delay(&self) -> Option<Duration> {
        match self.recovery {
            Recovery::Retry { delay } | Recovery::RepeatNoSoonerThan { delay } => Some(delay),
            Recovery::NewSnapshot | Recovery::QueryOutcome | Recovery::Stop => None,
        }
    }
}

/// One failure, as the policy reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The stable code that was returned.
    pub code: ErrorCode,
    /// What the refuser asked the caller to wait, when it said.
    ///
    /// A managed service states this; a host error carries only its code, and the bounded backoff
    /// stands in for it. A delay inside a message is a delay nothing can act on, which is why this
    /// is a field.
    pub retry_after: Option<Duration>,
}

impl Failure {
    /// A failure the refuser said nothing more about.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            retry_after: None,
        }
    }

    /// A failure whose refuser asked the caller to wait a stated time.
    #[must_use]
    pub const fn after(code: ErrorCode, retry_after: Duration) -> Self {
        Self {
            code,
            retry_after: Some(retry_after),
        }
    }
}

/// Returns the policy row for one code.
///
/// This is the whole table. The match is exhaustive rather than defaulted, so adding a code to the
/// protocol is a change that has to be decided here.
#[must_use]
pub const fn entry(code: ErrorCode) -> Entry {
    // The step and the action answer different questions. The step is what happens to the request;
    // the action is what a person can do about it. They often disagree: a request that cannot
    // succeed may still leave the person with nothing to do, and a condition the library waits out
    // may still be worth naming.
    let (step, action) = match code {
        // Authentication, pairing and schema failures: a configuration or software change.
        ErrorCode::InvalidArgument => (Step::Stop, UserAction::Update),
        ErrorCode::UnsupportedSchema | ErrorCode::UnsupportedCapability => {
            (Step::Stop, UserAction::Update)
        }
        ErrorCode::PermissionDenied => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::PairingExpired
        | ErrorCode::PairingRejected
        | ErrorCode::PairingAuthFailed
        | ErrorCode::PairingAttemptsExhausted => (Step::Stop, UserAction::PairAgain),
        ErrorCode::RendezvousConfigError => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::InputIncompatible => (Step::Stop, UserAction::Update),
        ErrorCode::HostNotConfigured => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::ClockUntrusted => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::ShellIntegrationUnsupported => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::RepositoryUntrusted => (Step::Stop, UserAction::FixConfiguration),
        ErrorCode::PluginGrantRequired | ErrorCode::PluginDisabled => {
            (Step::Stop, UserAction::FixConfiguration)
        }
        ErrorCode::NotInKrSession => (Step::Stop, UserAction::FixConfiguration),
        // A reused identifier with a different payload is a client fault, not a person's.
        ErrorCode::IdConflict => (Step::Stop, UserAction::Update),

        // Transient conditions. An eligible request is sent again under the bounded backoff.
        ErrorCode::RendezvousUnavailable
        | ErrorCode::TerminalUnavailable
        | ErrorCode::TerminalProbeFailed
        | ErrorCode::SessionLimit
        | ErrorCode::ResourceUnavailable
        | ErrorCode::EnvironmentUnavailable
        | ErrorCode::DesktopUnavailable
        | ErrorCode::EditorBusy
        | ErrorCode::UpstreamUnavailable
        | ErrorCode::PackageUnavailableOffline => (Step::Transient, UserAction::Wait),
        // Transient, but a store that is full does not empty itself.
        ErrorCode::StorageUnavailable => (Step::Transient, UserAction::FixConfiguration),

        // The host knows when. Its retry-after is honoured, and the bounded backoff stands in when
        // it did not say.
        ErrorCode::RateLimited | ErrorCode::ServiceCapacity | ErrorCode::QuotaExceeded => {
            (Step::Wait, UserAction::Wait)
        }

        // The two the specification names by hand.
        ErrorCode::OutcomeUnknown => (Step::QueryOutcome, UserAction::CheckTheOutcome),
        ErrorCode::ResyncRequired => (Step::NewSnapshot, UserAction::Resync),

        // A view that has moved on. The request cannot succeed; refreshing is what the person does.
        ErrorCode::StaleSession => (Step::Stop, UserAction::Resync),

        // Refusals a person resolves by choosing again, where the host's own message is the whole
        // of it: which session, which attachment, which draft, whose lease, what to do about a
        // transfer whose bytes did not match.
        ErrorCode::UnknownSession
        | ErrorCode::AmbiguousSession
        | ErrorCode::AmbiguousAttachment
        | ErrorCode::SessionClosed
        | ErrorCode::LeaseLost
        | ErrorCode::GeometryNotOwner
        | ErrorCode::DraftConflict
        | ErrorCode::AttachmentIntegrity
        | ErrorCode::QuestionResolved
        | ErrorCode::QuestionExpired
        | ErrorCode::OwnerConfirmationRequired
        | ErrorCode::CausalLimit
        | ErrorCode::SourceChanged => (Step::Stop, UserAction::Nothing),
    };
    Entry { step, action }
}

/// Returns the direct action a user interface offers for one code.
///
/// It is what the code alone supports. A refuser that knows more than its code says carries its own
/// action instead: a managed service that answered `PERMISSION_DENIED` because the account is not
/// signed in knows that, and the code it had to answer with does not, so
/// [`crate::ClientError::user_action`] takes the service's rather than this.
#[must_use]
pub const fn user_action(code: ErrorCode) -> UserAction {
    entry(code).action
}

/// One request's attempt budget and backoff.
///
/// A caller holds one of these for one logical request and consults it on each failure. The
/// backoff grows with each delay it hands out, so a request that keeps failing waits longer each
/// time; the budget is what stops it waiting for ever.
#[derive(Clone, Debug)]
pub struct Attempts {
    backoff: Backoff,
    remaining: u32,
}

impl Default for Attempts {
    fn default() -> Self {
        Self::new()
    }
}

impl Attempts {
    /// Creates a budget at [`MAX_AUTOMATIC_RETRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_retries(MAX_AUTOMATIC_RETRIES)
    }

    /// Creates a budget of a stated number of retries.
    #[must_use]
    pub fn with_retries(retries: u32) -> Self {
        Self {
            backoff: Backoff::new(RETRY_BACKOFF_MIN, RETRY_BACKOFF_MAX),
            remaining: retries,
        }
    }

    /// Returns how many automatic retries are left.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Returns the longest the next delay can be, before jitter.
    ///
    /// A client that wants to tell a person how long it is about to wait reads this; the delay it
    /// actually waits is drawn below it and reported on the decision.
    #[must_use]
    pub const fn ceiling(&self) -> Duration {
        self.backoff.ceiling()
    }

    /// Decides what to do about one failure of a request in `class`.
    ///
    /// A decision that retries spends one of the budget. Everything else leaves it alone, because
    /// nothing was sent again.
    pub fn decide(&mut self, failure: Failure, class: RequestClass) -> Decision {
        let Entry { step, action } = entry(failure.code);
        let category = failure.code.retry_category();
        let recovery = match step {
            Step::NewSnapshot => Recovery::NewSnapshot,
            Step::QueryOutcome => Recovery::QueryOutcome,
            Step::Stop => Recovery::Stop,
            Step::Transient | Step::Wait => {
                // The host's own figure wins where it gave one: it knows when its allowance
                // refills or its capacity returns, and a backoff drawn here would be a guess
                // beside an answer.
                let delay = failure
                    .retry_after
                    .unwrap_or_else(|| self.backoff.next_delay());
                // Both conditions, and the budget. A category that is not transient never retries,
                // whatever the class: that is what keeps `QUOTA_EXCEEDED` a refusal the caller
                // schedules around rather than a wait the library performs.
                let automatic = category.permits_automatic_retry()
                    && class.permits_automatic_retry()
                    && self.remaining > 0
                    && delay <= MAX_AUTOMATIC_DELAY;
                if automatic {
                    self.remaining -= 1;
                    Recovery::Retry { delay }
                } else {
                    Recovery::RepeatNoSoonerThan { delay }
                }
            }
        };
        Decision {
            code: failure.code,
            category,
            class,
            recovery,
            action,
        }
    }
}

/// Returns what the policy says about one failure, on a fresh budget.
///
/// A caller deciding what to show a person wants this rather than [`Attempts`]: the step and the
/// action do not depend on how many attempts are left, and the delay is the shortest the policy
/// would use.
///
/// It is not a record of what already happened. The budget is fresh, so a transient failure of an
/// eligible request reads as [`Recovery::Retry`] here even when the call that produced it had
/// already spent its attempts and given up. Read the recovery a call returned from the call, and
/// read this for the step and the action.
#[must_use]
pub fn decision(failure: Failure, class: RequestClass) -> Decision {
    Attempts::new().decide(failure, class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_decision_and_an_action() {
        for code in ErrorCode::ALL {
            let decision = decision(Failure::new(*code), RequestClass::IdempotentRead);
            assert_eq!(decision.code, *code);
            assert_eq!(decision.category, code.retry_category());
            // An action is a key a client can translate, and every key is one of the eight.
            assert!(
                UserAction::ALL.contains(&decision.action),
                "{} has an action outside the vocabulary",
                code.as_str()
            );
            assert!(!decision.action.as_str().is_empty());
        }
        // Every action the table can produce must be reachable from some code: one no code
        // produces is a string a client would translate for nothing. Signing in is the exception,
        // and deliberately so. Section 23's required codes have no "not authenticated", so a host
        // error never means it; a managed service that knows its caller is signed out carries the
        // action itself, which `crates/kr-client/tests/relay_service.rs` checks.
        for action in UserAction::ALL {
            if action == UserAction::SignIn {
                assert!(
                    !ErrorCode::ALL
                        .iter()
                        .any(|code| user_action(*code) == action),
                    "no code should mean the account is signed out"
                );
                continue;
            }
            assert!(
                ErrorCode::ALL
                    .iter()
                    .any(|code| user_action(*code) == action),
                "no code produces {}",
                action.as_str()
            );
        }
    }

    #[test]
    fn only_the_three_classes_section_twenty_three_names_retry_automatically() {
        for code in ErrorCode::ALL {
            for class in RequestClass::ALL {
                let decision = decision(Failure::new(*code), class);
                if decision.retries_automatically() {
                    assert!(
                        RequestClass::AUTOMATIC.contains(&class),
                        "{} retried automatically for {}",
                        code.as_str(),
                        class.as_str()
                    );
                    assert_eq!(
                        decision.category,
                        RetryCategory::Transient,
                        "{} retried automatically outside the transient category",
                        code.as_str()
                    );
                }
            }
        }
        assert_eq!(RequestClass::AUTOMATIC.len(), 3);
        assert!(!RequestClass::Dispatchable.permits_automatic_retry());
    }

    #[test]
    fn an_unknown_outcome_never_retries_however_it_is_asked() {
        for class in RequestClass::ALL {
            let decision = decision(Failure::new(ErrorCode::OutcomeUnknown), class);
            assert_eq!(decision.recovery, Recovery::QueryOutcome);
            assert!(!decision.retries_automatically());
            assert_eq!(decision.action, UserAction::CheckTheOutcome);
        }
        // Even with a budget that has plenty left and a host that asked for a short delay.
        let mut attempts = Attempts::with_retries(64);
        let decision = attempts.decide(
            Failure::after(ErrorCode::OutcomeUnknown, Duration::from_millis(1)),
            RequestClass::IdempotentRead,
        );
        assert_eq!(decision.recovery, Recovery::QueryOutcome);
        assert_eq!(attempts.remaining(), 64, "nothing was sent again");
    }

    #[test]
    fn a_resynchronisation_asks_for_a_new_snapshot_rather_than_a_retry() {
        let decision = decision(
            Failure::new(ErrorCode::ResyncRequired),
            RequestClass::IdempotentRead,
        );
        assert_eq!(decision.recovery, Recovery::NewSnapshot);
        assert_eq!(decision.action, UserAction::Resync);
    }

    #[test]
    fn authentication_pairing_and_schema_failures_need_a_change_rather_than_a_delay() {
        for code in [
            ErrorCode::PairingAuthFailed,
            ErrorCode::PairingExpired,
            ErrorCode::PairingRejected,
            ErrorCode::PairingAttemptsExhausted,
            ErrorCode::UnsupportedSchema,
            ErrorCode::UnsupportedCapability,
            ErrorCode::InvalidArgument,
            ErrorCode::PermissionDenied,
        ] {
            let decision = decision(Failure::new(code), RequestClass::IdempotentRead);
            assert_eq!(
                decision.recovery,
                Recovery::Stop,
                "{} must not be retried",
                code.as_str()
            );
            assert!(matches!(
                decision.action,
                UserAction::PairAgain | UserAction::Update | UserAction::FixConfiguration
            ));
        }
        // The codes section 23 calls authentication and schema failures are the ones the protocol
        // marks as needing a configuration or software change. A pairing invitation that expired
        // or was refused is a new owner action instead, which is why it is not in this list.
        for code in [
            ErrorCode::PairingAuthFailed,
            ErrorCode::UnsupportedSchema,
            ErrorCode::UnsupportedCapability,
            ErrorCode::InvalidArgument,
            ErrorCode::PermissionDenied,
        ] {
            assert_eq!(
                code.retry_category(),
                RetryCategory::ConfigurationChange,
                "{} is not a configuration or software change",
                code.as_str()
            );
        }
        // Every code the protocol marks that way stops here, whatever the class asks for.
        for code in ErrorCode::ALL
            .iter()
            .filter(|code| code.retry_category() == RetryCategory::ConfigurationChange)
        {
            for class in RequestClass::ALL {
                assert_eq!(
                    decision(Failure::new(*code), class).recovery,
                    Recovery::Stop,
                    "{} was not stopped for {}",
                    code.as_str(),
                    class.as_str()
                );
            }
        }
    }

    #[test]
    fn the_hosts_retry_after_is_honoured_and_a_bounded_backoff_stands_in_when_it_said_nothing() {
        for code in [
            ErrorCode::RateLimited,
            ErrorCode::ServiceCapacity,
            ErrorCode::QuotaExceeded,
        ] {
            let stated = Duration::from_secs(42);
            let stated_decision =
                decision(Failure::after(code, stated), RequestClass::IdempotentRead);
            assert_eq!(
                stated_decision.delay(),
                Some(stated),
                "{} ignored the host's figure",
                code.as_str()
            );
            // Forty-two seconds is longer than a caller should be held inside one call, so it is
            // reported rather than waited out.
            assert_eq!(
                stated_decision.recovery,
                Recovery::RepeatNoSoonerThan { delay: stated }
            );

            let delay = decision(Failure::new(code), RequestClass::IdempotentRead)
                .delay()
                .expect("a bounded backoff stands in");
            assert!(delay >= RETRY_BACKOFF_MIN && delay <= RETRY_BACKOFF_MAX);
        }
        // An exhausted allowance is a refusal whatever the class, because the category says so.
        let spent = decision(
            Failure::new(ErrorCode::QuotaExceeded),
            RequestClass::IdempotentRead,
        );
        assert!(!spent.retries_automatically());
        assert_eq!(spent.category, RetryCategory::NoRetry);
    }

    #[test]
    fn a_short_stated_delay_is_waited_out_and_a_long_one_is_handed_back() {
        let mut attempts = Attempts::new();
        let short = attempts.decide(
            Failure::after(ErrorCode::ResourceUnavailable, Duration::from_millis(5)),
            RequestClass::TransferChunk,
        );
        assert_eq!(
            short.recovery,
            Recovery::Retry {
                delay: Duration::from_millis(5)
            }
        );
        let long = attempts.decide(
            Failure::after(ErrorCode::ResourceUnavailable, MAX_AUTOMATIC_DELAY * 2),
            RequestClass::TransferChunk,
        );
        assert!(matches!(long.recovery, Recovery::RepeatNoSoonerThan { .. }));
        assert_eq!(
            attempts.remaining(),
            MAX_AUTOMATIC_RETRIES - 1,
            "only the attempt that was made was charged"
        );
    }

    #[test]
    fn the_budget_runs_out_and_the_decision_returns_to_the_caller() {
        let mut attempts = Attempts::with_retries(2);
        for _ in 0..2 {
            let decision = attempts.decide(
                Failure::new(ErrorCode::ResourceUnavailable),
                RequestClass::IdempotentRead,
            );
            assert!(decision.retries_automatically());
        }
        assert_eq!(attempts.remaining(), 0);
        let decision = attempts.decide(
            Failure::new(ErrorCode::ResourceUnavailable),
            RequestClass::IdempotentRead,
        );
        assert!(matches!(
            decision.recovery,
            Recovery::RepeatNoSoonerThan { .. }
        ));
    }

    #[test]
    fn a_transient_failure_of_a_dispatchable_request_is_never_retried_by_the_library() {
        for code in ErrorCode::ALL {
            let decision = decision(Failure::new(*code), RequestClass::Dispatchable);
            assert!(
                !decision.retries_automatically(),
                "{} retried a request that may have been dispatched",
                code.as_str()
            );
        }
    }

    #[test]
    fn the_delay_grows_while_a_request_keeps_failing() {
        let mut attempts = Attempts::with_retries(u32::MAX);
        assert_eq!(attempts.ceiling(), RETRY_BACKOFF_MIN);
        let mut delays = Vec::new();
        let mut ceilings = Vec::new();
        for _ in 0..8 {
            delays.push(
                attempts
                    .decide(
                        Failure::new(ErrorCode::ResourceUnavailable),
                        RequestClass::IdempotentRead,
                    )
                    .delay()
                    .expect("a transient failure has a delay"),
            );
            ceilings.push(attempts.ceiling());
        }
        // The delay itself is drawn under the ceiling, so what rises deterministically is the
        // ceiling. Asserting on a jittered draw would be asserting on the draw.
        assert_eq!(ceilings[0], RETRY_BACKOFF_MIN * 2);
        assert!(ceilings.windows(2).all(|pair| pair[1] >= pair[0]));
        assert_eq!(attempts.ceiling(), RETRY_BACKOFF_MAX);
        assert!(delays.iter().all(|delay| *delay >= RETRY_BACKOFF_MIN));
        assert!(delays.iter().all(|delay| *delay <= RETRY_BACKOFF_MAX));
    }
}
