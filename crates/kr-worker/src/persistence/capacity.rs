//! What a full durable store admits, and what it refuses before dispatch.
//!
//! Section 24: *if a required durable store is full, reject new durable mutations before dispatch,
//! subject only to the explicit stop and native-terminal exceptions.* The two halves of that
//! matter equally. **Before dispatch** is what keeps the refusal a rejection rather than an
//! uncertain outcome: nothing has been sent, so the caller is told no rather than told nothing.
//! And the exceptions are exactly two, named in sections 7 and 11 rather than invented here.
//!
//! A full store is not a special case of a broken one, and the difference is worth keeping: a
//! person whose disk is full can do something about it, and the refusal says so.

use kr_protocol::error::{ErrorCode, ProtocolError};

use crate::persistence::fault::{DurabilityPosture, FaultKind, WorkClass};

/// An exception a full or faulted durable store does not refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exception {
    /// Section 7: `session.close` proceeds on the worker's current in-memory authority and
    /// reports `durability=volatile`. Storage failure must not prevent an authorised stop.
    AuthorisedStop,
    /// Section 11: raw terminal input and interruption remain available under the live input
    /// lease. Neither exception authorises a hidden rich retry.
    NativeTerminal,
}

impl Exception {
    /// Returns which section names this exception.
    #[must_use]
    pub const fn stated_in(self) -> &'static str {
        match self {
            Self::AuthorisedStop => {
                "section 7, storage failure must not prevent an authorised stop"
            }
            Self::NativeTerminal => {
                "section 11, raw terminal input and interruption under the live input lease"
            }
        }
    }
}

/// What a store's capacity admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreCapacity;

impl StoreCapacity {
    /// Returns the exception this class of work falls under, if any.
    #[must_use]
    pub const fn exception_for(work: WorkClass) -> Option<Exception> {
        match work {
            WorkClass::AuthorisedStop => Some(Exception::AuthorisedStop),
            WorkClass::NativeTerminal => Some(Exception::NativeTerminal),
            // A read writes nothing, so a full store does not refuse it. It is not an exception
            // to the rule; it is outside it.
            WorkClass::RichMutation | WorkClass::Read => None,
        }
    }

    /// Returns whether this class of work proceeds under this posture.
    #[must_use]
    pub fn admits(posture: &DurabilityPosture, work: WorkClass) -> bool {
        posture.admits(work)
    }

    /// Returns the refusal a new durable mutation receives, before anything is dispatched.
    ///
    /// `STORAGE_UNAVAILABLE` is the code section 7 names for every other typed mutation when the
    /// journal cannot be written, and a full store is that condition.
    #[must_use]
    pub fn refusal(kind: FaultKind) -> ProtocolError {
        let detail = match kind {
            FaultKind::Full => {
                "the session journal's durable store is full, so no new mutation is dispatched"
            }
            FaultKind::Absent => {
                "the session journal is unavailable, so no durable mutation is accepted"
            }
            FaultKind::Corrupt => {
                "the session journal cannot be read back, so no new mutation is dispatched"
            }
            FaultKind::WriteFailed => {
                "the session journal could not be written, so no new mutation is dispatched"
            }
        };
        ProtocolError::new(ErrorCode::StorageUnavailable, detail.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::fault::JournalFault;
    use kr_protocol::scalars::TimestampMs;

    fn full() -> DurabilityPosture {
        DurabilityPosture::VolatileNative(JournalFault {
            kind: FaultKind::Full,
            detail: "database or disk is full".to_owned(),
            observed_at_ms: TimestampMs::new(5),
            durable_through: 3,
        })
    }

    #[test]
    fn a_full_store_refuses_a_rich_mutation_and_admits_exactly_two_exceptions() {
        let posture = full();
        assert!(!StoreCapacity::admits(&posture, WorkClass::RichMutation));
        assert!(StoreCapacity::admits(&posture, WorkClass::AuthorisedStop));
        assert!(StoreCapacity::admits(&posture, WorkClass::NativeTerminal));
        assert!(StoreCapacity::admits(&posture, WorkClass::Read));
    }

    #[test]
    fn every_admitted_write_names_the_section_that_admits_it() {
        assert_eq!(
            StoreCapacity::exception_for(WorkClass::AuthorisedStop),
            Some(Exception::AuthorisedStop)
        );
        assert_eq!(
            StoreCapacity::exception_for(WorkClass::NativeTerminal),
            Some(Exception::NativeTerminal)
        );
        assert_eq!(StoreCapacity::exception_for(WorkClass::RichMutation), None);
        assert!(
            Exception::AuthorisedStop
                .stated_in()
                .starts_with("section 7")
        );
        assert!(
            Exception::NativeTerminal
                .stated_in()
                .starts_with("section 11")
        );
    }

    #[test]
    fn a_full_store_is_refused_as_a_full_store_rather_than_as_a_broken_one() {
        let refusal = StoreCapacity::refusal(FaultKind::Full);
        assert_eq!(refusal.code, ErrorCode::StorageUnavailable);
        assert!(refusal.message.contains("full"));
        let broken = StoreCapacity::refusal(FaultKind::WriteFailed);
        assert_eq!(broken.code, ErrorCode::StorageUnavailable);
        assert!(!broken.message.contains("full"));
    }

    #[test]
    fn a_healthy_store_admits_everything() {
        for work in [
            WorkClass::RichMutation,
            WorkClass::AuthorisedStop,
            WorkClass::NativeTerminal,
            WorkClass::Read,
        ] {
            assert!(StoreCapacity::admits(&DurabilityPosture::Full, work));
        }
    }
}
