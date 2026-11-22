//! The standing of a client's token: which tokens the broker serves, decided from facts that the
//! platform's own calls read off the token.
//!
//! The broker computes what a client may do from the client's permission entries, and that
//! computation does not model an elevated administrator (whose token would widen a grant to folders
//! only administrators can change), a restricted token, an app container, a token below medium
//! integrity or a connection that cannot be identified. Each of them is refused, with a text, before
//! anything is computed or granted. The facts are read in `win::client`; the decision is here so
//! that it is held to every combination on every platform.

use crate::frame::invocation::RefusedKind;
use crate::refusal::Refusal;

/// The medium integrity level: the level of an ordinary person's session.
pub const MEDIUM_INTEGRITY: u32 = 0x2000;
/// The high integrity level: the level of an elevated session.
pub const HIGH_INTEGRITY: u32 = 0x3000;
/// The least level of impersonation at which the broker can read a caller's token: identification.
pub const IDENTIFICATION: u32 = 1;

/// The rule that refuses an elevated token.
pub const RULE_ELEVATED: &str = "client-elevated";
/// The rule that refuses a restricted token.
pub const RULE_RESTRICTED: &str = "client-restricted";
/// The rule that refuses an app container.
pub const RULE_APP_CONTAINER: &str = "client-app-container";
/// The rule that refuses a token below medium integrity.
pub const RULE_LOW: &str = "client-low-integrity";
/// The rule that refuses a connection below identification level.
pub const RULE_LEVEL: &str = "client-identification-level";

/// The rule that refuses a connection whose caller cannot be identified.
pub const RULE_IDENTIFY: &str = "client-identify";
/// The rule that refuses a caller whose process cannot be held, or runs as another account than
/// the connection's.
pub const RULE_PROCESS: &str = "client-process";
/// The rule that refuses an account that is not enrolled.
pub const RULE_NOT_ENROLLED: &str = "client-not-enrolled";

/// What a person reads when the client runs with administrator rights.
// text: ELEVATED_WORDS
pub const ELEVATED_WORDS: &str = "this program runs with administrator rights; run it from an ordinary session, not an elevated one";
/// What a person reads when the client runs with a restricted token.
// text: RESTRICTED_WORDS
pub const RESTRICTED_WORDS: &str =
    "this program runs with a restricted token; run it from an ordinary session";
/// What a person reads when the client runs inside an app container.
// text: APP_CONTAINER_WORDS
pub const APP_CONTAINER_WORDS: &str =
    "this program runs inside an app container; run it from an ordinary session";
/// What a person reads when the client runs below medium integrity.
// text: LOW_WORDS
pub const LOW_WORDS: &str =
    "this program runs at a low integrity level; run it from an ordinary session";
/// What a person reads when the broker cannot identify the client's connection.
// text: LEVEL_WORDS
pub const LEVEL_WORDS: &str =
    "the broker cannot identify the caller at the level its connection allows";

/// What a person reads when the caller's process does not run as the account that opened the
/// connection.
// text: PROCESS_WORDS
pub const PROCESS_WORDS: &str =
    "the caller's process does not run as the account that opened the connection";
/// What a person reads when the account is not enrolled.
// text: NOT_ENROLLED_WORDS
pub const NOT_ENROLLED_WORDS: &str = "this account is not enrolled for the repository boundary";

/// What the platform says of a client's token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenFacts {
    /// The level at which the caller allows the broker to act as it: 0 anonymous, 1 identification,
    /// 2 impersonation, 3 delegation.
    pub impersonation_level: u32,
    /// The token's own elevation flag.
    pub elevated: bool,
    /// Whether the Administrators group is enabled in the token (not deny-only). An administrator
    /// whose token was never split reports the default elevation type, so the group is read as well.
    pub administrators_enabled: bool,
    /// The relative identifier of the token's integrity level.
    pub integrity: u32,
    /// Whether the token is restricted.
    pub restricted: bool,
    /// Whether the token belongs to an app container.
    pub app_container: bool,
}

/// Decides whether a client with this token is served.
///
/// # Errors
///
/// Refuses with the kind `authentication`, naming the first rule that holds in this order: elevated,
/// restricted, app container, below medium integrity, below identification level.
pub fn refuse(facts: &TokenFacts) -> Result<(), Refusal> {
    let refused = |rule: &'static str, words: &str| {
        Err(Refusal::new(RefusedKind::Authentication, rule, words))
    };
    if facts.elevated || facts.administrators_enabled || facts.integrity >= HIGH_INTEGRITY {
        return refused(RULE_ELEVATED, ELEVATED_WORDS);
    }
    if facts.restricted {
        return refused(RULE_RESTRICTED, RESTRICTED_WORDS);
    }
    if facts.app_container {
        return refused(RULE_APP_CONTAINER, APP_CONTAINER_WORDS);
    }
    if facts.integrity < MEDIUM_INTEGRITY {
        return refused(RULE_LOW, LOW_WORDS);
    }
    if facts.impersonation_level < IDENTIFICATION {
        return refused(RULE_LEVEL, LEVEL_WORDS);
    }
    Ok(())
}

/// Decides that the process the pipe names runs as the account whose token opened the connection.
///
/// # Errors
///
/// Refuses with the kind `authentication` when the two accounts differ.
pub fn same_user(caller: &str, process: &str) -> Result<(), Refusal> {
    if caller == process {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusedKind::Authentication,
            RULE_PROCESS,
            PROCESS_WORDS,
        ))
    }
}

/// Decides that the account is one of the enrolled persons.
///
/// # Errors
///
/// Refuses with the kind `authentication` when the account is not in the list.
pub fn enrolled(user: &str, persons: &[String]) -> Result<(), Refusal> {
    if persons.iter().any(|person| person == user) {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusedKind::Authentication,
            RULE_NOT_ENROLLED,
            NOT_ENROLLED_WORDS,
        ))
    }
}

/// The refusal for a connection whose caller the broker could not identify, by any step.
#[must_use]
pub fn unidentified(rule: &'static str) -> Refusal {
    Refusal::new(RefusedKind::Authentication, rule, LEVEL_WORDS)
}
