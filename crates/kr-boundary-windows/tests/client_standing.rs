//! Which clients of the broker are refused for what their token is, and which are not. The
//! permission computation does not model an elevated administrator, a restricted token, an app
//! container, a low integrity level or a connection that cannot be identified, so the broker
//! refuses each of them, with a text, before it computes anything for the client.

use kr_boundary_windows::frame::invocation::{MAX_DETAIL_BYTES, RefusedKind};
use kr_boundary_windows::standing::{
    HIGH_INTEGRITY, MEDIUM_INTEGRITY, RULE_APP_CONTAINER, RULE_ELEVATED, RULE_LEVEL, RULE_LOW,
    RULE_RESTRICTED, TokenFacts, refuse,
};

/// What an ordinary person's token reads as: medium integrity, nothing elevated, nothing
/// restricted, identified at the level the pipe's own open asks for.
fn ordinary() -> TokenFacts {
    TokenFacts {
        impersonation_level: 2,
        elevated: false,
        administrators_enabled: false,
        integrity: MEDIUM_INTEGRITY,
        restricted: false,
        app_container: false,
    }
}

fn refused_by(facts: &TokenFacts) -> &'static str {
    let refusal = refuse(facts).expect_err("the client is refused");
    assert_eq!(refusal.kind, RefusedKind::Authentication);
    assert!(!refusal.detail().is_empty());
    assert!(refusal.detail().len() <= MAX_DETAIL_BYTES);
    assert!(
        refusal
            .detail()
            .bytes()
            .all(|byte| (0x20..0x7f).contains(&byte))
    );
    refusal.rule
}

#[test]
fn an_ordinary_persons_token_is_not_refused() {
    assert_eq!(refuse(&ordinary()), Ok(()));
}

#[test]
fn a_token_between_medium_and_high_integrity_is_not_refused() {
    let facts = TokenFacts {
        integrity: MEDIUM_INTEGRITY + 0x100,
        ..ordinary()
    };
    assert_eq!(refuse(&facts), Ok(()));
}

#[test]
fn an_elevated_token_is_refused_by_the_flag_alone() {
    let facts = TokenFacts {
        elevated: true,
        ..ordinary()
    };
    assert_eq!(refused_by(&facts), RULE_ELEVATED);
}

#[test]
fn an_unsplit_administrator_is_refused_by_the_group_alone() {
    // An administrator whose token was never split reports the default elevation type; the group
    // enabled in the token is what shows it.
    let facts = TokenFacts {
        administrators_enabled: true,
        ..ordinary()
    };
    assert_eq!(refused_by(&facts), RULE_ELEVATED);
}

#[test]
fn a_token_at_high_integrity_or_above_is_refused_by_the_level_alone() {
    for integrity in [HIGH_INTEGRITY, HIGH_INTEGRITY + 0x1000] {
        let facts = TokenFacts {
            integrity,
            ..ordinary()
        };
        assert_eq!(
            refused_by(&facts),
            RULE_ELEVATED,
            "integrity {integrity:#x}"
        );
    }
}

#[test]
fn a_restricted_token_is_refused() {
    let facts = TokenFacts {
        restricted: true,
        ..ordinary()
    };
    assert_eq!(refused_by(&facts), RULE_RESTRICTED);
}

#[test]
fn an_app_container_is_refused() {
    let facts = TokenFacts {
        app_container: true,
        ..ordinary()
    };
    assert_eq!(refused_by(&facts), RULE_APP_CONTAINER);
}

#[test]
fn a_token_below_medium_integrity_is_refused() {
    for integrity in [0, 0x1000, MEDIUM_INTEGRITY - 1] {
        let facts = TokenFacts {
            integrity,
            ..ordinary()
        };
        assert_eq!(refused_by(&facts), RULE_LOW, "integrity {integrity:#x}");
    }
}

#[test]
fn a_connection_below_identification_level_is_refused() {
    let facts = TokenFacts {
        impersonation_level: 0,
        ..ordinary()
    };
    assert_eq!(refused_by(&facts), RULE_LEVEL);
}

#[test]
fn a_token_in_several_of_these_states_is_refused_by_the_first_in_the_order_of_the_rules() {
    let facts = TokenFacts {
        impersonation_level: 0,
        elevated: true,
        administrators_enabled: true,
        integrity: 0x1000,
        restricted: true,
        app_container: true,
    };
    assert_eq!(refused_by(&facts), RULE_ELEVATED);
    let facts = TokenFacts {
        elevated: false,
        administrators_enabled: false,
        ..facts
    };
    assert_eq!(refused_by(&facts), RULE_RESTRICTED);
    let facts = TokenFacts {
        restricted: false,
        ..facts
    };
    assert_eq!(refused_by(&facts), RULE_APP_CONTAINER);
    let facts = TokenFacts {
        app_container: false,
        ..facts
    };
    assert_eq!(refused_by(&facts), RULE_LOW);
    let facts = TokenFacts {
        integrity: MEDIUM_INTEGRITY,
        ..facts
    };
    assert_eq!(refused_by(&facts), RULE_LEVEL);
}

#[test]
fn the_process_must_run_as_the_account_that_opened_the_connection() {
    use kr_boundary_windows::standing::{RULE_PROCESS, same_user};
    assert_eq!(
        same_user("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"),
        Ok(())
    );
    let refusal = same_user("S-1-5-21-1-2-3-1001", "S-1-5-18").unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Authentication);
    assert_eq!(refusal.rule, RULE_PROCESS);
}

#[test]
fn only_an_enrolled_account_is_served() {
    use kr_boundary_windows::standing::{RULE_NOT_ENROLLED, enrolled};
    let persons = vec![
        "S-1-5-21-1-2-3-1001".to_owned(),
        "S-1-5-21-1-2-3-1002".to_owned(),
    ];
    assert_eq!(enrolled("S-1-5-21-1-2-3-1002", &persons), Ok(()));
    let refusal = enrolled("S-1-5-21-1-2-3-1003", &persons).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Authentication);
    assert_eq!(refusal.rule, RULE_NOT_ENROLLED);
    assert!(enrolled("S-1-5-21-1-2-3-1001", &[]).is_err());
}
