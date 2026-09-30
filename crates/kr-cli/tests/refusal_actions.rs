//! A refusal is said as the action a person takes, and not as its protocol code.
//!
//! Requirement row closed here: KR-REQ-23.57, the command line's half.

use kr_cli::error::CliError;
use kr_client::retry::UserAction;
use kr_client::shown::Said as _;
use kr_protocol::error::{ErrorCode, ProtocolError};

/// KR-REQ-23.57: what a person is told of a refusal is the action its code calls for and never the
/// code; a code that calls for nothing is said by the host's own words alone.
#[test]
fn a_refusal_is_said_as_its_action_and_not_as_its_code() {
    for code in ErrorCode::ALL {
        let said = CliError::Refused(ProtocolError::new(*code, "the host's words"))
            .said()
            .into_string();
        assert!(!said.contains(code.as_str()), "{said}");
        let action = kr_client::retry::user_action(*code);
        assert!(said.contains(action.message()), "{said}");
        assert!(said.contains("the host's words"), "{said}");
        if action == UserAction::Nothing {
            assert_eq!(said, "the host's words", "{code:?} calls for nothing");
        }
    }
}

/// KR-REQ-23.57: a refuser that knows more than its code says, a managed service that classifies
/// its own refusal, is heard: its action is the one a person is told, not the one the code alone
/// calls for.
#[test]
fn a_service_that_names_its_own_action_is_heard() {
    let code = ErrorCode::PermissionDenied;
    let own = UserAction::SignIn;
    assert_ne!(kr_client::retry::user_action(code), own);
    let said = CliError::ServiceRefused {
        error: ProtocolError::new(code, "the account is not signed in"),
        action: own,
    }
    .said()
    .into_string();
    assert!(said.contains(own.message()), "{said}");
    assert!(
        !said.contains(kr_client::retry::user_action(code).message()),
        "{said}"
    );
    assert!(!said.contains(code.as_str()), "{said}");
}

/// KR-REQ-23.57: a refusal this command makes in words of its own that say what to do is said by
/// those words alone, whatever action its code would call for, and `--json` still carries the code.
#[test]
fn a_refusal_in_its_own_words_is_not_given_the_codes_action_as_well() {
    for code in [
        ErrorCode::PermissionDenied,
        ErrorCode::ResourceUnavailable,
        ErrorCode::InvalidArgument,
    ] {
        assert_ne!(
            kr_client::retry::user_action(code),
            UserAction::Nothing,
            "{code:?} would add an action of its own"
        );
        let refused = CliError::refused_in_its_own_words(code, "cancel the invitation first");
        assert_eq!(
            refused.said().into_string(),
            "cancel the invitation first",
            "{code:?}"
        );
        assert_eq!(refused.code(), code, "the `--json` code is kept");
        assert!(
            refused
                .machine_message()
                .into_string()
                .starts_with(code.as_str()),
            "{code:?}"
        );
        assert_eq!(refused.exit_code(), 8, "the status of a refusal");
    }
}
