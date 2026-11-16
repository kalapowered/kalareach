//! What a person is asked to do after the words of a stop of the keeper that gets a member's lease
//! (KR-REQ-17.53, KR-REQ-17.48).
//!
//! A stop whose words say their own next step asks nothing more: a second instruction would repeat
//! the first or contradict it. A stop that states only a fact asks what tells the person what to do.

use std::time::Duration;

use kr_client::organisation::LeaseStop;
use kr_client::retry::UserAction;

/// Every stop, with what it asks of the person after its words.
fn every_stop() -> [(LeaseStop, UserAction); 10] {
    [
        // Each of these says its own next step: sign in again, ask the administrator, update this
        // app, wait, or that this app asks again.
        (LeaseStop::SignIn, UserAction::Nothing),
        (LeaseStop::TokenRefused, UserAction::Nothing),
        (LeaseStop::NotAMember, UserAction::Nothing),
        (LeaseStop::Refused("bad_signature"), UserAction::Nothing),
        (LeaseStop::Unusable, UserAction::Nothing),
        (
            LeaseStop::Later(Duration::from_secs(600)),
            UserAction::Nothing,
        ),
        (LeaseStop::Unreachable, UserAction::Nothing),
        (LeaseStop::AccountChanged, UserAction::Nothing),
        (LeaseStop::Presenting, UserAction::Nothing),
        // This one states a fact: the connection ended before a lease was held.
        (LeaseStop::ConnectionEnded, UserAction::Wait),
    ]
}

#[test]
fn kr_req_17_53_a_stop_that_says_its_next_step_asks_nothing_and_one_that_states_a_fact_asks_a_wait()
{
    for (stop, asks) in every_stop() {
        assert_eq!(stop.user_action(), asks, "{stop}");
    }
}

#[test]
fn kr_req_17_53_an_account_that_is_not_a_member_is_told_what_to_do() {
    assert_eq!(
        LeaseStop::NotAMember.to_string(),
        "this account is not a member of the organisation this host answers to; sign in with an \
         account that is a member, or ask your organisation's administrator"
    );
}
