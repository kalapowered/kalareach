//! Privacy mode against the services its work reaches.
//!
//! Section 24 turns privacy mode on while work is on its way to a service, and asks two things of
//! what follows. No result that work produced under the old generation is published afterwards,
//! and cleanup is reconciled before privacy mode reports complete. And what had already left is not
//! erased: it is shown, and removed only by an action of its own, separately authorised. Every other
//! suite holds the client's privacy operations to a service written for the test. These legs hold
//! them to the web service itself: a local deployment that `wrangler dev` serves, or a deployment
//! over HTTPS.
//!
//! * **Sync** (`tests/sync.rs`): a settings write and a draft publication are at the service, their
//!   answers held on the way back, when the client enables privacy mode. It holds the client to its
//!   fence, its cancellation, its cleanup and its reconciliation, and to what disabling privacy mode
//!   brings back, which is nothing.
//! * **Retained artifacts** (`tests/retained.rs`, a local deployment only): two backup collections
//!   and a notification the push gateway still holds are in place when the client enables privacy
//!   mode. Nothing of them goes, and each goes only through its own action: the account console's
//!   deletion with the account's session, and the gateway's forget with the credential the
//!   installation issued.
//!
//! # What they run against
//!
//! [`ORIGIN_VARIABLE`] names the service and [`STATE_VARIABLE`] the persistence directory of a local
//! deployment, which the retained-artifact leg reads beside the running service. A leg without the
//! variables it needs says why it did nothing and passes, so an ordinary test run of this workspace
//! stays offline; [`REQUIRE_VARIABLE`] set to `1` turns that absence into a failure, which is how a
//! run that promised a service finds out that it did not get one. `scripts/e2e-privacy.sh` sets them.
//!
//! # What they leave
//!
//! Every key is made for the run and discarded with it, and every identifier is drawn fresh. The
//! sync leg ends every request identity it presented and empties every collection it wrote, whether
//! it passed or failed, and names anything the service would not take back in [`GIVE_BACK`]'s
//! words. What a deployment keeps by its own rules stays: the receipt of each identity for thirty
//! days, a content-free record of each removed object's place in the order, spent nonces, and the
//! ledger's record of the installation the run key made.

pub mod giveback;
pub mod held;
pub mod local;
pub mod push;

pub use kr_sync_integration::{
    Deployment, GIVE_BACK, ORIGIN_VARIABLE, REQUIRE_VARIABLE, RunKey, fresh_uuid, now_ms, proved,
};

/// The variable naming a local deployment's persistence directory.
///
/// The retained-artifact leg reads two things there that a device receives from outside the
/// service: the sign-in code the deployment's mail sink kept, and the challenge its push gateway sent
/// through the provider. A deployment reached over HTTPS has neither, so that leg is local only.
pub const STATE_VARIABLE: &str = "KR_PRIVACY_STATE";

/// The variable naming the origin a run is about to use, which
/// `the_origin_a_run_is_about_to_use_is_one_a_credential_travels_to` holds to the product's own rule.
///
/// `scripts/e2e-privacy.sh` runs that check before it starts or sends anything, so the script accepts
/// exactly the origins a managed-service credential may be bound to and refuses the rest as unusable,
/// without a second copy of the rule that could drift from the product's.
pub const CHECK_ORIGIN_VARIABLE: &str = "KR_PRIVACY_CHECK_ORIGIN";

/// Whether this run was promised the services its legs need.
#[must_use]
pub fn required() -> bool {
    std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1")
}

/// The value of one variable, or nothing when the run did not set it.
///
/// # Panics
///
/// Panics when the run was promised its services and the variable is missing, because a leg that
/// was meant to run and quietly did not has proved nothing.
#[must_use]
pub fn variable(name: &str) -> Option<String> {
    let value = std::env::var(name).unwrap_or_default();
    if value.is_empty() {
        assert!(
            !required(),
            "{REQUIRE_VARIABLE}=1 and {name} is not set, so this leg could not run"
        );
        eprintln!("skipping: {name} is not set, so nothing was sent anywhere");
        return None;
    }
    Some(value)
}

/// The line a leg prints once it has given back everything it took.
///
/// `scripts/e2e-privacy.sh` says a leg's collections were emptied only when it finds this line, so a
/// leg that stopped before it could give anything back is never reported as having done so.
pub const GAVE_BACK: &str = "this leg gave back everything it took";

/// Reports what a leg could not give back, one line each, or that it gave back everything.
pub fn report_left(left: &[String]) {
    if left.is_empty() {
        println!("{GAVE_BACK}");
    }
    for what in left {
        println!("{}", not_given_back(what));
    }
}

/// One line of what a leg could not give back, as `scripts/e2e-privacy.sh` collects it.
///
/// One line whatever the failure said: the script reads a leg's output line by line, so a line
/// break inside a failure would cut what follows it out of the report. Every control character is
/// written as its escape instead.
#[must_use]
pub fn not_given_back(what: &str) -> String {
    let mut line = format!("this leg could not {GIVE_BACK}: ");
    for character in what.chars() {
        match character {
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            control if control.is_control() => {
                line.push_str(&format!("\\u{{{:x}}}", u32::from(control)));
            }
            other => line.push(other),
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use kr_protocol::service::GatewayOrigin;

    use super::*;

    /// The check `scripts/e2e-privacy.sh` runs on the origin it was given; it does nothing when no
    /// origin is named.
    #[test]
    fn the_origin_a_run_is_about_to_use_is_one_a_credential_travels_to() {
        let Ok(origin) = std::env::var(CHECK_ORIGIN_VARIABLE) else {
            return;
        };
        if let Err(error) = GatewayOrigin::new(origin) {
            panic!("not an origin a service credential travels to: {error}");
        }
    }

    #[test]
    fn what_a_leg_left_is_one_line_in_the_words_the_script_reads() {
        let line = not_given_back("a collection still held\r\nan object\t\u{7}");
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(line.contains(GIVE_BACK), "{line}");
        assert!(
            line.ends_with("a collection still held\\r\\nan object\\t\\u{7}"),
            "{line}"
        );
    }
}
