//! The push gateway a build talks to.
//!
//! The official applications send their notification requests to the managed service's gateway. An
//! independently signed build names its own with the build input `KR_PUSH_GATEWAY_ORIGIN`, beside
//! the Firebase and APNs inputs it already gives. The input is read once, when the application is
//! built: nothing at run time or in the interface changes it, and the account the application signs
//! in to is not moved by it.
//!
//! This file is compiled twice. The build step refuses a build given a value that is not an origin,
//! so a mistyped input stops the build instead of giving an application that cannot register. The
//! library reads the value the build step accepted.

use kr_protocol::service::GatewayOrigin;

/// The build input that names the push gateway.
pub const BUILD_INPUT: &str = "KR_PUSH_GATEWAY_ORIGIN";

/// Returns the origin `value` names, or why it is not one a build may be given: an
/// `https://host[:port]` origin with nothing after the authority.
///
/// # Errors
///
/// Returns the rule the value breaks.
pub fn check(value: &str) -> Result<GatewayOrigin, String> {
    if !value.starts_with("https://") {
        return Err("a push gateway origin is an https origin".to_owned());
    }
    GatewayOrigin::new(value).map_err(|error| error.to_string())
}

/// The gateway a build talks to: the one the build was given, or `official` when it was given none.
///
/// # Errors
///
/// Returns the rule the given value breaks. The build step has refused such a value already, so
/// this is only reached by a caller that did not go through it.
pub fn choose(given: Option<&str>, official: &str) -> Result<GatewayOrigin, String> {
    match given {
        None | Some("") => GatewayOrigin::new(official).map_err(|error| error.to_string()),
        Some(value) => check(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICIAL: &str = "https://reach.kala.to";

    /// A build given no gateway talks to the official one, at the same text as before the input
    /// existed, so a store build puts the same origin in every request it signs.
    #[test]
    fn a_build_given_no_gateway_talks_to_the_official_one() {
        for given in [None, Some("")] {
            let chosen = choose(given, OFFICIAL).expect("the official origin");
            assert_eq!(chosen.as_str(), OFFICIAL);
        }
    }

    /// A build given its own gateway talks to that one.
    #[test]
    fn a_build_given_its_own_gateway_talks_to_it() {
        for own in [
            "https://push.builder.example",
            "https://push.builder.example:8443",
        ] {
            let chosen = choose(Some(own), OFFICIAL).expect("the builder's origin");
            assert_eq!(chosen.as_str(), own);
            check(own).expect("the build step takes it");
        }
    }

    /// What is not an `https://host[:port]` origin refuses the build rather than an application
    /// that cannot register: another scheme (a loopback one among them), a path, a query, a
    /// fragment, credentials, a missing or a non-canonical host, and surrounding space.
    #[test]
    fn a_value_that_is_not_an_https_origin_refuses_the_build() {
        for malformed in [
            "http://push.builder.example",
            "http://127.0.0.1:8787",
            "ftp://push.builder.example",
            "push.builder.example",
            "https://",
            "https://push.builder.example/",
            "https://push.builder.example/api/push",
            "https://push.builder.example?a=1",
            "https://push.builder.example#fragment",
            "https://user@push.builder.example",
            "https://Push.Builder.Example",
            "https://push.builder.example:443",
            " https://push.builder.example",
            "https://push.builder.example ",
        ] {
            assert!(check(malformed).is_err(), "{malformed:?}");
            assert!(choose(Some(malformed), OFFICIAL).is_err(), "{malformed:?}");
        }
    }
}
