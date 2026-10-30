//! The push gateway a build talks to.
//!
//! The official applications send their notification requests to the managed service's gateway. An
//! independently signed build names its own with the build input `KR_PUSH_GATEWAY_ORIGIN`, beside
//! the Firebase and APNs inputs it already gives. The input is read once, when the application is
//! built: a release build has no other way to change the origin, and the account the application
//! signs in to is not moved by it.
//!
//! This file is compiled twice. The build step decides what a build may be given and writes what it
//! accepted to a file in the build's output directory; the library includes that file and reads the
//! origin from it. So the origin the build step reports is the origin the library uses, and nothing
//! else about the build can change it.

use kr_protocol::service::GatewayOrigin;

/// The build input that names the push gateway.
pub const BUILD_INPUT: &str = "KR_PUSH_GATEWAY_ORIGIN";

/// The build input the store scripts set to 1: this build is an official one, which registers with
/// the official gateway and is given no gateway of its own.
pub const OFFICIAL_BUILD_MARK: &str = "KR_OFFICIAL_BUILD";

/// The file in the build's output directory where the build step writes the origin it accepted.
macro_rules! record_file {
    () => {
        "push_gateway_origin"
    };
}
pub(crate) use record_file;

/// The text of the file the build step wrote: what the library reads its origin from.
///
/// The library includes the file where it is used, so the build step and the library name one file
/// and the compiler stops a library built without it.
macro_rules! the_builds_record {
    () => {
        include_str!(concat!(
            env!("OUT_DIR"),
            "/",
            $crate::push_origin::record_file!()
        ))
    };
}
pub(crate) use the_builds_record;

/// Separates the parts of the record. A control character stands in no origin and in no ordinary
/// text, so the record is found in the packaged library by what surrounds it.
pub const RECORD_SEPARATOR: char = '\u{1f}';

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

/// What a build may be given for its push gateway: nothing, or an origin. The official build is
/// given nothing, because it registers with the official gateway, and the mark that says so holds
/// whichever way the input reached the build, a Cargo configuration file's `[env]` table included.
///
/// # Errors
///
/// Returns the rule the input breaks.
pub fn accept(given: Option<&str>, official_build: bool) -> Result<Option<GatewayOrigin>, String> {
    match given {
        None | Some("") => Ok(None),
        Some(_) if official_build => Err(format!(
            "this build is marked official by {OFFICIAL_BUILD_MARK}, which registers with the \
             official push gateway and is given none: unset {BUILD_INPUT}, in the environment and \
             in any Cargo configuration file's [env] table"
        )),
        Some(value) => check(value).map(Some),
    }
}

/// The origin the build step recorded, or the empty text when it recorded none.
///
/// # Errors
///
/// Returns a failure when `record` is not what the build step writes.
pub fn given_by(record: &str) -> Result<&str, String> {
    let mut parts = record.split(RECORD_SEPARATOR);
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(""), Some(_), Some(given), Some(""), None) => Ok(given),
        _ => Err("the build recorded no push gateway origin".to_owned()),
    }
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
            accept(Some(own), false).expect("the build step takes it");
        }
    }

    /// What is not an `https://host[:port]` origin refuses the build rather than an application that
    /// cannot register. The `https` scheme is this module's rule: the protocol's origin type also
    /// takes a loopback `http` one. The rest of the grammar is that type's, which the module defers
    /// to; a path stands for it.
    #[test]
    fn a_value_that_is_not_an_https_origin_refuses_the_build() {
        for malformed in [
            "http://127.0.0.1:8787",
            "https://push.builder.example/api/push",
        ] {
            assert!(accept(Some(malformed), false).is_err(), "{malformed:?}");
            assert!(choose(Some(malformed), OFFICIAL).is_err(), "{malformed:?}");
        }
    }

    /// An official build is given no gateway of its own: any value refuses it, the official
    /// gateway's own text and a well-formed origin alike, and no value is the official build's
    /// answer.
    #[test]
    fn an_official_build_is_given_no_gateway() {
        for given in [OFFICIAL, "https://push.builder.example"] {
            assert!(accept(Some(given), true).is_err(), "{given:?}");
        }
        for given in [None, Some("")] {
            assert_eq!(accept(given, true), Ok(None));
        }
    }

    /// The record is read as the build step writes it, and nothing else is a record.
    #[test]
    fn the_record_is_read_as_the_build_step_writes_it() {
        let separator = RECORD_SEPARATOR;
        for (given, record) in [
            ("", format!("{separator}name{separator}{separator}")),
            (
                "https://push.builder.example",
                format!("{separator}name{separator}https://push.builder.example{separator}"),
            ),
        ] {
            assert_eq!(given_by(&record), Ok(given));
        }
        for malformed in ["", "https://push.builder.example", "\u{1f}name\u{1f}x"] {
            assert!(given_by(malformed).is_err(), "{malformed:?}");
        }
    }
}
