//! The marker test for the command line: one marker, planted where a person, a stored file, a host
//! or a peer supplies text, and no rendering of the failure that holds it.
//!
//! The spellings are the client library's: the marker's text, its bytes as decimals and as
//! hexadecimal, and base64 and base64url in each alignment. The renderings are every way the
//! command line says a failure: `Display`, both `Debug` forms, the line the reporter writes on
//! standard error, the `--json` failure document, and the panic an `expect` on it raises.

use crate::error::CliError;

/// Stands for everything a diagnostic must not show.
pub(crate) const MARKER: &str = "kr-marker-7c1e";

/// Encodes `bytes` in base64 with `alphabet`, unpadded.
fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let group = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for position in 0..=chunk.len() {
            let index = (bits >> (18 - 6 * position)) & 0x3f;
            encoded.push(char::from(alphabet[index as usize]));
        }
    }
    encoded
}

/// Every spelling of the marker a rendering could carry it in.
fn spellings() -> Vec<String> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = MARKER.as_bytes();
    let decimal = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut spellings = vec![MARKER.to_owned(), decimal, hex];
    for alphabet in [STANDARD, URL_SAFE] {
        for lead in 0..3 {
            let mut padded = vec![0_u8; lead];
            padded.extend_from_slice(bytes);
            let encoded = base64(&padded, alphabet);
            // What is between the first four characters and the last three is the marker's own in
            // every alignment.
            spellings.push(encoded[4..encoded.len() - 3].to_owned());
        }
    }
    spellings
}

/// Holds every rendering to carrying no spelling of the marker, as it is and with its whitespace
/// taken out.
pub(crate) fn assert_unmarked(label: &str, renderings: &[String]) {
    let spellings = spellings();
    for rendering in renderings {
        let condensed = rendering.split_whitespace().collect::<String>();
        for spelling in &spellings {
            let spelling_condensed = spelling.split_whitespace().collect::<String>();
            assert!(
                !rendering.contains(spelling.as_str())
                    && !condensed.contains(spelling_condensed.as_str()),
                "{label}: a rendering carries the marker ({spelling}): {rendering}"
            );
        }
    }
}

/// Every way the command line says a failure.
pub(crate) fn failure_renderings(error: CliError) -> Vec<String> {
    let mut renderings = vec![
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
        kr_client::shown!("kr: {}", error).into_string(),
        crate::report::failure(&error).to_string(),
    ];
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let failed: Result<(), CliError> = std::hint::black_box(Err(error));
        failed.expect("the command failed");
    }))
    .expect_err("the expect panics");
    renderings.push(
        caught
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| caught.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default(),
    );
    renderings
}

/// The spellings cover what they say they do, so a rendering in any of them is caught.
#[test]
fn every_spelling_of_the_marker_is_caught() {
    let bytes = MARKER.as_bytes();
    let renderings = [
        MARKER.to_owned(),
        format!("{bytes:?}"),
        format!("{bytes:#?}"),
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        format!(
            "xx{}yy",
            base64(
                bytes,
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            )
        ),
        base64(
            &[b"a".as_slice(), bytes].concat(),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        ),
    ];
    for rendering in renderings {
        let caught = std::panic::catch_unwind(|| {
            assert_unmarked("the control", std::slice::from_ref(&rendering));
        });
        assert!(caught.is_err(), "not caught: {rendering}");
    }
    assert_unmarked("a rendering without it", &["neutral-value".to_owned()]);
}
