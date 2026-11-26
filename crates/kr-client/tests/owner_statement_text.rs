//! The words a package writes for a launch grant are the words an owner's confirmation shows.
//!
//! The owner's client refuses to show a statement that holds a control character, a character that
//! reorders or hides text, or white space other than the space, and then offers nothing to
//! confirm. The package check holds the publisher's words to the same text, so a package that
//! passes the check is a package an owner can confirm. These cases hold the two rules equal for
//! every Unicode scalar value.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.26 | a launch's words pass the package check exactly when the owner's client shows them whole |

use kr_client::pairing::owner::is_plain_text;
use kr_plugin_sdk::text::GrantWords;

/// KR-REQ-11.26: for every Unicode scalar value, words that hold it pass the package check exactly
/// when the owner's client shows them as they are written.
#[test]
fn kr_req_11_26_grant_words_are_the_text_the_owners_client_shows() {
    for code in 0..=0x0010_FFFF_u32 {
        let Some(character) = char::from_u32(code) else {
            continue;
        };
        let words = format!("Starts it{character}now");
        let accepted = GrantWords::new(&words).is_ok();
        assert_eq!(
            accepted,
            is_plain_text(&words),
            "U+{code:04X}: the package check and the owner's client disagree"
        );
    }
}
