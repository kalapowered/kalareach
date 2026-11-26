//! The words a package writes for its ACP launch take the text rule of the owner's client.
//!
//! The owner's client refuses to show a statement that holds a control character, a character that
//! reorders or hides text, or white space other than the space, and then offers nothing to
//! confirm. The package check holds the publisher's words of the launch to the same text. These
//! cases hold the two rules equal for every Unicode scalar value, for the launch's words alone:
//! the words of a bridge and of a command integration take a wider text rule.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.26 | the words of a launch pass the package check exactly when the owner's client treats them as plain text |

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
