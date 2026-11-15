//! What a check of `kr doctor` says when a managed service has no capacity for something new.
//!
//! A service that has no managed capacity for a new name refuses with the code and the delay it
//! always used, and names the alternatives that still work. That is a limit of the service, and a
//! check says so in words that blame nothing on this host. Its sentences hold only words this build
//! wrote, so the alternatives it lists are the ones this build recognises, each as the service wrote
//! it, and the ones it does not recognise are counted ([`kr_client::services::Offered`]).
//!
//! What the host does about the refusal is decided by its code and its delay alone. These words
//! are chosen after that, and only when the refusal named alternatives: a refusal that names none
//! is a fault, and a check keeps its fault words.

use kr_client::services::Offered;
use kr_protocol::hostinfo::export::Sentence;

/// The service's limit on new mailboxes, said as a limit of the service.
pub const MAILBOXES: &str = "the service has no managed capacity for new mailboxes now, which is a limit of the service and not a fault of this host";

/// The service's limit on new authority feeds, said as a limit of the service.
pub const AUTHORITY_FEEDS: &str = "the service has no managed capacity for new authority feeds now, which is a limit of the service and not a fault of this host";

/// The service's limit on new backup collections, said as a limit of the service.
pub const BACKUP_COLLECTIONS: &str = "the service has no managed capacity for new backup collections now, which is a limit of the service and not a fault of this host";

/// Ends `sentence` with what a refusal named: "Until then:" and each alternative this build
/// recognises, on its own, and how many more the service named that this build cannot show. With
/// none recognised there is no "Until then:" and the count stands alone.
#[must_use]
pub fn listed(sentence: Sentence, offered: Offered) -> Sentence {
    let mut sentence = sentence;
    let mut any = false;
    for alternative in offered.recognised() {
        sentence = sentence
            .stated(if any { " " } else { ". Until then: " })
            .stated(alternative.words());
        any = true;
    }
    if offered.more() > 0 {
        sentence = sentence
            .stated(if any {
                " The service named "
            } else {
                ". The service named "
            })
            .number(offered.more())
            .stated(if any {
                " more that this version cannot show."
            } else {
                " that this version cannot show."
            });
    }
    sentence
}

#[cfg(test)]
mod tests {
    use kr_client::services::Alternatives;

    use super::*;

    /// What the sentence is, when it begins with a stop's own words.
    fn said(texts: &[&str]) -> String {
        let named = Alternatives::for_test(texts);
        listed(Sentence::new().stated("a stop"), named.offered()).render()
    }

    /// KR-REQ-17.48: a refusal that names only alternatives this build recognises lists them, each
    /// on its own, after "Until then:", in the words the service wrote.
    #[test]
    fn kr_req_17_48_every_alternative_recognised_is_listed_after_until_then() {
        assert_eq!(
            said(&[
                "An authority feed service that you run yourself.",
                "A revocation made on the host itself, without the feed."
            ]),
            "a stop. Until then: An authority feed service that you run yourself. A revocation made on the host itself, without the feed."
        );
    }

    /// KR-REQ-17.48: a refusal that names some this build does not recognise lists the others and
    /// says how many more it cannot show.
    #[test]
    fn kr_req_17_48_some_alternatives_recognised_are_listed_and_the_rest_counted() {
        assert_eq!(
            said(&[
                "A mailbox service that you run yourself.",
                "A path this version has never heard of."
            ]),
            "a stop. Until then: A mailbox service that you run yourself. The service named 1 more that this version cannot show."
        );
    }

    /// KR-REQ-17.48: a refusal that names alternatives and none is recognised ends with the count
    /// and has no "Until then:".
    #[test]
    fn kr_req_17_48_no_alternative_recognised_ends_with_the_count_and_no_until_then() {
        assert_eq!(
            said(&["A path this version has never heard of.", "Another one."]),
            "a stop. The service named 2 that this version cannot show."
        );
    }
}
