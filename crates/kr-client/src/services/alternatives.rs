//! The alternatives a managed service names beside a refusal for a short budget.
//!
//! When a service has no managed capacity for a new name, it refuses with the code and the delay
//! it always used, and adds a list of alternatives inside the error object: the paths that still
//! work. The list changes what a person is told and nothing a caller does. The code and the delay
//! decide the action, so no loop of this client reads the list; a refusal without it is read as it
//! always was, and what it says is the fault's words.
//!
//! A line that cannot carry a service's text, such as a check of `kr doctor`, whose sentences hold
//! only words this build wrote, lists the alternatives it recognises. [`Alternative`] holds the
//! words of every alternative this build knows, in one place, and a received text is recognised
//! only when it equals one of them exactly. What a build does not recognise is counted
//! ([`Offered::more`]) and never dropped in silence. A line that can carry a service's text takes
//! every alternative as the service wrote it ([`Alternatives::as_given`]).
//!
//! The list is read by one rule ([`Alternatives::from_member`]), whichever reader meets it, and a
//! line that carries a service's text and a wait composes them in one way ([`told_capacity`]).

use std::fmt;

use crate::shown::{ServiceMessage, Shown};

/// The words that lead the list of alternatives in a text told to a person. What composes such a
/// text ([`Alternatives::until_then`]) and the tests that read one both read this
/// one constant, so that neither can say it differently.
const UNTIL_THEN: &str = "Until then:";

/// The most alternatives one refusal is read to carry. A service names two at most; a list past
/// this is cut, and the cut ones are counted as ones this build cannot show.
const MOST: usize = 16;

/// One alternative whose words this build knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alternative {
    /// A mailbox service that the host's person runs.
    OwnMailboxService,
    /// An authority feed service that the host's person runs.
    OwnAuthorityFeedService,
    /// A revocation made on the host itself, with no feed.
    RevocationOnTheHost,
    /// A settings sync service that the person runs.
    OwnSettingsSyncService,
    /// A backup storage service that the person runs.
    OwnBackupStorageService,
    /// A connection between the devices that goes through no managed relay.
    DirectConnection,
    /// A relay the person runs.
    OwnRelay,
}

impl Alternative {
    /// Every alternative this build knows, in the order [`Offered::recognised`] lists them.
    pub const ALL: [Self; 7] = [
        Self::OwnMailboxService,
        Self::OwnAuthorityFeedService,
        Self::RevocationOnTheHost,
        Self::OwnSettingsSyncService,
        Self::OwnBackupStorageService,
        Self::DirectConnection,
        Self::OwnRelay,
    ];

    /// The words of the alternative, exactly as a service writes them.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::OwnMailboxService => "A mailbox service that you run yourself.",
            Self::OwnAuthorityFeedService => "An authority feed service that you run yourself.",
            Self::RevocationOnTheHost => "A revocation made on the host itself, without the feed.",
            Self::OwnSettingsSyncService => "A settings sync service that you run yourself.",
            Self::OwnBackupStorageService => "A backup storage service that you run yourself.",
            Self::DirectConnection => {
                "A direct connection between the devices, which needs no managed relay."
            }
            Self::OwnRelay => {
                "A relay that the host's owner runs. The host must name it in its configuration \
                 and use no managed relay. A new invitation from that host then names it."
            }
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    /// The alternative whose words are exactly `text`.
    fn recognised(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|alternative| alternative.words() == text)
    }
}

/// What a refusal's list of alternatives said, as the service wrote it.
///
/// Empty when the refusal carried no list, which is every refusal for a fault and every refusal
/// from a service that does not name alternatives. A refusal is returned by value from most of
/// this client, so an empty list is one pointer and a list is held apart from it.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Alternatives(Option<Box<[ServiceMessage]>>);

impl Alternatives {
    /// A refusal that named no alternatives.
    pub(crate) const fn none() -> Self {
        Self(None)
    }

    /// The alternatives a refusal's `alternatives` member named, when it named a list of texts. A
    /// member of any other shape is read as none: what a service adds to tell a person more is
    /// never a reason to refuse to read what it decided.
    #[must_use]
    pub fn from_member(member: Option<serde_json::Value>) -> Self {
        let Some(serde_json::Value::Array(items)) = member else {
            return Self::none();
        };
        let mut texts = Vec::with_capacity(items.len());
        for item in items {
            match item {
                serde_json::Value::String(text) => texts.push(text),
                _ => return Self::none(),
            }
        }
        Self::named(texts)
    }

    /// The alternatives a refusal named, in the order it named them. A list in which no entry has
    /// text names no path, so it is no list: every entry stays as it was written when one has text.
    pub(crate) fn named(texts: Vec<String>) -> Self {
        let items: Box<[ServiceMessage]> = texts
            .into_iter()
            .map(ServiceMessage::from_refusal)
            .collect();
        if items
            .iter()
            .all(|item| Shown::service(item).as_str().trim().is_empty())
        {
            return Self::none();
        }
        Self(Some(items))
    }

    fn items(&self) -> &[ServiceMessage] {
        self.0.as_deref().unwrap_or(&[])
    }

    /// The alternatives a test names, as a refusal from a service would have named them.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn for_test(texts: &[&str]) -> Self {
        Self::named(texts.iter().map(|text| (*text).to_owned()).collect())
    }

    /// Whether the refusal named none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items().is_empty()
    }

    /// Every alternative as the service wrote it, for a line that carries a service's text.
    #[must_use]
    pub fn as_given(&self) -> Vec<Shown> {
        self.items().iter().map(Shown::service).collect()
    }

    /// "Until then:" and every alternative as the service wrote it, each on its own, for a line
    /// that carries a service's text. `None` when the refusal named none.
    #[must_use]
    pub fn until_then(&self) -> Option<Shown> {
        if self.is_empty() {
            return None;
        }
        Some(Shown::joined(
            std::iter::once(Shown::said(UNTIL_THEN)).chain(self.as_given()),
            " ",
        ))
    }

    /// The alternatives this build recognises and how many it does not, for a line that carries
    /// only this build's own words.
    #[must_use]
    pub fn offered(&self) -> Offered {
        let mut offered = Offered::default();
        for (index, text) in self.items().iter().enumerate() {
            let recognised = (index < MOST)
                .then(|| Alternative::recognised(Shown::service(text).as_str()))
                .flatten();
            match recognised {
                Some(alternative) => offered.known |= alternative.bit(),
                None => offered.more = offered.more.saturating_add(1),
            }
        }
        offered
    }
}

impl fmt::Debug for Alternatives {
    /// Whether it named any. Never one of them, which are the service's.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Alternatives")
            .field("named", &self.0.is_some())
            .finish()
    }
}

/// The alternatives of one refusal that a line of this build's own words can list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offered {
    known: u8,
    more: u8,
}

impl Offered {
    /// Whether the refusal named any alternative at all, recognised or not.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.known == 0 && self.more == 0
    }

    /// The alternatives this build recognises, each once, in [`Alternative::ALL`]'s order.
    pub fn recognised(self) -> impl Iterator<Item = Alternative> {
        Alternative::ALL
            .into_iter()
            .filter(move |alternative| self.known & alternative.bit() != 0)
    }

    /// How many the service named that this build does not recognise.
    #[must_use]
    pub const fn more(self) -> u64 {
        self.more as u64
    }

    /// What either of two refusals named, for a line that holds both: each recognised alternative
    /// once, and the larger of the two counts of those this build does not recognise.
    #[must_use]
    pub const fn either(self, other: Self) -> Self {
        Self {
            known: self.known | other.known,
            more: if self.more >= other.more {
                self.more
            } else {
                other.more
            },
        }
    }
}

/// The longest wait a person is told to expect: a service that names a longer one is said to name
/// this.
const LONGEST_SAID_SECONDS: u64 = 24 * 60 * 60;

/// How long a wait of `seconds` is said to be, in the one unit that fits it, rounded up so that,
/// up to the cap, a person is never told to try again before the service said to. A wait above the
/// cap is said as a day.
fn about(seconds: u64) -> Shown {
    let seconds = seconds.clamp(1, LONGEST_SAID_SECONDS);
    let minutes = seconds.div_ceil(60);
    let hours = minutes.div_ceil(60);
    match seconds {
        1 => Shown::said("1 second"),
        2..=59 => crate::shown!("{} seconds", seconds),
        _ if minutes == 1 => Shown::said("1 minute"),
        _ if minutes < 60 => crate::shown!("{} minutes", minutes),
        _ if hours == 1 => Shown::said("1 hour"),
        _ => crate::shown!("{} hours", hours),
    }
}

/// What a person is told when a managed service had no capacity for what they asked and named the
/// paths that still work: the service's words as it wrote them, then the wait, only when the
/// answer names one, then "Until then:" and each alternative as it wrote it.
///
/// A line that has no service's words to say, or no alternative to list, is not this one, so this
/// returns nothing for an answer that carries no alternative with text and for one with no words.
/// The wait is said as at most a day, whatever the service named.
///
/// The three parts are the whole of what an answer gives a person, so no refusal as a whole is
/// handed to this, and the guard on [`ServiceMessage`] stays with this crate's own readers.
#[must_use]
pub fn told_capacity(
    message: &str,
    retry_after_seconds: Option<u64>,
    alternatives: &Alternatives,
) -> Option<String> {
    if message.trim().is_empty() {
        return None;
    }
    let until_then = alternatives.until_then()?;
    let mut parts = vec![Shown::service(&ServiceMessage::from_refusal(
        message.to_owned(),
    ))];
    if let Some(seconds) = retry_after_seconds {
        parts.push(crate::shown!("Try again in about {}.", about(seconds)));
    }
    parts.push(until_then);
    Some(Shown::joined(parts, " ").into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seven texts, typed again here from what a service writes, so that a change to one of
    /// the words of [`Alternative`] alone fails.
    const SEVEN: [&str; 7] = [
        "A mailbox service that you run yourself.",
        "An authority feed service that you run yourself.",
        "A revocation made on the host itself, without the feed.",
        "A settings sync service that you run yourself.",
        "A backup storage service that you run yourself.",
        "A direct connection between the devices, which needs no managed relay.",
        "A relay that the host's owner runs. The host must name it in its configuration and use no \
         managed relay. A new invitation from that host then names it.",
    ];

    /// KR-REQ-17.48: the seven alternatives a service names are the words this build recognises,
    /// and no others. A word changed in one place and not in the other is a refusal whose list a
    /// check of `kr doctor` would no longer show.
    #[test]
    fn kr_req_17_48_the_alternatives_this_build_recognises_are_exactly_the_seven_a_service_writes()
    {
        let words: Vec<&str> = Alternative::ALL.iter().map(|one| one.words()).collect();
        assert_eq!(words, SEVEN);
        for (index, text) in SEVEN.iter().enumerate() {
            assert_eq!(Alternative::recognised(text), Some(Alternative::ALL[index]));
        }
    }

    /// KR-REQ-17.48: a list is recognised by exact match. Words that differ in a letter, a
    /// full stop or a case are not recognised, and are counted instead of dropped.
    #[test]
    fn kr_req_17_48_an_alternative_that_is_not_recognised_is_counted_and_never_dropped() {
        let named = Alternatives::named(vec![
            SEVEN[0].to_owned(),
            "A mailbox service that you run yourself".to_owned(),
            "a mailbox service that you run yourself.".to_owned(),
            "Another path that this build has never heard of.".to_owned(),
            SEVEN[0].to_owned(),
        ]);
        let offered = named.offered();
        assert_eq!(
            offered.recognised().collect::<Vec<_>>(),
            vec![Alternative::OwnMailboxService],
            "each recognised alternative once"
        );
        assert_eq!(offered.more(), 3, "the three it cannot show are counted");
        assert!(!offered.is_empty());
        assert_eq!(named.as_given().len(), 5, "every one is kept as given");
        let told = named.until_then().expect("a list").into_string();
        assert!(told.starts_with("Until then: A mailbox service that you run yourself. "));
        assert!(told.ends_with(SEVEN[0]), "in the order it named them");
        assert!(Alternatives::none().until_then().is_none());
        assert!(Alternatives::none().offered().is_empty());
        assert!(Alternatives::none().is_empty());
    }

    /// KR-REQ-17.48: a line that holds two refusals lists what either named, each recognised
    /// alternative once, and says no fewer of the others than the larger count.
    #[test]
    fn kr_req_17_48_what_either_of_two_refusals_named_is_listed_once() {
        let first = Alternatives::named(vec![SEVEN[0].to_owned(), "A path of its own.".to_owned()])
            .offered();
        let second = Alternatives::named(vec![
            SEVEN[3].to_owned(),
            SEVEN[0].to_owned(),
            "A path of its own.".to_owned(),
            "Another path of its own.".to_owned(),
        ])
        .offered();
        let both = first.either(second);
        assert_eq!(
            both.recognised().collect::<Vec<_>>(),
            vec![
                Alternative::OwnMailboxService,
                Alternative::OwnSettingsSyncService
            ],
        );
        assert_eq!(both.more(), 2);
        assert_eq!(second.either(first), both, "in either order");
        assert_eq!(Offered::default().either(first), first);
    }

    /// KR-REQ-17.48: the list is the service's text, so its rendering says whether it named any
    /// and never what they say.
    #[test]
    fn kr_req_17_48_a_rendering_of_the_alternatives_says_whether_it_named_any_and_never_what() {
        let rendered = format!("{:?}", Alternatives::named(vec![SEVEN[2].to_owned()]));
        assert!(rendered.contains("true"));
        assert!(!rendered.contains("revocation"));
        assert!(format!("{:?}", Alternatives::none()).contains("false"));
    }

    /// The words of a refusal for a short budget, and the item of its list, typed here from what a
    /// service writes.
    const WORDS: &str = "Managed capacity for new pairing invitations is not available now.";
    const DIRECT_INVITATION: &str = "A direct invitation, which needs no rendezvous service and \
                                     works where the new device can reach this host directly.";

    /// KR-REQ-17.48: one rule reads the list, whichever reader meets it. A list of texts is the
    /// alternatives, in order; a member of any other shape, an empty list and no member are none.
    #[test]
    fn kr_req_17_48_the_list_is_read_by_one_rule_and_a_member_of_another_shape_is_none() {
        use serde_json::json;

        let named = Alternatives::from_member(Some(json!([WORDS, DIRECT_INVITATION])));
        assert_eq!(
            named
                .as_given()
                .iter()
                .map(Shown::as_str)
                .collect::<Vec<_>>(),
            vec![WORDS, DIRECT_INVITATION]
        );
        for member in [
            None,
            Some(json!([])),
            Some(json!([WORDS, 7])),
            Some(json!([WORDS, null])),
            Some(json!([[WORDS]])),
            Some(json!(WORDS)),
            Some(json!({"0": WORDS})),
            Some(json!(null)),
            Some(json!(true)),
        ] {
            assert!(
                Alternatives::from_member(member.clone()).is_empty(),
                "{member:?}"
            );
        }
    }

    /// KR-REQ-17.48: a person is told the service's words, the wait only when the answer names
    /// one, then "Until then:" and each alternative as the service wrote it.
    #[test]
    fn kr_req_17_48_a_capacity_answer_is_told_in_the_service_words_then_the_wait_then_the_list() {
        let list = Alternatives::from_member(Some(serde_json::json!([DIRECT_INVITATION])));
        assert_eq!(
            told_capacity(WORDS, Some(82_800), &list).as_deref(),
            Some(
                "Managed capacity for new pairing invitations is not available now. Try again in \
                 about 23 hours. Until then: A direct invitation, which needs no rendezvous \
                 service and works where the new device can reach this host directly."
            )
        );
        assert_eq!(
            told_capacity(WORDS, None, &list).as_deref(),
            Some(
                "Managed capacity for new pairing invitations is not available now. Until then: A \
                 direct invitation, which needs no rendezvous service and works where the new \
                 device can reach this host directly."
            ),
            "no wait is said when the answer names none"
        );
        let two = Alternatives::from_member(Some(serde_json::json!(["First.", "Second."])));
        assert_eq!(
            told_capacity("Words.", Some(5), &two).as_deref(),
            Some("Words. Try again in about 5 seconds. Until then: First. Second.")
        );
    }

    /// KR-REQ-17.48: a wait is said in the one unit that fits it, rounded up, and never as more
    /// than a day.
    #[test]
    fn kr_req_17_48_a_wait_is_said_rounded_up_in_one_unit_and_never_as_more_than_a_day() {
        let list = Alternatives::from_member(Some(serde_json::json!(["Path."])));
        let said = |seconds| {
            told_capacity("Words.", Some(seconds), &list)
                .expect("told")
                .strip_prefix("Words. Try again in about ")
                .and_then(|rest| rest.strip_suffix(". Until then: Path."))
                .map(str::to_owned)
                .expect("the wait's sentence")
        };
        for (seconds, wait) in [
            (0, "1 second"),
            (1, "1 second"),
            (2, "2 seconds"),
            (59, "59 seconds"),
            (60, "1 minute"),
            (61, "2 minutes"),
            (3540, "59 minutes"),
            (3541, "1 hour"),
            (3598, "1 hour"),
            (3600, "1 hour"),
            (3601, "2 hours"),
            (82_800, "23 hours"),
            (86_399, "24 hours"),
            (86_400, "24 hours"),
            (86_401, "24 hours"),
            (200_000, "24 hours"),
            (u64::MAX, "24 hours"),
        ] {
            assert_eq!(said(seconds), wait, "{seconds} seconds");
        }
    }

    /// KR-REQ-17.48: an answer that names no alternative, or has no words, is not told as a
    /// capacity answer.
    #[test]
    fn kr_req_17_48_an_answer_with_no_alternative_or_no_words_is_not_told_as_capacity() {
        let list = Alternatives::from_member(Some(serde_json::json!(["Path."])));
        assert!(told_capacity(WORDS, Some(60), &Alternatives::none()).is_none());
        assert!(told_capacity(WORDS, None, &Alternatives::none()).is_none());
        assert!(told_capacity("", Some(60), &list).is_none());
        assert!(told_capacity("  \n", None, &list).is_none());
    }

    /// KR-REQ-17.48: every text made from an answer with a list holds the lead-in with the list
    /// after it, whatever the wait and however many alternatives it names. An answer whose list has
    /// no entry with text is not told at all. The lead-in is one constant.
    #[test]
    fn kr_req_17_48_every_capacity_text_that_is_composed_holds_the_lead_in_and_the_list() {
        let one = Alternatives::from_member(Some(serde_json::json!([DIRECT_INVITATION])));
        let several = Alternatives::from_member(Some(serde_json::json!([
            "First.",
            "Second, here.",
            "Third."
        ])));
        for (alternatives, wait) in [
            (&one, None),
            (&one, Some(0)),
            (&one, Some(1)),
            (&one, Some(59)),
            (&one, Some(3600)),
            (&one, Some(86_400)),
            (&one, Some(u64::MAX)),
            (&several, None),
            (&several, Some(5)),
            (&several, Some(200_000)),
        ] {
            let told = told_capacity(WORDS, wait, alternatives).expect("told");
            assert!(told.contains(&format!(" {UNTIL_THEN} ")), "{told}");
        }
        // The words of the service may be anything, a sentence of several lines included.
        assert!(told_capacity("Two\nlines.", None, &one).is_some());
        // A list in which no entry has text names nothing a person can do, so the answer is not
        // told as a capacity answer, whatever the wait; one entry with text is enough.
        for no_text in [
            serde_json::json!([""]),
            serde_json::json!(["  "]),
            serde_json::json!(["", " \t\n"]),
        ] {
            let blank = Alternatives::from_member(Some(no_text));
            for wait in [None, Some(3600)] {
                assert_eq!(told_capacity(WORDS, wait, &blank), None, "{wait:?}");
            }
        }
        for mixed in [
            serde_json::json!(["", "A path."]),
            serde_json::json!(["A path.", " "]),
        ] {
            let mixed = Alternatives::from_member(Some(mixed));
            let told = told_capacity(WORDS, Some(3600), &mixed).expect("told");
            assert!(
                told.contains(UNTIL_THEN) && told.contains("A path."),
                "{told}"
            );
        }
    }
}
