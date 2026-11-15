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

use std::fmt;

use crate::shown::{ServiceMessage, Shown};

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
            Self::OwnRelay => "A self-hosted relay configured in the service settings.",
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

    /// The alternatives a refusal named, in the order it named them.
    pub(crate) fn named(texts: Vec<String>) -> Self {
        if texts.is_empty() {
            return Self::none();
        }
        Self(Some(
            texts
                .into_iter()
                .map(ServiceMessage::from_refusal)
                .collect(),
        ))
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
            std::iter::once(Shown::said("Until then:")).chain(self.as_given()),
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
        "A self-hosted relay configured in the service settings.",
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
}
