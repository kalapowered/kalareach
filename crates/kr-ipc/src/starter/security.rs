//! What a window station or a desktop admits, read from the text of its security descriptor, and
//! whether one object admits no more than another.
//!
//! The starter makes a headless worker's desktop with the access list and integrity label of its
//! own, and a window station that already exists keeps the security it was made with. Before it
//! starts a child on either, it asks whether the object admits more than the starter's own does.
//! More is refused. Less is not: a station made from an earlier reading of the interactive one has
//! not the entries that were added to that one later (a "Run as different user", for one), and the
//! worker, which runs as the starter does, is admitted to it all the same. What counts as less is
//! narrow: the starter's own entries with allowing entries left out, other than one for the
//! owner's rights, and denying entries put in, still in the starter's order. The flags that say
//! which children inherit an entry, and entries that only children inherit, are not compared,
//! except in an allowing entry for the owner's rights, which is compared whole.
//!
//! Any other list is refused as well, whether or not it admits more, and the refusal says which
//! it is. An object "admits more" when its entries show a loss that the starter's own does not
//! have: no access list, a null one, an allowing entry for a trustee that the starter's own allows
//! nothing (other than the owner's rights), a denying entry taken away, a lower integrity level or
//! a weaker policy. That is a reading of the entries, not an evaluation of which entry decides for
//! a given process, so an allowing entry behind a denying one is still called wider. An object
//! whose entries differ in any other way (other rights on an entry, another order, an entry more
//! or less often, an entry for the owner's rights left out) "is not one the starter accepts",
//! because this module compares neither rights nor order.
//!
//! The text of an access list is checked against the system's own count of its entries, so that no
//! text, whatever it holds, can be read as fewer entries than the list has.
//!
//! The text is what the system writes for a descriptor, `D:` and its entries for an access list or
//! `S:` and its label entry for the integrity label. Nothing here calls the system, so it is read
//! and compared the same way wherever it runs.

use std::fmt;

/// The text of the two lists of one object's security, as the system writes them.
pub(super) struct Texts<'a> {
    /// The access list, for a descriptor asked for it alone.
    pub(super) access: &'a str,
    /// How many entries the access list itself holds, as the system counts them, which the text
    /// must account for.
    pub(super) access_entries: usize,
    /// The integrity label, for a descriptor asked for it alone.
    pub(super) label: &'a str,
}

/// Why an object is not used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// The text of one of its lists is not one this reads.
    Unreadable { what: &'static str, why: String },
    /// The object is refused, for the reason `refusal` gives.
    Refused {
        what: &'static str,
        refusal: Refusal,
    },
}

impl Stop {
    /// Whether the text could not be read, as against the object being refused.
    pub(super) const fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unreadable { .. })
    }
}

impl fmt::Display for Stop {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { what, why } => write!(out, "its {what} could not be read: {why}"),
            Self::Refused { what, refusal } if refusal.admits_more => write!(
                out,
                "its {what} admits more than the starter's own does: {}",
                refusal.why
            ),
            Self::Refused { what, refusal } => write!(
                out,
                "its {what} is not one the starter accepts: {}",
                refusal.why
            ),
        }
    }
}

/// Why an object that was read is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Refusal {
    /// Whether the text shows that the object admits more than the starter's own does. If not, the
    /// object is one the starter does not accept, and may admit no more.
    admits_more: bool,
    /// What differs.
    why: String,
}

impl Refusal {
    fn more(why: impl Into<String>) -> Self {
        Self {
            admits_more: true,
            why: why.into(),
        }
    }

    fn not_accepted(why: impl Into<String>) -> Self {
        Self {
            admits_more: false,
            why: why.into(),
        }
    }
}

/// Requires the object whose security reads `found` to be one the starter uses, given that the
/// starter's own reads `own`: by its access list, and then by its integrity label.
///
/// # Errors
///
/// Returns why the object is not used: that a list could not be read, that it admits more than the
/// starter's own, or that it is not one the starter accepts.
pub(super) fn require_no_more(own: &Texts<'_>, found: &Texts<'_>) -> Result<(), Stop> {
    let unreadable = |what: &'static str| move |why| Stop::Unreadable { what, why };
    let (own_list, found_list) = (
        access_list_of(own.access, own.access_entries).map_err(unreadable("access list"))?,
        access_list_of(found.access, found.access_entries).map_err(unreadable("access list"))?,
    );
    if let Some(refusal) = access_list_refusal(&own_list, &found_list) {
        return Err(Stop::Refused {
            what: "access list",
            refusal,
        });
    }
    let (own_label, found_label) = (
        label(own.label).map_err(unreadable("integrity label"))?,
        label(found.label).map_err(unreadable("integrity label"))?,
    );
    match label_refusal(own_label, found_label) {
        Some(refusal) => Err(Stop::Refused {
            what: "integrity label",
            refusal,
        }),
        None => Ok(()),
    }
}

/// What a security descriptor's access list is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AccessList {
    /// The descriptor has no access list at all.
    Absent,
    /// The access list is null, which gives everyone every access. It is not an empty list.
    Null,
    /// The entries, in the order the system evaluates them. An empty list admits nobody.
    Entries(Vec<Entry>),
}

/// How an entry of an access list decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    /// It grants.
    Allow,
    /// It denies.
    Deny,
    /// A kind this module does not evaluate, and an allowing entry for the owner's rights, which
    /// narrows what the owner has of its own accord: only an equal entry may stand for it.
    Other,
}

/// One entry of an access list.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    decision: Decision,
    /// Everything that decides whom the entry affects and what it affects: the kind, the rights,
    /// the object identifiers, the trustee and any condition. The flags that say which child
    /// objects inherit the entry are not in it, because they do not change who may use this
    /// object; an entry for the owner's rights keeps them.
    meaning: String,
    /// Whom the entry is for.
    trustee: String,
}

/// An integrity label: the level a process needs to write to an object, and what the object
/// refuses to lower ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Label {
    level: u32,
    policy: u32,
}

/// The label of an object that has none: medium integrity, and no writing from below.
const IMPLICIT_LABEL: Label = Label {
    level: 0x2000,
    policy: NO_WRITE_UP,
};

/// The policy bit that refuses a write from a lower level.
const NO_WRITE_UP: u32 = 0x1;

/// Reads the access list from the text of a descriptor asked for its access list alone, and
/// requires the text to hold as many entries as the list itself does.
///
/// # Errors
///
/// Returns what was not understood when the text is not an access list, or that it holds another
/// number of entries than the list.
fn access_list_of(text: &str, entries: usize) -> Result<AccessList, String> {
    let (list, written) = read_access_list(text)?;
    if written != entries {
        return Err(format!(
            "the text holds {written} entries where the list holds {entries}: {:?}",
            text.trim()
        ));
    }
    Ok(list)
}

/// Reads the access list from the text alone.
#[cfg(test)]
fn access_list(text: &str) -> Result<AccessList, String> {
    read_access_list(text).map(|(list, _)| list)
}

/// Reads the access list from the text of a descriptor asked for its access list alone, with the
/// number of entries the text holds.
///
/// # Errors
///
/// Returns what was not understood when the text is not an access list.
fn read_access_list(text: &str) -> Result<(AccessList, usize), String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok((AccessList::Absent, 0));
    }
    let Some(rest) = text.strip_prefix("D:") else {
        return Err(format!("{text:?} does not begin with an access list"));
    };
    let (flags, entries) = rest.find('(').map_or((rest, ""), |at| rest.split_at(at));
    if flags.contains("NO_ACCESS_CONTROL") {
        return if entries.is_empty() {
            Ok((AccessList::Null, 0))
        } else {
            Err(format!("{text:?} has entries in a null access list"))
        };
    }
    let mut list = Vec::new();
    let written = parenthesised(entries)?;
    let count = written.len();
    for inner in written {
        let mut fields = split_top_level(inner);
        if fields.len() < 6 {
            return Err(format!("the entry ({inner}) has too few fields"));
        }
        let kind = fields[0];
        let trustee = fields[5].to_owned();
        // An entry for the owner's rights narrows what the owner has of its own accord, so taking
        // one away widens that: it can only be matched, never left out. Whether the system counts
        // one that only children inherit is not something this reads, so such an entry is kept too,
        // with its flags.
        if matches!(fields[5], "OW" | "S-1-3-4") && !matches!(kind, "D" | "OD" | "XD") {
            list.push(Entry {
                decision: Decision::Other,
                meaning: fields.join(";"),
                trustee,
            });
            continue;
        }
        // An entry that only children inherit decides nothing about this object.
        if inherit_only(fields[1]) {
            continue;
        }
        let decision = match kind {
            "A" | "OA" | "XA" | "ZA" => Decision::Allow,
            "D" | "OD" | "XD" => Decision::Deny,
            _ => Decision::Other,
        };
        fields.remove(1);
        list.push(Entry {
            decision,
            meaning: fields.join(";"),
            trustee,
        });
    }
    Ok((AccessList::Entries(list), count))
}

/// Reads the integrity label from the text of a descriptor asked for its label alone.
///
/// # Errors
///
/// Returns what was not understood when the text holds a label entry that cannot be read, or more
/// than one.
fn label(text: &str) -> Result<Label, String> {
    let rest = text
        .trim()
        .strip_prefix("S:")
        .unwrap_or_else(|| text.trim());
    let (_, entries) = rest.find('(').map_or((rest, ""), |at| rest.split_at(at));
    let mut found = None;
    for inner in parenthesised(entries)? {
        let fields = split_top_level(inner);
        if fields.first() != Some(&"ML") || fields.get(1).is_some_and(|flags| inherit_only(flags)) {
            continue;
        }
        let (Some(policy), Some(level)) = (fields.get(2), fields.get(5)) else {
            return Err(format!("the label entry ({inner}) has too few fields"));
        };
        let label = Label {
            level: level_of(level).ok_or_else(|| format!("the level {level:?} is not known"))?,
            policy: policy_of(policy)
                .ok_or_else(|| format!("the policy {policy:?} is not known"))?,
        };
        if found.replace(label).is_some() {
            return Err(format!("{text:?} has more than one label entry"));
        }
    }
    Ok(found.unwrap_or(IMPLICIT_LABEL))
}

/// Says why `found` is refused against `own`, or nothing when it is used.
///
/// Fewer allowing entries admit less, except an entry for the owner's rights, and further denying
/// entries admit less. A missing denying entry, an allowing entry for a trustee the starter's own
/// allows nothing, and a null or absent list where there were entries admit more. Every other
/// difference, an entry with other rights, one more or less often, entries in another order that
/// the system may evaluate differently, cannot be shown to admit more or to admit no more, and is
/// refused as not accepted.
fn access_list_refusal(own: &AccessList, found: &AccessList) -> Option<Refusal> {
    match (own, found) {
        (AccessList::Entries(own), AccessList::Entries(found)) => entries_refusal(own, found),
        // Everyone is admitted by the starter's own, so nothing can be more.
        (AccessList::Absent | AccessList::Null, _) => None,
        (AccessList::Entries(_), AccessList::Absent) => Some(Refusal::more(
            "it has no access list, which admits everyone",
        )),
        (AccessList::Entries(_), AccessList::Null) => Some(Refusal::more(
            "its access list is null, which admits everyone",
        )),
    }
}

/// Says why a label is refused against the starter's own, or nothing when it is used.
fn label_refusal(own: Label, found: Label) -> Option<Refusal> {
    if found.level < own.level {
        return Some(Refusal::more(format!(
            "its level {:#x} is below the starter's own {:#x}",
            found.level, own.level
        )));
    }
    if found.policy & own.policy != own.policy {
        return Some(Refusal::more(format!(
            "its policy {:#x} refuses less than the starter's own {:#x}",
            found.policy, own.policy
        )));
    }
    None
}

/// Says why `found` is not `own` with allowing entries left out and denying entries put in.
///
/// The two lists line up when each entry of `found` is either one of `own`'s, in the same order, or
/// a further denying entry, and each entry of `own` is either matched or an allowing entry that
/// `found` leaves out. Which entries are the further ones is not told by looking at them one at a
/// time, so every way of lining the lists up is tried.
fn entries_refusal(own: &[Entry], found: &[Entry]) -> Option<Refusal> {
    // `lined[i][j]`: `own[..i]` and `found[..j]` line up.
    let mut lined = vec![vec![false; found.len() + 1]; own.len() + 1];
    lined[0][0] = true;
    for i in 0..=own.len() {
        for j in 0..=found.len() {
            if i == 0 && j == 0 {
                continue;
            }
            let left_out = i > 0 && own[i - 1].decision == Decision::Allow && lined[i - 1][j];
            let put_in = j > 0 && found[j - 1].decision == Decision::Deny && lined[i][j - 1];
            let matched = i > 0 && j > 0 && own[i - 1] == found[j - 1] && lined[i - 1][j - 1];
            lined[i][j] = left_out || put_in || matched;
        }
    }
    if lined[own.len()][found.len()] {
        return None;
    }
    let for_trustee = |list: &[Entry], decision: Decision, trustee: &str| {
        list.iter()
            .any(|entry| entry.decision == decision && entry.trustee == trustee)
    };
    // The text shows that these admit more: nothing in the starter's own allows the trustee, or
    // nothing in the found list denies the trustee that the starter's own denies.
    if let Some(entry) = found.iter().find(|entry| {
        entry.decision == Decision::Allow && !for_trustee(own, Decision::Allow, &entry.trustee)
    }) {
        return Some(Refusal::more(format!(
            "it allows {} in the entry ({}), where the starter's own allows nothing for it",
            entry.trustee, entry.meaning
        )));
    }
    if let Some(entry) = own.iter().find(|entry| {
        entry.decision == Decision::Deny && !for_trustee(found, Decision::Deny, &entry.trustee)
    }) {
        return Some(Refusal::more(format!(
            "it lacks the denying entry ({}) that the starter's own has",
            entry.meaning
        )));
    }
    // Everything else differs in a way the text alone does not show to admit more.
    let times = |list: &[Entry], entry: &Entry| list.iter().filter(|other| *other == entry).count();
    if let Some(entry) = found
        .iter()
        .find(|entry| entry.decision != Decision::Deny && times(found, entry) > times(own, entry))
    {
        let counterpart = own.iter().find(|other| {
            other.decision == entry.decision
                && other.trustee == entry.trustee
                && times(own, other) > times(found, other)
        });
        return Some(Refusal::not_accepted(match counterpart {
            Some(other) => format!(
                "its entry ({}) is not the starter's own ({}) for the same trustee, so its \
                 rights or its conditions differ",
                entry.meaning, other.meaning
            ),
            None => format!(
                "it has the entry ({}) more often than the starter's own does",
                entry.meaning
            ),
        }));
    }
    if let Some(entry) = own
        .iter()
        .find(|entry| entry.decision != Decision::Allow && times(own, entry) > times(found, entry))
    {
        return Some(Refusal::not_accepted(format!(
            "it lacks an entry ({}) that the starter's own has and that only an equal entry may \
             stand for",
            entry.meaning
        )));
    }
    Some(Refusal::not_accepted(
        "its entries are not in the starter's order, which cannot be shown to admit no more",
    ))
}

/// Whether the flags of an entry say that only children inherit it. The flags are two letters each,
/// so a pair is looked for and not a run of letters that two flags make.
fn inherit_only(flags: &str) -> bool {
    flags.as_bytes().chunks(2).any(|flag| flag == b"IO")
}

/// The characters of `text` that are not in a string literal of a condition, with their places.
///
/// A literal is between double quotes, may hold parentheses and semicolons, and ends at the next
/// double quote: the grammar gives it no escape. Neither the quotes nor what they hold are among
/// the characters returned.
fn outside_literals(text: &str) -> impl Iterator<Item = (usize, char)> + '_ {
    let mut inside = false;
    text.char_indices().filter(move |&(_, character)| {
        if character == '"' {
            inside = !inside;
            return false;
        }
        !inside
    })
}

/// The text inside each top-level pair of parentheses of `text`, which holds nothing else.
///
/// A string literal of a condition may hold parentheses, which do not count, and ends at the next
/// double quote. A double quote outside an entry, and an entry or a literal that is not closed,
/// are errors.
fn parenthesised(text: &str) -> Result<Vec<&str>, String> {
    let mut entries = Vec::new();
    let mut depth = 0_u32;
    let mut start = 0;
    let mut inside = false;
    for (index, character) in text.char_indices() {
        match character {
            '"' if depth == 0 => {
                return Err(format!("{text:?} has a string outside an entry"));
            }
            '"' => inside = !inside,
            _ if inside => {}
            '(' => {
                if depth == 0 {
                    start = index + 1;
                }
                depth += 1;
            }
            ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("{text:?} closes a parenthesis it did not open"))?;
                if depth == 0 {
                    entries.push(&text[start..index]);
                }
            }
            character if depth == 0 && !character.is_whitespace() => {
                return Err(format!("{text:?} has {character:?} outside an entry"));
            }
            _ => {}
        }
    }
    // A string that is never closed holds every parenthesis after it, so the entry it is in is
    // never closed either.
    if depth != 0 {
        return Err(format!("{text:?} leaves a parenthesis or a string open"));
    }
    Ok(entries)
}

/// The fields of an entry, which a condition's own parentheses and semicolons do not split, nor do
/// those in its string literals.
fn split_top_level(entry: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut depth = 0_u32;
    let mut start = 0;
    for (index, character) in outside_literals(entry) {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                fields.push(&entry[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    fields.push(&entry[start..]);
    fields
}

/// The integrity level a trustee field names.
fn level_of(trustee: &str) -> Option<u32> {
    match trustee {
        "LW" => Some(0x1000),
        "ME" => Some(0x2000),
        "MP" => Some(0x2100),
        "HI" => Some(0x3000),
        "SI" => Some(0x4000),
        other => other
            .strip_prefix("S-1-16-")
            .and_then(|level| level.parse().ok()),
    }
}

/// The policy bits a rights field names.
fn policy_of(rights: &str) -> Option<u32> {
    if let Some(hex) = rights.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    let mut policy = 0;
    let mut rest = rights;
    while !rest.is_empty() {
        let (word, tail) = rest.split_at_checked(2)?;
        policy |= match word {
            "NW" => NO_WRITE_UP,
            "NR" => 0x2,
            "NX" => 0x4,
            _ => return None,
        };
        rest = tail;
    }
    Some(policy)
}

#[cfg(test)]
mod tests {
    use super::{
        AccessList, Refusal, Stop, Texts, access_list, access_list_refusal, label, label_refusal,
        require_no_more, split_top_level,
    };

    fn list(text: &str) -> AccessList {
        access_list(text).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    /// Why `found` is refused against `own`, or nothing when it is used.
    fn refused(own: &str, found: &str) -> Option<Refusal> {
        access_list_refusal(&list(own), &list(found))
    }

    /// Why `found` is refused against `own`, which it must be.
    fn why(own: &str, found: &str) -> Refusal {
        refused(own, found).unwrap_or_else(|| panic!("{found} was used against {own}"))
    }

    fn admits_more(own: &str, found: &str) -> bool {
        why(own, found).admits_more
    }

    /// Refused although the text does not show that it admits more.
    fn not_accepted(own: &str, found: &str) -> bool {
        !why(own, found).admits_more
    }

    /// The number of entries a text of honest input holds, counted by its parentheses alone, as
    /// the system counts the entries of the list it wrote the text from.
    fn counted(access: &str) -> usize {
        let mut depth = 0_u32;
        let mut entries = 0;
        for character in access.chars() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    entries += usize::from(depth == 0);
                }
                _ => {}
            }
        }
        entries
    }

    fn texts<'a>(access: &'a str, label: &'a str) -> Texts<'a> {
        Texts {
            access,
            access_entries: counted(access),
            label,
        }
    }

    fn entries(text: &str) -> usize {
        match list(text) {
            AccessList::Entries(entries) => entries.len(),
            other => panic!("{text} reads as {other:?}"),
        }
    }

    /// KR-REQ-03.24: an absent, a null and an empty access list are three lists, and the entries
    /// of a list keep the order the system evaluates them in.
    #[test]
    fn an_access_list_keeps_its_order_and_tells_absent_null_and_empty_apart() {
        assert_eq!(list(""), AccessList::Absent);
        assert_eq!(list("D:NO_ACCESS_CONTROL"), AccessList::Null);
        assert_eq!(list("D:"), AccessList::Entries(Vec::new()));
        assert_eq!(list("D:P"), AccessList::Entries(Vec::new()));
        assert_ne!(list("D:NO_ACCESS_CONTROL"), list("D:"));
        assert_ne!(list(""), list("D:"));
        // The flags before the null word say how the list is protected, and it is null all the
        // same: read as an empty list, it would be one that admits nobody.
        assert_eq!(list("D:PNO_ACCESS_CONTROL"), AccessList::Null);
        assert_eq!(list("D:PAINO_ACCESS_CONTROL"), AccessList::Null);

        // The flags before the first entry say how the list is protected and inherited, which
        // does not change whom it admits.
        assert_eq!(
            list("D:PAI(A;;GA;;;SY)(A;;GA;;;S-1-5-5-0-1)"),
            list("D:(A;;GA;;;SY)(A;;GA;;;S-1-5-5-0-1)")
        );
        assert_ne!(
            list("D:(A;;GA;;;SY)(A;;GA;;;S-1-5-5-0-1)"),
            list("D:(A;;GA;;;S-1-5-5-0-1)(A;;GA;;;SY)")
        );
        // The flags of an entry that say which children inherit it do not change whom it admits
        // either, and an entry that only children inherit admits nobody.
        assert_eq!(list("D:(A;OICI;GA;;;SY)"), list("D:(A;;GA;;;SY)"));
        assert_eq!(list("D:(A;OICIIO;GA;;;WD)"), list("D:"));
        assert_eq!(list("D:(A;CIOI;GA;;;WD)"), list("D:(A;;GA;;;WD)"));
        // A condition holds parentheses and semicolons of its own.
        assert_eq!(
            entries("D:(XA;;FX;;;S-1-1-0;(@User.Title==\"PM\";1))(A;;GA;;;SY)"),
            2
        );

        assert!(access_list("O:SY").is_err());
        assert!(access_list("D:(A;;GA;;;SY").is_err());
        assert!(access_list("D:(A;;GA)").is_err());
        // An entry has six fields, and one with five is not read as one with a trustee.
        assert!(access_list("D:(A;;GA;;SY)").is_err());
        assert!(access_list("D:NO_ACCESS_CONTROL(A;;GA;;;SY)").is_err());
    }

    /// KR-REQ-03.24: a string in a condition may hold parentheses and semicolons, and the entries
    /// after it are still read as entries: a list with an allowing entry hidden behind a string
    /// that holds a parenthesis is not taken for one that has none.
    #[test]
    fn a_parenthesis_in_a_string_of_a_condition_hides_no_entry_after_it() {
        let own = "D:(A;;0x1;;;SY)";
        // Read by counting every parenthesis, this is one denying entry that ends at the last
        // parenthesis of the second string, and the allowing entry for everyone goes unseen.
        let hiding = "D:(XD;;0x1;;;BG;(@User.X==\"a(b\"))(A;;GA;;;WD)\
                      (XD;;0x1;;;BG;(@User.X==\"c)d\"))(A;;0x1;;;SY)";
        assert_eq!(entries(hiding), 4);
        let refusal = why(own, hiding);
        assert!(refusal.admits_more, "{refusal:?}");
        assert!(refusal.why.contains("WD"), "{refusal:?}");

        // A parenthesis or a semicolon in a string does not end an entry or split a field.
        assert_eq!(entries("D:(XA;;FX;;;WD;(@User.X==\"a(b\"))(A;;GA;;;SY)"), 2);
        assert_eq!(entries("D:(XA;;FX;;;WD;(@User.X==\"a)b\"))(A;;GA;;;SY)"), 2);
        assert_eq!(
            entries("D:(XA;;FX;;;WD;(@User.X==\"a;b;c;d;e;f\"))(A;;GA;;;SY)"),
            2
        );
        // A string that is not closed is not read at all.
        assert!(access_list("D:(XA;;FX;;;WD;(@User.X==\"a))(A;;GA;;;SY)").is_err());
        assert!(access_list("D:(XA;;FX;;;WD;(@User.X==\"a(b\"))(A;;GA;;;SY)\"").is_err());
    }

    /// KR-REQ-03.24: the fields of an entry are split at the semicolons outside its condition, and a
    /// condition's strings, which may hold an unbalanced parenthesis or a semicolon, do not end it.
    #[test]
    fn the_fields_of_an_entry_are_split_outside_its_condition_and_its_strings() {
        let last = "x";
        for condition in [
            "(@User.X==\"a(b\")",
            "(@User.X==\"a)b\")",
            "(@User.X==\"a;b\")",
            "(@User.X==1;2)",
            "((@User.X==1;2)||(@User.Y==\"(\"))",
        ] {
            let entry = format!("XA;;FX;;;WD;{condition};{last}");
            assert_eq!(
                split_top_level(&entry),
                ["XA", "", "FX", "", "", "WD", condition, last],
                "{entry}"
            );
        }
    }

    /// KR-REQ-03.24: an object that admits more than the starter's own is refused, whichever way
    /// it admits more, and the refusal says that it admits more.
    #[test]
    fn an_access_list_that_admits_more_than_the_starters_own_is_refused() {
        let own = "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)";
        assert_eq!(refused(own, own), None);

        // A further allowing entry for a trustee the starter's own allows nothing, and a null or
        // absent list where there were entries.
        assert!(admits_more(
            own,
            "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;WD)"
        ));
        assert!(admits_more(own, "D:NO_ACCESS_CONTROL"));
        assert!(admits_more(own, "D:PNO_ACCESS_CONTROL"));
        assert!(admits_more(own, ""));
        assert!(admits_more("D:", "D:(A;;0x1;;;WD)"));
        // Taking away a denying entry admits more.
        assert!(admits_more(
            "D:(D;;0x1;;;BG)(A;;0x1;;;SY)",
            "D:(A;;0x1;;;SY)"
        ));
        // Deny then allow and allow then deny are different lists: the first admits nobody, the
        // second admits everyone. The same entries in another order are not shown to admit more.
        let denying_first = "D:(D;;0x1;;;WD)(A;;0x1;;;WD)";
        let allowing_first = "D:(A;;0x1;;;WD)(D;;0x1;;;WD)";
        assert!(not_accepted(denying_first, allowing_first));

        // An entry for the owner's rights narrows what the owner has of its own accord, so
        // leaving it out admits more than the starter's own does; the text does not say so, and
        // it is refused as one the starter does not accept.
        assert!(not_accepted(
            "D:(A;;0x20000;;;OW)(A;;0x1;;;WD)",
            "D:(A;;0x1;;;WD)"
        ));
        assert_eq!(
            refused(
                "D:(A;;0x20000;;;OW)(A;;0x1;;;WD)",
                "D:(A;;0x20000;;;OW)(A;;0x1;;;WD)"
            ),
            None
        );
        // One that only children inherit is kept too: whether the system counts it is not read.
        assert!(not_accepted(
            "D:(A;OICIIO;0x20000;;;OW)(A;;0x1;;;WD)",
            "D:(A;;0x1;;;WD)"
        ));
        assert!(not_accepted(
            "D:(A;;0x1;;;WD)",
            "D:(A;OICIIO;0x20000;;;S-1-3-4)(A;;0x1;;;WD)"
        ));
        // A denying entry for the owner's rights only takes access away.
        assert_eq!(
            refused("D:(A;;0x1;;;WD)", "D:(D;;0x20000;;;OW)(A;;0x1;;;WD)"),
            None
        );
    }

    /// KR-REQ-03.24: an object that is not the starter's own list with allowing entries left out
    /// and denying entries put in, and whose text does not show that it admits more, is refused in
    /// words that do not say so: a narrower mask, the same entries in another order, an entry more
    /// or less often.
    #[test]
    fn a_list_that_is_not_accepted_but_shows_no_more_is_not_called_wider() {
        // The same trustee with a narrower mask admits less, and with a wider one admits more;
        // the text of two masks does not say which, so neither is called wider.
        assert!(not_accepted("D:(A;;0xF;;;SY)", "D:(A;;0x1;;;SY)"));
        assert!(not_accepted("D:(A;;0x1;;;SY)", "D:(A;;0xF;;;SY)"));
        assert!(
            why("D:(A;;0xF;;;SY)", "D:(A;;0x1;;;SY)")
                .why
                .contains("differ")
        );
        // The same entries in another order.
        let swapped = why(
            "D:(A;;0x1;;;SY)(A;;0x1;;;BA)",
            "D:(A;;0x1;;;BA)(A;;0x1;;;SY)",
        );
        assert!(!swapped.admits_more, "{swapped:?}");
        assert!(swapped.why.contains("order"), "{swapped:?}");
        // An allowing entry twice where the starter's own has it once admits what it admits.
        let twice = why("D:(A;;0x1;;;WD)", "D:(A;;0x1;;;WD)(A;;0x1;;;WD)");
        assert!(!twice.admits_more, "{twice:?}");
        assert!(twice.why.contains("more often"), "{twice:?}");
        // A denying entry once where the starter's own has it twice, or with other rights.
        let once = why("D:(D;;0x1;;;WD)(D;;0x1;;;WD)", "D:(D;;0x1;;;WD)");
        assert!(!once.admits_more, "{once:?}");
        assert!(once.why.contains("lacks"), "{once:?}");
        assert!(not_accepted("D:(D;;0x3;;;BG)", "D:(D;;0x1;;;BG)"));
        // The same kind and trustee under another condition.
        assert!(not_accepted(
            "D:(XA;;FX;;;WD;(@User.X==1))",
            "D:(XA;;FX;;;WD;(@User.X==2))"
        ));

        // When entries are out of order as well, the reason is the order, and not an entry that
        // was put in or left out as an entry may be.
        let with_a_deny_put_in = why(
            "D:(A;;0x1;;;SY)(A;;0x1;;;BA)",
            "D:(D;;0x1;;;BG)(A;;0x1;;;BA)(A;;0x1;;;SY)",
        );
        assert!(!with_a_deny_put_in.admits_more, "{with_a_deny_put_in:?}");
        assert!(
            with_a_deny_put_in.why.contains("order"),
            "{with_a_deny_put_in:?}"
        );
        let with_an_allow_left_out = why(
            "D:(A;;0x1;;;SY)(A;;0x1;;;BA)(A;;0x1;;;WD)",
            "D:(A;;0x1;;;WD)(A;;0x1;;;BA)",
        );
        assert!(
            !with_an_allow_left_out.admits_more,
            "{with_an_allow_left_out:?}"
        );
        assert!(
            with_an_allow_left_out.why.contains("order"),
            "{with_an_allow_left_out:?}"
        );

        // What does admit more says so: a trustee nothing allows, a denying entry gone.
        let added = why("D:(A;;0x1;;;SY)", "D:(A;;0x1;;;SY)(A;;0x1;;;WD)");
        assert!(added.admits_more, "{added:?}");
        let gone = why("D:(D;;0x1;;;BG)(A;;0x1;;;SY)", "D:(A;;0x1;;;SY)");
        assert!(gone.admits_more, "{gone:?}");
        assert!(gone.why.contains("BG"), "{gone:?}");
    }

    /// KR-REQ-03.24: an entry of a kind this does not evaluate is neither left out nor put in, and
    /// the kinds that it does evaluate are the allowing and denying ones the system writes.
    #[test]
    fn the_kinds_of_entry_are_read_as_what_they_do() {
        // A kind that is not read: not left out, not put in, matched only by an equal entry.
        let own = "D:(ZZ;;0x1;;;WD)(A;;0x1;;;SY)";
        assert_eq!(refused(own, own), None);
        assert!(refused(own, "D:(A;;0x1;;;SY)").is_some());
        assert!(refused("D:(A;;0x1;;;SY)", "D:(ZZ;;0x1;;;BG)(A;;0x1;;;SY)").is_some());

        // Object and conditional entries put in that deny are denying entries put in; those left
        // out that allow are allowing entries left out.
        let allowing = "D:(OA;;0x1;;;WD)(XA;;0x1;;;WD;(@User.X==1))(ZA;;0x1;;;WD)(A;;0x1;;;SY)";
        assert_eq!(refused(allowing, "D:(A;;0x1;;;SY)"), None);
        assert_eq!(
            refused(
                "D:(A;;0x1;;;SY)",
                "D:(OD;;0x1;;;BG)(XD;;0x1;;;BG;(@User.X==1))(A;;0x1;;;SY)"
            ),
            None
        );
        // And the other way round, they are not: an allowing entry put in, a denying one left out.
        assert!(refused("D:(A;;0x1;;;SY)", "D:(OA;;0x1;;;BG)(A;;0x1;;;SY)").is_some());
        assert!(
            refused(
                "D:(A;;0x1;;;SY)",
                "D:(XA;;0x1;;;BG;(@User.X==1))(A;;0x1;;;SY)"
            )
            .is_some()
        );
        assert!(refused("D:(OD;;0x1;;;BG)(A;;0x1;;;SY)", "D:(A;;0x1;;;SY)").is_some());
        assert!(
            refused(
                "D:(XD;;0x1;;;BG;(@User.X==1))(A;;0x1;;;SY)",
                "D:(A;;0x1;;;SY)"
            )
            .is_some()
        );
    }

    /// KR-REQ-03.24: an entry for the owner's rights is compared with its inheritance flags, which
    /// an entry for anyone else is not.
    #[test]
    fn an_entry_for_the_owners_rights_keeps_its_flags() {
        for owner in ["OW", "S-1-3-4"] {
            let with_flags = format!("D:(A;OI;0x20000;;;{owner})(A;;0x1;;;WD)");
            let without = format!("D:(A;;0x20000;;;{owner})(A;;0x1;;;WD)");
            assert_eq!(refused(&with_flags, &with_flags), None);
            assert!(refused(&with_flags, &without).is_some());
            assert!(refused(&without, &with_flags).is_some());
        }
        // The flags of an entry for anyone else are not compared.
        assert_eq!(
            refused("D:(A;OI;0x20000;;;BA)", "D:(A;;0x20000;;;BA)"),
            None
        );
    }

    /// KR-REQ-03.24: an object that admits less than the starter's own is not refused: a station
    /// made before an entry was added to the interactive one has not that entry.
    #[test]
    fn an_access_list_that_admits_less_than_the_starters_own_is_not_refused() {
        let own = "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;S-1-5-5-0-2)";
        // An entry added to the interactive station after the other was made.
        assert_eq!(refused(own, "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)"), None);
        assert_eq!(refused(own, "D:(A;;0x1;;;S-1-5-5-0-1)"), None);
        // Nobody at all, and a further denying entry, admit less.
        assert_eq!(refused(own, "D:"), None);
        assert_eq!(refused(own, "D:(D;;0x1;;;BG)(A;;0x1;;;SY)"), None);
        // A further denying entry may come before entries that match the starter's own, whichever
        // of the denying entries the starter's own has is the one it matches.
        assert_eq!(
            refused(
                "D:(A;;0x1;;;WD)(D;;0x1;;;WD)",
                "D:(D;;0x1;;;WD)(A;;0x1;;;WD)(D;;0x1;;;WD)"
            ),
            None
        );
        // Where the starter's own admits everyone, nothing admits more.
        assert_eq!(refused("D:NO_ACCESS_CONTROL", "D:(A;;0x1;;;SY)"), None);
        assert_eq!(refused("D:NO_ACCESS_CONTROL", "D:"), None);
        // The same entries under other flags are the same entries.
        assert_eq!(refused("D:PAI(A;OICI;0x1;;;SY)", "D:(A;;0x1;;;SY)"), None);
    }

    /// KR-REQ-03.24: a label at a lower level, or one that refuses less, admits more, and an object
    /// that has no label has the medium one.
    #[test]
    fn a_label_below_the_starters_own_or_refusing_less_is_refused() {
        let read = |text: &str| label(text).unwrap_or_else(|error| panic!("{text}: {error}"));
        let own = read("S:(ML;;NW;;;ME)");
        assert_eq!(read(""), own, "no label is the medium one");
        assert_eq!(read("S:"), own);
        assert_eq!(read("S:AI(ML;;NW;;;S-1-16-8192)"), own);
        assert_eq!(read("S:(ML;;0x1;;;ME)"), own);

        assert_eq!(label_refusal(own, own), None);
        assert!(label_refusal(own, read("S:(ML;;NW;;;LW)")).is_some_and(|why| why.admits_more));
        assert!(label_refusal(own, read("S:(ML;;NR;;;ME)")).is_some_and(|why| why.admits_more));
        // Higher, and refusing more, admit less.
        assert_eq!(label_refusal(own, read("S:(ML;;NW;;;HI)")), None);
        assert_eq!(label_refusal(own, read("S:(ML;;NWNR;;;ME)")), None);
        // A label no lower than the medium one, against none, is not more.
        assert_eq!(label_refusal(read(""), read("S:(ML;;NW;;;HI)")), None);
        assert!(label_refusal(read(""), read("S:(ML;;NW;;;LW)")).is_some());

        // A label that only children inherit is not the object's own.
        assert_eq!(read("S:(ML;OIIO;NW;;;HI)"), own);
        assert!(label_refusal(read("S:(ML;;NW;;;HI)"), read("S:(ML;OIIO;NW;;;HI)")).is_some());

        assert!(label("S:(ML;;NW;;;XX)").is_err());
        assert!(label("S:(ML;;QQ;;;ME)").is_err());
        assert!(label("S:(ML;;NW;;;ME)(ML;;NW;;;LW)").is_err());
    }

    /// KR-REQ-03.24: an object is used only when both its access list and its label are no more
    /// than the starter's own, and the refusal names the one that is, in words that say whether it
    /// admits more.
    #[test]
    fn an_object_is_used_only_when_its_access_list_and_its_label_are_acceptable() {
        let own_list = "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)";
        let medium = "S:(ML;;NW;;;ME)";
        let own = texts(own_list, medium);
        let found = |access, label| require_no_more(&own, &texts(access, label));
        assert_eq!(found(own_list, medium), Ok(()));
        // Less of both, and the medium label that no label stands for.
        assert_eq!(found("D:(A;;0x1;;;SY)", ""), Ok(()));

        // The access list is checked, and named.
        let wider = found("D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;WD)", medium);
        assert!(
            matches!(&wider, Err(Stop::Refused { what: "access list", refusal }) if refusal.admits_more),
            "{wider:?}"
        );
        let narrower_mask = found("D:(A;;0x3;;;SY)(A;;0x1;;;S-1-5-5-0-1)", medium);
        assert!(
            matches!(&narrower_mask, Err(Stop::Refused { what: "access list", refusal }) if !refusal.admits_more),
            "{narrower_mask:?}"
        );

        // The label is checked too, with an access list that is the starter's own, and a label
        // that is no lower is not refused.
        let lower = found(own_list, "S:(ML;;NW;;;LW)");
        assert!(
            matches!(&lower, Err(Stop::Refused { what: "integrity label", refusal }) if refusal.admits_more),
            "{lower:?}"
        );
        let weaker = found(own_list, "S:(ML;;0x0;;;ME)");
        assert!(
            matches!(
                &weaker,
                Err(Stop::Refused {
                    what: "integrity label",
                    ..
                })
            ),
            "{weaker:?}"
        );
        assert_eq!(found(own_list, "S:(ML;;NW;;;HI)"), Ok(()));

        // A list that cannot be read stops the start, and is not a refusal.
        let unread = found("not a list", medium);
        assert!(
            matches!(&unread, Err(stop) if stop.is_unreadable()),
            "{unread:?}"
        );
        let unread_label = found(own_list, "S:(ML;;NW;;;XX)");
        assert!(
            matches!(&unread_label, Err(stop) if stop.is_unreadable()),
            "{unread_label:?}"
        );
    }

    /// KR-REQ-03.24: a text is read only when it holds as many entries as the list it was written
    /// from, so that whatever a string of a condition holds, no entry of the list goes unread: a
    /// double quote inside a string, for which the grammar has no form, would otherwise end the
    /// string early and hide the entries up to the next quote.
    #[test]
    fn a_text_that_holds_fewer_entries_than_the_list_is_not_read() {
        let hiding = "D:(XD;;0x1;;;BG;(@User.X==\"a\"b\"))(A;;GA;;;WD)\
                      (XD;;0x1;;;BG;(@User.X==\"c\"d\"))(A;;0x1;;;SY)";
        // Read for itself the text has two entries, and the list it came from has four.
        assert_eq!(entries(hiding), 2);
        let own = texts("D:(A;;0x1;;;SY)", "");
        let hidden = require_no_more(
            &own,
            &Texts {
                access: hiding,
                access_entries: 4,
                label: "",
            },
        );
        assert!(
            matches!(&hidden, Err(stop) if stop.is_unreadable()),
            "{hidden:?}"
        );
        // A text that holds the entries the list holds is read as before, and so is a null list.
        let honest = "D:(A;;0x1;;;SY)(A;;0x1;;;WD)";
        assert!(matches!(
            require_no_more(&own, &texts(honest, "")),
            Err(Stop::Refused { .. })
        ));
        let more = require_no_more(
            &own,
            &Texts {
                access: honest,
                access_entries: 1,
                label: "",
            },
        );
        assert!(
            matches!(&more, Err(stop) if stop.is_unreadable()),
            "{more:?}"
        );
        assert_eq!(
            require_no_more(
                &Texts {
                    access: "D:NO_ACCESS_CONTROL",
                    access_entries: 0,
                    label: "",
                },
                &Texts {
                    access: "D:(A;;0x1;;;SY)",
                    access_entries: 1,
                    label: "",
                },
            ),
            Ok(())
        );
        // A string outside an entry is not skipped: it is an error, and so is one never closed.
        assert!(access_list("D:(A;;0x1;;;SY)\"(A;;GA;;;WD)\"").is_err());
        assert!(access_list("D:(A;;0x1;;;SY)(XA;;FX;;;WD;(@User.X==\"a))").is_err());
    }

    /// KR-REQ-03.24: what a person reads says whether the object admits more, or is only one the
    /// starter does not accept.
    #[test]
    fn the_refusal_a_person_reads_says_whether_the_object_admits_more() {
        let own = texts("D:(A;;0xF;;;SY)", "");
        let said = |access| {
            require_no_more(&own, &texts(access, ""))
                .expect_err("refused")
                .to_string()
        };
        let wider = said("D:(A;;0xF;;;SY)(A;;0x1;;;WD)");
        assert!(wider.contains("admits more"), "{wider}");
        assert!(wider.contains("access list"), "{wider}");
        let narrower = said("D:(A;;0x1;;;SY)");
        assert!(!narrower.contains("admits more"), "{narrower}");
        assert!(
            narrower.contains("not one the starter accepts"),
            "{narrower}"
        );
        assert!(narrower.contains("access list"), "{narrower}");
    }
}
