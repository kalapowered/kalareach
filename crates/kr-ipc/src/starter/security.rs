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
//! which children inherit an entry, and entries that only children inherit, are not compared. Any
//! other list is refused, whether or not it admits more.
//!
//! The text is what the system writes for a descriptor, `D:` and its entries for an access list or
//! `S:` and its label entry for the integrity label. Nothing here calls the system, so it is read
//! and compared the same way wherever it runs.

/// What a security descriptor's access list is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AccessList {
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
pub(super) struct Entry {
    decision: Decision,
    /// Everything that decides whom the entry affects and what it affects: the kind, the rights,
    /// the object identifiers, the trustee and any condition. The flags that say which child
    /// objects inherit the entry are not in it, because they do not change who may use this
    /// object.
    meaning: String,
}

/// An integrity label: the level a process needs to write to an object, and what the object
/// refuses to lower ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Label {
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

/// Reads the access list from the text of a descriptor asked for its access list alone.
///
/// # Errors
///
/// Returns what was not understood when the text is not an access list.
pub(super) fn access_list(text: &str) -> Result<AccessList, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(AccessList::Absent);
    }
    let Some(rest) = text.strip_prefix("D:") else {
        return Err(format!("{text:?} does not begin with an access list"));
    };
    let (flags, entries) = rest.find('(').map_or((rest, ""), |at| rest.split_at(at));
    if flags.contains("NO_ACCESS_CONTROL") {
        return if entries.is_empty() {
            Ok(AccessList::Null)
        } else {
            Err(format!("{text:?} has entries in a null access list"))
        };
    }
    let mut list = Vec::new();
    for inner in parenthesised(entries)? {
        let mut fields = split_top_level(inner);
        if fields.len() < 6 {
            return Err(format!("the entry ({inner}) has too few fields"));
        }
        let kind = fields[0];
        // An entry for the owner's rights narrows what the owner has of its own accord, so taking
        // one away widens that: it can only be matched, never left out. Whether the system counts
        // one that only children inherit is not something this reads, so such an entry is kept too,
        // with its flags.
        if matches!(fields[5], "OW" | "S-1-3-4") && !matches!(kind, "D" | "OD" | "XD") {
            list.push(Entry {
                decision: Decision::Other,
                meaning: fields.join(";"),
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
        });
    }
    Ok(AccessList::Entries(list))
}

/// Reads the integrity label from the text of a descriptor asked for its label alone.
///
/// # Errors
///
/// Returns what was not understood when the text holds a label entry that cannot be read, or more
/// than one.
pub(super) fn label(text: &str) -> Result<Label, String> {
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

/// Says why `found` admits more than `own`, or nothing when it admits no more.
///
/// Fewer allowing entries admit less, except an entry for the owner's rights, and further denying
/// entries admit less. A missing denying entry, a further allowing one, a null list where there
/// were entries, and entries in another order, which the system may evaluate differently, each
/// admit more or cannot be shown to admit no more, and are refused.
pub(super) fn access_list_admits_more(own: &AccessList, found: &AccessList) -> Option<String> {
    match (own, found) {
        (AccessList::Entries(own), AccessList::Entries(found)) => entries_admit_more(own, found),
        // Everyone is admitted by the starter's own, so nothing can be more.
        (AccessList::Absent | AccessList::Null, _) => None,
        (AccessList::Entries(_), AccessList::Absent) => {
            Some("it has no access list, which admits everyone".to_owned())
        }
        (AccessList::Entries(_), AccessList::Null) => {
            Some("its access list is null, which admits everyone".to_owned())
        }
    }
}

/// Says why a label admits more than the starter's own, or nothing when it admits no more.
pub(super) fn label_admits_more(own: Label, found: Label) -> Option<String> {
    if found.level < own.level {
        return Some(format!(
            "its level {:#x} is below the starter's own {:#x}",
            found.level, own.level
        ));
    }
    if found.policy & own.policy != own.policy {
        return Some(format!(
            "its policy {:#x} refuses less than the starter's own {:#x}",
            found.policy, own.policy
        ));
    }
    None
}

/// Says why `found` is not `own` with allowing entries left out and denying entries put in.
///
/// The two lists line up when each entry of `found` is either one of `own`'s, in the same order, or
/// a further denying entry, and each entry of `own` is either matched or an allowing entry that
/// `found` leaves out. Which entries are the further ones is not told by looking at them one at a
/// time, so every way of lining the lists up is tried.
fn entries_admit_more(own: &[Entry], found: &[Entry]) -> Option<String> {
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
    let times = |list: &[Entry], entry: &Entry| list.iter().filter(|other| *other == entry).count();
    if let Some(entry) = found
        .iter()
        .find(|entry| entry.decision != Decision::Deny && times(found, entry) > times(own, entry))
    {
        return Some(format!(
            "it has the entry ({}) more often than the starter's own does",
            entry.meaning
        ));
    }
    if let Some(entry) = own
        .iter()
        .find(|entry| entry.decision != Decision::Allow && times(own, entry) > times(found, entry))
    {
        return Some(format!(
            "it lacks an entry ({}) that the starter's own has",
            entry.meaning
        ));
    }
    Some(
        "its entries are not in the starter's order, which cannot be shown to admit no more"
            .to_owned(),
    )
}

/// Whether the flags of an entry say that only children inherit it. The flags are two letters each,
/// so a pair is looked for and not a run of letters that two flags make.
fn inherit_only(flags: &str) -> bool {
    flags.as_bytes().chunks(2).any(|flag| flag == b"IO")
}

/// The text inside each top-level pair of parentheses of `text`, which holds nothing else.
fn parenthesised(text: &str) -> Result<Vec<&str>, String> {
    let mut entries = Vec::new();
    let mut depth = 0_u32;
    let mut start = 0;
    for (index, character) in text.char_indices() {
        match character {
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
    if depth != 0 {
        return Err(format!("{text:?} leaves a parenthesis open"));
    }
    Ok(entries)
}

/// The fields of an entry, which a condition's own parentheses and semicolons do not split.
fn split_top_level(entry: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut depth = 0_u32;
    let mut start = 0;
    for (index, character) in entry.char_indices() {
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
    use super::{AccessList, access_list, access_list_admits_more, label, label_admits_more};

    fn list(text: &str) -> AccessList {
        access_list(text).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    fn more(own: &str, found: &str) -> Option<String> {
        access_list_admits_more(&list(own), &list(found))
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
        assert!(matches!(
            list("D:(XA;;FX;;;S-1-1-0;(@User.Title==\"PM\";1))(A;;GA;;;SY)"),
            AccessList::Entries(entries) if entries.len() == 2
        ));

        assert!(access_list("O:SY").is_err());
        assert!(access_list("D:(A;;GA;;;SY").is_err());
        assert!(access_list("D:(A;;GA)").is_err());
        assert!(access_list("D:NO_ACCESS_CONTROL(A;;GA;;;SY)").is_err());
    }

    /// KR-REQ-03.24: an object that admits more than the starter's own is refused, whichever way
    /// it admits more.
    #[test]
    fn an_access_list_that_admits_more_than_the_starters_own_is_refused() {
        let own = "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)";
        assert_eq!(more(own, own), None);

        // A further allowing entry, and a null or absent list where there were entries.
        assert!(more(own, "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;WD)").is_some());
        assert!(more(own, "D:NO_ACCESS_CONTROL").is_some());
        assert!(more(own, "").is_some());
        // The same entry with other rights is another entry.
        assert!(more(own, "D:(A;;0x2;;;SY)(A;;0x1;;;S-1-5-5-0-1)").is_some());

        // Deny then allow and allow then deny are different lists: the first admits nobody, the
        // second admits everyone.
        let denying_first = "D:(D;;0x1;;;WD)(A;;0x1;;;WD)";
        let allowing_first = "D:(A;;0x1;;;WD)(D;;0x1;;;WD)";
        assert!(more(denying_first, allowing_first).is_some());
        // Taking away a denying entry admits more; entries in another order cannot be shown to
        // admit no more.
        assert!(more("D:(D;;0x1;;;BG)(A;;0x1;;;SY)", "D:(A;;0x1;;;SY)").is_some());
        assert!(more(own, "D:(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;SY)").is_some());
        // An entry for the owner's rights narrows what the owner has of its own accord, so
        // leaving it out admits more.
        assert!(more("D:(A;;0x20000;;;OW)(A;;0x1;;;WD)", "D:(A;;0x1;;;WD)").is_some());
        assert_eq!(
            more(
                "D:(A;;0x20000;;;OW)(A;;0x1;;;WD)",
                "D:(A;;0x20000;;;OW)(A;;0x1;;;WD)"
            ),
            None
        );
        // One that only children inherit is kept too: whether the system counts it is not read.
        assert!(more("D:(A;OICIIO;0x20000;;;OW)(A;;0x1;;;WD)", "D:(A;;0x1;;;WD)").is_some());
        assert!(
            more(
                "D:(A;;0x1;;;WD)",
                "D:(A;OICIIO;0x20000;;;S-1-3-4)(A;;0x1;;;WD)"
            )
            .is_some()
        );
        // A denying entry for the owner's rights only takes access away.
        assert_eq!(
            more("D:(A;;0x1;;;WD)", "D:(D;;0x20000;;;OW)(A;;0x1;;;WD)"),
            None
        );

        // The reason names what differs: a count, an entry, or the order.
        let said = |own: &str, found: &str| more(own, found).expect("refused");
        assert!(said("D:(D;;0x1;;;WD)(D;;0x1;;;WD)", "D:(D;;0x1;;;WD)").contains("lacks"));
        assert!(said("D:(A;;0x1;;;WD)", "D:(A;;0x1;;;WD)(A;;0x1;;;WD)").contains("more often"));
        assert!(
            said(
                "D:(A;;0x1;;;SY)(A;;0x1;;;BA)",
                "D:(A;;0x1;;;BA)(A;;0x1;;;SY)"
            )
            .contains("order")
        );
    }

    /// KR-REQ-03.24: an object that admits less than the starter's own is not refused: a station
    /// made before an entry was added to the interactive one has not that entry.
    #[test]
    fn an_access_list_that_admits_less_than_the_starters_own_is_not_refused() {
        let own = "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)(A;;0x1;;;S-1-5-5-0-2)";
        // An entry added to the interactive station after the other was made.
        assert_eq!(more(own, "D:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-5-0-1)"), None);
        assert_eq!(more(own, "D:(A;;0x1;;;S-1-5-5-0-1)"), None);
        // Nobody at all, and a further denying entry, admit less.
        assert_eq!(more(own, "D:"), None);
        assert_eq!(more(own, "D:(D;;0x1;;;BG)(A;;0x1;;;SY)"), None);
        // A further denying entry may come before entries that match the starter's own, whichever
        // of the denying entries the starter's own has is the one it matches.
        assert_eq!(
            more(
                "D:(A;;0x1;;;WD)(D;;0x1;;;WD)",
                "D:(D;;0x1;;;WD)(A;;0x1;;;WD)(D;;0x1;;;WD)"
            ),
            None
        );
        // Where the starter's own admits everyone, nothing admits more.
        assert_eq!(more("D:NO_ACCESS_CONTROL", "D:(A;;0x1;;;SY)"), None);
        assert_eq!(more("D:NO_ACCESS_CONTROL", "D:"), None);
        // The same entries under other flags are the same entries.
        assert_eq!(more("D:PAI(A;OICI;0x1;;;SY)", "D:(A;;0x1;;;SY)"), None);
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

        assert_eq!(label_admits_more(own, own), None);
        assert!(label_admits_more(own, read("S:(ML;;NW;;;LW)")).is_some());
        assert!(label_admits_more(own, read("S:(ML;;NR;;;ME)")).is_some());
        // Higher, and refusing more, admit less.
        assert_eq!(label_admits_more(own, read("S:(ML;;NW;;;HI)")), None);
        assert_eq!(label_admits_more(own, read("S:(ML;;NWNR;;;ME)")), None);
        // A label no lower than the medium one, against none, is not more.
        assert_eq!(label_admits_more(read(""), read("S:(ML;;NW;;;HI)")), None);
        assert!(label_admits_more(read(""), read("S:(ML;;NW;;;LW)")).is_some());

        // A label that only children inherit is not the object's own.
        assert_eq!(read("S:(ML;OIIO;NW;;;HI)"), own);
        assert!(label_admits_more(read("S:(ML;;NW;;;HI)"), read("S:(ML;OIIO;NW;;;HI)")).is_some());

        assert!(label("S:(ML;;NW;;;XX)").is_err());
        assert!(label("S:(ML;;QQ;;;ME)").is_err());
        assert!(label("S:(ML;;NW;;;ME)(ML;;NW;;;LW)").is_err());
    }
}
