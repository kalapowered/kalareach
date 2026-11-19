//! What `kr doctor` says of the grants this host holds, and the line a revocation writes to the
//! host's log when it passes over rows that cannot be read.
//!
//! A row is named by its place in the table and by what is wrong with it, never by its key, its
//! payload or the device it names: paired devices read the doctor too.

use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};

use super::Controller;
use crate::error::DamageClass;

/// At most this many damaged rows are named in the detail; the rest are counted.
const NAMED_ROWS: usize = 10;

const TITLE: &str = "The grants this host holds can all be read";

const REMEDY: &str = "Stop the host, run kr host repair-grants to list the damaged rows, run kr host \
                      repair-grants --apply to remove them and withdraw the grants below them, then \
                      start the host. The command first writes a copy of the registry; kr host \
                      repair-grants --undo <copy> --apply puts that copy back, and every change made \
                      to the registry after the copy was made is lost.";

/// The status and the detail for the damaged rows (place and class, in the table's order) and the
/// count of live grants that trace to no root. Each part appears only when its condition holds: a
/// store with only a missing parent or a loop has rows that all decode.
fn detail(damaged: &[(u64, DamageClass)], unplaced: u64) -> (DoctorStatus, Sentence) {
    if damaged.is_empty() && unplaced == 0 {
        return (
            DoctorStatus::Ok,
            Sentence::new()
                .stated("Every grants row can be read, and every live grant traces to a root."),
        );
    }
    let mut sentence = Sentence::new();
    if !damaged.is_empty() {
        sentence = sentence.stated(if damaged.len() == 1 {
            "A grants row cannot be read: "
        } else {
            "Some grants rows cannot be read: "
        });
        for (position, (place, class)) in damaged.iter().take(NAMED_ROWS).enumerate() {
            if position > 0 {
                sentence = sentence.stated(", ");
            }
            sentence = sentence
                .stated("row ")
                .number(*place)
                .stated(" (")
                .stated(class.phrase())
                .stated(")");
        }
        sentence = sentence.stated(".");
        match damaged.len().saturating_sub(NAMED_ROWS) {
            0 => {}
            1 => sentence = sentence.stated(" 1 more row is not named."),
            more => {
                sentence = sentence
                    .stated(" ")
                    .number(u64::try_from(more).unwrap_or(u64::MAX))
                    .stated(" more rows are not named.");
            }
        }
    }
    if unplaced > 0 {
        if !damaged.is_empty() {
            sentence = sentence.stated(" ");
        }
        sentence = sentence.number(unplaced);
        sentence = if unplaced == 1 {
            sentence.stated(
                " live grant traces to no root: it sits below a row that cannot be read or is \
                 missing, or its chain of parents forms a loop.",
            )
        } else {
            sentence.stated(
                " live grants trace to no root: each sits below a row that cannot be read or is \
                 missing, or its chain of parents forms a loop.",
            )
        };
    }
    if !damaged.is_empty() {
        sentence = sentence.stated(
            " A row that cannot be read gives no new access, though a connection opened before \
             the damage keeps what it held until the owner's next revocation. Until it is \
             repaired this host can refuse to list, transfer, share, offer or redeem grants where \
             such a row is involved.",
        );
    }
    sentence = sentence.stated(
        " The owner's revocation of a device still withdraws every grant of the device and every \
         grant that traces to no root, and marks each row that cannot be read as revoked.",
    );
    (DoctorStatus::Failed, sentence)
}

/// The line a revocation of the owner's writes to the host's log when it marked rows that cannot
/// be read or withdrew grants that trace to no root; none for a repeat, which does neither. It
/// holds counts and no key or payload.
#[must_use]
pub(super) fn grants_passed_over_line(marked: u32, withdrawn_unplaced: u32) -> Option<String> {
    (marked > 0 || withdrawn_unplaced > 0).then(|| {
        format!(
            "kr-controller: a revocation marked {marked} grants rows that cannot be read as \
             revoked and withdrew {withdrawn_unplaced} grants that trace to no root; see the \
             grants check of kr doctor"
        )
    })
}

impl Controller {
    /// The `grants-readable` check: whether every grants row can be read and every live grant
    /// traces to a root.
    pub(super) fn grants_check(&self) -> DoctorCheck {
        match self.sharing.grants().scan() {
            Ok(scan) => {
                let damaged: Vec<(u64, DamageClass)> = scan
                    .damaged
                    .iter()
                    .map(|row| (row.place, row.damage.class))
                    .collect();
                let unplaced = u64::try_from(scan.unplaced_live().len()).unwrap_or(u64::MAX);
                let (status, sentence) = detail(&damaged, unplaced);
                let remedy = (status == DoctorStatus::Failed).then_some(REMEDY);
                DoctorCheck::new("grants-readable", TITLE, status, sentence, remedy)
            }
            Err(_) => DoctorCheck::new(
                "grants-readable",
                TITLE,
                DoctorStatus::Failed,
                Sentence::new().stated("The grants table of this host could not be read."),
                None,
            ),
        }
    }

    /// Writes [`grants_passed_over_line`] to the host's log.
    pub(super) fn report_grants_passed_over(marked: u32, withdrawn_unplaced: u32) {
        if let Some(line) = grants_passed_over_line(marked, withdrawn_unplaced) {
            eprintln!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(damaged: &[(u64, DamageClass)], unplaced: u64) -> (DoctorStatus, String) {
        let (status, sentence) = detail(damaged, unplaced);
        (status, sentence.as_str().to_owned())
    }

    /// One row of each class is named by its place and its class phrase, in the table's order, with
    /// the part on what a damaged row does and the part on the owner's revocation, and no part on
    /// grants that trace to no root.
    #[test]
    fn the_doctor_names_each_damaged_row_by_place_and_class() {
        let rows = [
            (1, DamageClass::ColumnOfAnotherType("grant_id")),
            (3, DamageClass::RecordDoesNotDecode),
            (4, DamageClass::KeyNamesAnotherGrant),
            (6, DamageClass::RecipientColumnDisagrees),
            (7, DamageClass::ParentColumnDisagrees),
        ];
        let (status, detail) = text(&rows, 0);
        assert_eq!(status, DoctorStatus::Failed);
        assert_eq!(
            detail,
            "Some grants rows cannot be read: row 1 (a column holds a value of the wrong type), \
             row 3 (its record does not decode), row 4 (its key does not name the grant it \
             holds), row 6 (its recipient column does not match its record), row 7 (its parent \
             column does not match its record). A row that cannot be read gives no new access, \
             though a connection opened before the damage keeps what it held until the owner's \
             next revocation. Until it is repaired this host can refuse to list, transfer, \
             share, offer or redeem grants where such a row is involved. The owner's revocation \
             of a device still withdraws every grant of the device and every grant that traces \
             to no root, and marks each row that cannot be read as revoked."
        );
        let (_, one) = text(&rows[..1], 0);
        assert!(
            one.starts_with("A grants row cannot be read: row 1 ("),
            "{one}"
        );
    }

    /// A store with a row of each class, written by raw SQL, a malformed key among them, and a live
    /// grant below a deleted row: the check reads the places and the classes from the store, and
    /// its detail holds no key and no decoded identifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_doctor_check_of_a_damaged_store_names_each_row_by_place_and_class_and_no_key() {
        use crate::service::a_revocation_beside_a_row_that_cannot_be_read::{
            device_id, grant_id, issue, key,
        };
        use crate::service::a_transfer_left_unanswered::daemon;
        use crate::service::one_barrier_for_every_restriction::beside;

        let (temp, controller) = daemon().await;
        let holder = device_id(0xe5);
        for byte in 0x41..=0x47 {
            issue(&controller, byte, None, holder);
        }
        issue(&controller, 0x49, None, holder);
        issue(&controller, 0x48, Some(0x49), holder);
        let damage = |grant: u8, set: &str| {
            format!(
                "UPDATE grants SET {set} WHERE grant_id = {};",
                key(grant_id(grant))
            )
        };
        beside(&temp)
            .execute_batch(&format!(
                "{}{}{}{}{}DELETE FROM grants WHERE grant_id = {};",
                damage(0x41, "grant = 7"),
                damage(0x43, "grant = X'00'"),
                damage(0x44, "grant_id = X'0102'"),
                damage(
                    0x46,
                    "recipient_device_id = X'abababababababababababababababab'"
                ),
                damage(0x47, "parent_grant_id = X'00'"),
                key(grant_id(0x49)),
            ))
            .expect("the rows are damaged");

        let check = controller.grants_check();
        assert_eq!(check.status, DoctorStatus::Failed);
        assert_eq!(
            check.detail(),
            "Some grants rows cannot be read: row 1 (a column holds a value of the wrong type), \
             row 3 (its record does not decode), row 4 (its key does not name the grant it \
             holds), row 6 (its recipient column does not match its record), row 7 (its parent \
             column does not match its record). 1 live grant traces to no root: it sits below a \
             row that cannot be read or is missing, or its chain of parents forms a loop. A row \
             that cannot be read gives no new access, though a connection opened before the \
             damage keeps what it held until the owner's next revocation. Until it is repaired \
             this host can refuse to list, transfer, share, offer or redeem grants where such a \
             row is involved. The owner's revocation of a device still withdraws every grant of \
             the device and every grant that traces to no root, and marks each row that cannot \
             be read as revoked."
        );
        for byte in 0x41..=0x49_u8 {
            let hex = format!("{byte:02x}").repeat(16);
            assert!(
                !check.detail().to_lowercase().contains(&hex),
                "no grant identifier is in the detail"
            );
        }
        assert!(!check.detail().contains("0102") && !check.detail().contains("abab"));
    }

    /// A store whose rows all decode, with live grants that sit below a missing row or in a loop,
    /// counts them and says nothing of a row that cannot be read, nor of grants refusing to list.
    #[test]
    fn the_doctor_counts_the_live_grants_that_trace_to_no_root_when_no_row_is_damaged() {
        let (status, detail) = text(&[], 4);
        assert_eq!(status, DoctorStatus::Failed);
        assert_eq!(
            detail,
            "4 live grants trace to no root: each sits below a row that cannot be read or is \
             missing, or its chain of parents forms a loop. The owner's revocation of a device \
             still withdraws every grant of the device and every grant that traces to no root, \
             and marks each row that cannot be read as revoked."
        );
        assert!(
            !detail.contains("Some grants rows cannot be read"),
            "{detail}"
        );
        assert!(!detail.contains("refuse to list"), "{detail}");
        let (_, one) = text(&[], 1);
        assert!(
            one.starts_with("1 live grant traces to no root: it sits below a row"),
            "{one}"
        );
        let (_, both) = text(&[(2, DamageClass::RecordDoesNotDecode)], 4);
        assert!(
            both.contains(
                "(its record does not decode). 4 live grants trace to no root: each sits"
            ),
            "{both}"
        );
    }

    #[test]
    fn the_doctor_check_of_a_sound_store_is_ok() {
        let (status, detail) = text(&[], 0);
        assert_eq!(status, DoctorStatus::Ok);
        assert_eq!(
            detail,
            "Every grants row can be read, and every live grant traces to a root."
        );
    }

    /// Twelve damaged rows: ten are named, two are counted, and nothing but places and classes is
    /// in the text.
    #[test]
    fn the_doctor_check_names_no_payload_value_and_no_more_than_ten_rows() {
        let rows: Vec<(u64, DamageClass)> = (1..=12)
            .map(|place| (place, DamageClass::RecordDoesNotDecode))
            .collect();
        let (_, detail) = text(&rows, 0);
        assert!(detail.contains("row 10 ("), "{detail}");
        assert!(!detail.contains("row 11"), "{detail}");
        assert!(detail.contains(" 2 more rows are not named."), "{detail}");
        let (_, eleven) = text(&rows[..11], 0);
        assert!(eleven.contains(" 1 more row is not named."), "{eleven}");
    }

    #[test]
    fn the_grants_passed_over_line_is_exact_and_names_no_key() {
        assert_eq!(
            grants_passed_over_line(2, 3).as_deref(),
            Some(
                "kr-controller: a revocation marked 2 grants rows that cannot be read as revoked \
                 and withdrew 3 grants that trace to no root; see the grants check of kr doctor"
            )
        );
        assert_eq!(grants_passed_over_line(0, 0), None);
        assert!(grants_passed_over_line(1, 0).is_some());
        assert!(grants_passed_over_line(0, 1).is_some());
    }
}
