//! The doctor's check of the native bridges this host has put in applications' directories.
//!
//! A check's sentence carries nothing that arrived from outside this build: what it can say of a
//! package's name, an application's name, a path or a note from the journal is its class and its
//! length. What it states of a bridge is therefore what this host measured or computed: where the
//! bridge stands, how many files it published, and each file's digest, which a person compares with
//! the one the package's recipe names.

use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};

use super::BridgeReport;

const ID: &str = "native-bridges";
const TITLE: &str = "The native bridges installed packages have put in place";

/// What the doctor says of every bridge this host has a journal for: where each stands, the
/// application it is for and each file it published by digest.
///
/// A bridge that is applying or removing, one that is unsettled because something may be this
/// host's and cannot be shown to be, and one that is applied or removed with something that no
/// longer matches or was left in place, is a warning: its recipe is half done, or the files are not
/// what was applied. A bridge the host refused has nothing of it in place, and is reported as
/// refused with why, which is every recipe on Windows.
#[must_use]
pub fn check(reports: &[BridgeReport]) -> DoctorCheck {
    if reports.is_empty() {
        return DoctorCheck::new(
            ID,
            TITLE,
            DoctorStatus::NotApplicable,
            Sentence::new().stated("no package has put a native bridge in place on this host"),
            None,
        );
    }
    let mut detail = Sentence::new();
    let mut warn = false;
    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            detail = detail.stated("; ");
        }
        detail = detail.withheld(ContentClass::Name, &report.plugin_id);
        if let Some(application) = &report.application {
            detail = detail
                .stated(" for ")
                .withheld(ContentClass::Name, application);
        }
        let (words, trouble) = match report.state.as_str() {
            "applied" => (" is applied", !report.notes.is_empty()),
            "applying" => (" is applying, and not every change is in place", true),
            "removing" => (" is removing, and not every change is gone", true),
            "refused" => (" was refused, and nothing of it is in place", false),
            "removed" => (" was removed", !report.notes.is_empty()),
            "unsettled" => (
                " is unsettled: something may be this host's and cannot be shown to be",
                true,
            ),
            _ => (" is in a state this build does not know", true),
        };
        warn |= trouble;
        detail = detail.stated(words);
        if !report.files.is_empty() {
            detail = detail
                .stated(", with ")
                .number(report.files.len() as u64)
                .stated(" published files, by digest ");
            for (position, file) in report.files.iter().enumerate() {
                if position > 0 {
                    detail = detail.stated(", ");
                }
                // The first sixteen digits of a digest this host recorded, as it writes its own.
                detail = match file
                    .digest
                    .get(..16)
                    .and_then(|prefix| u64::from_str_radix(prefix, 16).ok())
                {
                    Some(prefix) => detail.hexadecimal(prefix),
                    None => detail.stated("unreadable"),
                };
            }
        }
        for (position, note) in report.notes.iter().enumerate() {
            detail = detail
                .stated(if position == 0 { ": " } else { "; " })
                .withheld(ContentClass::Message, note);
        }
    }
    DoctorCheck::new(
        ID,
        TITLE,
        if warn {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        detail,
        warn.then_some(
            "A bridge that did not finish is settled by the next reconciliation of its package. \
             Something this host cannot show to be its own is never taken: it stays where it is, \
             and the bridge is not reported as applied until its owner has removed it.",
        ),
    )
}

/// The check for a host whose bridges' records could not be read.
#[must_use]
pub fn unread_check() -> DoctorCheck {
    DoctorCheck::new(
        ID,
        TITLE,
        DoctorStatus::Warning,
        Sentence::new().stated(
            "the records of the native bridges could not be read, so what this host has put in \
             applications' directories is not known",
        ),
        Some(
            "Look at the host's native bridge records under its state directory, or remove the \
             package and install it again.",
        ),
    )
}
