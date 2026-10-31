//! A headless worker's window station when it is not the one the starter would make, against a real
//! daemon and a real worker.
//!
//! KR-REQ-03.24: a headless worker is started on a desktop of its own, on the window station of its
//! logon. A station that exists already keeps the security it was made with, so the starter reads
//! the station back and refuses to start a worker on one that admits more than the starter's own
//! station does, and starts it on one that admits less: the interactive station gains entries
//! while a logon lasts (a "Run as different user" may add one for the account it starts a program
//! as), and a station made before that has not the new entry. A station that differs in a way the
//! lists alone do not show to admit more, such as one entry with another mask, is refused too, and
//! the refusal does not say that it admits more.
//!
//! The desktop is checked the same way. A desktop that exists already on the station keeps the
//! security it was made with, so a desktop that admits more than the starter's own is refused. The
//! name of a worker's desktop is not one a case can know, so the case asks the starter for a
//! desktop of a name it chose, the way the daemon's task does.
//!
//! These cases change the security of objects that every headless start of this logon meets, so
//! they run one at a time, and each puts back what it changed. They need a signed-in interactive
//! session, and the daemon's task must run in the same logon as this test, which holds when the
//! account is not an administrator with an elevated token over a filtered one: a window station made
//! without a name belongs to its maker's logon. Each case first shows that the starter does meet a
//! station this test makes, and fails if it does not, rather than passing without having shown
//! anything. No other headless worker of this logon may be running.

#![cfg(windows)]

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;
mod windows_station;

use std::path::Path;

use kr_ipc::starter::{ChildCommand, ChildRefusal, StartedChild, current_session, end_process};
use windows_session::WorkerHost;
use windows_station::{EntryOnInteractive, HeldDesktop, HeldStation};

/// The arguments of a session that needs no shell package: these cases are about where its worker
/// starts.
const NATIVE: &[&str] = &["--shell-mode", "native_compat"];

/// The integrity label no object can have a lower one than: untrusted, with no writing from below.
const UNTRUSTED_LABEL: &str = "S:(ML;;NW;;;S-1-16-0)";

/// Held by each case for as long as it changes the security of anything.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What a refused start says when it was refused for a window station that admits more than the
/// starter's own.
fn refused_for_the_station(said: &str) -> bool {
    said.contains("check the window station's security") && said.contains("admits more")
}

/// What a refused start says when it was refused for a window station that is not one the starter
/// accepts and that the lists alone do not show to admit more.
fn not_accepted_for_the_station(said: &str) -> bool {
    said.contains("check the window station's security")
        && said.contains("is not one the starter accepts")
        && !said.contains("admits more")
}

/// Holds a window station of the logon that admits everyone, where the starter's own does not, and
/// requires the start that meets it to be refused for that station, which shows that the starter
/// and this test are in one logon.
async fn the_starter_meets_the_stations_this_test_makes(host: &WorkerHost) {
    let wider = HeldStation::make(|own| format!("{own}(A;;0x1;;;WD)"))
        .unwrap_or_else(|error| panic!("a station wider than the starter's own: {error}"));
    let refused = host.kr_new(NATIVE).await;
    assert!(
        !refused.succeeded() && refused_for_the_station(&refused.said()),
        "the start was not refused for a window station of this test's logon that admits everyone, \
         so the starter may be in another logon and these cases would show nothing, or the check \
         is gone ({}): {}",
        wider.access_list,
        refused.said()
    );
}

/// KR-REQ-03.24: a window station that exists already and admits everyone, where the starter's
/// own does not, is refused, with the step that refused it named, and no worker is started on it.
/// Control: once it is gone the next start is not refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logon_station_that_admits_more_than_the_starters_own_refuses_the_start() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;

    let wider = HeldStation::make(|own| format!("{own}(A;;0x1;;;WD)"))
        .unwrap_or_else(|error| panic!("a station wider than the starter's own: {error}"));
    let refused = host.kr_new(NATIVE).await;
    assert!(
        !refused.succeeded(),
        "a headless session was started on a window station that admits everyone: {}",
        wider.access_list
    );
    let said = refused.said();
    assert!(
        refused_for_the_station(&said),
        "the refusal does not say which check refused: {said}"
    );

    drop(wider);
    let after = host.kr_new(NATIVE).await;
    assert!(
        after.succeeded(),
        "the start after the wider station was gone was refused: {}",
        after.said()
    );
}

/// KR-REQ-03.24: a window station that exists already and whose list is the starter's own with the
/// mask of one entry narrowed is refused, and the refusal says that the station is not one the
/// starter accepts and not that it admits more: a narrower mask admits less, which the lists alone
/// do not show. Control: once it is gone the next start is not refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logon_station_with_a_narrower_entry_is_refused_without_being_called_wider() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;
    the_starter_meets_the_stations_this_test_makes(&host).await;

    let narrower = HeldStation::make(with_a_narrower_entry)
        .unwrap_or_else(|error| panic!("a station with a narrower entry: {error}"));
    let refused = host.kr_new(NATIVE).await;
    assert!(
        !refused.succeeded(),
        "a headless session was started on a window station that is not the starter's own: {}",
        narrower.access_list
    );
    let said = refused.said();
    assert!(
        not_accepted_for_the_station(&said),
        "the refusal does not say that the station is not one the starter accepts, or says that it \
         admits more: {said}"
    );

    drop(narrower);
    let after = host.kr_new(NATIVE).await;
    assert!(
        after.succeeded(),
        "the start after the narrower station was gone was refused: {}",
        after.said()
    );
}

/// KR-REQ-03.24: a window station that exists already, with the starter's own access list and the
/// lowest integrity label, which is below whatever the interactive station has, is refused for its
/// label, with the step named, and the refusal says that it admits more. The starter would raise a
/// label that it may change, so the station withholds that right from everyone with a denying
/// entry, which is a further entry and admits less. Control: once it is gone the next start is not
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logon_station_with_a_lower_integrity_label_refuses_the_start() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;
    the_starter_meets_the_stations_this_test_makes(&host).await;

    let lower = HeldStation::make_labelled(without_the_right_to_relabel, UNTRUSTED_LABEL)
        .unwrap_or_else(|error| panic!("a station with the lowest integrity label: {error}"));
    assert!(
        lower.label.contains("S-1-16-0"),
        "the station was made with another label than the lowest one: {:?}",
        lower.label
    );
    let refused = host.kr_new(NATIVE).await;
    assert!(
        !refused.succeeded(),
        "a headless session was started on a window station with the lowest integrity label: {}",
        lower.label
    );
    let said = refused.said();
    assert!(
        refused_for_the_station(&said) && said.contains("integrity label"),
        "the refusal does not say that the integrity label admits more: {said}"
    );

    drop(lower);
    let after = host.kr_new(NATIVE).await;
    assert!(
        after.succeeded(),
        "the start after the low-label station was gone was refused: {}",
        after.said()
    );
}

/// Starts a program that ends at once on the desktop `label` of this logon's window station, as the
/// task's starter does for a headless worker.
fn start_on_desktop(label: &str) -> Result<StartedChild, ChildRefusal> {
    let system = std::env::var_os("SystemRoot").expect("the system directory");
    let program = Path::new(&system).join("System32").join("cmd.exe");
    kr_ipc::starter::start_child(&ChildCommand {
        application: &program,
        command_line: "cmd.exe /c exit 0",
        directory: Path::new(&system),
        environment: &[],
        session: current_session().expect("this process's session"),
        output: None,
        own_desktop: Some(label),
    })
}

/// KR-REQ-03.24: a desktop that exists already on the logon's window station and admits more than
/// the starter's own is refused, with the step named, and no program is started on it. Control: a
/// desktop that does not exist yet is made on the same station and a program starts on it, which
/// shows that the starter meets the station this test holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desktop_that_exists_already_and_admits_more_than_the_starters_own_refuses_the_start() {
    const WIDER: &str = "kr-test-wider-desktop";
    const FRESH: &str = "kr-test-fresh-desktop";
    let _alone = ONE_AT_A_TIME.lock().await;

    let station = HeldStation::make(|own| own.to_owned()).unwrap_or_else(|error| {
        panic!("the logon's station as the starter would make it: {error}")
    });
    let wider = HeldDesktop::make(&station, WIDER, |own| format!("{own}(A;;0x1;;;WD)"))
        .unwrap_or_else(|error| panic!("a desktop wider than the starter's own: {error}"));

    let refused = start_on_desktop(WIDER).err().unwrap_or_else(|| {
        panic!(
            "a program was started on a desktop that admits everyone: {}",
            wider.access_list
        )
    });
    assert!(
        refused.detail.contains("check the desktop's security"),
        "the refusal does not say which check refused: {}",
        refused.detail
    );
    assert!(
        refused.remaining_pid.is_none(),
        "a program was created for the refused start: {refused:?}"
    );

    let started = start_on_desktop(FRESH).unwrap_or_else(|refusal| {
        panic!(
            "the start on a desktop that does not exist yet was refused, so the starter may not meet \
             the station this test holds ({}): {}",
            station.access_list, refusal.detail
        )
    });
    // The program ends by itself; a second end is not an error.
    let _ = end_process(&started.identity);
}

/// KR-REQ-03.24: a window station that exists already and admits less than the starter's own, for
/// want of an entry, is used, and the worker on it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logon_station_that_admits_less_than_the_starters_own_starts_the_worker() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;
    the_starter_meets_the_stations_this_test_makes(&host).await;

    let narrower = HeldStation::make(without_administrators)
        .unwrap_or_else(|error| panic!("a station narrower than the starter's own: {error}"));
    let created = host.kr_new(NATIVE).await;
    assert!(
        created.succeeded(),
        "a headless session was refused a window station that admits less ({}): {}",
        narrower.access_list,
        created.said()
    );
}

/// KR-REQ-03.24: an entry added to the interactive station and desktop while a headless session is
/// open, as a "Run as different user" may add one, does not refuse the next headless start: the
/// station the first session holds has not the entry, and admits less.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_added_to_the_interactive_station_does_not_refuse_a_later_headless_start() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;
    the_starter_meets_the_stations_this_test_makes(&host).await;

    let first = host.kr_new(NATIVE).await;
    assert!(first.succeeded(), "the first session: {}", first.said());

    let added = EntryOnInteractive::add()
        .unwrap_or_else(|error| panic!("an entry on the interactive station: {error}"));
    let list = added
        .station_access_list()
        .unwrap_or_else(|error| panic!("the interactive station's list: {error}"));
    assert!(
        list.contains("S-1-5-5-0-4242424"),
        "the entry is not on the interactive station: {list}"
    );
    let second = host.kr_new(NATIVE).await;
    assert!(
        second.succeeded(),
        "a headless start was refused after an entry was added to the interactive station: {}",
        second.said()
    );
    added
        .put_back()
        .unwrap_or_else(|error| panic!("the interactive station was not left as it was: {error}"));
}

/// The station's access list without the entry for the administrators that applies to the station
/// itself, which the account does not need to use the station.
fn without_administrators(own: &str) -> String {
    const TRUSTEE: &str = ";;;BA)";
    let mut from = 0;
    while let Some(found) = own[from..].find(TRUSTEE) {
        let at = from + found;
        let start = own[..at]
            .rfind('(')
            .unwrap_or_else(|| panic!("the entry has no start: {own}"));
        let flags = own[start + 1..at].split(';').nth(1).unwrap_or_default();
        if !flags.contains("IO") {
            return format!("{}{}", &own[..start], &own[at + TRUSTEE.len()..]);
        }
        from = at + TRUSTEE.len();
    }
    panic!("the interactive station has no entry for the administrators that applies to it: {own}")
}

/// The station's access list with the mask of its first allowing entry that has a hexadecimal mask
/// narrowed by the lowest bit it holds.
fn with_a_narrower_entry(own: &str) -> String {
    let mut from = 0;
    while let Some(at) = own[from..].find('(') {
        let start = from + at;
        let end = start
            + own[start..]
                .find(')')
                .unwrap_or_else(|| panic!("the entry is not closed: {own}"));
        let mut fields: Vec<&str> = own[start + 1..end].split(';').collect();
        let mask = fields
            .get(2)
            .and_then(|rights| rights.strip_prefix("0x"))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .filter(|mask| *mask != 0);
        if let Some(mask) = mask
            && fields.len() >= 6
            && fields[0] == "A"
            && !fields[1].contains("IO")
        {
            let narrower = format!("0x{:x}", mask & (mask - 1));
            fields[2] = &narrower;
            return format!("{}({}){}", &own[..start], fields.join(";"), &own[end + 1..]);
        }
        from = end + 1;
    }
    panic!("the interactive station has no allowing entry with a hexadecimal mask to narrow: {own}")
}

/// The station's access list with a denying entry put in front that takes the right to change the
/// owner and the label from everyone.
fn without_the_right_to_relabel(own: &str) -> String {
    let at = own
        .find('(')
        .unwrap_or_else(|| panic!("the interactive station has no entry: {own}"));
    format!("{}(D;;WO;;;WD){}", &own[..at], &own[at..])
}
