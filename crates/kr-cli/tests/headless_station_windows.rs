//! A headless worker's window station when it is not the one the starter would make, against a real
//! daemon and a real worker.
//!
//! KR-REQ-03.24: a headless worker is started on a desktop of its own, on the window station of its
//! logon. A station that exists already keeps the security it was made with, so the starter reads
//! the station back and refuses to start a worker on one that admits more than the starter's own
//! station does, and starts it on one that admits less: the interactive station gains entries
//! while a logon lasts ("Run as different user" adds one for the account it starts a program as),
//! and a station made before that has not the new entry.
//!
//! These cases change the security of objects that every headless start of this logon meets, so
//! they run one at a time, and each puts back what it changed. They need a signed-in interactive
//! session, which is where the logon's stations are the ones the starter meets.

#![cfg(windows)]

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;
mod windows_station;

use windows_session::WorkerHost;
use windows_station::{EntryOnInteractive, HeldStation};

/// The arguments of a session that needs no shell package: these cases are about where its worker
/// starts.
const NATIVE: &[&str] = &["--shell-mode", "native_compat"];

/// Held by each case for as long as it changes the security of anything.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        said.contains("check the window station's security") && said.contains("admits more"),
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

/// KR-REQ-03.24: a window station that exists already and admits less than the starter's own, for
/// want of an entry, is used, and the worker on it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logon_station_that_admits_less_than_the_starters_own_starts_the_worker() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;

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
/// open, as "Run as different user" adds one, does not refuse the next headless start: the
/// station the first session holds has not the entry, and admits less.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_added_to_the_interactive_station_does_not_refuse_a_later_headless_start() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let host = WorkerHost::start().await;

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
