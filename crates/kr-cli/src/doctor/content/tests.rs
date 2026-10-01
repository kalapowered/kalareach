//! The privacy rule and the composition of the content export, without a host.

use super::*;
use kr_protocol::ids::SessionEpoch;
use kr_protocol::privacy::{PrivacyCompletion, PrivacySession, PrivacySessionStanding};
use kr_protocol::scalars::{TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber};

fn session_id(token: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([token; 16]))
}

/// A session the host lists, running `/bin/sh` in `/work`.
fn listed(token: u8) -> SessionSummary {
    SessionSummary {
        session_id: session_id(token),
        session_epoch: SessionEpoch::V1,
        environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
        display_number: DisplayNumber::new(u64::from(token)),
        state: SessionState::Live,
        shell_mode: ShellMode::NativeCompat,
        shell_path: "/bin/sh".to_owned(),
        cwd: "/work".to_owned(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: TimestampMs::new(1_000),
        dimensions: Dimensions::new(80, 24),
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
    }
}

/// Privacy mode's report at `generation`, on or off, with `owing` sessions still owing cleanup.
fn report(generation: u64, enabled: bool, owing: &[u8]) -> PrivacyReport {
    PrivacyReport {
        generation: U64::new(generation),
        enabled,
        changed_at_ms: TimestampMs::new(1),
        completion: PrivacyCompletion::Complete,
        sessions: owing
            .iter()
            .map(|token| PrivacySession {
                session_id: session_id(*token),
                generation: U64::new(generation),
                standing: PrivacySessionStanding::WorkerEnded,
            })
            .collect(),
        disabled: Vec::new(),
        kept: Vec::new(),
        exported: Vec::new(),
        unlisted: Vec::new(),
    }
}

/// Why each session of a selection is out, by token.
fn outcome(selection: &[Listed]) -> Vec<(SessionId, Option<Why>)> {
    selection
        .iter()
        .map(|listed| (listed.summary.session_id, listed.why))
        .collect()
}

/// KR-REQ-29.04: with privacy mode never enabled, no session is private: the control for every
/// case below.
#[test]
fn nothing_is_private_where_privacy_mode_was_never_on() {
    let selection = select(
        &report(0, false, &[]),
        vec![listed(1), listed(2)],
        &report(0, false, &[]),
    );
    assert_eq!(
        outcome(&selection),
        vec![(session_id(1), None), (session_id(2), None)]
    );
}

/// KR-REQ-29.04: while privacy mode is on, every session is private, live or closed, whether or
/// not the host lists it as owing anything: the switch is one for the environment.
#[test]
fn every_session_is_private_while_privacy_mode_is_on_at_either_read() {
    for (before, after) in [
        (report(1, true, &[]), report(1, true, &[])),
        (report(1, true, &[]), report(1, false, &[])),
        (report(0, false, &[]), report(1, true, &[])),
    ] {
        let selection = select(&before, vec![listed(1), listed(2)], &after);
        assert_eq!(
            outcome(&selection),
            vec![
                (session_id(1), Some(Why::PrivacyOn)),
                (session_id(2), Some(Why::PrivacyOn))
            ],
            "on at {} then {}",
            before.enabled,
            after.enabled
        );
    }
}

/// KR-REQ-29.04: a generation that moved between the reads, with privacy mode off at both ends, is
/// a mode that was turned on and off around the list: nothing read across it is exported.
#[test]
fn a_generation_that_moved_with_privacy_mode_off_at_both_ends_leaves_every_session_out() {
    let selection = select(
        &report(0, false, &[]),
        vec![listed(1)],
        &report(2, false, &[]),
    );
    assert_eq!(outcome(&selection), vec![(session_id(1), Some(Why::Moved))]);
}

/// KR-REQ-29.04: with privacy mode off, a session the host still lists as owing cleanup is private
/// and one it does not list is not, whichever of the two reads lists it.
#[test]
fn a_session_that_still_owes_cleanup_is_private_whatever_the_switch_says() {
    for (before, after) in [
        (report(3, false, &[2]), report(3, false, &[])),
        (report(3, false, &[]), report(3, false, &[2])),
        (report(3, false, &[2]), report(3, false, &[2])),
    ] {
        let selection = select(&before, vec![listed(1), listed(2), listed(3)], &after);
        assert_eq!(
            outcome(&selection),
            vec![
                (session_id(1), None),
                (session_id(2), Some(Why::OwesCleanup)),
                (session_id(3), None)
            ]
        );
    }
}

/// What the host says, scripted: its privacy reports in order, then its sessions, and a record of
/// what was asked in what order.
struct Scripted {
    privacy: Vec<Result<PrivacyReport>>,
    sessions: Vec<SessionSummary>,
    asked: Vec<&'static str>,
}

impl Host for Scripted {
    async fn privacy(&mut self) -> Result<PrivacyReport> {
        self.asked.push("privacy");
        self.privacy.remove(0)
    }

    async fn sessions(&mut self, _: EnvironmentId) -> Result<SessionListResult> {
        self.asked.push("sessions");
        Ok(SessionListResult {
            sessions: self.sessions.clone(),
        })
    }
}

fn failure() -> CliError {
    CliError::Other(Shown::said("the host did not answer"))
}

/// KR-REQ-29.04: privacy mode is read, then the sessions, then privacy mode again.
#[tokio::test]
async fn privacy_mode_is_read_on_both_sides_of_the_sessions() {
    let mut host = Scripted {
        privacy: vec![Ok(report(0, false, &[])), Ok(report(0, false, &[]))],
        sessions: vec![listed(1)],
        asked: Vec::new(),
    };
    let reading = read(&mut host, EnvironmentId::new(Uuid::from_bytes([9; 16])))
        .await
        .expect("a reading");
    assert_eq!(host.asked, ["privacy", "sessions", "privacy"]);
    assert_eq!(outcome(&reading.listed), vec![(session_id(1), None)]);
}

/// KR-REQ-29.04: a privacy read that fails, at either end, fails the reading: nothing is composed
/// from sessions that could not be told apart from private ones.
#[tokio::test]
async fn a_failed_privacy_read_at_either_end_fails_the_reading() {
    for script in [
        vec![Err(failure()), Ok(report(0, false, &[]))],
        vec![Ok(report(0, false, &[])), Err(failure())],
    ] {
        let mut host = Scripted {
            privacy: script,
            sessions: vec![listed(1)],
            asked: Vec::new(),
        };
        let refused = read(&mut host, EnvironmentId::new(Uuid::from_bytes([9; 16]))).await;
        assert!(refused.is_err(), "the reading fails with the host's answer");
    }
}

/// KR-REQ-29.04: the file names the sessions that are in and none that are out, and the sentence
/// the preview and the manifest carry says how many were left out and why.
#[test]
fn the_export_names_what_is_in_and_says_why_the_rest_is_out() {
    let selection = select(
        &report(2, false, &[2]),
        vec![listed(1), listed(2), listed(3)],
        &report(2, false, &[2]),
    );
    let composed = compose(&Reading { listed: selection }).expect("composes");
    assert_eq!(composed.left_out(), [(Why::OwesCleanup, 1)]);
    let content = composed.into_content();
    let text = String::from_utf8(content.bytes.clone()).expect("text");
    assert!(text.contains(&session_id(1).to_string()), "{text}");
    assert!(text.contains(&session_id(3).to_string()), "{text}");
    assert!(
        !text.contains(&session_id(2).to_string()),
        "a session that is out is not named: {text}"
    );
    assert_eq!(
        content.describe().as_str(),
        "  content/sessions.json: the shell, working directory and closure of 2 sessions; 1 session \
         left out: it still owes the cleanup privacy mode asked for"
    );
}

/// KR-REQ-29.04: when every session is out the entry is still there, with no sessions in it, so the
/// manifest records the omission rather than a bundle that looks as if the host had none.
#[test]
fn an_export_with_every_session_out_is_an_empty_list_that_says_so() {
    let selection = select(
        &report(1, true, &[]),
        vec![listed(1), listed(2)],
        &report(1, true, &[]),
    );
    let content = compose(&Reading { listed: selection })
        .expect("composes")
        .into_content();
    let record: serde_json::Value = serde_json::from_slice(&content.bytes).expect("JSON");
    assert_eq!(record["sessions"], serde_json::json!([]));
    assert_eq!(
        content.describe().as_str(),
        "  content/sessions.json: the shell, working directory and closure of 0 sessions; 2 sessions \
         left out: privacy mode is on"
    );
}
