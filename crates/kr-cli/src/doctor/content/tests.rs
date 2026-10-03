//! The privacy rule and the composition of the content export, without a host.

use super::redact::Paths;
use super::*;
use kr_protocol::hostinfo::ComposedBundle;
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
        environment_sources: None,
    }
}

/// The rules for a host whose home is `/home/tom`.
fn rules() -> Rules {
    Rules::new(
        Some("/home/tom".to_owned()),
        Paths {
            ignores_case: false,
            backslash_separates: false,
        },
    )
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
/// not the host lists it as owing anything: the switch is one for the environment. Said as on when
/// it is on at the second read, and as changed when it was on at the first and is off at the second:
/// what was read across a change is out either way.
#[test]
fn every_session_is_private_while_privacy_mode_is_on_at_either_read() {
    for (before, after, why) in [
        (report(1, true, &[]), report(1, true, &[]), Why::PrivacyOn),
        (report(0, false, &[]), report(1, true, &[]), Why::PrivacyOn),
        (report(1, true, &[]), report(2, false, &[]), Why::Moved),
        (report(1, true, &[]), report(1, false, &[]), Why::Moved),
    ] {
        let selection = select(&before, vec![listed(1), listed(2)], &after);
        assert_eq!(
            outcome(&selection),
            vec![(session_id(1), Some(why)), (session_id(2), Some(why))],
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
    let composed = compose(&Reading { listed: selection }, &[], &rules()).expect("composes");
    assert_eq!(composed.left_out(), [(Why::OwesCleanup, 1)]);
    let text = composed.text();
    assert!(text.contains(&session_id(1).to_string()), "{text}");
    assert!(text.contains(&session_id(3).to_string()), "{text}");
    assert!(
        !text.contains(&session_id(2).to_string()),
        "a session that is out is not named: {text}"
    );
    assert_eq!(
        composed.content.describe().as_str(),
        format!(
            "  content/sessions.json: the shell, working directory and closure of 2 sessions, \
             redacted by session-content-1 and printed before it was written (digest {}); 1 \
             session left out: privacy cleanup is still owed",
            composed.digest().hex()
        )
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
    let composed = compose(&Reading { listed: selection }, &[], &rules()).expect("composes");
    let record: serde_json::Value = serde_json::from_str(composed.text()).expect("JSON");
    assert_eq!(record["sessions"], serde_json::json!([]));
    assert_eq!(record["redaction"], "session-content-1");
    assert!(
        composed
            .content
            .describe()
            .as_str()
            .contains("closure of 0 sessions, redacted by session-content-1"),
        "{}",
        composed.content.describe()
    );
    assert!(
        composed
            .content
            .describe()
            .as_str()
            .ends_with("; 2 sessions left out: privacy mode is on"),
        "{}",
        composed.content.describe()
    );
}

/// KR-REQ-29.04: the record of a closed session holds the closure's closed words and numbers and
/// counts what it stopped and what survived; the names and descriptions the closure carries are
/// text the record does not repeat, and the field list is exactly the one the design names.
#[test]
fn a_closed_session_is_recorded_by_its_closure_and_counts_and_names_nothing_else() {
    use kr_protocol::session::{ClosureRecord, SurvivingResource, TerminatedProcess};

    let marker = "kr-marker-5d2a";
    let mut closed = listed(4);
    closed.state = SessionState::Closed;
    closed.closure = Nullable::some(ClosureRecord {
        session_id: session_id(4),
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::RootSignal,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::some("SIGTERM".to_owned()),
        terminated: vec![TerminatedProcess {
            identity: kr_protocol::identity::ProcessStartIdentity::new(
                7,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                9,
            ),
            name: Nullable::some(marker.to_owned()),
            forced: true,
        }],
        surviving: vec![
            SurvivingResource {
                kind: marker.to_owned(),
                detail: marker.to_owned(),
            },
            SurvivingResource {
                kind: "desktop".to_owned(),
                detail: marker.to_owned(),
            },
        ],
        ownership_coverage: OwnershipCoverage::Incomplete,
        durability: Durability::Volatile,
        closed_at_ms: TimestampMs::new(2_000),
    });
    let selection = select(&report(0, false, &[]), vec![closed], &report(0, false, &[]));
    let text = compose(&Reading { listed: selection }, &[], &rules())
        .expect("composes")
        .text()
        .to_owned();
    assert!(
        !text.contains(marker),
        "no name or description is repeated: {text}"
    );
    let record: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        record
            .as_object()
            .expect("an object")
            .keys()
            .collect::<Vec<_>>(),
        ["redaction", "sessions"]
    );
    let session = &record["sessions"][0];
    let keys = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(keys(&record), ["redaction", "sessions"]);
    assert_eq!(
        keys(session),
        [
            "closure",
            "created_at_ms",
            "cwd",
            "display_number",
            "environment_sources",
            "session_id",
            "shell",
            "shell_mode",
            "state",
            "worker_profile"
        ]
    );
    assert_eq!(
        keys(&session["closure"]),
        [
            "closed_at_ms",
            "durability",
            "ownership_coverage",
            "reason",
            "root_exit_code",
            "root_signal",
            "surviving_count",
            "terminated_count"
        ]
    );
    assert_eq!(session["closure"]["terminated_count"], 1);
    assert_eq!(session["closure"]["surviving_count"], 2);
    assert_eq!(session["closure"]["ownership_coverage"], "incomplete");
    assert_eq!(session["closure"]["durability"], "volatile");
    assert_eq!(session["closure"]["root_signal"], "SIGTERM");
    assert_eq!(session["closure"]["reason"], "root_signal");
}

/// What the host says, scripted per call: the last answer repeats, so a host can change once.
struct Changing {
    reports: Vec<PrivacyReport>,
    lists: Vec<Vec<SessionSummary>>,
    privacy_calls: usize,
    list_calls: usize,
}

impl Changing {
    fn new(reports: Vec<PrivacyReport>, lists: Vec<Vec<SessionSummary>>) -> Self {
        Self {
            reports,
            lists,
            privacy_calls: 0,
            list_calls: 0,
        }
    }
}

impl Host for Changing {
    async fn privacy(&mut self) -> Result<PrivacyReport> {
        let at = self.privacy_calls.min(self.reports.len() - 1);
        self.privacy_calls += 1;
        Ok(self.reports[at].clone())
    }

    async fn sessions(&mut self, _: EnvironmentId) -> Result<SessionListResult> {
        let at = self.list_calls.min(self.lists.len() - 1);
        self.list_calls += 1;
        Ok(SessionListResult {
            sessions: self.lists[at].clone(),
        })
    }
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([9; 16]))
}

/// A host that is plainly the same on every call: privacy mode never on, two sessions.
fn steady() -> Changing {
    Changing::new(
        vec![report(0, false, &[])],
        vec![vec![listed(1), listed(2)]],
    )
}

/// What `export` printed and asked, so a test can say what the person saw and was asked.
#[derive(Default)]
struct Seen {
    previews: Vec<String>,
    questions: Vec<String>,
}

/// Runs the export with a person who gives `typed` in order, then the end of their input.
async fn exported(
    host: &mut Changing,
    decision: Decision,
    exclude: Vec<SessionId>,
    typed: &[&str],
    seen: &mut Seen,
) -> Result<Exported> {
    let mut answers = typed.iter().map(|text| (*text).to_owned());
    let previews = std::cell::RefCell::new(Vec::new());
    let questions = std::cell::RefCell::new(Vec::new());
    let outcome = export_with(
        host,
        environment(),
        decision,
        exclude,
        &rules(),
        &mut |preview: &Preview| {
            previews.borrow_mut().push(
                preview
                    .lines()
                    .iter()
                    .map(Line::text)
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            Ok(())
        },
        &mut |question: &Shown| {
            questions.borrow_mut().push(question.as_str().to_owned());
            Ok(answers.next())
        },
    )
    .await;
    seen.previews = previews.into_inner();
    seen.questions = questions.into_inner();
    outcome
}

/// What a preview run printed, for the digest it shows.
fn digest_in(preview: &str) -> Digest {
    let line = preview
        .lines()
        .find(|line| line.starts_with("Digest "))
        .expect("the preview prints a digest");
    Digest::parse(line.trim_start_matches("Digest ")).expect("a digest")
}

/// KR-REQ-29.04: a preview prints the whole content with its digest and the filter's limit, and
/// writes nothing: there is nothing approved to write.
#[tokio::test]
async fn a_preview_prints_the_content_and_its_digest_and_approves_nothing() {
    let mut seen = Seen::default();
    let done = exported(&mut steady(), Decision::Preview, Vec::new(), &[], &mut seen)
        .await
        .expect("previews");
    assert!(done.approved().is_none(), "a preview writes nothing");
    assert!(seen.questions.is_empty(), "and asks nothing");
    let [shown] = seen.previews.as_slice() else {
        panic!("one preview: {:?}", seen.previews.len())
    };
    assert!(shown.contains(&session_id(1).to_string()), "{shown}");
    assert!(shown.contains("session-content-1"), "{shown}");
    assert!(shown.contains("A filter is not a guarantee"), "{shown}");
    assert!(shown.contains("cannot recall either"), "{shown}");
    assert_eq!(digest_in(shown), done.composed().digest());
}

/// KR-REQ-29.04: what is written is what was shown. A confirmed run with the digest of a preview
/// approves content whose bytes are the text the preview printed.
#[tokio::test]
async fn a_confirmed_run_writes_the_bytes_the_preview_showed() {
    let mut first = Seen::default();
    let previewed = exported(
        &mut steady(),
        Decision::Preview,
        Vec::new(),
        &[],
        &mut first,
    )
    .await
    .expect("previews");
    let digest = previewed.composed().digest();

    let mut second = Seen::default();
    let confirmed = exported(
        &mut steady(),
        Decision::Confirmed(digest),
        Vec::new(),
        &[],
        &mut second,
    )
    .await
    .expect("confirms");
    let approved = confirmed.approved().expect("approved");
    assert_eq!(
        second.previews.len(),
        1,
        "it prints the content again as it writes"
    );
    assert_eq!(
        approved.content().bytes_for_test(),
        previewed.composed().text().as_bytes(),
        "the bytes are the bytes the preview printed"
    );
    // The printed lines hold the file's text, line for line, with the preview's own indent.
    for line in previewed.composed().text().lines() {
        assert!(second.previews[0].contains(line), "{line}");
    }
}

/// KR-REQ-29.04: a digest that is not the content's refuses, and prints none of it: a person's
/// log was only asked for content they had already seen. The control is the matching digest above.
#[tokio::test]
async fn a_digest_that_is_not_the_contents_refuses_and_prints_nothing() {
    let mut seen = Seen::default();
    let wrong = Digest::parse(&"ab".repeat(32)).expect("a digest");
    let refused = exported(
        &mut steady(),
        Decision::Confirmed(wrong),
        Vec::new(),
        &[],
        &mut seen,
    )
    .await
    .expect_err("a different digest is refused");
    assert!(
        format!("{refused}").contains("not what was shown"),
        "{refused}"
    );
    assert!(seen.previews.is_empty(), "no content was printed");
}

/// KR-REQ-29.04: content that changed since the preview, here because privacy mode is on now,
/// has another digest and is refused without being printed.
#[tokio::test]
async fn content_that_changed_since_the_preview_is_refused_unprinted() {
    let mut first = Seen::default();
    let digest = exported(
        &mut steady(),
        Decision::Preview,
        Vec::new(),
        &[],
        &mut first,
    )
    .await
    .expect("previews")
    .composed()
    .digest();
    let mut private = Changing::new(vec![report(1, true, &[])], vec![vec![listed(1), listed(2)]]);
    let mut seen = Seen::default();
    let refused = exported(
        &mut private,
        Decision::Confirmed(digest),
        Vec::new(),
        &[],
        &mut seen,
    )
    .await
    .expect_err("changed content is refused");
    assert!(
        format!("{refused}").contains("not what was shown"),
        "{refused}"
    );
    assert!(seen.previews.is_empty(), "{:?}", seen.previews);
}

/// KR-REQ-29.04: at a terminal the person is shown the content and asked, and `yes` approves it.
#[tokio::test]
async fn at_a_terminal_yes_approves_what_was_shown() {
    let mut seen = Seen::default();
    let done = exported(
        &mut steady(),
        Decision::Ask,
        Vec::new(),
        &["yes"],
        &mut seen,
    )
    .await
    .expect("approved");
    assert!(done.approved().is_some());
    assert_eq!(seen.previews.len(), 1, "shown once");
    assert_eq!(seen.questions.len(), 1, "asked once");
}

/// KR-REQ-29.04: a person who declines, or whose input ends, or who types anything that is not yes
/// or an identifier, writes nothing: no approval exists.
#[tokio::test]
async fn at_a_terminal_anything_but_yes_writes_nothing() {
    for typed in [&["no"][..], &["y"], &[""], &["perhaps"], &[]] {
        let mut seen = Seen::default();
        let refused = exported(&mut steady(), Decision::Ask, Vec::new(), typed, &mut seen)
            .await
            .expect_err("not approved");
        assert!(
            format!("{refused}").contains("nothing was written"),
            "{typed:?}: {refused}"
        );
        assert_eq!(seen.previews.len(), 1, "{typed:?}: it was shown first");
    }
}

/// KR-REQ-29.04: naming a session at the question leaves it out and shows the content again; an
/// identifier that is not in the content is said and asked about again. The digest changes with the
/// content, and the session is counted as left out by choice.
#[tokio::test]
async fn at_a_terminal_a_session_can_be_dropped_and_the_content_shown_again() {
    let dropped = session_id(2).to_string();
    let unlisted = session_id(7).to_string();
    let mut seen = Seen::default();
    let done = exported(
        &mut steady(),
        Decision::Ask,
        Vec::new(),
        &[&unlisted, &dropped, "yes"],
        &mut seen,
    )
    .await
    .expect("approved");
    assert_eq!(seen.previews.len(), 2, "shown again after the drop");
    assert!(seen.previews[0].contains(&dropped));
    assert!(!seen.previews[1].contains(&dropped), "{}", seen.previews[1]);
    assert_eq!(
        seen.questions.len(),
        3,
        "the unlisted one is asked about again"
    );
    assert!(seen.questions[1].contains("not the identifier of a session"));
    assert_eq!(done.composed().left_out(), [(Why::Dropped, 1)]);
    assert_eq!(done.composed().kept(), [session_id(1)]);
    assert_ne!(digest_in(&seen.previews[0]), digest_in(&seen.previews[1]));
}

/// KR-REQ-29.04: a person's yes is for the content they were shown. When the host says something
/// else after the question, here that privacy mode is on, nothing is approved.
#[tokio::test]
async fn a_yes_for_content_that_changed_during_the_question_approves_nothing() {
    // Two reads before the question (privacy, list, privacy); the host changes for the read after.
    let mut host = Changing::new(
        vec![
            report(0, false, &[]),
            report(0, false, &[]),
            report(1, true, &[]),
        ],
        vec![vec![listed(1), listed(2)]],
    );
    let mut seen = Seen::default();
    let refused = exported(&mut host, Decision::Ask, Vec::new(), &["yes"], &mut seen)
        .await
        .expect_err("changed content is not approved");
    assert!(
        format!("{refused}").contains("not what was shown"),
        "{refused}"
    );
    assert_eq!(
        seen.previews.len(),
        1,
        "only the content they saw was ever printed"
    );
}

/// KR-REQ-29.04: a preview that cannot be printed stops the export: no approval, so no bundle.
#[tokio::test]
async fn a_preview_that_cannot_be_printed_stops_the_export() {
    let refused = export_with(
        &mut steady(),
        environment(),
        Decision::Ask,
        Vec::new(),
        &rules(),
        &mut |_: &Preview| Err(CliError::Other(Shown::said("the stream is closed"))),
        &mut |_: &Shown| Ok(Some("yes".to_owned())),
    )
    .await
    .expect_err("no preview, no export");
    assert!(
        format!("{refused}").contains("the stream is closed"),
        "{refused}"
    );
}

/// KR-REQ-29.04: a session named for exclusion that the host never listed is a usage failure, not
/// a silently different export.
#[tokio::test]
async fn excluding_a_session_the_host_never_listed_is_a_usage_failure() {
    let mut seen = Seen::default();
    let refused = exported(
        &mut steady(),
        Decision::Preview,
        vec![session_id(7)],
        &[],
        &mut seen,
    )
    .await
    .expect_err("refused");
    assert!(matches!(refused, CliError::Usage(_)), "{refused}");
    assert!(seen.previews.is_empty());
}

/// KR-REQ-29.04: the digest covers what is in and what was left out, and never two different
/// exports with one digest: dropping a session, or a different reason for the same content, differs.
#[test]
fn the_digest_covers_the_content_and_the_reasons() {
    let both = compose(
        &Reading {
            listed: select(
                &report(0, false, &[]),
                vec![listed(1), listed(2)],
                &report(0, false, &[]),
            ),
        },
        &[],
        &rules(),
    )
    .expect("composes");
    let again = compose(
        &Reading {
            listed: select(
                &report(0, false, &[]),
                vec![listed(1), listed(2)],
                &report(0, false, &[]),
            ),
        },
        &[],
        &rules(),
    )
    .expect("composes");
    assert_eq!(
        both.digest(),
        again.digest(),
        "the same export, the same digest"
    );
    let dropped = compose(
        &Reading {
            listed: select(
                &report(0, false, &[]),
                vec![listed(1), listed(2)],
                &report(0, false, &[]),
            ),
        },
        &[session_id(2)],
        &rules(),
    )
    .expect("composes");
    assert_ne!(both.digest(), dropped.digest());
    // One session, two reasons for being out: same entry bytes, different digest.
    let owing = compose(
        &Reading {
            listed: select(
                &report(1, false, &[2]),
                vec![listed(1), listed(2)],
                &report(1, false, &[2]),
            ),
        },
        &[],
        &rules(),
    )
    .expect("composes");
    let chosen = compose(
        &Reading {
            listed: select(
                &report(1, false, &[]),
                vec![listed(1), listed(2)],
                &report(1, false, &[]),
            ),
        },
        &[session_id(2)],
        &rules(),
    )
    .expect("composes");
    assert_eq!(owing.text(), chosen.text(), "the file is the same");
    assert_ne!(
        owing.digest(),
        chosen.digest(),
        "what was left out and why is not"
    );
}

/// KR-REQ-29.04: a digest as the preview prints it reads back, in either case, and nothing else
/// does.
#[test]
fn a_digest_reads_back_as_printed_and_nothing_else_does() {
    let digest = Digest::parse(&"0f".repeat(32)).expect("a digest");
    assert_eq!(digest.hex(), "0f".repeat(32));
    assert_eq!(Digest::parse(&"0F".repeat(32)), Some(digest));
    assert_eq!(
        Digest::parse(&format!("  {}\n", "0f".repeat(32))),
        Some(digest)
    );
    for text in [
        "",
        "0f",
        &"0f".repeat(31),
        &"0f".repeat(33),
        &"zz".repeat(32),
        "sha256:abc",
    ] {
        assert!(Digest::parse(text).is_none(), "{text}");
    }
}

/// KR-REQ-29.04: characters that would hide or reorder text on a terminal are written as escapes,
/// so the text on the screen is the text in the file. The control is an ordinary non-ASCII letter.
#[test]
fn characters_that_change_what_a_terminal_shows_are_escaped() {
    let mut closed = listed(4);
    closed.cwd = "/work/caf\u{e9}".to_owned();
    closed.shell_path = "/bin/\u{202e}hs\u{7f}\u{85}\u{200b}\u{feff}sh".to_owned();
    let selection = select(&report(0, false, &[]), vec![closed], &report(0, false, &[]));
    let composed = compose(&Reading { listed: selection }, &[], &rules()).expect("composes");
    let text = composed.text();
    for hidden in ['\u{202e}', '\u{7f}', '\u{85}', '\u{200b}', '\u{feff}'] {
        assert!(!text.contains(hidden), "{hidden:?} is in {text}");
    }
    assert!(text.contains("\\u202e") && text.contains("\\u007f") && text.contains("\\u0085"));
    assert!(
        text.contains("caf\u{e9}"),
        "an ordinary letter stays: {text}"
    );
    let record: serde_json::Value = serde_json::from_str(text).expect("still JSON");
    assert_eq!(
        record["sessions"][0]["shell"],
        "/bin/\u{202e}hs\u{7f}\u{85}\u{200b}\u{feff}sh"
    );
}

/// An archive's entries, by name.
fn entries(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 512 <= archive.len() && archive[at] != 0 {
        let header = &archive[at..at + 512];
        let end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let name = String::from_utf8_lossy(&header[..end]).into_owned();
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&header[124..135])
                .trim_matches(['\0', ' '])
                .trim(),
            8,
        )
        .expect("an octal size");
        found.push((name, archive[at + 512..at + 512 + size].to_vec()));
        at += 512 + size.div_ceil(512) * 512;
    }
    found
}

/// KR-REQ-29.04: planted credentials in every text field of every session reach neither the
/// preview, nor the file, nor the manifest, nor the report, through the whole path from what the
/// host lists to the archive on disk; the control is an ordinary path and command line, which stay.
#[tokio::test]
async fn planted_credentials_in_every_text_field_reach_nothing_the_export_prints_or_writes() {
    use kr_protocol::session::ClosureRecord;

    const MARKERS: [&str; 9] = [
        "kr-marker-token-1",
        "kr-marker-pass-2",
        "kr-marker-url-3",
        "kr-marker-quoted-4",
        "kr-marker-signal-5",
        "kr-marker-equals-6",
        "kr-marker-overlap-7",
        "kr-marker-apostrophe-8",
        "kr-marker-whole-9",
    ];
    let mut planted = listed(1);
    planted.shell_path = format!(
        "/opt/tools/sh --password {} -e \"PASSWORD=two words {}\"",
        MARKERS[1], MARKERS[8]
    );
    planted.cwd = format!(
        "/home/tom/work TOKEN={} https://user:{}@host.example/ --secret \"two words {}\"",
        MARKERS[0], MARKERS[2], MARKERS[3]
    );
    let mut closed = listed(2);
    closed.state = SessionState::Closed;
    closed.cwd = format!("/home/tom/--api-key={}", MARKERS[5]);
    closed.closure = Nullable::some(ClosureRecord {
        session_id: session_id(2),
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::RootSignal,
        root_exit_code: Nullable::null(),
        root_signal: Some(format!("signal TOKEN={}", MARKERS[4])).into(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Complete,
        durability: Durability::Durable,
        closed_at_ms: TimestampMs::new(2_000),
    });
    let mut ordinary = listed(3);
    ordinary.cwd = format!(
        "/home/tom/projects/ordinary --password TOKEN=\"two words {}\" --url=\"https://o'neil:{}@host/\"",
        MARKERS[6], MARKERS[7]
    );
    ordinary.shell_path = "/bin/zsh".to_owned();
    let mut host = Changing::new(
        vec![report(0, false, &[])],
        vec![vec![planted, closed, ordinary]],
    );

    let mut seen = Seen::default();
    let previewed = exported(&mut host, Decision::Preview, Vec::new(), &[], &mut seen)
        .await
        .expect("previews");
    let digest = previewed.composed().digest();
    let mut confirmed_seen = Seen::default();
    let confirmed = exported(
        &mut host,
        Decision::Confirmed(digest),
        Vec::new(),
        &[],
        &mut confirmed_seen,
    )
    .await
    .expect("confirms");
    let approved = confirmed.approved().expect("approved");

    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("support.tar");
    let bundle = ComposedBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        crate::doctor::tests::result(),
        Vec::new(),
    );
    bundle::write(&path, &bundle, Some(approved)).expect("writes");
    let archive = std::fs::read(&path).expect("reads it back");
    let found = entries(&archive);
    assert_eq!(
        found.len(),
        3,
        "the manifest, the report and one content entry"
    );

    for marker in MARKERS {
        for printed in seen.previews.iter().chain(&confirmed_seen.previews) {
            assert!(
                !printed.contains(marker),
                "{marker} in the preview: {printed}"
            );
        }
        for (name, bytes) in &found {
            assert!(
                !String::from_utf8_lossy(bytes).contains(marker),
                "{marker} in {name}"
            );
        }
    }
    let written = found
        .iter()
        .find(|(name, _)| name == "content/sessions.json")
        .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
        .expect("the content entry");
    assert_eq!(
        written,
        previewed.composed().text(),
        "what is written is what was shown"
    );
    for readable in [
        "[home]/projects/ordinary --password [redacted]",
        // The shell path holds a quoted argument around a credential: the field is withheld.
        "[withheld: ",
        "https://[redacted]@host/",
        "/bin/zsh",
        "TOKEN=[redacted]",
        "--password [redacted]",
    ] {
        assert!(written.contains(readable), "{readable}: {written}");
    }
    let manifest = found
        .iter()
        .find(|(name, _)| name == "manifest.json")
        .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
        .expect("the manifest");
    assert!(
        manifest.contains("redacted by session-content-1"),
        "{manifest}"
    );
    assert!(
        manifest.contains(&digest.hex()),
        "the manifest records the digest: {manifest}"
    );
}

/// A writer that takes `allowed` writes and then fails, or fails only when it is flushed.
struct Failing {
    allowed: usize,
    on_flush: bool,
    taken: Vec<u8>,
}

impl std::io::Write for Failing {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.allowed == 0 {
            return Err(std::io::Error::other("the stream is full"));
        }
        self.allowed -= 1;
        self.taken.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.on_flush {
            Err(std::io::Error::other("the stream could not be flushed"))
        } else {
            Ok(())
        }
    }
}

/// KR-REQ-29.04: a preview that fails part of the way through, or only when it is flushed, stops the
/// export: no approval exists, whichever way the person would have answered, and the failure says
/// that nothing was written. The control is a writer that takes everything: it approves.
#[tokio::test]
async fn a_preview_that_fails_part_way_or_at_the_flush_approves_nothing() {
    let attempt = |allowed: usize, on_flush: bool| async move {
        let mut writer = Failing {
            allowed,
            on_flush,
            taken: Vec::new(),
        };
        let outcome = export_with(
            &mut steady(),
            environment(),
            Decision::Confirmed(
                exported(
                    &mut steady(),
                    Decision::Preview,
                    Vec::new(),
                    &[],
                    &mut Seen::default(),
                )
                .await
                .expect("previews")
                .composed()
                .digest(),
            ),
            Vec::new(),
            &rules(),
            &mut |preview: &Preview| crate::report::write_preview(&mut writer, preview),
            &mut |_: &Shown| Ok(Some("yes".to_owned())),
        )
        .await;
        (outcome, writer.taken)
    };

    let (partial, taken) = attempt(3, false).await;
    let refused = partial.expect_err("a partial preview stops the export");
    assert!(
        format!("{refused}").contains("nothing was written"),
        "{refused}"
    );
    assert!(!taken.is_empty(), "some of it did get out before it failed");

    let (flushed, _) = attempt(usize::MAX, true).await;
    let refused = flushed.expect_err("a flush that fails stops the export");
    assert!(
        format!("{refused}").contains("nothing was written"),
        "{refused}"
    );

    let (whole, taken) = attempt(usize::MAX, false).await;
    assert!(whole.expect("the control").approved().is_some());
    let text = String::from_utf8(taken).expect("text");
    assert!(text.contains("Digest "), "{text}");
}

/// KR-REQ-29.04: the preview says what the filter and the reads cannot do: the window before it
/// was printed, a session whose cleanup is done and is in the content once privacy mode is off,
/// and that the preview is itself output the host and a viewing device can read.
#[tokio::test]
async fn the_preview_states_what_the_export_cannot_promise() {
    let mut seen = Seen::default();
    exported(&mut steady(), Decision::Preview, Vec::new(), &[], &mut seen)
        .await
        .expect("previews");
    let shown = seen.previews[0].replace("\n", " ");
    for stated in [
        "A filter is not a guarantee that no secret remains",
        "the home directory of the user running this command",
        "A field shown as [withheld: N characters] has a quote before a credential's value or a \
         quote left open",
        "so none of its text is shown",
        "after the host was last read does not stop this preview or the write",
        "after this preview is printed or the bundle is written cannot recall either",
        "finished its cleanup is in the content once privacy mode is off",
        "ordinary terminal output",
        "any device viewing the session can read",
    ] {
        assert!(shown.contains(stated), "{stated}: {shown}");
    }
}

/// KR-REQ-29.04: a session dropped at the question that the host no longer lists is no usage
/// failure: only a session named on the command line has to be one the host lists.
#[tokio::test]
async fn a_dropped_session_the_host_stops_listing_does_not_fail_the_export() {
    let dropped = session_id(2).to_string();
    let mut host = Changing::new(
        vec![report(0, false, &[])],
        vec![vec![listed(1), listed(2)], vec![listed(1)]],
    );
    let mut seen = Seen::default();
    let done = exported(
        &mut host,
        Decision::Ask,
        Vec::new(),
        &[&dropped, "yes"],
        &mut seen,
    )
    .await
    .expect("approved");
    assert_eq!(done.composed().kept(), [session_id(1)]);
}

/// KR-REQ-29.04: characters that show as nothing, and the characters outside the basic plane among
/// them, are escaped: tag characters and variation selectors can carry text no terminal shows. An
/// escaped character outside the plane is the surrogate pair JSON spells it with, and the file
/// reads back as the same text. The control is an ordinary character outside the plane.
#[test]
fn invisible_characters_outside_the_basic_plane_are_escaped_as_pairs() {
    let mut closed = listed(4);
    closed.cwd =
        "/work/\u{e0041}\u{fe0f}\u{34f}\u{1d173}\u{890}\u{110bd}\u{13430}/\u{1f600}".to_owned();
    let selection = select(&report(0, false, &[]), vec![closed], &report(0, false, &[]));
    let composed = compose(&Reading { listed: selection }, &[], &rules()).expect("composes");
    let text = composed.text();
    for hidden in [
        '\u{e0041}',
        '\u{fe0f}',
        '\u{34f}',
        '\u{1d173}',
        '\u{890}',
        '\u{110bd}',
        '\u{13430}',
    ] {
        assert!(!text.contains(hidden), "{hidden:?} is in {text}");
    }
    assert!(text.contains("\\udb40\\udc41"), "{text}");
    assert!(
        text.contains("\u{1f600}"),
        "an ordinary character stays: {text}"
    );
    let record: serde_json::Value = serde_json::from_str(text).expect("still JSON");
    assert_eq!(
        record["sessions"][0]["cwd"],
        "/work/\u{e0041}\u{fe0f}\u{34f}\u{1d173}\u{890}\u{110bd}\u{13430}/\u{1f600}"
    );
}

/// KR-REQ-29.04: a confirmed run prints the preview exactly once and approves. That nothing is
/// approved before the print is held by the failing-preview tests above (a preview that cannot be
/// printed leaves no approval) and by the types: only the export makes an approval.
#[tokio::test]
async fn a_confirmed_run_prints_the_preview_once_and_approves() {
    let printed = std::cell::Cell::new(false);
    let order = std::cell::RefCell::new(Vec::new());
    let digest = exported(
        &mut steady(),
        Decision::Preview,
        Vec::new(),
        &[],
        &mut Seen::default(),
    )
    .await
    .expect("previews")
    .composed()
    .digest();
    let done = export_with(
        &mut steady(),
        environment(),
        Decision::Confirmed(digest),
        Vec::new(),
        &rules(),
        &mut |_: &Preview| {
            printed.set(true);
            order.borrow_mut().push("printed");
            Ok(())
        },
        &mut |_: &Shown| Ok(None),
    )
    .await
    .expect("approved");
    assert!(printed.get() && done.approved().is_some());
    assert_eq!(
        *order.borrow(),
        ["printed"],
        "printed once, before approval"
    );
}
