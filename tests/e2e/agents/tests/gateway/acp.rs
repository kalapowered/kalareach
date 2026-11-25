//! Cases 5b and 6b with an agent in ACP mode: what the host holds of an approval the agent waits
//! on, shown through the death of the daemon (5b) and through an upgrade of the agent's
//! installation (6b).
//!
//! The agents are stand-ins that this crate builds: a native program shaped like Qoder CLI, and a
//! script package shaped like Gemini CLI that a stand-in interpreter runs. No ACP launch exists
//! yet, so every case here is ignored and starts by failing with [`NO_LAUNCH`]. Run one by name
//! with `--ignored`. [`CONTROLS`] lists each control of each case with the part of the build whose
//! commit makes its case pass, the change to the product that must turn the control red, and the
//! red it shows. That part removes the case's `ignore` attribute and sets `waits` to false in its
//! own commit, and `the_acp_table_matches_the_ignored_cases_of_this_file` fails on a table and a
//! file that disagree.
//!
//! Not claimed: a run against a pinned build (see [`REAL_ARM`]), a kill made during a write, and
//! anything about a terminal route.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{Filed, recorded_as};

/// What each control reads and how it judges it, and the host a case works with.
#[path = "acp_controls.rs"]
mod controls;

/// What a case says when it starts before any ACP launch exists.
const NO_LAUNCH: &str = "no ACP launch exists: kr-hook has no `acp` subcommand, so no case can start an agent in ACP mode";

/// What a case says when the launch exists and the harness that starts a stand-in through it is not
/// written.
const NO_HOST: &str = "the harness that starts the stand-in through the ACP launch is not written";

/// The names of the subcommands in the forwarder's command table.
fn hook_subcommands() -> Vec<String> {
    use clap::CommandFactory as _;
    kr_hook::cli::Cli::command()
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .collect()
}

/// Whether the host has a launch for an agent in ACP mode: the forwarder names the `acp`
/// subcommand.
fn launch_exists() -> bool {
    hook_subcommands().iter().any(|name| name == "acp")
}

/// The first step of every case. It fails while no ACP launch exists.
fn starts_in_acp_mode(case: &str) {
    assert!(launch_exists(), "{case}: {NO_LAUNCH}");
}

/// The row of the table for control `id`.
fn control_of(id: &str) -> &'static Control {
    CONTROLS
        .iter()
        .find(|control| control.id == id)
        .unwrap_or_else(|| panic!("{id} is no control of the table"))
}

/// The text the table names as the red of control `id`.
fn red_of(id: &str) -> &'static str {
    control_of(id).red
}

/// Where the stand-in's program or package runs from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// The verified copy that the host makes, as it starts every agent.
    TheCopy,
    /// The installation itself, which only the harness does, as the control of 6b-6 shows.
    TheInstallation,
}

/// Starts the stand-in that the table names for control `id`, with `script`, through the launch and
/// runs `body` on the host. It fails first when the agent did not come through the ACP launch, unless
/// the control's row names a harness start, and then with the red the body returns.
fn run_case(
    id: &str,
    script: &Value,
    body: impl FnOnce(&mut controls::Hosted) -> Result<(), controls::Red>,
) {
    run_case_from(id, Source::TheCopy, script, body);
}

/// The same as [`run_case`], with the stand-in started from `source`.
fn run_case_from(
    id: &str,
    source: Source,
    script: &Value,
    body: impl FnOnce(&mut controls::Hosted) -> Result<(), controls::Red>,
) {
    starts_in_acp_mode(id);
    match controls::Hosted::start(control_of(id).shape, source, script) {
        Err(why) => panic!("{id}: {why}"),
        Ok(mut host) => {
            if control_of(id).harness_start.is_none()
                && let Some(why) = controls::why_not_an_acp_launch(&host.launch(), &host.record())
            {
                panic!("{id}: the agent was not started through the ACP launch: {why}");
            }
            if let Err(red) = body(&mut host) {
                panic!("{red}");
            }
        }
    }
}

/// The stand-in a case starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// The native program shaped like Qoder CLI.
    Qoder,
    /// The script package shaped like Gemini CLI, run by the stand-in interpreter.
    Gemini,
}

/// One control of a case: what it shows after a valid launch, the change to the product that must
/// turn it red, and the red.
struct Control {
    /// The case, `5b` or `6b`, and the number of the control in it. A `g` marks the Gemini-shaped
    /// twin of a control that the Qoder-shaped stand-in shows first.
    id: &'static str,
    /// The test that holds the control. A test may hold several.
    test: &'static str,
    /// The stand-in the test starts.
    shape: Shape,
    /// The part whose commit makes the test pass.
    owner: &'static str,
    /// Whether the test still waits for its owner: it is ignored while it does.
    waits: bool,
    /// What the control shows.
    shows: &'static str,
    /// The change to the product that must turn the control red.
    mutation: &'static str,
    /// What the case sees when it does.
    red: &'static str,
    /// Why the case starts the stand-in by the harness's own control start and not through the ACP
    /// launch, for the one control that does; none for every other control.
    harness_start: Option<&'static str>,
}

/// The parts that can own a test: the launch and the ending of the agent, the decoder and the
/// approvals, the instance's shape in the host's reads, and the Gemini start from a copy.
const OWNERS: [&str; 4] = ["ACP-3a", "ACP-4", "ACP-5", "ACP-7c"];

/// The tests that start no agent and read nothing of the host start with this word.
const GUARD_PREFIX: &str = "the_acp_";

/// Every control of cases 5b and 6b.
const CONTROLS: [Control; 33] = [
    Control {
        id: "5b-1",
        test: "acp_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "after only the daemon is killed and started again, the instance, the binding, the capability identity and the pending request read field for field as before",
        mutation: "the worker drops its pending request when the daemon's connection ends",
        red: "the read after the restart differs",
        harness_start: None,
    },
    Control {
        id: "5b-2",
        test: "acp_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "the request resolves once through the restarted daemon: the stand-in saw one reply, with the chosen id",
        mutation: "the answer is forwarded twice",
        red: "the stand-in's count of replies is 2",
        harness_start: None,
    },
    Control {
        id: "5b-3",
        test: "acp_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "with the daemon killed and then the worker, the restarted daemon refuses the instance and the request as a closed session's",
        mutation: "the daemon keeps the request",
        red: "the answer is accepted",
        harness_start: None,
    },
    Control {
        id: "5b-11",
        test: "acp_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "closing the session after the restart ends the agent through its owned root",
        mutation: "the owned-root record is not used to end the agent",
        red: "the agent keeps running",
        harness_start: None,
    },
    Control {
        id: "5b-4",
        test: "acp_two_concurrent_answers_to_one_request_reach_the_agent_once_also_across_a_daemon_reconnect",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "two concurrent answers to one request, and a retry after the daemon reconnects, reach the agent once",
        mutation: "the claim in arbitration is skipped",
        red: "both answers reach the stand-in",
        harness_start: None,
    },
    Control {
        id: "5b-5",
        test: "acp_a_cancel_racing_an_approval_has_one_winner_and_the_other_is_told",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "a cancel and an answer that race on one approval have one winner, and the other is told",
        mutation: "the cancel does not answer the pending approval",
        red: "the stand-in's tool call never settles, or both the cancel and the answer are accepted",
        harness_start: None,
    },
    Control {
        id: "5b-6",
        test: "acp_a_permission_request_after_a_cancel_is_answered_cancelled_by_a_qoder_shaped_agent",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "a permission request that the stand-in sends after `session/cancel` is answered cancelled",
        mutation: "the late request is left pending",
        red: "the stand-in blocks and its turn never ends",
        harness_start: None,
    },
    Control {
        id: "5b-6g",
        test: "acp_a_permission_request_after_a_cancel_is_answered_cancelled_by_a_gemini_shaped_agent",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "a permission request that the stand-in sends after `session/cancel` is answered cancelled",
        mutation: "the late request is left pending",
        red: "the stand-in blocks and its turn never ends",
        harness_start: None,
    },
    Control {
        id: "5b-7",
        test: "acp_the_same_request_id_in_a_second_instance_is_a_second_pending_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "the same request id in a second instance, or on a second connection, is a second pending request",
        mutation: "requests are keyed by the id alone",
        red: "one request, not two",
        harness_start: None,
    },
    Control {
        id: "5b-8",
        test: "acp_a_fresh_request_after_a_daemon_restart_is_a_pending_request",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "a fresh permission request after a daemon restart is listed as a pending request",
        mutation: "the new request is dropped",
        red: "no request appears",
        harness_start: None,
    },
    Control {
        id: "5b-9",
        test: "acp_an_agent_that_exits_before_dispatch_leaves_its_request_cancelled",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "an agent that exits before the answer is dispatched leaves its request cancelled",
        mutation: "the exit leaves the request pending",
        red: "the request is still pending",
        harness_start: None,
    },
    Control {
        id: "5b-10",
        test: "acp_an_agent_that_exits_after_dispatch_leaves_the_receipt_unknown_unless_evidence_came_first_for_a_qoder_shaped_agent",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "an agent that exits after the answer is dispatched leaves the receipt unknown when no evidence was seen, and leaves it applied when evidence that the agent used the answer was seen first",
        mutation: "the exit rewrites every answered request to unknown, or none",
        red: "the confirmed answer changes, or the unproved one reads applied",
        harness_start: None,
    },
    Control {
        id: "5b-10g",
        test: "acp_an_agent_that_exits_after_dispatch_leaves_the_receipt_unknown_unless_evidence_came_first_for_a_gemini_shaped_agent",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "an agent that exits after the answer is dispatched leaves the receipt unknown when no evidence was seen, and leaves it applied when evidence that the agent used the answer was seen first",
        mutation: "the exit rewrites every answered request to unknown, or none",
        red: "the confirmed answer changes, or the unproved one reads applied",
        harness_start: None,
    },
    Control {
        id: "5b-12",
        test: "acp_the_launcher_ends_the_agent_when_the_workers_connection_ends",
        shape: Shape::Qoder,
        owner: "ACP-3a",
        waits: true,
        shows: "the launcher ends the agent when the worker's connection ends; the case closes the worker's end and restarts no daemon, because a daemon restart does not close that connection",
        mutation: "the launcher ignores the closed connection",
        red: "the agent keeps running",
        harness_start: None,
    },
    Control {
        id: "5b-13",
        test: "acp_a_gemini_decline_stays_dispatching_until_the_next_request_the_reply_or_the_deadline",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "a decline sends the Gemini-shaped agent's client no update, so the receipt stays dispatching until the next request, the reply or the deadline of 300 seconds",
        mutation: "a decline counted as applied at dispatch, or the next request and the reply not taken as evidence of a decline",
        red: "the receipt reads applied at dispatch, or the receipts at the boundaries do not read unknown, applied and applied",
        harness_start: None,
    },
    Control {
        id: "5b-14",
        test: "acp_an_abort_that_settles_a_call_without_taking_the_answer_leaves_the_receipt_unknown",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "an abort that settles a call without taking the answer, with no cancel window of ours, leaves the receipt unknown: the stand-in aborts the tool after the answer was dispatched, sends the call's cancelled update and then replies to the prompt with the stop reason cancelled",
        mutation: "the reply, or the cancelled update, is counted as evidence",
        red: "the receipt reads applied, not unknown",
        harness_start: None,
    },
    Control {
        id: "5b-15",
        test: "acp_a_silent_unresolved_approval_is_cancelled_by_a_cancel_after_eleven_seconds",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "after an update of the agent's own turn and a permission request, then no traffic for 11 seconds by the injected clock, the person's Cancel reaches the stand-in as `session/cancel` and the pending approval is answered cancelled",
        mutation: "a quiet period of 10 seconds closes the turn and the cancel is refused as stale",
        red: "the stand-in's count of `session/cancel` is 0",
        harness_start: None,
    },
    Control {
        id: "5b-16",
        test: "acp_the_cancel_window_of_a_turn_of_the_agents_own_closes_thirty_seconds_after_the_cancel",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "with no prompt of ours in flight and steady traffic, the cancel window closes 30 seconds after the cancel by the injected clock: an approval at 29 seconds is answered cancelled and one at 31 seconds shows",
        mutation: "the window stays open while traffic goes on",
        red: "the approval at 31 seconds is answered cancelled",
        harness_start: None,
    },
    Control {
        id: "5b-17",
        test: "acp_the_cancel_window_with_a_prompt_in_flight_closes_at_that_prompts_reply_for_a_gemini_shaped_agent",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "with a prompt of ours in flight the window closes at that prompt's reply and not at 30 seconds: an approval at 31 seconds, before the reply, is answered cancelled, and a message sent meanwhile is refused",
        mutation: "the window is capped at 30 seconds",
        red: "the approval at 31 seconds shows",
        harness_start: None,
    },
    Control {
        id: "5b-18",
        test: "acp_a_prompt_answered_cancelled_while_the_agents_own_turn_goes_on_leaves_the_cancel_window_open",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "a prompt of ours that waits behind a turn of the agent's own and is answered cancelled at once does not close the window: a request of the old turn 3 seconds later is answered cancelled",
        mutation: "the window closes at our prompt's reply",
        red: "the request at 3 seconds shows and is not answered cancelled",
        harness_start: None,
    },
    Control {
        id: "5b-19",
        test: "acp_a_prompt_sent_five_seconds_after_a_cancel_shows_its_approval",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "a prompt sent 5 seconds after a Cancel closes the window: the worker dispatches it, the stand-in sends an approval for it, and the approval shows",
        mutation: "the window ignores the dispatch and stays open to 30 seconds",
        red: "the approval is answered cancelled",
        harness_start: None,
    },
    Control {
        id: "5b-20",
        test: "acp_an_answered_approval_of_a_turn_of_the_agents_own_reads_unknown_at_three_hundred_seconds",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "an answered approval of a turn of the agent's own, then no traffic and a live agent: at 300 seconds by the injected clock the receipt reads unknown, the source bytes are gone and the agent still runs",
        mutation: "the answer waits for the agent's exit",
        red: "the receipt still reads dispatching and the source bytes remain",
        harness_start: None,
    },
    Control {
        id: "5b-21",
        test: "acp_a_decline_in_a_turn_of_the_agents_own_reads_unknown_at_the_calls_failed_update",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "a decline in a turn of the agent's own, then the call's failed update: the receipt reads unknown at that update",
        mutation: "the terminal result of the call is ignored",
        red: "the receipt stays dispatching",
        harness_start: None,
    },
    Control {
        id: "5b-22",
        test: "acp_a_late_in_progress_update_moves_an_allow_from_unknown_to_applied",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "an allow in a turn of the agent's own whose in-progress update arrives after the deadline (the clock at 301 seconds, then the update) reads unknown and then applied",
        mutation: "the late update is ignored",
        red: "the receipt stays unknown",
        harness_start: None,
    },
    Control {
        id: "5b-23",
        test: "acp_a_completed_update_after_a_cancel_leaves_an_allow_applied_for_a_qoder_shaped_agent",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "the answer is dispatched, the person cancels, and the call's completed update arrives: the receipt reads applied",
        mutation: "every update after a cancel is ignored",
        red: "the receipt reads unknown, not applied",
        harness_start: None,
    },
    Control {
        id: "5b-23g",
        test: "acp_a_completed_update_after_a_cancel_leaves_an_allow_applied_for_a_gemini_shaped_agent",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "the answer is dispatched, the person cancels, and the call's completed update arrives: the receipt reads applied",
        mutation: "every update after a cancel is ignored",
        red: "the receipt reads unknown, not applied",
        harness_start: None,
    },
    Control {
        id: "6b-1",
        test: "acp_an_upgrade_leaves_a_qoder_shaped_process_its_copy_and_its_identity",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "after the installation's file is replaced in place, the process identity, the executable's digest and the copy's digest equal those before, and the installation's digest differs",
        mutation: "the launch runs the installation's file, not the copy",
        red: "the digests after the upgrade differ from those before",
        harness_start: None,
    },
    Control {
        id: "6b-2",
        test: "acp_a_fresh_request_after_an_upgrade_is_decoded_by_the_pinned_table_and_answered_with_its_ids",
        shape: Shape::Qoder,
        owner: "ACP-4",
        waits: true,
        shows: "the agent asks a fresh permission request after the upgrade; its decoded options equal those decoded before, and it is answered with the pinned table's ids",
        mutation: "the host decodes the fresh request with the table of the upgraded installation",
        red: "the decoded options differ from those before the upgrade",
        harness_start: None,
    },
    Control {
        id: "6b-3",
        test: "acp_a_build_outside_the_range_is_refused_with_a_message_that_names_the_range",
        shape: Shape::Qoder,
        owner: "ACP-3a",
        waits: true,
        shows: "a start of a build outside the range `=1.1.63` is refused, and the launcher prints a message that names the range",
        mutation: "the range is not checked, or the refusal's message leaves the range out",
        red: "the second start is admitted, or its message does not name the range",
        harness_start: None,
    },
    Control {
        id: "6b-3g",
        test: "acp_an_upgrade_leaves_a_gemini_shaped_process_the_chunk_of_its_copy",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "a start of a build outside the range `=0.60.0` is refused, and the launcher prints a message that names the range",
        mutation: "the range is not checked, or the refusal's message leaves the range out",
        red: "the second start is admitted, or its message does not name the range",
        harness_start: None,
    },
    Control {
        id: "6b-4",
        test: "acp_a_start_whose_version_differs_from_the_hashed_build_is_refused",
        shape: Shape::Qoder,
        owner: "ACP-5",
        waits: true,
        shows: "the version the agent reports equals the binding's, and a start whose version differs from the hashed build is refused",
        mutation: "the reported version is not compared with the hashed build",
        red: "a start with another version is admitted",
        harness_start: None,
    },
    Control {
        id: "6b-5",
        test: "acp_an_upgrade_leaves_a_gemini_shaped_process_the_chunk_of_its_copy",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "the package's chunk is replaced in place after the first permission request is answered, and the stand-in's later import still reads the copy's chunk: the marker holds the original chunk's bytes",
        mutation: "the launch runs the installation's package, not the copy",
        red: "the marker holds the replaced chunk's bytes",
        harness_start: None,
    },
    Control {
        id: "6b-6",
        test: "acp_without_the_copy_the_same_upgrade_changes_the_chunk_a_gemini_shaped_process_loads",
        shape: Shape::Gemini,
        owner: "ACP-7c",
        waits: true,
        shows: "started from the installation's folder with no copy, which only the harness does, the same upgrade makes the stand-in load the new chunk; the case fails unless the two starts differ",
        mutation: "the chunk that is replaced is not the one the stand-in imports",
        red: "the start without the copy loads the original chunk, so the control shows no difference",
        harness_start: Some(
            "the control start of 6b: the harness runs the stand-in from the installation's folder with no copy, which no launch does, so the check of the ACP launch would fail it by design",
        ),
    },
];

/// A real-arm row: a run against a pinned build that this file declares and does not make.
struct RealArm {
    /// The agent whose pinned build the row is about.
    agent: &'static str,
    /// The case, `5b` or `6b`.
    case: &'static str,
    /// Why the row is not run here.
    reason: &'static str,
}

/// The rows of the qualification that a run against a pinned build would show. They are not run
/// from this file, and each is recorded as not run.
const REAL_ARM: [RealArm; 4] = [
    RealArm {
        agent: "gemini",
        case: "5b",
        reason: "the run against the pinned Gemini CLI belongs to the live part of the ACP build: it uses the person's key and compares the person's settings files before and after",
    },
    RealArm {
        agent: "gemini",
        case: "6b",
        reason: "the run against the pinned Gemini CLI belongs to the live part of the ACP build: it compares the copy's tree digest and the installation's before and after the upgrade",
    },
    RealArm {
        agent: "qoder",
        case: "5b",
        reason: "no run against the pinned Qoder CLI is made from this repository: a tester's own run supplies it, and that report is kept apart from the stand-in's evidence",
    },
    RealArm {
        agent: "qoder",
        case: "6b",
        reason: "no run against the pinned Qoder CLI is made from this repository: a tester's own run supplies it, and that report is kept apart from the stand-in's evidence",
    },
];

/// The attribute that ignores a case that waits for a part, without the part's name. It is written
/// in two pieces so that this file's scan of its own source does not find it here.
const WAITING: &str = concat!("#[ignore", " = \"waits for ");

/// The cases of this file, read from its source: each `fn` that starts a case, with the part its
/// `ignore` attribute names, or `None` when it has none.
fn cases_in_source() -> BTreeMap<String, Option<String>> {
    let lines: Vec<&str> = include_str!("acp.rs").lines().map(str::trim).collect();
    let mut cases = BTreeMap::new();
    for (at, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("fn acp_") else {
            continue;
        };
        let name = format!("acp_{}", rest.split('(').next().unwrap_or_default());
        let waits_for = at
            .checked_sub(1)
            .and_then(|before| lines.get(before))
            .and_then(|attribute| attribute.strip_prefix(WAITING))
            .and_then(|part| part.strip_suffix("\"]"))
            .map(str::to_owned);
        cases.insert(name, waits_for);
    }
    cases
}

// The cases. Each is ignored while it waits for its owner and starts in ACP mode first.

/// Controls 5b-1, 5b-2, 5b-3 and 5b-11.
#[test]
#[ignore = "waits for ACP-5"]
fn acp_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request()
 {
    run_case(
        "5b-1",
        &controls::lingering(controls::restart_script()),
        controls::a_daemon_killed_with_a_request_pending,
    );
}

/// Control 5b-4.
#[test]
#[ignore = "waits for ACP-5"]
fn acp_two_concurrent_answers_to_one_request_reach_the_agent_once_also_across_a_daemon_reconnect() {
    run_case(
        "5b-4",
        &controls::restart_script(),
        controls::two_answers_at_once,
    );
}

/// Control 5b-5.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_cancel_racing_an_approval_has_one_winner_and_the_other_is_told() {
    run_case(
        "5b-5",
        &controls::race_script(),
        controls::a_cancel_racing_an_approval,
    );
}

/// Control 5b-6.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_permission_request_after_a_cancel_is_answered_cancelled_by_a_qoder_shaped_agent() {
    run_case(
        "5b-6",
        &controls::late_request_script(),
        controls::a_request_after_a_cancel,
    );
}

/// Control 5b-6g.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_a_permission_request_after_a_cancel_is_answered_cancelled_by_a_gemini_shaped_agent() {
    run_case(
        "5b-6g",
        &controls::late_request_of_a_waiting_agent_script(),
        controls::a_request_after_a_cancel_of_a_waiting_agent,
    );
}

/// Control 5b-7.
#[test]
#[ignore = "waits for ACP-5"]
fn acp_the_same_request_id_in_a_second_instance_is_a_second_pending_request() {
    run_case(
        "5b-7",
        &controls::restart_script(),
        controls::the_same_id_in_a_second_instance,
    );
}

/// Control 5b-8.
#[test]
#[ignore = "waits for ACP-5"]
fn acp_a_fresh_request_after_a_daemon_restart_is_a_pending_request() {
    run_case(
        "5b-8",
        &controls::restart_script(),
        controls::a_fresh_request_after_a_restart,
    );
}

/// Control 5b-9.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_an_agent_that_exits_before_dispatch_leaves_its_request_cancelled() {
    run_case(
        "5b-9",
        &controls::exit_script(),
        controls::an_agent_exits_before_dispatch,
    );
}

/// Control 5b-10.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_an_agent_that_exits_after_dispatch_leaves_the_receipt_unknown_unless_evidence_came_first_for_a_qoder_shaped_agent()
 {
    run_case(
        "5b-10",
        &controls::exit_script(),
        controls::an_agent_exits_after_dispatch,
    );
}

/// Control 5b-10g.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_an_agent_that_exits_after_dispatch_leaves_the_receipt_unknown_unless_evidence_came_first_for_a_gemini_shaped_agent()
 {
    run_case(
        "5b-10g",
        &controls::exit_script(),
        controls::a_gemini_shaped_agent_exits_after_dispatch,
    );
}

/// Control 5b-12.
#[test]
#[ignore = "waits for ACP-3a"]
fn acp_the_launcher_ends_the_agent_when_the_workers_connection_ends() {
    run_case(
        "5b-12",
        &controls::lingering(controls::exit_script()),
        controls::the_launcher_ends_the_agent,
    );
}

/// Control 5b-13.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_a_gemini_decline_stays_dispatching_until_the_next_request_the_reply_or_the_deadline() {
    run_case(
        "5b-13",
        &controls::decline_script(),
        controls::three_declines_and_no_update,
    );
}

/// Control 5b-14.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_an_abort_that_settles_a_call_without_taking_the_answer_leaves_the_receipt_unknown() {
    run_case(
        "5b-14",
        &controls::abort_script(),
        controls::an_abort_after_the_answer,
    );
}

/// Control 5b-15.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_silent_unresolved_approval_is_cancelled_by_a_cancel_after_eleven_seconds() {
    run_case(
        "5b-15",
        &controls::silent_script(),
        controls::a_cancel_after_eleven_quiet_seconds,
    );
}

/// Control 5b-16.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_the_cancel_window_of_a_turn_of_the_agents_own_closes_thirty_seconds_after_the_cancel() {
    run_case(
        "5b-16",
        &controls::window_script(),
        controls::approvals_at_twenty_nine_and_thirty_one_seconds,
    );
}

/// Control 5b-17.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_the_cancel_window_with_a_prompt_in_flight_closes_at_that_prompts_reply_for_a_gemini_shaped_agent()
 {
    run_case(
        "5b-17",
        &controls::thirty_one_seconds_script(),
        controls::an_approval_at_thirty_one_seconds_with_a_prompt_in_flight,
    );
}

/// Control 5b-18.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_prompt_answered_cancelled_while_the_agents_own_turn_goes_on_leaves_the_cancel_window_open()
{
    run_case(
        "5b-18",
        &controls::queued_prompt_script(),
        controls::a_prompt_answered_cancelled_while_the_old_turn_goes_on,
    );
}

/// Control 5b-19.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_prompt_sent_five_seconds_after_a_cancel_shows_its_approval() {
    run_case(
        "5b-19",
        &controls::prompt_after_a_cancel_script(),
        controls::a_prompt_five_seconds_after_a_cancel,
    );
}

/// Control 5b-20.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_an_answered_approval_of_a_turn_of_the_agents_own_reads_unknown_at_three_hundred_seconds() {
    run_case(
        "5b-20",
        &controls::silent_script(),
        controls::an_answer_and_three_hundred_seconds,
    );
}

/// Control 5b-21.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_decline_in_a_turn_of_the_agents_own_reads_unknown_at_the_calls_failed_update() {
    run_case(
        "5b-21",
        &controls::failed_script(),
        controls::a_decline_and_a_failed_update,
    );
}

/// Control 5b-22.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_late_in_progress_update_moves_an_allow_from_unknown_to_applied() {
    run_case(
        "5b-22",
        &controls::late_update_script(),
        controls::an_allow_a_deadline_and_a_late_update,
    );
}

/// Control 5b-23.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_completed_update_after_a_cancel_leaves_an_allow_applied_for_a_qoder_shaped_agent() {
    run_case(
        "5b-23",
        &controls::completed_after_a_cancel_script(),
        controls::a_completed_update_after_a_cancel,
    );
}

/// Control 5b-23g.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_a_completed_update_after_a_cancel_leaves_an_allow_applied_for_a_gemini_shaped_agent() {
    run_case(
        "5b-23g",
        &controls::completed_while_cancelling_script(),
        controls::a_completed_update_after_a_cancel_of_a_waiting_agent,
    );
}

/// Control 6b-1.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_an_upgrade_leaves_a_qoder_shaped_process_its_copy_and_its_identity() {
    run_case(
        "6b-1",
        &controls::upgrade_script(),
        controls::an_upgrade_while_the_agent_runs,
    );
}

/// Control 6b-2.
#[test]
#[ignore = "waits for ACP-4"]
fn acp_a_fresh_request_after_an_upgrade_is_decoded_by_the_pinned_table_and_answered_with_its_ids() {
    run_case(
        "6b-2",
        &controls::upgrade_script(),
        controls::a_fresh_request_after_an_upgrade,
    );
}

/// Control 6b-3.
#[test]
#[ignore = "waits for ACP-3a"]
fn acp_a_build_outside_the_range_is_refused_with_a_message_that_names_the_range() {
    run_case(
        "6b-3",
        &controls::upgrade_script(),
        controls::a_second_start_after_the_upgrade,
    );
}

/// Control 6b-4.
#[test]
#[ignore = "waits for ACP-5"]
fn acp_a_start_whose_version_differs_from_the_hashed_build_is_refused() {
    run_case(
        "6b-4",
        &controls::upgrade_script(),
        controls::a_start_that_reports_another_version,
    );
}

/// Controls 6b-3g and 6b-5.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_an_upgrade_leaves_a_gemini_shaped_process_the_chunk_of_its_copy() {
    run_case(
        "6b-5",
        &controls::chunk_script(),
        controls::an_upgrade_while_a_gemini_shaped_agent_runs,
    );
}

/// Control 6b-6.
#[test]
#[ignore = "waits for ACP-7c"]
fn acp_without_the_copy_the_same_upgrade_changes_the_chunk_a_gemini_shaped_process_loads() {
    run_case_from(
        "6b-6",
        Source::TheInstallation,
        &controls::chunk_script(),
        controls::an_upgrade_while_the_agent_runs_from_the_installation,
    );
}

// The guards. They start no agent and run in the workspace's gate.

/// The probe reads the forwarder's real command table, so a missing `acp` subcommand is a fact and
/// not a probe that cannot see.
#[test]
fn the_acp_probe_reads_the_command_table_of_the_forwarder() {
    let names = hook_subcommands();
    for known in ["claude-code", "launch"] {
        assert!(
            names.iter().any(|name| name == known),
            "the command table names `{known}`: {names:?}"
        );
    }
    assert_eq!(launch_exists(), names.iter().any(|name| name == "acp"));
}

/// Every control names a known owner, a mutation and a red, and the controls of one test agree on
/// its stand-in, its owner and whether it waits. A Gemini-shaped test waits for the part that
/// starts Gemini from its copy.
#[test]
fn the_acp_table_names_owner_mutation_and_red_of_every_control() {
    let mut ids = BTreeSet::new();
    let mut tests: BTreeMap<&str, (Shape, &str, bool)> = BTreeMap::new();
    for control in &CONTROLS {
        assert!(ids.insert(control.id), "{} is listed twice", control.id);
        assert!(
            control.id.starts_with("5b-") || control.id.starts_with("6b-"),
            "{} is a control of 5b or 6b",
            control.id
        );
        assert!(
            OWNERS.contains(&control.owner),
            "{} names the owner {}, which is none of {OWNERS:?}",
            control.id,
            control.owner
        );
        for (what, text) in [
            ("shows", control.shows),
            ("mutation", control.mutation),
            ("red", control.red),
        ] {
            assert!(!text.is_empty(), "{} has an empty {what}", control.id);
        }
        if control.shape == Shape::Gemini {
            assert_eq!(
                control.owner, "ACP-7c",
                "{} starts the Gemini-shaped stand-in",
                control.id
            );
        }
        let held = (control.shape, control.owner, control.waits);
        assert_eq!(
            *tests.entry(control.test).or_insert(held),
            held,
            "the controls of {} disagree on its stand-in, its owner or whether it waits",
            control.test
        );
    }
}

/// Only the control that starts the stand-in from the installation with no copy names a harness
/// start, and it says why.
#[test]
fn the_acp_table_names_the_one_harness_start_and_its_reason() {
    let starts: Vec<(&str, &str)> = CONTROLS
        .iter()
        .filter_map(|control| control.harness_start.map(|why| (control.id, why)))
        .collect();
    let ids: Vec<&str> = starts.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        ["6b-6"],
        "the controls that name a harness start (left) and the one control that starts with no copy (right)"
    );
    assert!(
        starts.iter().all(|(_, why)| !why.is_empty()),
        "a harness start names its reason"
    );
}

/// The table and this file agree: a test the table says waits is ignored for the same part, a
/// test it says does not wait has no `ignore`, and no case is missing from the table or left out
/// of the file.
#[test]
fn the_acp_table_matches_the_ignored_cases_of_this_file() {
    let in_source = cases_in_source();
    let mut in_table: BTreeMap<&str, Option<String>> = BTreeMap::new();
    for control in &CONTROLS {
        in_table.insert(
            control.test,
            control.waits.then(|| control.owner.to_owned()),
        );
    }
    let table: BTreeMap<String, Option<String>> = in_table
        .into_iter()
        .map(|(test, part)| (test.to_owned(), part))
        .collect();
    assert_eq!(
        in_source, table,
        "the cases of this file (left) and the table's tests (right) differ"
    );
    assert!(
        in_source.keys().all(|name| !name.starts_with(GUARD_PREFIX)),
        "a guard is named as a case"
    );
}

/// Each real-arm row is recorded as not run with its reason and never as passed, and the rows are
/// the two agents' 5b and 6b.
#[test]
fn the_acp_real_arm_rows_are_recorded_not_run_and_never_passed() {
    let mut rows = BTreeSet::new();
    for row in &REAL_ARM {
        assert!(rows.insert((row.agent, row.case)), "a row is listed twice");
        let shows = serde_json::json!({ "agent": row.agent, "not_run": row.reason });
        assert_eq!(
            recorded_as(&shows, &[], false),
            Filed::NotRun(row.reason.to_owned()),
            "the {} row of {} is recorded not run",
            row.agent,
            row.case
        );
    }
    let expected = BTreeSet::from([
        ("gemini", "5b"),
        ("gemini", "6b"),
        ("qoder", "5b"),
        ("qoder", "6b"),
    ]);
    assert_eq!(rows, expected);
}
