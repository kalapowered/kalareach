//! The parts of the qualification that need no login (2b, 2c, 5a, 6a, 8a and 14.03a), on the
//! gateway driver: the same host, managed shell, paired device and held ending as the gateway
//! cases, with the agent started by hand, so that the host's command integration is not turned on
//! and no gateway serves it.
//!
//! After the agent started nothing runs `kr`: the host's processes are ended by the identities the
//! run recorded, a daemon is started again with no `kr` and the device connects to it, and what
//! needs a command line (the second device's share, 8a) is done before the agent starts. No case
//! sends a prompt, so none charges a turn. On the stand-in route the agent is the application
//! stand-in started by hand (`by-hand`: a composer and nothing to serve); on a real route it is the
//! pinned build with no login, which shows the build's first screen.

use super::*;

use kr_e2e_agents::build::Action;
use kr_e2e_agents::detect::{
    Detection, Held, Launched, Shown, Surface, all_rejected, announced_now, backend_files,
    capabilities_of, check_detected, check_ended, check_observation_only, check_unchanged,
    checker_controls, wait_for_detection, wait_for_no_instance,
};
use kr_e2e_agents::observe::{
    AGENT_READS, Answer as Reply, TYPED_PROMPT, capability_states, invoke, live_bindings,
    target_of, typed_actions,
};
use kr_e2e_agents::stage::{Keyboard, events_snapshot};
use kr_e2e_m1b::run::{ended_within, running, signal};
use kr_protocol::ids::InputSequence;
use kr_protocol::input::{InputContent, InputWriteParams};
use kr_protocol::scalars::Bytes;

/// What the stand-in started by hand says on its first row.
const BY_HAND: &str = "codex-stand-in: by hand";

/// A file name of the working directory that a path typed at the composer names.
const SHOT: &str = "kalareach-shot.png";

/// A one-pixel PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0,
    0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

/// The bound a forwarder's answer is held to, after its first run under the host.
const FORWARDER_BOUND_MS: i64 = 500;

/// The route as the case's own record names it, beside the host-side `route` every case writes.
fn arm(ctx: &Context) -> &'static str {
    match ctx.route {
        Route::StandIn => "stand-in",
        Route::Real(_) => "pinned build",
    }
}

/// A case that starts its agent by hand and takes no login.
fn by_hand_case(
    part: &str,
    test: &str,
    setup: Setup,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    let leg = format!("staged-{}", part.replace('.', "-"));
    run_case_in(
        Setup {
            manual: true,
            no_login: true,
            ..setup
        },
        &leg,
        part,
        test,
        "by-hand",
        body,
    );
}

/// The package's actions, as its manifest declares them.
fn package_actions() -> Vec<Action> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(codex_package().join("plugin.json")).expect("the package's manifest"),
    )
    .expect("a manifest");
    serde_json::from_value(manifest["actions"].clone()).expect("the package's actions")
}

/// The text a harmless keystroke types at the agent's composer, and the text its screen shows once
/// it arrived.
fn harmless(ctx: &Context) -> (String, String) {
    match &ctx.route {
        Route::StandIn => ("kr-harmless".to_owned(), "> kr-harmless".to_owned()),
        Route::Real(real) => (
            real.build.harmless.input.clone(),
            real.build.harmless.shows.clone(),
        ),
    }
}

/// The agent a case started by hand: its worker and the process that runs the pinned program,
/// by the identities recorded when they were found.
struct HandAgent {
    worker: ProcessStartIdentity,
    agent: ProcessStartIdentity,
}

impl HandAgent {
    /// Types the agent's name in the session's shell, waits until the host announces an instance
    /// for it, and records the worker and the process that maps the pinned program below it.
    fn starts(ctx: &Context, session: &Session<'_>) -> Self {
        let _ = session.starts_the_agent_showing(BY_HAND, &[], None, &[]);
        let worker = ctx.run.worker_of(&session.session_id().to_string());
        let pid = u32::try_from(worker.pid.get()).expect("a pid");
        let agent = process_mapping_within(
            pid,
            inode_of(&ctx.executable),
            None,
            &[pid],
            &mut Vec::new(),
        )
        .unwrap_or_else(|why| panic!("the agent started by hand: {why}"));
        Self { worker, agent }
    }

    /// Whether both still run.
    fn runs(&self) -> Result<(), String> {
        all_run(&[("the worker", &self.worker), ("the agent", &self.agent)])
    }

    /// Ends the agent by its recorded identity.
    fn ends(&self) {
        signal(&self.agent, rustix::process::Signal::KILL);
        assert!(
            ended_within(&self.agent, LIVENESS),
            "the agent ended when killed"
        );
    }
}

/// Whether every process named runs, by its recorded start identity.
///
/// # Errors
///
/// Returns the processes that do not.
fn all_run(processes: &[(&str, &ProcessStartIdentity)]) -> Result<(), String> {
    let ended: Vec<String> = processes
        .iter()
        .filter(|(_, identity)| !running(identity))
        .map(|(what, identity)| format!("{what} (process {})", identity.pid.get()))
        .collect();
    if ended.is_empty() {
        Ok(())
    } else {
        Err(format!("these have ended: {}", ended.join(", ")))
    }
}

/// What the host shows of the agent in `session_id`, through `remote`.
fn shown_from(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
    detection: Detection,
) -> Shown {
    let binding = detection.only().and_then(|instance| {
        capabilities_of(
            remote,
            &ctx.runtime,
            subject(session_id, instance.application_instance_id),
        )
        .ok()
    });
    Shown {
        detection,
        binding,
        live_bindings: live_bindings(remote, &ctx.runtime, &codex()),
    }
}

/// What the host shows once it has had time to detect the agent.
fn detects(ctx: &Context, remote: &Remote, session_id: SessionId) -> Shown {
    let detection = wait_for_detection(remote, &ctx.runtime, session_id, &|| {
        ctx.checks_the_placed_files();
    });
    shown_from(ctx, remote, session_id, detection)
}

/// What the host shows now, with no wait.
fn shown_now(ctx: &Context, remote: &Remote, session_id: SessionId) -> Shown {
    let detection = Detection {
        instances: announced_now(remote, &ctx.runtime, session_id),
        waited_ms: 0,
    };
    shown_from(ctx, remote, session_id, detection)
}

/// What the host shows once it has had time to end the instance.
fn shown_gone(ctx: &Context, remote: &Remote, session_id: SessionId) -> Shown {
    let detection = wait_for_no_instance(remote, &ctx.runtime, session_id, &|| {
        ctx.checks_the_placed_files();
    });
    shown_from(ctx, remote, session_id, detection)
}

/// The typed surface a device reaches for the agent in `session_id`: each typed mutation and each
/// of the package's upstream actions, the capability records, the resources and every command
/// backend in the host's runtime directory. The agent reads come back apart.
fn surface(
    ctx: &Context,
    session: &Session<'_>,
    remote: &Remote,
    session_id: SessionId,
    shown: &Shown,
) -> (Surface, Vec<Reply>) {
    let upstream: Vec<Action> = package_actions()
        .into_iter()
        .filter(Action::upstream)
        .collect();
    let answers = typed_actions(
        remote,
        &ctx.runtime,
        session_id,
        &codex(),
        &upstream,
        Held::of(shown).map(|held| (held.instance, held.revision)),
    );
    let (reads, mutations): (Vec<Reply>, Vec<Reply>) = answers
        .into_iter()
        .partition(|answer| AGENT_READS.contains(&answer.call.as_str()));
    let snapshot = events_snapshot(remote, &ctx.runtime, session_id);
    let resources = snapshot.agent_resources.resources.len()
        + usize::from(snapshot.agent_resources.continue_after.0.is_some());
    (
        Surface {
            records: Surface::records_of(shown.binding.as_ref()),
            answers: mutations,
            resources,
            backend_files: backend_files(session.host.roots().runtime_root()),
        },
        reads,
    )
}

/// What the agent started by hand was launched as, for the check of its detection.
fn launched(agent: &HandAgent) -> Launched {
    Launched {
        plugin_id: codex(),
        running: agent.runs().is_ok(),
    }
}

/// The device's keyboard on `session_id`: attached, and holding the input lease where `lease`.
fn keyboard(ctx: &Context, session: &Session<'_>, lease: bool) -> Keyboard {
    let mut keyboard = Keyboard::attach(&session.remote, &ctx.runtime, session.session_id())
        .unwrap_or_else(|why| panic!("the device's keyboard attaches: {why}"));
    if lease {
        keyboard
            .acquire(&session.remote, &ctx.runtime)
            .unwrap_or_else(|why| panic!("the device takes the input lease: {why}"));
    }
    keyboard
}

/// Whether no capability of the installed package is advertised as qualified and available.
///
/// # Errors
///
/// Returns the capabilities that are.
fn advertises_nothing_as_available(states: &[(String, String)]) -> Result<(), String> {
    let available: Vec<&str> = states
        .iter()
        .filter(|(_, state)| state == "qualified_available")
        .map(|(capability, _)| capability.as_str())
        .collect();
    if available.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "advertised as qualified and available: {available:?}"
        ))
    }
}

/// Waits until the screen shows `needle`, in one row or across the rows a long line was wrapped
/// onto, within [`LIVENESS`]; returns the rows.
fn shows_across_rows(person: &Person, needle: &str) -> Vec<String> {
    let started = Instant::now();
    loop {
        let rows = person.window.screen();
        if rows.concat().contains(needle) {
            return rows;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the agent's composer shows no {needle:?} after {LIVENESS:?}:\n{}",
            rows.join("\n")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether the screen shows none of `needle`.
///
/// # Errors
///
/// Returns the rows that show it.
fn shows_no_trace(rows: &[String], needle: &str) -> Result<(), String> {
    let shown: Vec<&String> = rows.iter().filter(|row| row.contains(needle)).collect();
    if shown.is_empty() && !rows.concat().contains(needle) {
        Ok(())
    } else {
        Err(format!("the screen shows {needle:?}: {shown:?}"))
    }
}

/// The agent's process still maps the pinned program's image.
///
/// # Errors
///
/// Returns why the process is not known to run the pinned build.
fn image_is_pinned(actual: &Result<u64, String>, pinned: u64) -> Result<(), String> {
    match actual {
        Ok(image) if *image == pinned => Ok(()),
        Ok(image) => Err(format!(
            "the process runs the program with inode {image}, not the pinned build's (inode {pinned})"
        )),
        Err(why) => Err(format!("the process's program was not read: {why}")),
    }
}

/// The input a device's keyboard sent forwarded every byte of `typed` to the terminal.
///
/// # Errors
///
/// Returns what was forwarded.
fn forwarded_whole(forwarded: u64, typed: &str) -> Result<(), String> {
    let length = u64::try_from(typed.len()).unwrap_or(u64::MAX);
    if forwarded == length {
        Ok(())
    } else {
        Err(format!("{forwarded} of the {length} bytes were forwarded"))
    }
}

/// What the presentation actions and the upstream actions were answered with, under the binding:
/// each presentation action is admitted, each upstream action refused.
///
/// # Errors
///
/// Returns the calls the host answered otherwise.
fn presentation_admitted_and_upstream_refused(
    presentation: &[Reply],
    upstream: &[Reply],
) -> Result<(), String> {
    if presentation.is_empty() {
        return Err("no presentation action was sent".to_owned());
    }
    let mut wrong: Vec<String> = presentation
        .iter()
        .filter(|answer| answer.refused.is_some() || answer.error.is_some())
        .map(|answer| format!("{} was not admitted: {}", answer.call, answer.detail))
        .collect();
    wrong.extend(
        upstream
            .iter()
            .filter(|answer| answer.refused.is_none())
            .map(|answer| format!("{} was not refused: {}", answer.call, answer.detail)),
    );
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("; "))
    }
}

/// Whether the host answered every one of the actions refused.
///
/// # Errors
///
/// Returns the calls that were not.
fn all_refused(answers: &[Reply]) -> Result<(), String> {
    let accepted: Vec<&str> = answers
        .iter()
        .filter(|answer| answer.refused.is_none())
        .map(|answer| answer.call.as_str())
        .collect();
    if accepted.is_empty() {
        Ok(())
    } else {
        Err(format!("not refused: {accepted:?}"))
    }
}

/// What the forwarder a forging session ran answered neutrally, where its registration leads it to
/// stop and, where `timed`, within the bound.
///
/// # Errors
///
/// Returns what the answer got wrong.
fn judges_a_forwarder_answer(
    result: &serde_json::Value,
    stopped_at: Option<&str>,
    timed: bool,
) -> Result<(), String> {
    if result["exit"] != 0 {
        return Err(format!("the forwarder did not exit 0: {result}"));
    }
    if result["stdout"].as_str().map(str::trim) != Some("{}") {
        return Err(format!(
            "the forwarder did not answer exactly {{}}: {result}"
        ));
    }
    if timed
        && !result["elapsed_ms"]
            .as_i64()
            .is_some_and(|ms| (0..=FORWARDER_BOUND_MS).contains(&ms))
    {
        return Err(format!(
            "the forwarder did not answer within {FORWARDER_BOUND_MS} ms: {result}"
        ));
    }
    let said = result["stderr_first_line"].as_str().unwrap_or_default();
    if !stopped_at.map_or(said.is_empty(), |stage| said.contains(stage)) {
        return Err(format!(
            "the forwarder did not stop where its registration leads: {result}"
        ));
    }
    Ok(())
}
