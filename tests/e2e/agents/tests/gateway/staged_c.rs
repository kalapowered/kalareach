//! The parts of the qualification that start the agent by hand with the person's login (2a, 7 and
//! 7f), on the gateway driver: the same host, managed shell, paired device and held ending as the
//! gateway cases, with the host's command integration not turned on, so that nothing serves the
//! launch through a gateway and the host sees a native terminal.
//!
//! After the agent started nothing runs `kr`: what the device does is protocol traffic on the
//! connections it made before, and the host's processes are ended by the identities the run
//! recorded. Every prompt is charged to the entry's budget before it is typed, and the key that
//! submits it is typed only once the charge was made. On the stand-in route the agent is the
//! application stand-in started by hand, which has no model and no login: the parts show what that
//! can show, and the result says so. A real route is the pinned build with the person's approved
//! login, whose entry names the keys, the screens and the records the parts read.

use super::*;

use kr_e2e_agents::account::conversation_id;
use kr_e2e_agents::build::Action;
use kr_e2e_agents::conversation::turn_between;
use kr_e2e_agents::detect::{
    Detection, Held, Launched, Shown, Surface, announced_now, backend_files, capabilities_of,
    check_detected, check_observation_only, check_unchanged, wait_for_detection,
};
use kr_e2e_agents::observe::{
    AGENT_READS, Answer as Reply, capability_states, live_bindings, typed_actions,
};
use kr_e2e_agents::stage::{Keyboard, events_snapshot};
use kr_e2e_m1b::run::running;

/// What the stand-in started by hand says on its first row.
const BY_HAND: &str = "codex-stand-in: by hand";

/// The identifier the stand-in's `resume` and `fork` are given: it saves no conversation.
const STAND_IN_CONVERSATION: &str = "00000000-0000-4000-8000-000000000001";

/// What a case waits at most for the screen to show the text it typed before it submits it: an
/// agent drawing a reply can take what is typed late.
const TYPED_SHOWS_BY: Duration = Duration::from_secs(10);

/// How long the record of a reply is waited for after the screen showed it.
const RECORD_SETTLES: Duration = Duration::from_secs(20);

/// The route as the case's own record names it, beside the host-side `route` every case writes.
fn arm(ctx: &Context) -> &'static str {
    match ctx.route {
        Route::StandIn => "stand-in",
        Route::Real(_) => "pinned build",
    }
}

/// A case that starts its agent by hand and takes the person's login on a real route.
fn by_hand_login_case(
    part: &str,
    test: &str,
    setup: Setup,
    variants: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    let leg = format!("staged-{}", part.replace('.', "-"));
    run_case_in(
        Setup {
            manual: true,
            ..setup
        },
        &leg,
        part,
        test,
        variants,
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

// ---------------------------------------------------------------------------------------------
// The sessions, the agents and what the host shows of them.
// ---------------------------------------------------------------------------------------------

/// One of a case's sessions.
#[derive(Clone, Copy)]
pub(super) enum Seat {
    First,
    Second,
}

/// A session's person, the device's connection to it and its identifier.
struct Seated<'s> {
    person: &'s Person,
    remote: &'s Remote,
    session_id: SessionId,
}

/// The session at `seat`.
fn seated<'s>(session: &'s Session<'_>, seat: Seat) -> Seated<'s> {
    match seat {
        Seat::First => Seated {
            person: &session.person,
            remote: &session.remote,
            session_id: session.session_id(),
        },
        Seat::Second => {
            let second = session.second.as_ref().expect("a case with two sessions");
            Seated {
                person: &second.person,
                remote: &second.remote,
                session_id: second.person.session_id,
            }
        }
    }
}

/// The agent a case started by hand: its worker and the process that runs the pinned program, by
/// the identities recorded when they were found.
struct HandAgent {
    worker: ProcessStartIdentity,
    agent: ProcessStartIdentity,
}

impl HandAgent {
    /// The agent that runs below the worker of `session_id`, once the screen showed it up.
    fn found(ctx: &Context, session_id: SessionId) -> Self {
        let worker = ctx.run.worker_of(&session_id.to_string());
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
        let ended: Vec<String> = [("the worker", &self.worker), ("the agent", &self.agent)]
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
}

/// Types the agent's name in the shell of `seat`, with `extra` after it, and waits until its first
/// screen is up: the stand-in's own line, or, on a real route, the agent's composer (the person's
/// login is given, so the first screen of the build is the composer and not a sign-in).
///
/// `first_start` is whether this is the case's first start of any agent: the entry's isolation
/// probes run before it, once, as they do before any case's first start.
fn starts_by_hand(
    ctx: &Context,
    session: &Session<'_>,
    seat: Seat,
    extra: &[&str],
    first_start: bool,
) -> HandAgent {
    let at = seated(session, seat);
    // Before anything of the agent runs, the shell's own environment is read at its prompt: the
    // first start only, since an agent's start can change what a later read would show.
    if !session.environment_read.replace(true) {
        match session
            .person
            .reads_the_environment(&session.person.expected)
        {
            Ok(compared) => eprintln!("{compared}"),
            Err(why) => panic!("{why}"),
        }
    }
    // From here the harness runs no `kr`, whatever the route.
    if matches!(ctx.route, Route::StandIn) && session.stand_in_leaves_the_tree {
        session.host.agent_is_a_stand_in();
    }
    session.host.agent_starts();
    match &ctx.route {
        Route::StandIn => {
            let _ = at.person.types_until_it_shows(
                &launch_words("codex", extra).join(" "),
                BY_HAND,
                "the stand-in is up by hand",
                &|| ctx.checks_the_placed_files(),
            );
        }
        Route::Real(real) => {
            if first_start {
                let absent = real.absent_list(&ctx.run);
                real.checks_absent(&ctx.run, &absent);
                // No probe is given the login: none of them needs an account.
                real.proves_isolation(&ctx.run, &ctx.without_login(&ctx.variables(&session.host)));
                real.checks_absent(&ctx.run, &absent);
            }
            let _ = at.person.types_until_it_shows(
                &real.typed(extra),
                &real.account.composer,
                "the agent reaches its composer",
                &|| {
                    ctx.checks_the_placed_files();
                    real.checks_the_route(&ctx.run);
                },
            );
        }
    }
    HandAgent::found(ctx, at.session_id)
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
fn detects(ctx: &Context, at: &Seated<'_>) -> Shown {
    let detection = wait_for_detection(at.remote, &ctx.runtime, at.session_id, &|| {
        ctx.checks_the_placed_files();
    });
    shown_from(ctx, at.remote, at.session_id, detection)
}

/// What the host shows now, with no wait.
fn shown_now(ctx: &Context, at: &Seated<'_>) -> Shown {
    let detection = Detection {
        instances: announced_now(at.remote, &ctx.runtime, at.session_id),
        waited_ms: 0,
    };
    shown_from(ctx, at.remote, at.session_id, detection)
}

/// The detection of the launch that `agent` is, as section 12 requires it.
fn detected(agent: &HandAgent, shown: &Shown, what: &str) {
    let launched = Launched {
        plugin_id: codex(),
        running: agent.runs().is_ok(),
    };
    if let Err(why) = check_detected(&launched, shown) {
        panic!("the host did not detect {what} as a manual launch: {why}");
    }
}

/// The typed surface a device reaches for the agent in `at`: each typed mutation and each of the
/// package's upstream actions, the capability records, the resources and every command backend in
/// the host's runtime directory. The agent reads come back apart.
fn surface(
    ctx: &Context,
    session: &Session<'_>,
    at: &Seated<'_>,
    shown: &Shown,
) -> (Surface, Vec<Reply>) {
    let upstream: Vec<Action> = package_actions()
        .into_iter()
        .filter(Action::upstream)
        .collect();
    let answers = typed_actions(
        at.remote,
        &ctx.runtime,
        at.session_id,
        &codex(),
        &upstream,
        Held::of(shown).map(|held| (held.instance, held.revision)),
    );
    let (reads, mutations): (Vec<Reply>, Vec<Reply>) = answers
        .into_iter()
        .partition(|answer| AGENT_READS.contains(&answer.call.as_str()));
    let snapshot = events_snapshot(at.remote, &ctx.runtime, at.session_id);
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

// ---------------------------------------------------------------------------------------------
// What the device types, and what a turn costs.
// ---------------------------------------------------------------------------------------------

/// The turns a case charged to the budget and the ones it submitted.
pub(super) struct Turns<'a> {
    ctx: &'a Context,
    real: &'a Real,
    part: &'a str,
    pub(super) charged: u64,
    pub(super) submitted: u64,
}

/// Whether the turn about to be submitted, the `submitted`th, was charged before: no turn is
/// submitted that the budget was not asked for first.
///
/// # Errors
///
/// Returns that the submission has no charge before it.
fn charged_first(charged: u64, submitted: u64) -> Result<(), String> {
    if charged >= submitted {
        Ok(())
    } else {
        Err(format!(
            "turn {submitted} is submitted with {charged} charged before it"
        ))
    }
}

/// Whether the case charged exactly the turns it submitted, and the number it was to.
///
/// # Errors
///
/// Returns what the counts say.
pub(super) fn turns_as_planned(charged: u64, submitted: u64, planned: u64) -> Result<(), String> {
    if charged == submitted && charged == planned {
        Ok(())
    } else {
        Err(format!(
            "{charged} turn(s) charged, {submitted} submitted, {planned} planned"
        ))
    }
}

/// The device's keyboard on a session, and the person's screen it types at.
pub(super) struct Typing<'a> {
    ctx: &'a Context,
    at: Seated<'a>,
    keys: Keyboard,
}

impl<'a> Typing<'a> {
    /// Attaches the device's keyboard to the session at `seat` and takes the input lease.
    pub(super) fn attach(ctx: &'a Context, session: &'a Session<'_>, seat: Seat) -> Self {
        let at = seated(session, seat);
        let mut keys = Keyboard::attach(at.remote, &ctx.runtime, at.session_id)
            .unwrap_or_else(|why| panic!("the device's keyboard attaches: {why}"));
        keys.acquire(at.remote, &ctx.runtime)
            .unwrap_or_else(|why| panic!("the device takes the input lease: {why}"));
        Self { ctx, at, keys }
    }

    /// Types `text` from the device: every byte is forwarded to the terminal.
    pub(super) fn types(&mut self, text: &str) {
        let written = self
            .keys
            .type_text(self.at.remote, &self.ctx.runtime, text)
            .unwrap_or_else(|why| panic!("{why}"));
        let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
        assert!(
            written.forwarded_bytes.get() >= length,
            "{} of the {length} byte(s) typed were forwarded to the terminal",
            written.forwarded_bytes.get()
        );
    }

    /// Where an approval dialog of the agent's is on the screen, a typed digit or the key that
    /// submits would be taken as a choice, which may approve a command: the dialog is refused with
    /// the agent's own key and the case stops.
    fn no_dialog(&mut self, real: &Real, when: &str) {
        let shows = &real.account.approval.shows;
        if self
            .at
            .person
            .window
            .screen()
            .iter()
            .any(|row| row.contains(shows))
        {
            let deny = real.account.approval.deny.clone();
            self.types(&deny);
            panic!(
                "a dialog showing {shows:?} was on the screen {when}, so no prompt or key that \
                 submits was sent"
            );
        }
    }

    /// Charges one turn, then types `text` at the composer from the device, waits until the screen
    /// shows `mark`, which begins the text, and types `key` once the line end can arrive on its own.
    pub(super) fn submits(
        &mut self,
        turns: &mut Turns<'_>,
        what: &str,
        text: &str,
        mark: &str,
        key: &str,
    ) {
        self.no_dialog(turns.real, "before the case typed a prompt");
        turns.real.charge(&turns.ctx.run, turns.part, what);
        turns.charged += 1;
        self.types(text);
        let started = Instant::now();
        while started.elapsed() < TYPED_SHOWS_BY
            && !self
                .at
                .person
                .window
                .screen()
                .iter()
                .any(|row| row.contains(mark))
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(300));
        self.no_dialog(turns.real, "where the case was about to submit");
        turns.submitted += 1;
        charged_first(turns.charged, turns.submitted)
            .unwrap_or_else(|why| panic!("the key that submits is not typed: {why}"));
        self.types(key);
    }
}

impl<'a> Turns<'a> {
    pub(super) fn new(ctx: &'a Context, real: &'a Real, part: &'a str) -> Self {
        Self {
            ctx,
            real,
            part,
            charged: 0,
            submitted: 0,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The agent's own record, read as the audit of the turns reads it.
// ---------------------------------------------------------------------------------------------

/// The agent's record as text.
fn record_text(ctx: &Context, real: &Real) -> String {
    real.conversations(&ctx.run)
        .unwrap_or_else(|why| panic!("the agent's record is not whole: {why}"))
}

/// The first line after line `after`, where one is given, that holds every one of `needles`.
fn first_line_with(text: &str, after: Option<usize>, needles: &[&str]) -> Option<usize> {
    text.lines()
        .enumerate()
        .skip(after.map_or(0, |line| line + 1))
        .find(|(_, line)| needles.iter().all(|needle| line.contains(needle)))
        .map(|(index, _)| index)
}

/// Waits until a line of the record holds every one of `needles`, and returns its number.
fn waits_for_a_line(ctx: &Context, real: &Real, needles: &[&str], why: &str) -> usize {
    let started = Instant::now();
    loop {
        if let Some(line) = first_line_with(&record_text(ctx, real), None, needles) {
            return line;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "{why}: no line of the agent's record holds {needles:?} after {LIVENESS:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Waits, a while at most, until a line of the record holds every one of `needles`: the agent
/// writes its record of a reply shortly after the screen shows it.
fn settles(ctx: &Context, real: &Real, needles: &[&str]) {
    let started = Instant::now();
    while first_line_with(&record_text(ctx, real), None, needles).is_none()
        && started.elapsed() < RECORD_SETTLES
    {
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The lines of the record from `from`, each by its number, the kind its `type` member names, and
/// which of `needles` it holds, by their labels: what a failed order check says of where each thing
/// landed, with none of the lines' text.
fn outline(text: &str, from: Option<usize>, needles: &[(&str, &str)]) -> String {
    text.lines()
        .enumerate()
        .skip(from.unwrap_or(0))
        .map(|(index, line)| {
            let kind = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| value["type"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "?".to_owned());
            let held: Vec<&str> = needles
                .iter()
                .filter(|(_, needle)| line.contains(needle))
                .map(|(label, _)| *label)
                .collect();
            format!("{index}:{kind}:{}", held.join("+"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------------------------
// Part 2a: each of the agent's own terminal controls, from a paired device, on its own.
// ---------------------------------------------------------------------------------------------

/// Whether a turn still runs, as the view and the record show it.
#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Running {
    busy: bool,
    unfinished: bool,
}

impl Running {
    const fn holds(self) -> bool {
        self.busy && self.unfinished
    }
}

/// Where a prompt entered during a running turn landed in the record, as the queue and steering
/// checks read it: the line of the running turn's last reply, of the second prompt, and of that
/// prompt's answer.
#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Order {
    /// Whether the running turn still ran across the second prompt's submission: just before, the
    /// view showed it busy and the record held no closing reply; just after, the record still held
    /// none.
    busy_at_submission: bool,
    /// The reading just before.
    before: Running,
    /// The reading just after.
    after: Running,
    /// Whether the agent writes a record of a prompt it queued behind a running turn.
    records_queue: bool,
    /// Its record of the second prompt, queued, where it wrote one.
    queued_record: Option<usize>,
    /// The running turn's reply that finished its work.
    first_finished: Option<usize>,
    /// The second prompt.
    second_prompt: Option<usize>,
    /// The second prompt's answer.
    second_answered: Option<usize>,
    /// Whether a turn started between the running turn's prompt and the second prompt, where the
    /// agent writes a line at each turn's start.
    new_turn: Option<bool>,
}

/// A prompt entered during a turn waited for it: it was entered while the turn ran, the turn's work
/// finished before the prompt joined the record, the prompt was answered after that, and, where the
/// agent writes a line at each turn's start, it started a turn of its own.
///
/// # Errors
///
/// Returns what the order lacks.
fn check_queued(order: &Order) -> Result<(), String> {
    match (
        order.first_finished,
        order.second_prompt,
        order.second_answered,
    ) {
        _ if !order.busy_at_submission => Err(format!(
            "the second prompt was not entered while a turn ran: just before {:?}, just after {:?}",
            order.before, order.after
        )),
        _ if order.new_turn == Some(false) => Err(format!(
            "the second prompt joined the running turn rather than starting one of its own: \
             {order:?}"
        )),
        (finished, _, _)
            if order.records_queue
                && !matches!((order.queued_record, finished), (Some(queued), Some(done)) if queued < done) =>
        {
            Err(format!(
                "the agent's record does not hold the second prompt as queued before the turn \
                 finished: {order:?}"
            ))
        }
        (Some(finished), Some(prompt), Some(answered))
            if finished < prompt && prompt < answered =>
        {
            Ok(())
        }
        _ => Err(format!(
            "the record does not hold the turn's finished work, then the prompt, then its answer: \
             {order:?}"
        )),
    }
}

/// A prompt entered during a turn steered it: it was entered while the turn ran, it joined that
/// turn, and it was answered. Where the agent writes a line at each turn's start, joining means no
/// turn started between the running turn's prompt and this one. Where it writes none, the prompt
/// must have joined the record before the turn's work finished, which it then never did.
///
/// # Errors
///
/// Returns what the order lacks.
fn check_steered(order: &Order) -> Result<(), String> {
    match (
        order.first_finished,
        order.second_prompt,
        order.second_answered,
        order.new_turn,
    ) {
        _ if !order.busy_at_submission => {
            Err("the steering prompt was not entered while a turn ran".to_owned())
        }
        (_, _, _, Some(true)) => Err(format!(
            "the steering prompt started a turn of its own rather than joining the running one: \
             {order:?}"
        )),
        (_, Some(prompt), Some(answered), Some(false))
        | (None, Some(prompt), Some(answered), None)
            if prompt < answered =>
        {
            Ok(())
        }
        _ => Err(format!(
            "the running turn did not take the prompt: {order:?}"
        )),
    }
}

/// Whether the package leaves the typed queue off (12.08): no record of `agent.prompt.queue` is
/// advertised as qualified and available, though the agent queues a prompt entered during a turn
/// on its own terminal.
///
/// # Errors
///
/// Returns that the queue is advertised.
fn queue_declared_off(states: &[(String, String)]) -> Result<(), String> {
    match states
        .iter()
        .find(|(capability, _)| capability == "agent.prompt.queue")
    {
        Some((_, state)) if state == "qualified_available" => {
            Err("agent.prompt.queue is advertised as qualified and available".to_owned())
        }
        _ => Ok(()),
    }
}

/// The turn that begins the reply: a long count, and what the screen shows once the reply began.
/// Interrupted before its reply begins, a turn can be withdrawn whole rather than stopped.
fn long_turn(mark: &str, reply_mark: Option<&str>) -> (String, String) {
    match reply_mark {
        Some(reply_mark) => (
            format!(
                "({mark}-i) Without using any tool or file, count from 1 to 400 in your reply, \
                 one number per line, and write nothing else."
            ),
            reply_mark.to_owned(),
        ),
        None => (
            format!(
                "({mark}-i) Without using any tool or file, write the code {mark} in upper case \
                 at the start of every line of your reply, then a space and the number, count \
                 from 1 to 400, one number per line, and write nothing else."
            ),
            mark.to_uppercase(),
        ),
    }
}

/// Whether the turn whose prompt is after line `prompt` of the record, and whose reply closes with
/// `done`, still runs now: the screen is read again for up to `within` while it does not yet show
/// the agent busy, since an agent drawing its reply redraws its whole screen.
fn turn_runs(
    ctx: &Context,
    real: &Real,
    person: &Person,
    prompt: Option<usize>,
    done: &str,
    within: Duration,
) -> Running {
    let until = Instant::now() + within;
    loop {
        let busy = person
            .window
            .screen()
            .iter()
            .any(|row| row.contains(&real.account.busy));
        if busy || Instant::now() >= until {
            return Running {
                busy,
                unfinished: first_line_with(
                    &record_text(ctx, real),
                    prompt,
                    &[done, &real.account.reply_line],
                )
                .is_none(),
            };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The turn that the real route runs for the queue and for the steering: a count with a closing
/// line of its own, which only the model writes.
fn counting_turn(mark: &str, tag: &str, done: &str) -> String {
    format!(
        "({mark}-{tag}) Without using any tool or file, count from 1 to 300 in your reply, one \
         number per line, then write {done} on a line of its own, and nothing else."
    )
}

/// KR-REQ-12.32, case 2, part 2a: with the person's login, each of the agent's own terminal
/// controls from a paired device, on its own. A slash command that calls no model shows its screen.
/// A long turn stops at the agent's interrupt key, and the agent says so. A prompt entered while a
/// turn runs, which the view shows busy and whose finishing reply the record does not yet hold
/// both just before and just after the entry, waits for it: the agent's record holds the turn's
/// finished work, then the prompt, then its answer. Where the agent steers a running turn with a
/// prompt entered during it, the turn takes the prompt before its work finishes, which then never
/// does. The typed steer, queue and commands stay refused, since the launch has only observation
/// and the terminal. The queue and steering checks are also handed orders made wrong on purpose,
/// which they must reject (the guard cases below). On the stand-in route, which has no model, the
/// case shows the device's keys reaching the agent's composer, and the result says so.
#[test]
fn gateway_slash_commands_interrupts_queued_prompts_and_steering_each_work_from_a_device_at_the_agents_terminal()
 {
    const TEST: &str = "gateway_slash_commands_interrupts_queued_prompts_and_steering_each_work_from_a_device_at_the_agents_terminal";
    by_hand_login_case("2a", TEST, Setup::default(), "by-hand", |ctx, session| {
        let at = seated(session, Seat::First);
        let agent = starts_by_hand(ctx, session, Seat::First, &[], true);
        let shown = detects(ctx, &at);
        detected(&agent, &shown, "the agent's launch");
        let mut typing = Typing::attach(ctx, session, Seat::First);
        let driven = match &ctx.route {
            Route::StandIn => {
                // The stand-in takes a typed line and says what it came to: the device's keys,
                // a slash command and the key that submits it, reach the composer.
                typing.types("/status");
                let _ = at
                    .person
                    .sees("/status", "the composer shows the slash command");
                std::thread::sleep(Duration::from_millis(300));
                typing.types("\r");
                let _ = at
                    .person
                    .sees("by hand: took", "the stand-in says what it took");
                serde_json::json!({
                    "arm": arm(ctx),
                    "slash": "typed and submitted from the device, and taken by the stand-in",
                    "models_turns": 0,
                    "why_not": "the stand-in has no model, so it has no turn to interrupt, queue behind or steer",
                })
            }
            Route::Real(real) => drives_the_controls(ctx, real, session, &mut typing),
        };
        // The typed forms stay refused, and the agent goes on.
        let after = shown_now(ctx, &at);
        check_unchanged(Held::of(&shown), &after)
            .unwrap_or_else(|why| panic!("the controls change nothing the host shows: {why}"));
        let (offered, reads) = surface(ctx, session, &at, &after);
        check_observation_only(&offered).unwrap_or_else(|why| {
            panic!("the typed steer, queue and commands stay refused: {why}")
        });
        // The package leaves the typed queue off, though the agent queues a prompt on its own
        // terminal.
        let states = capability_states(at.remote, &ctx.runtime, &codex());
        queue_declared_off(&states).unwrap_or_else(|why| panic!("{why}"));
        agent
            .runs()
            .unwrap_or_else(|why| panic!("the agent goes on: {why}"));
        serde_json::json!({
            "arm": arm(ctx),
            "detection": shown.detection.evidence(),
            "driven": driven,
            "capability_states": states,
            "surface": offered.evidence(),
            "agent_reads": reads.iter().map(Reply::evidence).collect::<Vec<_>>(),
        })
    });
}

/// The slash command, the interrupt, the queued prompt and, where the agent steers, the steering
/// prompt, each typed from the device with the person's login: the real arm of part 2a.
fn drives_the_controls(
    ctx: &Context,
    real: &Real,
    session: &Session<'_>,
    typing: &mut Typing<'_>,
) -> serde_json::Value {
    let account = &real.account;
    let person = &session.person;
    let mut turns = Turns::new(ctx, real, "2a");
    // A slash command that calls no model.
    typing.types(&account.slash.input);
    std::thread::sleep(Duration::from_millis(300));
    typing.types(&account.submit);
    let slash = person.sees(&account.slash.shows, "the slash command shows its screen");
    if !account.dismiss.is_empty() {
        typing.types(&account.dismiss);
        // Keys typed while the slash command's screen is still closing would go to it.
        person.stops_seeing(&account.slash.shows, "the slash command's screen closes");
    }
    person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "the composer is back after the slash command",
    );
    // An interrupt of a long turn, once its reply is on the screen.
    let mark = mark();
    let upper = mark.to_uppercase();
    let (long, reply_begins) = long_turn(&mark, account.reply_mark.as_deref());
    typing.submits(
        &mut turns,
        "a long turn to interrupt",
        &long,
        &format!("({mark}-i)"),
        &account.submit,
    );
    let _ = person.sees(&account.busy, "the turn runs");
    let _ = person.sees(&reply_begins, "the turn's reply begins");
    // An agent whose first press only arms the interrupt wants the key again, as a separate press.
    for press in 0..account.interrupt_presses.max(1) {
        if press > 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
        typing.types(&account.interrupt.input);
    }
    let interrupted = person.sees(&account.interrupt.shows, "the agent says the turn stopped");
    person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "the composer is back after the interrupt",
    );
    // The record exists once the interrupted prompt is in it; a prompt entered into a running turn
    // goes in as soon as the agent shows the turn running.
    let _ = waits_for_a_line(
        ctx,
        real,
        &[&format!("{mark}-i"), &account.prompt_line],
        "the interrupted prompt is recorded",
    );
    // A prompt entered while a turn runs, which waits for it.
    let (queued_question, queued_sum) = fresh_question(&[&mark]);
    let queued_done = format!("DONE-{upper}-Q");
    typing.submits(
        &mut turns,
        "a turn to queue behind",
        &counting_turn(&mark, "q", &queued_done),
        &format!("({mark}-q)"),
        &account.submit,
    );
    let _ = person.sees(&account.busy, "the first turn runs");
    let none = Duration::ZERO;
    let before_queue = turn_runs(ctx, real, person, None, &queued_done, none);
    let queue_key = account
        .queue_key
        .clone()
        .unwrap_or_else(|| account.submit.clone());
    typing.submits(
        &mut turns,
        "a prompt entered during the turn",
        &format!("({mark}-r) {queued_question}"),
        &format!("({mark}-r)"),
        &queue_key,
    );
    let after_queue = turn_runs(
        ctx,
        real,
        person,
        None,
        &queued_done,
        Duration::from_secs(2),
    );
    let _ = person.sees(&queued_sum, "the queued prompt is answered");
    person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "the composer is back after the queue",
    );
    settles(ctx, real, &[&queued_sum, &account.reply_line]);
    let text = record_text(ctx, real);
    let first_prompt = first_line_with(&text, None, &[&format!("{mark}-q"), &account.prompt_line]);
    let second_prompt = first_line_with(&text, None, &[&format!("{mark}-r"), &account.prompt_line]);
    let queued_record = account
        .queued_line
        .as_ref()
        .and_then(|marker| first_line_with(&text, first_prompt, &[&format!("{mark}-r"), marker]));
    let queue = Order {
        busy_at_submission: before_queue.holds()
            && if account.queued_line.is_some() {
                after_queue.unfinished
            } else {
                after_queue.holds()
            },
        before: before_queue,
        after: after_queue,
        records_queue: account.queued_line.is_some(),
        queued_record,
        first_finished: first_line_with(&text, first_prompt, &[&queued_done, &account.reply_line]),
        second_prompt,
        second_answered: first_line_with(&text, second_prompt, &[&queued_sum, &account.reply_line]),
        new_turn: first_prompt.and_then(|from| {
            turn_between(&text, from, second_prompt?, account.turn_line.as_deref()?)
        }),
    };
    let labels = [
        ("q", format!("{mark}-q")),
        ("r", format!("{mark}-r")),
        ("done", queued_done.clone()),
        ("sum", queued_sum.clone()),
        (
            "queued",
            account
                .queued_line
                .clone()
                .unwrap_or_else(|| "\u{0}".to_owned()),
        ),
        (
            "turn",
            account
                .turn_line
                .clone()
                .unwrap_or_else(|| "\u{0}".to_owned()),
        ),
    ];
    let outlined = |from: Option<usize>, text: &str| {
        let needles: Vec<(&str, &str)> = labels
            .iter()
            .map(|(label, needle)| (*label, needle.as_str()))
            .collect();
        outline(text, from, &needles)
    };
    // A fast model can finish the turn before the second prompt is entered, and a screen can fail
    // to show a turn that goes on: either way the turn was not shown to be running when the prompt
    // was entered, which is a cause of its own.
    assert!(
        queue.busy_at_submission,
        "the agent was not shown to be running its turn when the second prompt was entered: {}; \
         the record from the first prompt: {}",
        check_queued(&queue).err().unwrap_or_default(),
        outlined(first_prompt, &text)
    );
    check_queued(&queue).unwrap_or_else(|why| {
        panic!(
            "the prompt waited for the turn: {why}; the record from the first prompt: {}",
            outlined(first_prompt, &text)
        )
    });
    // Steering, where the agent's terminal route steers a running turn.
    let steering = if account.steers {
        let (steer_question, steer_sum) = fresh_question(&[&mark, &queued_sum]);
        let steered_done = format!("DONE-{upper}-S");
        typing.submits(
            &mut turns,
            "a turn to steer",
            &counting_turn(&mark, "s", &steered_done),
            &format!("({mark}-s)"),
            &account.submit,
        );
        let _ = person.sees(&account.busy, "the turn to steer runs");
        let before_steer = turn_runs(ctx, real, person, None, &steered_done, none);
        typing.submits(
            &mut turns,
            "a steering prompt",
            &format!("({mark}-t) Stop counting. {steer_question}"),
            &format!("({mark}-t)"),
            &account.submit,
        );
        // Where steering is a second step, the prompt waits, and its key goes once the screen says
        // it would steer.
        if let (Some(key), Some(ready)) = (&account.steer_key, &account.steer_ready) {
            let _ = person.sees(ready, "the prompt waits and can be steered");
            typing.types(key);
        }
        let after_steer = turn_runs(ctx, real, person, None, &steered_done, none);
        let _ = person.sees(&steer_sum, "the steered turn answers");
        person.waits_for_the_composer(
            &account.composer,
            &account.busy,
            "the composer is back after steering",
        );
        settles(ctx, real, &[&steer_sum, &account.reply_line]);
        let text = record_text(ctx, real);
        let steered_prompt =
            first_line_with(&text, None, &[&format!("{mark}-s"), &account.prompt_line]);
        // A steering prompt is a line of its own kind where the agent writes one.
        let steering_prompt = first_line_with(
            &text,
            None,
            &[
                &format!("{mark}-t"),
                account
                    .steer_line
                    .as_deref()
                    .unwrap_or(&account.prompt_line),
            ],
        );
        let steer = Order {
            busy_at_submission: before_steer.holds() && after_steer.unfinished,
            before: before_steer,
            after: after_steer,
            records_queue: false,
            queued_record: None,
            first_finished: first_line_with(
                &text,
                steered_prompt,
                &[&steered_done, &account.reply_line],
            ),
            second_prompt: steering_prompt,
            second_answered: first_line_with(
                &text,
                steering_prompt,
                &[&steer_sum, &account.reply_line],
            ),
            new_turn: steered_prompt.and_then(|from| {
                turn_between(&text, from, steering_prompt?, account.turn_line.as_deref()?)
            }),
        };
        check_steered(&steer).unwrap_or_else(|why| {
            panic!(
                "the running turn took the prompt: {why}; the record from its prompt: {}",
                outlined(steered_prompt, &text)
            )
        });
        serde_json::json!({ "steered": true, "order": steer })
    } else {
        serde_json::json!({ "steered": false, "why": "a prompt entered during a turn waits for it, as the queued step shows" })
    };
    let planned = if account.steers { 5 } else { 3 };
    turns_as_planned(turns.charged, turns.submitted, planned)
        .unwrap_or_else(|why| panic!("the turns of the part: {why}"));
    serde_json::json!({
        "arm": "pinned build",
        "login": account.login,
        "turns_charged": turns.charged,
        "slash": { "typed": account.slash.input, "shows": account.slash.shows, "seen": !slash.is_empty() },
        "interrupt": { "key": account.interrupt.input, "shows": account.interrupt.shows, "seen": !interrupted.is_empty() },
        "queued": { "answer": queued_sum, "order": queue },
        "steering": steering,
        "control": { "what": "orders made wrong on purpose, which the queue and steering checks reject", "breaks_property": false, "why_not": "the controls are the agent's own terminal keys, which only the agent could refuse, so the checks are shown wrong orders instead (the guard cases)" },
    })
}

/// A queued order that is right.
#[cfg(test)]
fn a_queued_order() -> Order {
    Order {
        busy_at_submission: true,
        before: Running {
            busy: true,
            unfinished: true,
        },
        after: Running {
            busy: true,
            unfinished: true,
        },
        records_queue: true,
        queued_record: Some(4),
        first_finished: Some(6),
        second_prompt: Some(8),
        second_answered: Some(10),
        new_turn: Some(true),
    }
}

/// A prompt that is not shown to be entered during a running turn, one that joined the record
/// before the turn finished, one the agent kept no record of as queued and one that joined the
/// running turn all fail the queue check.
#[test]
fn an_order_the_agent_could_not_have_queued_fails_the_queue_check_of_2a() {
    let right = a_queued_order();
    assert!(check_queued(&right).is_ok());
    assert!(
        check_queued(&Order {
            busy_at_submission: false,
            ..right
        })
        .is_err(),
        "entered with no turn running"
    );
    assert!(
        check_queued(&Order {
            second_prompt: right.first_finished.map(|line| line - 1),
            ..right
        })
        .is_err(),
        "the prompt joined before the turn finished"
    );
    assert!(
        check_queued(&Order {
            queued_record: None,
            ..right
        })
        .is_err(),
        "the agent kept no record of the prompt as queued"
    );
    assert!(
        check_queued(&Order {
            new_turn: Some(false),
            ..right
        })
        .is_err(),
        "the prompt joined the running turn"
    );
}

/// A steering prompt that started a turn of its own, one entered with no turn running and one that
/// came after the turn's work finished fail the steering check.
#[test]
fn an_order_the_agent_could_not_have_steered_fails_the_steer_check_of_2a() {
    let right = Order {
        records_queue: false,
        queued_record: None,
        first_finished: None,
        second_prompt: Some(8),
        second_answered: Some(10),
        new_turn: Some(false),
        ..a_queued_order()
    };
    assert!(check_steered(&right).is_ok());
    assert!(
        check_steered(&Order {
            new_turn: Some(true),
            ..right
        })
        .is_err(),
        "a turn started between the prompts"
    );
    assert!(
        check_steered(&Order {
            busy_at_submission: false,
            ..right
        })
        .is_err(),
        "entered with no turn running"
    );
    assert!(
        check_steered(&Order {
            new_turn: None,
            first_finished: Some(0),
            ..right
        })
        .is_err(),
        "the turn finished its work"
    );
}

/// A typed queue the package advertises as qualified and available fails the check of 2a, which
/// keeps it declared off.
#[test]
fn a_typed_queue_advertised_as_available_fails_the_check_of_2a() {
    let record = |capability: &str, state: &str| (capability.to_owned(), state.to_owned());
    assert!(queue_declared_off(&[record("agent.prompt.queue", "declared_off")]).is_ok());
    assert!(queue_declared_off(&[record("agent.prompt", "qualified_available")]).is_ok());
    assert!(queue_declared_off(&[]).is_ok());
    assert!(
        queue_declared_off(&[record("agent.prompt.queue", "qualified_available")]).is_err(),
        "the queue is advertised as qualified and available"
    );
}

/// A turn submitted with no charge before it, and a case whose charges are not its submissions or
/// not the planned number, fail the check of 2a.
#[test]
fn a_turn_submitted_without_its_charge_fails_the_check_of_2a() {
    assert!(charged_first(1, 1).is_ok());
    assert!(charged_first(2, 2).is_ok());
    assert!(charged_first(1, 2).is_err());
    assert!(charged_first(0, 1).is_err());
    assert!(turns_as_planned(5, 5, 5).is_ok());
    assert!(turns_as_planned(4, 5, 5).is_err());
    assert!(turns_as_planned(5, 4, 5).is_err());
    assert!(turns_as_planned(3, 3, 5).is_err());
}

// ---------------------------------------------------------------------------------------------
// Parts 7 and 7f: a second process on a saved conversation another process holds.
// ---------------------------------------------------------------------------------------------

/// How the agent's second start went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Started {
    /// Its first screen is the composer: the agent runs a second process.
    Running,
    /// Its start reached no composer, and the screen shows one of the texts the entry names for a
    /// refusal.
    Refused,
    /// Its start ended with the shell's prompt back and none of those texts.
    Ended,
}

/// What the agent did with a saved conversation another process holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taken {
    /// It would not run a second process on it.
    Refused,
    /// It continued the saved conversation: the second process's question is in the file the first
    /// one wrote, which two processes write now.
    Merged,
    /// It started a conversation of its own from the saved one: the question is in another file.
    Forked,
    /// Its start ended with no text that shows the held conversation was the cause.
    Ended,
}

impl Taken {
    /// The word the record names it by.
    const fn word(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Merged => "merged",
            Self::Forked => "forked",
            Self::Ended => "ended",
        }
    }
}

/// What the agent did, from how its start went and, where it ran, whether the second process's
/// question is in the file the first one wrote.
///
/// # Errors
///
/// Returns that a running second process left no answer to where its question was recorded.
fn taken(started: Started, same_file: Option<bool>) -> Result<Taken, String> {
    match (started, same_file) {
        (Started::Refused, _) => Ok(Taken::Refused),
        (Started::Ended, _) => Ok(Taken::Ended),
        (Started::Running, Some(true)) => Ok(Taken::Merged),
        (Started::Running, Some(false)) => Ok(Taken::Forked),
        (Started::Running, None) => Err(
            "the second process ran, and its question is in no file of the agent's record"
                .to_owned(),
        ),
    }
}

/// Whether what the agent did is what the part requires: part 7 passes where the agent refused or
/// continued the conversation (a start that ended with no text that says why shows nothing, and a
/// conversation of its own is what 7f is about); part 7f passes only where the agent forked.
///
/// # Errors
///
/// Returns what the part's check lacks.
fn check_taken(forks: bool, what: Taken) -> Result<(), String> {
    match (forks, what) {
        (false, Taken::Refused | Taken::Merged) | (true, Taken::Forked) => Ok(()),
        (false, Taken::Forked) => Err(
            "the agent started a conversation of its own from the saved one, which is what part \
             7f is about and not part 7"
                .to_owned(),
        ),
        (true, Taken::Refused | Taken::Merged) => Err(format!(
            "the agent {} the saved conversation, so two executions from one saved history were \
             not shown",
            what.word()
        )),
        (_, Taken::Ended) => Err(
            "the second start ended with the shell's prompt back and none of the texts the entry \
             names for a refusal, so what the agent did with the saved conversation was not shown"
                .to_owned(),
        ),
    }
}

/// Whether the marker typed into the second session is on its own screen and on the first's no
/// more than there: the two executions are kept apart.
///
/// # Errors
///
/// Returns where the marker is, or is not.
fn isolated(first: &[String], second: &[String], marker: &str) -> Result<(), String> {
    if !second.iter().any(|row| row.contains(marker)) {
        return Err("the marker typed into the second session is not on its own screen".to_owned());
    }
    if first.iter().any(|row| row.contains(marker)) {
        return Err(
            "the marker typed into the second session is on the first session's screen".to_owned(),
        );
    }
    Ok(())
}

/// Waits for the second start to end one way or the other, and says how: the composer, one of the
/// refusal texts, or the shell's prompt back below the typed command.
fn second_start(person: &Person, composer: &str, refusals: &[String]) -> (Started, Option<String>) {
    let started = Instant::now();
    loop {
        let rows = person.window.screen();
        if rows.iter().any(|row| row.contains(composer)) {
            return (Started::Running, None);
        }
        if let Some(text) = refusals
            .iter()
            .find(|text| rows.iter().any(|row| row.contains(text.as_str())))
        {
            return (Started::Refused, Some(text.clone()));
        }
        let last = rows.iter().rev().find(|row| !row.trim().is_empty());
        if last.is_some_and(|row| row.trim() == PROMPT.trim()) {
            return (Started::Ended, None);
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the second start neither reached the composer nor ended after {LIVENESS:?}; the \
             screen is:\n{}",
            rows.join("\n")
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The conversation the one file of the record that holds `mark` in a prompt line is: its
/// identifier (the member of its first line the entry names, else what its place says), how many
/// files the record holds, and the file's place.
fn saved_conversation(ctx: &Context, real: &Real, mark: &str) -> (String, usize, PathBuf) {
    let started = Instant::now();
    loop {
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        read_record(
            ctx.run.root(),
            ctx.run.pin(),
            &conversations_relative(&real.account),
            &mut |place, content| {
                files.push((
                    PathBuf::from(String::from_utf8_lossy(place).into_owned()),
                    String::from_utf8_lossy(content).into_owned(),
                ));
            },
        )
        .unwrap_or_else(|why| panic!("the agent's record is not whole: {why}"));
        let holding: Vec<&(PathBuf, String)> = files
            .iter()
            .filter(|(_, content)| {
                first_line_with(content, None, &[mark, &real.account.prompt_line]).is_some()
            })
            .collect();
        if let [(place, content)] = holding.as_slice() {
            let member = real
                .account
                .conversation_id_member
                .as_deref()
                .and_then(|member| {
                    let first: serde_json::Value =
                        serde_json::from_str(content.lines().next()?).ok()?;
                    first[member].as_str().map(str::to_owned)
                });
            return (
                member.unwrap_or_else(|| conversation_id(place)),
                files.len(),
                place.clone(),
            );
        }
        assert!(
            started.elapsed() < LIVENESS,
            "one file of the agent's record holds the code in a prompt line after {LIVENESS:?}, \
             and {} do",
            holding.len()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Whether the one file of the record that holds `needle` in a prompt line is the file at
/// `first`, the one session A's conversation was written to: the second process's question is
/// then in the file the first one wrote. `None` where no file or more than one holds it.
fn same_file(ctx: &Context, real: &Real, first: &Path, needle: &str) -> Option<bool> {
    let mut holding: Vec<PathBuf> = Vec::new();
    read_record(
        ctx.run.root(),
        ctx.run.pin(),
        &conversations_relative(&real.account),
        &mut |place, content| {
            let content = String::from_utf8_lossy(content);
            if first_line_with(&content, None, &[needle, &real.account.prompt_line]).is_some() {
                holding.push(PathBuf::from(String::from_utf8_lossy(place).into_owned()));
            }
        },
    )
    .unwrap_or_else(|why| panic!("the agent's record is not whole: {why}"));
    match holding.as_slice() {
        [place] => Some(place == first),
        _ => None,
    }
}

/// Part 7 or part 7f: session A holds a conversation, session B is started with the agent's
/// command on it, and what the agent did and what the host showed are recorded. `forks` is
/// whether the part is the one for the agent's fork command, which passes only when the agent
/// forked.
fn second_process(
    ctx: &Context,
    session: &Session<'_>,
    part: &str,
    forks: bool,
) -> serde_json::Value {
    let (a, b) = (seated(session, Seat::First), seated(session, Seat::Second));
    let agent_a = starts_by_hand(ctx, session, Seat::First, &[], true);
    let shown_a = detects(ctx, &a);
    detected(&agent_a, &shown_a, "session A's launch");
    let mut typing_a = Typing::attach(ctx, session, Seat::First);
    let mark = mark();
    let Route::Real(real) = &ctx.route else {
        return second_process_by_hand(ctx, session, forks, &agent_a, &shown_a, &mut typing_a);
    };
    let account = &real.account;
    // The command that starts the second process, with the conversation's identifier in it.
    let (question, sum) = fresh_question(&[&mark]);
    let mut turns = Turns::new(ctx, real, part);
    typing_a.submits(
        &mut turns,
        "a conversation to resume",
        &format!("({mark}) Remember the code {mark}. {question}"),
        &format!("({mark})"),
        &account.submit,
    );
    let _ = a.person.sees(&sum, "session A is answered");
    a.person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "session A is back at its composer",
    );
    let (conversation, files_before, first_place) = saved_conversation(ctx, real, &mark);
    let command = if forks {
        &account.fork
    } else {
        &account.resume
    };
    let words: Vec<String> = command
        .iter()
        .map(|word| word.replace("{conversation}", &conversation))
        .collect();
    let extra: Vec<&str> = words.iter().map(String::as_str).collect();
    // Session B: the agent's own command on the saved conversation. No `kr` runs: B's shell is open.
    b.person.clears_the_screen();
    ctx.checks_the_placed_files();
    real.checks_the_route(&ctx.run);
    b.person.types(&real.typed(&extra));
    let (started, refusal) = second_start(b.person, &account.composer, &account.resume_refused);
    let first_after = shown_now(ctx, &a);
    check_unchanged(Held::of(&shown_a), &first_after)
        .unwrap_or_else(|why| panic!("session A's instance and revision are as they were: {why}"));
    let mut evidence = serde_json::json!({
        "arm": arm(ctx),
        "login": account.login,
        "conversation": conversation,
        "files_before_the_second_start": files_before,
        "session_a": { "detection": shown_a.detection.evidence() },
        "session_b": { "started_with": words, "same_conversation": !forks },
    });
    if started != Started::Running {
        // The agent's start ended: the host shows no instance for it, and session A as it was.
        check_unchanged(None, &shown_now(ctx, &b)).unwrap_or_else(|why| {
            panic!("the refused start announces no instance of its own: {why}")
        });
        let what = taken(started, None).unwrap_or_else(|why| panic!("{why}"));
        evidence["resume"] = serde_json::json!({ "outcome": what.word(), "shown": refusal });
        evidence["control"] = serde_json::json!({ "what": "session B's marker typed into session A", "breaks_property": false, "why_not": "no second execution ran, so there was no second session to type a marker from" });
        check_taken(forks, what).unwrap_or_else(|why| panic!("{why}"));
        evidence["turns_charged"] = turns.charged.into();
        return evidence;
    }
    // A second process runs: the host detects it as an instance of its own.
    let agent_b = HandAgent::found(ctx, b.session_id);
    let shown_b = detects(ctx, &b);
    detected(&agent_b, &shown_b, "session B's launch");
    assert_ne!(
        Held::of(&shown_a).map(|held| held.instance),
        Held::of(&shown_b).map(|held| held.instance),
        "the two launches are two instances"
    );
    let mut typing_b = Typing::attach(ctx, session, Seat::Second);
    let (question_b, sum_b) = fresh_question(&[&mark, &sum]);
    let mark_b = format!("{mark}-b");
    typing_b.submits(
        &mut turns,
        "the second process's question",
        &format!("({mark_b}) {question_b}"),
        &format!("({mark_b})"),
        &account.submit,
    );
    let _ = b.person.sees(&sum_b, "session B is answered");
    b.person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "session B is back at its composer",
    );
    settles(ctx, real, &[&mark_b, &account.prompt_line]);
    let what = taken(started, same_file(ctx, real, &first_place, &mark_b))
        .unwrap_or_else(|why| panic!("{why}"));
    // Each session shows only its own marker, and A's binding is as it was.
    isolated(
        &a.person.window.screen(),
        &b.person.window.screen(),
        &mark_b,
    )
    .unwrap_or_else(|why| panic!("the two executions are kept apart: {why}"));
    check_unchanged(Held::of(&shown_a), &shown_now(ctx, &a))
        .unwrap_or_else(|why| panic!("session A's instance and revision are as they were: {why}"));
    // The control breaks the property: B's marker typed into A's session, and the check fails.
    typing_a.types(&mark_b);
    let _ = a.person.sees(
        &mark_b,
        "session A's composer shows the marker typed into it",
    );
    let control = isolated(
        &a.person.window.screen(),
        &b.person.window.screen(),
        &mark_b,
    );
    assert!(
        control.is_err(),
        "the isolation check fails with B's marker typed into A"
    );
    typing_a.types(&account.clear);
    agent_a
        .runs()
        .and(agent_b.runs())
        .unwrap_or_else(|why| panic!("both executions go on: {why}"));
    evidence["resume"] = serde_json::json!({ "outcome": what.word() });
    evidence["session_b"]["detection"] = shown_b.detection.evidence();
    evidence["turns_charged"] = turns.charged.into();
    evidence["control"] = serde_json::json!({ "what": "session B's marker typed into session A", "breaks_property": true, "check": control.err() });
    check_taken(forks, what).unwrap_or_else(|why| panic!("{why}"));
    turns_as_planned(turns.charged, turns.submitted, 2)
        .unwrap_or_else(|why| panic!("the turns of the part: {why}"));
    evidence
}

/// The stand-in arm of parts 7 and 7f: the stand-in saves no conversation and has no model, so the
/// case shows the two executions the agent's `resume` or `fork` makes of it by hand, and what the
/// host shows of them, and not what the agent did with the saved conversation.
fn second_process_by_hand(
    ctx: &Context,
    session: &Session<'_>,
    forks: bool,
    agent_a: &HandAgent,
    shown_a: &Shown,
    typing_a: &mut Typing<'_>,
) -> serde_json::Value {
    let (a, b) = (seated(session, Seat::First), seated(session, Seat::Second));
    let word = if forks { "fork" } else { "resume" };
    let agent_b = starts_by_hand(
        ctx,
        session,
        Seat::Second,
        &[word, STAND_IN_CONVERSATION],
        false,
    );
    let shown_b = detects(ctx, &b);
    detected(&agent_b, &shown_b, "session B's launch");
    assert_ne!(
        Held::of(shown_a).map(|held| held.instance),
        Held::of(&shown_b).map(|held| held.instance),
        "the two launches are two instances"
    );
    let mut typing_b = Typing::attach(ctx, session, Seat::Second);
    let marker = format!("{}-b", mark());
    typing_b.types(&marker);
    let _ = b
        .person
        .sees(&marker, "session B's composer shows what was typed");
    isolated(
        &a.person.window.screen(),
        &b.person.window.screen(),
        &marker,
    )
    .unwrap_or_else(|why| panic!("the two executions are kept apart: {why}"));
    check_unchanged(Held::of(shown_a), &shown_now(ctx, &a))
        .unwrap_or_else(|why| panic!("session A's instance and revision are as they were: {why}"));
    // The control breaks the property: B's marker typed into A's session, and the check fails.
    typing_a.types(&marker);
    let _ = a.person.sees(
        &marker,
        "session A's composer shows the marker typed into it",
    );
    let control = isolated(
        &a.person.window.screen(),
        &b.person.window.screen(),
        &marker,
    );
    assert!(
        control.is_err(),
        "the isolation check fails with B's marker typed into A"
    );
    agent_a
        .runs()
        .and(agent_b.runs())
        .unwrap_or_else(|why| panic!("both executions go on: {why}"));
    serde_json::json!({
        "arm": arm(ctx),
        "session_a": { "detection": shown_a.detection.evidence() },
        "session_b": { "started_with": [word, STAND_IN_CONVERSATION], "detection": shown_b.detection.evidence() },
        "turns_charged": 0,
        "why_not": "the stand-in saves no conversation and has no model, so what the agent does with a saved conversation is the pinned build's to show",
        "control": { "what": "session B's marker typed into session A", "breaks_property": true, "check": control.err() },
    })
}

/// KR-REQ-12.32, case 7, part 7: with the person's login, session A holds a conversation with a
/// marker, and session B starts the agent's ordinary resume command on the same saved
/// conversation. The record names what the agent did: refused to run a second process on it, or
/// continued the conversation both write now (merged); a conversation of its own is what part 7f
/// is about and fails this part. Where the agent runs a second process on the conversation, the host
/// keeps the two apart as two live executions: it detects each launch as its own instance, marked
/// input to one never reaches the other, and A's binding revision stays as it was; where the agent
/// refuses, the host shows no instance for the refused start and A as it was. The control breaks the
/// property: B's marker typed into A's session, and the isolation check fails on it.
#[test]
fn gateway_a_second_process_on_the_same_saved_conversation_is_another_execution_not_merged() {
    const TEST: &str =
        "gateway_a_second_process_on_the_same_saved_conversation_is_another_execution_not_merged";
    by_hand_login_case(
        "7",
        TEST,
        Setup {
            second: true,
            ..Setup::default()
        },
        "by-hand",
        |ctx, session| second_process(ctx, session, "7", false),
    );
}

/// KR-REQ-12.32, case 7, part 7f: as part 7, with the agent's own command that starts a
/// conversation of its own from a saved one (its `fork`). Session B answers from the saved
/// conversation's history under an identifier of its own, in a file of its own, and the host keeps
/// the two apart as two live executions as part 7 requires. A real route whose entry names no such
/// command is not run, with no charge.
#[test]
fn gateway_a_forked_conversation_is_another_execution_with_a_conversation_of_its_own() {
    const TEST: &str =
        "gateway_a_forked_conversation_is_another_execution_with_a_conversation_of_its_own";
    by_hand_login_case(
        "7f",
        TEST,
        Setup {
            second: true,
            ..Setup::default()
        },
        "by-hand",
        |ctx, session| {
            if let Route::Real(real) = &ctx.route
                && real.account.fork.is_empty()
            {
                return serde_json::json!({
                    "arm": arm(ctx),
                    "not_run": "the entry names no command of the agent's that starts a conversation of its own from a saved one",
                    "turns_charged": 0,
                });
            }
            second_process(ctx, session, "7f", true)
        },
    );
}

/// A marker on the second session's screen and on the first's too, one on neither and one on the
/// first's only fail the isolation check of part 7.
#[test]
fn a_marker_that_two_sessions_show_fails_the_isolation_check_of_7() {
    let rows = |text: &str| vec!["kr-session$ ".to_owned(), text.to_owned()];
    assert!(isolated(&rows("nothing"), &rows("> krabc-b"), "krabc-b").is_ok());
    assert!(
        isolated(&rows("> krabc-b"), &rows("> krabc-b"), "krabc-b").is_err(),
        "the first session shows it too"
    );
    assert!(
        isolated(&rows("nothing"), &rows("nothing"), "krabc-b").is_err(),
        "the second session does not show it"
    );
    assert!(
        isolated(&rows("> krabc-b"), &rows("nothing"), "krabc-b").is_err(),
        "only the first session shows it"
    );
}

/// A resume that started a conversation of its own, and one whose start ended with no text that
/// says why, fail part 7; a start that ran and left no record of its question is no answer.
#[test]
fn an_ordinary_resume_that_forked_or_ended_with_no_reason_fails_the_check_of_7() {
    assert!(check_taken(false, taken(Started::Refused, None).unwrap()).is_ok());
    assert!(check_taken(false, taken(Started::Running, Some(true)).unwrap()).is_ok());
    assert!(
        check_taken(false, taken(Started::Running, Some(false)).unwrap()).is_err(),
        "a conversation of its own is part 7f's"
    );
    assert!(
        check_taken(false, taken(Started::Ended, None).unwrap()).is_err(),
        "an end with no reason shows nothing"
    );
    assert!(
        taken(Started::Running, None).is_err(),
        "a question recorded in no file is no answer"
    );
}

/// A fork the agent refused or merged, and a start that ended with no text that says why, fail part
/// 7f.
#[test]
fn a_fork_that_the_agent_refused_or_merged_fails_the_check_of_7f() {
    assert!(check_taken(true, taken(Started::Running, Some(false)).unwrap()).is_ok());
    assert!(
        check_taken(true, taken(Started::Refused, None).unwrap()).is_err(),
        "a refused fork shows no second history"
    );
    assert!(
        check_taken(true, taken(Started::Running, Some(true)).unwrap()).is_err(),
        "a merged fork is not a conversation of its own"
    );
    assert!(
        check_taken(true, taken(Started::Ended, None).unwrap()).is_err(),
        "an end with no reason shows nothing"
    );
}
