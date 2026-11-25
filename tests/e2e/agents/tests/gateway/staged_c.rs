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
use kr_e2e_m1b::window::Quiet;

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
fn package_actions(subject: &Subject) -> Vec<Action> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            subject
                .package()
                .expect("the subject's package")
                .join("plugin.json"),
        )
        .expect("the package's manifest"),
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
                &ctx.subject.typed_line(extra),
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
            if first_start {
                says_when_no_draft_is_named(&real.account);
            }
            at.person.waits_for_the_start_draft_to_end(
                &real.account.composer,
                &real.account.draft,
                "the agent reaches its composer",
            );
            // The driver skips this switch for a start by hand: the build list's request for a
            // run that stops before any turn is honoured here, with the agent up and nothing
            // charged.
            assert!(
                !real.account.stop_before_turns,
                "the build list asks to stop before any turn: the agent is up as it asks and no \
                 turn was started"
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
        live_bindings: live_bindings(remote, &ctx.runtime, &ctx.subject.plugin()),
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
fn detected(ctx: &Context, agent: &HandAgent, shown: &Shown, what: &str) {
    let launched = Launched {
        plugin_id: ctx.subject.plugin(),
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
    let upstream: Vec<Action> = package_actions(&ctx.subject)
        .into_iter()
        .filter(Action::upstream)
        .collect();
    let answers = typed_actions(
        at.remote,
        &ctx.runtime,
        at.session_id,
        &ctx.subject.plugin(),
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

/// Whether the host took every one of the `length` bytes typed: each forwarded to the terminal, or
/// held as the start of a bracketed-paste delimiter, as a lone Escape is while the terminal takes
/// pastes (the worker forwards it once its short deadline passes), which the agent's interrupt key
/// is.
///
/// # Errors
///
/// Returns how many bytes were taken.
fn bytes_taken(forwarded: u64, held: u64, length: u64) -> Result<(), String> {
    if forwarded.saturating_add(held) >= length {
        Ok(())
    } else {
        Err(format!(
            "{forwarded} byte(s) forwarded and {held} held of the {length} typed"
        ))
    }
}

/// A lone Escape that the worker holds for its deadline is taken, as the interrupt key is, and a
/// byte that was neither forwarded nor held is not.
#[test]
fn a_byte_neither_forwarded_nor_held_is_not_taken_and_a_held_escape_is() {
    assert!(bytes_taken(1, 0, 1).is_ok());
    assert!(bytes_taken(0, 1, 1).is_ok());
    assert!(bytes_taken(5, 0, 7).is_err());
    assert!(bytes_taken(5, 1, 7).is_err());
    assert!(bytes_taken(6, 1, 7).is_ok());
    assert!(bytes_taken(0, 0, 1).is_err());
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
        bytes_taken(
            written.forwarded_bytes.get(),
            written.held_prefix_bytes.get(),
            u64::try_from(text.len()).unwrap_or(u64::MAX),
        )
        .unwrap_or_else(|why| panic!("{why}"));
    }

    /// Where a dialog of the agent's is on the screen, the command's or any other it asks (network
    /// access, edits, permissions, input), a typed letter or the key that submits would be taken as
    /// a choice, which may approve it: the dialog is refused with its own key and the case stops.
    fn no_dialog(&mut self, real: &Real, when: &str) {
        let approval = &real.account.approval;
        let rows = self.at.person.window.screen();
        if let Some((shown, key)) = dialog_on(
            &rows,
            &approval.shows,
            &approval.others,
            &approval.deny,
            approval.refusal(),
        ) {
            let (shown, key) = (shown.to_owned(), key.to_owned());
            self.types(&key);
            panic!(
                "a dialog showing {shown:?} was on the screen {when}, so no prompt or key that \
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

/// The dialog of the agent's that `rows` show, with the key that refuses it: the command dialog
/// (`shows`) with the agent's own key (`deny`), and each of the other requests the agent asks
/// (`others`; none is ever allowed) with the key that refuses any request (`refusal`).
fn dialog_on<'a>(
    rows: &[String],
    shows: &'a str,
    others: &'a [String],
    deny: &'a str,
    refusal: &'a str,
) -> Option<(&'a str, &'a str)> {
    std::iter::once((shows, deny))
        .chain(others.iter().map(|other| (other.as_str(), refusal)))
        .find(|(text, _)| !text.is_empty() && rows.iter().any(|row| row.contains(text)))
}

/// A dialog is found whether it is the command's or any other the entry names, and each is refused
/// with its own key; a screen with none shows none.
#[test]
fn a_dialog_the_entry_names_is_found_and_refused_with_its_own_key() {
    let rows = |text: &str| vec!["a row".to_owned(), text.to_owned()];
    let others = ["Allow network access".to_owned(), "Allow edits".to_owned()];
    let found = |screen: &[String]| dialog_on(screen, "Allow command", &others, "d", "n");
    assert_eq!(
        found(&rows("Allow command? (y/n)")),
        Some(("Allow command", "d"))
    );
    assert_eq!(
        found(&rows("Allow network access?")),
        Some(("Allow network access", "n"))
    );
    assert_eq!(
        found(&rows("Allow edits to a.txt")),
        Some(("Allow edits", "n"))
    );
    assert_eq!(found(&rows("ask me anything")), None);
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
        detected(ctx, &agent, &shown, "the agent's launch");
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
        let states = capability_states(at.remote, &ctx.runtime, &ctx.subject.plugin());
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
    /// The screen shows one of the texts the entry names for a refusal: the agent ended, or, as
    /// Codex does, went on running with the conversation open read-only and a notice in place of
    /// the composer.
    Refused,
    /// Its start ended, with the shell's prompt back below the typed line or with the agent's
    /// process gone, and none of those texts.
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

/// What the agent did, from how its start went and, where it ran, where the second process's
/// question was recorded: in the file the first process wrote or not, and under the first
/// process's conversation identifier or not. The two must agree: a question in another file that
/// carries the first conversation's identifier is a copy of it, and a question in the first file
/// under another identifier is not a continuation.
///
/// # Errors
///
/// Returns that a running second process left no answer to where its question was recorded, or
/// that the file and the identifier disagree.
fn taken(
    started: Started,
    same_file: Option<bool>,
    same_identifier: Option<bool>,
) -> Result<Taken, String> {
    match (started, same_file, same_identifier) {
        (Started::Refused, _, _) => Ok(Taken::Refused),
        (Started::Ended, _, _) => Ok(Taken::Ended),
        (Started::Running, Some(true), Some(true)) => Ok(Taken::Merged),
        (Started::Running, Some(false), Some(false)) => Ok(Taken::Forked),
        (Started::Running, Some(file), Some(identifier)) => Err(format!(
            "the second process's question is {} the first conversation's file and {} its \
             identifier, which do not say the same thing",
            if file { "in" } else { "not in" },
            if identifier { "under" } else { "not under" }
        )),
        (Started::Running, _, _) => Err(
            "the second process ran, and its question is in no file of the agent's record, or in \
             more than one"
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
            "the second start ended with none of the entry's refusal texts on the screen, so the \
             screen did not show what the agent did with the saved conversation"
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

/// Whether the shell's prompt is back below the typed line: a row below the last row that shows the
/// line `typed` is the prompt alone. The prompt that stood on the screen before the line's echo
/// came back is no end, and neither is the echo with nothing below it.
fn prompt_back(rows: &[String], typed: &str) -> bool {
    rows.iter()
        .rposition(|row| row.contains(typed))
        .is_some_and(|echo| {
            rows[echo + 1..]
                .iter()
                .any(|row| row.trim() == PROMPT.trim())
        })
}

/// The prompt that stood on the screen before the typed line's echo came back is no end of the
/// start, nor is the echo with nothing below it; the prompt below the echo is.
#[test]
fn the_old_shell_prompt_is_no_end_of_the_second_start_and_the_prompt_below_the_echo_is() {
    let typed = "codex resume 0123-4567";
    let screen = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    assert!(
        !prompt_back(&screen(&["kr-session$ "]), typed),
        "the prompt that was on the screen before the echo came back is no end"
    );
    assert!(
        !prompt_back(&screen(&["kr-session$ codex resume 0123-4567"]), typed),
        "the echo with nothing below it is no end"
    );
    assert!(
        prompt_back(
            &screen(&[
                "kr-session$ codex resume 0123-4567",
                "no such conversation",
                "kr-session$ "
            ]),
            typed
        ),
        "the prompt below the echo is an end"
    );
}

/// How the second start stands on `rows`, or `None` while it stands nowhere yet. One of the texts
/// the entry names for a refusal is a refusal, whether the process went on running or not (Codex
/// shows a card, "This conversation is open in another app", in place of the composer and keeps
/// the conversation read-only). The composer with the start done is a running continuation or
/// fork; the composer beside one of the entry's draft texts (Codex's `Resuming session…` and
/// `Forking session…`) is the startup draft, which is drawn for a start that ends read-only as
/// for one that goes on, and says nothing yet. The shell's prompt
/// below the typed line's echo is an end, and so is the end of the agent's own process, which
/// needs no echo of the typed line: the echo wraps, scrolls off or is cleared, and the start is
/// still over. The process's end comes after the card's words, which an agent that printed them
/// and ended leaves on the screen, and before the composer, which an ended agent leaves too.
fn second_screen(
    rows: &[String],
    typed: &str,
    composer: &str,
    refusals: &[String],
    draft: &[String],
    agent_ended: bool,
) -> Option<(Started, Option<String>)> {
    if let Some(text) = refusals
        .iter()
        .find(|text| rows.iter().any(|row| row.contains(text.as_str())))
    {
        return Some((Started::Refused, Some(text.clone())));
    }
    if agent_ended {
        return Some((Started::Ended, None));
    }
    if rows.iter().any(|row| row.contains(composer)) {
        return if draft_showing(rows, composer, draft).is_some() {
            None
        } else {
            Some((Started::Running, None))
        };
    }
    prompt_back(rows, typed).then_some((Started::Ended, None))
}

/// The card that says the conversation is open in another app is a refusal where the entry names
/// its words, the startup composer beside "Resuming session…" or "Forking session…" is no answer
/// yet, and the composer with the start done is a continuation.
#[test]
fn a_card_is_a_refusal_the_startup_composer_is_no_answer_and_a_resumed_composer_is_a_continuation()
{
    let screen = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    let typed = "codex resume 0123-4567";
    let composer = "Ask Codex to do anything";
    let refusals = [
        "This conversation is open in another app".to_owned(),
        "Close it there and press R to continue here.".to_owned(),
    ];
    let draft = [
        "Resuming session…".to_owned(),
        "Forking session…".to_owned(),
    ];
    let card = screen(&[
        "kr-session$ codex resume 0123-4567",
        "> (kr1) Remember the code kr1.",
        "  This conversation is open in another app  R to Retry",
        "  Close it there and press R to continue here.",
    ]);
    assert_eq!(
        second_screen(&card, typed, composer, &refusals, &draft, false),
        Some((
            Started::Refused,
            Some("This conversation is open in another app".to_owned())
        ))
    );
    let resume_draft = screen(&[
        "kr-session$ codex resume 0123-4567",
        "  Resuming session…",
        "> Ask Codex to do anything",
    ]);
    assert_eq!(
        second_screen(&resume_draft, typed, composer, &refusals, &draft, false),
        None
    );
    let fork_draft = screen(&[
        "kr-session$ codex fork 0123-4567",
        "  Forking session…",
        "> Ask Codex to do anything",
    ]);
    assert_eq!(
        second_screen(&fork_draft, typed, composer, &refusals, &draft, false),
        None,
        "the fork's startup composer, beside Forking session…, is no running fork"
    );
    let resumed = screen(&[
        "kr-session$ codex resume 0123-4567",
        "> (kr1) Remember the code kr1.",
        "> Ask Codex to do anything",
    ]);
    assert_eq!(
        second_screen(&resumed, typed, composer, &refusals, &draft, false),
        Some((Started::Running, None))
    );
}

/// A start whose process has ended is an end whatever the screen shows of the typed line: the echo
/// wrapped over two rows, scrolled off, or cleared by the agent leaves no prompt below it to find,
/// and the start is still over. A card's words that stand on the screen of an agent that has ended
/// are still a refusal, and a start whose process runs and shows nothing yet is no end.
#[test]
fn a_start_whose_process_ended_is_an_end_whatever_the_screen_shows_of_the_typed_line() {
    let screen = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    let typed = "codex resume 0123-4567";
    let composer = "Ask Codex to do anything";
    let refusals = ["This conversation is open in another app".to_owned()];
    let read =
        |rows: &[String], ended: bool| second_screen(rows, typed, composer, &refusals, &[], ended);
    let wrapped = screen(&[
        "kr-session$ codex resume 0123-",
        "4567",
        "no such conversation",
    ]);
    assert_eq!(
        read(&wrapped, true),
        Some((Started::Ended, None)),
        "an echo wrapped over two rows leaves no prompt below it, and the process has ended"
    );
    let cleared = screen(&["", ""]);
    assert_eq!(
        read(&cleared, true),
        Some((Started::Ended, None)),
        "a screen the agent cleared shows no echo, and the process has ended"
    );
    assert_eq!(
        read(&cleared, false),
        None,
        "a start whose process runs and shows nothing yet is no end"
    );
    let card = screen(&["  This conversation is open in another app"]);
    assert_eq!(
        read(&card, true),
        Some((
            Started::Refused,
            Some("This conversation is open in another app".to_owned())
        )),
        "a card on the screen of an agent that has ended is still a refusal"
    );
    let stale = screen(&["> Ask Codex to do anything"]);
    assert_eq!(
        read(&stale, true),
        Some((Started::Ended, None)),
        "a composer on the screen of an agent that has ended is no running agent"
    );
}

/// The agent's process below the worker of `session_id` now: one read of the process table, or why
/// the table could not be read.
fn agent_now(ctx: &Context, session_id: SessionId) -> Result<Option<ProcessStartIdentity>, String> {
    let worker =
        u32::try_from(ctx.run.worker_of(&session_id.to_string()).pid.get()).expect("a pid");
    process_mapping_once(worker, inode_of(&ctx.executable), None).map_err(|why| why.to_string())
}

/// What a part says when the process table could not be read for the agent's process: a read that
/// failed, which is not a read that found nothing.
fn process_not_looked_for(why: &str) -> String {
    format!("the agent's process could not be looked for: {why}")
}

/// A failed read of the process table is said to be one that could not look, not one that did not.
#[test]
fn a_failed_read_of_the_process_table_says_the_agents_process_could_not_be_looked_for() {
    assert_eq!(
        process_not_looked_for("ps did not end"),
        "the agent's process could not be looked for: ps did not end"
    );
}

/// How long the window must have taken no byte, after the agent's process is seen to end, before the
/// screen is read: what the agent wrote just before its end can still be on its way to the window.
const QUIET: Duration = Duration::from_millis(500);

/// Whether the screen can be read as the last the agent drew: while the agent's process runs, the
/// screen is as far as the window has taken what it drew; once it has ended, only when the window
/// has taken no byte for [`QUIET`] since the end was seen, or its output has ended (nothing more
/// can come).
const fn last_drawn(agent_ended: bool, window_quiet: bool) -> bool {
    !agent_ended || window_quiet
}

/// What one poll of a second start has seen: whether the agent's process has ended, how many bytes
/// the window has taken as of `now`, whether its output has ended, and whether its reader failed.
#[derive(Clone, Copy)]
struct Look {
    agent_ended: bool,
    mark: usize,
    now: Instant,
    output_ended: bool,
    reader_failed: bool,
}

/// What the polls of a second start have seen since the first of them saw the agent's process end:
/// the window's quiet count, and how many bytes the window had taken when that count began.
struct EndSeen {
    quiet: Quiet,
    mark: usize,
}

/// One poll of a second start: the screen is read only once it can be read as the last the agent
/// drew ([`last_drawn`]), and judged by [`second_screen`]. `screen` reads it. `end` is where the
/// poll that first sees the agent's process end starts the window's quiet count. A window whose
/// reader failed has not taken all the agent drew, so its screen is not judged: the poll gives
/// [`reader_failed_text`] with that screen, whether or not the agent runs.
fn second_poll(
    end: &mut Option<EndSeen>,
    look: Look,
    screen: impl FnOnce() -> Vec<String>,
    typed: &str,
    composer: &str,
    refusals: &[String],
    draft: &[String],
) -> Result<Option<(Started, Option<String>)>, String> {
    if look.reader_failed {
        return Err(reader_failed_text(&screen()));
    }
    let window_quiet = look.agent_ended && {
        end.get_or_insert_with(|| EndSeen {
            quiet: Quiet::new(look.mark, look.now),
            mark: look.mark,
        })
        .quiet
        .is_quiet(look.mark, look.now, QUIET)
            || look.output_ended
    };
    if !last_drawn(look.agent_ended, window_quiet) {
        return Ok(None);
    }
    Ok(second_screen(
        &screen(),
        typed,
        composer,
        refusals,
        draft,
        look.agent_ended,
    ))
}

/// The text of the second start's failure when the window's reader failed, with the screen.
fn reader_failed_text(screen: &[String]) -> String {
    let screen = screen.join("\n");
    format!(
        "the second start was not judged: the window's reader failed with an unknown number of \
         bytes not taken, so the screen may lack the last of what the agent drew; the screen \
         is:\n{screen}"
    )
}

/// A refusal printed just before the agent's process ends reaches the window after the end is
/// seen: the screen is read only once the window has been quiet, and the one read then shows the
/// refusal, not an end with none of the entry's texts on the screen.
#[test]
fn a_refusal_printed_just_before_the_agents_end_is_read_once_the_window_is_quiet() {
    let screen = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    let typed = "codex resume 0123-4567";
    let composer = "Ask Codex to do anything";
    let refusals = ["This conversation is open in another app".to_owned()];
    let before = screen(&["kr-session$ codex resume 0123-4567", "  Resuming session…"]);
    let after = screen(&[
        "kr-session$ codex resume 0123-4567",
        "  This conversation is open in another app",
    ]);
    // The end is seen at 0 ms; the card's bytes reach the window at 300 ms, behind the end.
    let start = Instant::now();
    let mut end: Option<EndSeen> = None;
    let reads = std::cell::Cell::new(0_u32);
    let mut read = None;
    for at in (0..=2000_u64).step_by(50) {
        let look = Look {
            agent_ended: true,
            mark: if at < 300 { 100 } else { 160 },
            now: start + Duration::from_millis(at),
            output_ended: false,
            reader_failed: false,
        };
        let rows = if at < 300 { &before } else { &after };
        let polled = second_poll(
            &mut end,
            look,
            || {
                reads.set(reads.get() + 1);
                rows.clone()
            },
            typed,
            composer,
            &refusals,
            &[],
        )
        .expect("a window whose reader runs is judged");
        if polled.is_some() {
            read = Some((at, polled));
            break;
        }
        assert_eq!(
            reads.get(),
            0,
            "no screen is read at {at} ms, before the window is quiet"
        );
    }
    let (at, how) = read.expect("the window goes quiet");
    assert_eq!(
        how,
        Some((
            Started::Refused,
            Some("This conversation is open in another app".to_owned())
        )),
        "the screen read at {at} ms, after the end, has the card the agent printed before it"
    );
    assert!(
        at >= 300 + 500,
        "{at} ms: the read waits for {QUIET:?} of no byte"
    );
    assert_eq!(reads.get(), 1, "the screen is read once");
    assert_eq!(
        end.map(|end| end.mark),
        Some(100),
        "the count's mark is the window's as of the poll that first saw the end, not as of the \
         bytes that came after"
    );
    assert!(
        last_drawn(false, false),
        "a screen read while the agent runs is as far as the window has taken it"
    );
    assert!(
        !last_drawn(true, false),
        "a screen read after the end, with bytes still arriving, is not the last"
    );
}

/// A window whose reader failed has not taken all the agent drew: the second start fails with the
/// screen it has, whether the agent runs or has ended and whether or not the window is quiet, even
/// where the screen alone would be judged.
#[test]
fn a_reader_error_fails_the_second_start_with_the_screen_it_ended_with() {
    let rows = vec![
        "kr-session$ codex resume 0123-4567".to_owned(),
        "> Ask Codex to do anything".to_owned(),
    ];
    let refusals = ["This conversation is open in another app".to_owned()];
    let now = Instant::now();
    for (agent_ended, output_ended) in [(false, false), (true, false), (true, true)] {
        let reads = std::cell::Cell::new(0_u32);
        let look = Look {
            agent_ended,
            mark: 100,
            now,
            output_ended,
            reader_failed: true,
        };
        let polled = second_poll(
            &mut None,
            look,
            || {
                reads.set(reads.get() + 1);
                rows.clone()
            },
            "codex resume 0123-4567",
            "Ask Codex to do anything",
            &refusals,
            &[],
        );
        assert_eq!(
            polled,
            Err(reader_failed_text(&rows)),
            "a reader error fails the poll (agent ended {agent_ended}, output ended {output_ended})"
        );
        assert_eq!(reads.get(), 1, "the screen is read once, for the text");
    }
    assert_eq!(
        reader_failed_text(&rows),
        "the second start was not judged: the window's reader failed with an unknown number of \
         bytes not taken, so the screen may lack the last of what the agent drew; the screen \
         is:\nkr-session$ codex resume 0123-4567\n> Ask Codex to do anything",
        "the text says the reader failed and gives the screen"
    );
}

/// The screen of an agent whose process runs is read at once, and so is the screen of one that has
/// ended once the window's output has ended; the composer of an ended agent is no running agent.
#[test]
fn a_running_agents_screen_and_an_ended_windows_output_are_read_at_once() {
    let rows = vec![
        "kr-session$ codex resume 0123-4567".to_owned(),
        "> Ask Codex to do anything".to_owned(),
    ];
    let refusals = ["This conversation is open in another app".to_owned()];
    let poll = |agent_ended: bool, output_ended: bool| {
        let reads = std::cell::Cell::new(0_u32);
        let look = Look {
            agent_ended,
            mark: 100,
            now: Instant::now(),
            output_ended,
            reader_failed: false,
        };
        let mut end = None;
        let how = second_poll(
            &mut end,
            look,
            || {
                reads.set(reads.get() + 1);
                rows.clone()
            },
            "codex resume 0123-4567",
            "Ask Codex to do anything",
            &refusals,
            &[],
        )
        .expect("a window whose reader runs is judged");
        (how, reads.get(), end.map(|end: EndSeen| end.mark))
    };
    assert_eq!(
        poll(false, false),
        (Some((Started::Running, None)), 1, None),
        "the screen of an agent that runs is read at once, and no end is counted from"
    );
    assert_eq!(
        poll(true, false),
        (None, 0, Some(100)),
        "the screen of an agent that has ended waits for the window to be quiet, counted from the \
         mark of the poll that saw the end"
    );
    assert_eq!(
        poll(true, true),
        (Some((Started::Ended, None)), 1, Some(100)),
        "a window whose output has ended is read at once, and an ended agent's composer is no running agent"
    );
}

/// Waits for the second start of the agent in `at` to end one way or the other, and says how, by
/// [`second_screen`], with the agent's process where it was seen: the process below the session's
/// worker that maps the agent's file is looked for until it is seen, and its end is read before
/// each read of the screen. Once it has ended the screen is read only when the window has taken no
/// byte for [`QUIET`] since the end was seen, so that the screen it is judged with is the last the
/// agent drew, unless the agent's bytes are held on the way for longer than that. A window whose
/// reader failed fails the part with its screen.
fn second_start(
    ctx: &Context,
    at: &Seated<'_>,
    typed: &str,
    composer: &str,
    refusals: &[String],
    draft: &[String],
) -> (Started, Option<String>, Option<ProcessStartIdentity>) {
    let mut agent: Option<ProcessStartIdentity> = None;
    let mut end: Option<EndSeen> = None;
    let started = Instant::now();
    loop {
        if agent.is_none() {
            agent = agent_now(ctx, at.session_id)
                .unwrap_or_else(|why| panic!("{}", process_not_looked_for(&why)));
        }
        let window = &at.person.window;
        let look = Look {
            agent_ended: agent.as_ref().is_some_and(|identity| !running(identity)),
            mark: window.mark(),
            now: Instant::now(),
            output_ended: window.output_ended(),
            reader_failed: window.reader_failed(),
        };
        if let Some((how, shown)) = second_poll(
            &mut end,
            look,
            || window.screen(),
            typed,
            composer,
            refusals,
            draft,
        )
        .unwrap_or_else(|text| panic!("{text}"))
        {
            return (how, shown, agent);
        }
        assert!(
            started.elapsed() < LIVENESS,
            "{}",
            second_start_timeout(
                agent.as_ref().map(running),
                end.as_ref().map(|end| end.mark),
                window.mark(),
                &window.screen()
            )
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The text of the second start's failure at its time bound, from how the agent's process stands as
/// the text is made (`None` where it was never seen, then whether it runs), the window's mark when a
/// poll first saw the process end (`None` where none did), the window's mark as the text is made,
/// and the screen.
fn second_start_timeout(
    agent_runs: Option<bool>,
    end_mark: Option<usize>,
    mark: usize,
    screen: &[String],
) -> String {
    let screen = screen.join("\n");
    match (agent_runs, end_mark) {
        (None, _) => format!(
            "the second start neither reached the composer nor ended within {LIVENESS:?}; the \
             agent's process was not seen; the screen is:\n{screen}"
        ),
        (Some(true), _) => format!(
            "the second start neither reached the composer nor ended within {LIVENESS:?}; the \
             agent's process was seen and still running; the screen is:\n{screen}"
        ),
        (Some(false), None) => format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended after \
             the last poll of it, so the window was not seen to take output after the end; the \
             screen is:\n{screen}"
        ),
        (Some(false), Some(seen)) if mark != seen => format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended, and \
             the window kept taking output; the screen is:\n{screen}"
        ),
        (Some(false), Some(_)) => format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended, the \
             end was first seen less than {QUIET:?} before the bound, and the window has taken \
             no byte since; the screen is:\n{screen}"
        ),
    }
}

/// The time-out text of a second start says how the agent's process stands as it is made, and says
/// of the window's output only what the polls saw: that it moved after the end, or that it did not.
#[test]
fn the_time_out_of_a_second_start_says_how_the_agents_process_stands_as_it_is_made() {
    let screen = [
        "kr-session$ codex resume 0123-4567".to_owned(),
        "  loading".to_owned(),
    ];
    let shown = "kr-session$ codex resume 0123-4567\n  loading";
    assert_eq!(
        second_start_timeout(None, None, 100, &screen),
        format!(
            "the second start neither reached the composer nor ended within {LIVENESS:?}; the \
             agent's process was not seen; the screen is:\n{shown}"
        ),
        "a process that was never seen is said not to be seen"
    );
    assert_eq!(
        second_start_timeout(Some(true), None, 100, &screen),
        format!(
            "the second start neither reached the composer nor ended within {LIVENESS:?}; the \
             agent's process was seen and still running; the screen is:\n{shown}"
        ),
        "a process that runs is said to run"
    );
    assert_eq!(
        second_start_timeout(Some(false), Some(100), 160, &screen),
        format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended, and \
             the window kept taking output; the screen is:\n{shown}"
        ),
        "output seen to move after the end is said to have kept coming"
    );
    assert_eq!(
        second_start_timeout(Some(false), Some(100), 100, &screen),
        format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended, the \
             end was first seen less than {QUIET:?} before the bound, and the window has taken \
             no byte since; the screen is:\n{shown}"
        ),
        "an end first seen just before the bound, with no byte since, is not said to have kept \
         taking output"
    );
    assert_eq!(
        second_start_timeout(Some(false), None, 100, &screen),
        format!(
            "the second start was not read within {LIVENESS:?}: the agent's process ended after \
             the last poll of it, so the window was not seen to take output after the end; the \
             screen is:\n{shown}"
        ),
        "an end that no poll saw is said so, and nothing is said of the output"
    );
}

/// What became of the agent's process after it refused the second start.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Standing {
    /// It went on running with the conversation open read-only and a notice in place of the
    /// composer, as Codex does.
    ReadOnly,
    /// It ended after the refusal, or was not found once the refusal showed.
    Ended,
    /// The process table could not be read, so the standing is not known; the refusal is as it was.
    Unknown(String),
}

/// How a refused start stands, from whether the agent's process runs now (`None` where none was
/// found below the session's worker), or why the process table could not be read.
fn refusal_standing(runs: Result<Option<bool>, String>) -> Standing {
    match runs {
        Ok(runs) if runs.unwrap_or(false) => Standing::ReadOnly,
        Ok(_) => Standing::Ended,
        Err(why) => Standing::Unknown(why),
    }
}

/// What part 7's evidence records of a refusal's standing, by key: where the standing is not known
/// both answers are null, and the reason stands beside them.
fn standing_evidence(standing: &Standing) -> Vec<(&'static str, serde_json::Value)> {
    match standing {
        Standing::ReadOnly => vec![
            ("still_running_read_only", serde_json::json!(true)),
            ("ended_after_the_refusal", serde_json::json!(false)),
        ],
        Standing::Ended => vec![
            ("still_running_read_only", serde_json::json!(false)),
            ("ended_after_the_refusal", serde_json::json!(true)),
        ],
        Standing::Unknown(why) => vec![
            ("still_running_read_only", serde_json::Value::Null),
            ("ended_after_the_refusal", serde_json::Value::Null),
            ("process_read_failed", serde_json::json!(why)),
        ],
    }
}

/// A refusal after which the agent's process ended, or was not found, is an ended refusal and no
/// failure of the part; one after which it runs is a read-only conversation. The part passes on a
/// refusal either way.
#[test]
fn a_refusal_that_ended_the_agent_is_an_ended_refusal_and_a_card_that_runs_is_read_only() {
    assert_eq!(refusal_standing(Ok(Some(true))), Standing::ReadOnly);
    assert_eq!(refusal_standing(Ok(Some(false))), Standing::Ended);
    assert_eq!(refusal_standing(Ok(None)), Standing::Ended);
    let refused = taken(Started::Refused, None, None).expect("a refusal is an outcome");
    assert_eq!(refused, Taken::Refused);
    assert!(check_taken(false, refused).is_ok());
}

/// A refusal whose process table could not be read afterwards is still a refusal: the evidence
/// records an unknown standing, with the reason, in place of failing a part that passed.
#[test]
fn a_refusal_whose_process_table_could_not_be_read_records_an_unknown_standing() {
    let unknown = refusal_standing(Err("ps did not end".to_owned()));
    assert_eq!(unknown, Standing::Unknown("ps did not end".to_owned()));
    assert_eq!(
        standing_evidence(&unknown),
        vec![
            ("still_running_read_only", serde_json::Value::Null),
            ("ended_after_the_refusal", serde_json::Value::Null),
            ("process_read_failed", serde_json::json!("ps did not end")),
        ],
        "neither answer is claimed, and the reason is kept"
    );
    assert_eq!(
        standing_evidence(&Standing::Ended),
        vec![
            ("still_running_read_only", serde_json::json!(false)),
            ("ended_after_the_refusal", serde_json::json!(true)),
        ]
    );
    assert_eq!(
        standing_evidence(&Standing::ReadOnly),
        vec![
            ("still_running_read_only", serde_json::json!(true)),
            ("ended_after_the_refusal", serde_json::json!(false)),
        ]
    );
}

/// Every file of the agent's record with its content, in the order of their places.
fn record_files(ctx: &Context, real: &Real) -> Vec<(PathBuf, String)> {
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
    files.sort();
    files
}

/// Whether the agent's record is as it was: the same files with the same content. A conversation
/// that is open read-only in a second process is not written by it.
///
/// # Errors
///
/// Returns what changed.
fn record_unchanged(
    before: &[(PathBuf, String)],
    after: &[(PathBuf, String)],
) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "the agent's record held {} file(s) and now holds {}, or a file's content changed",
            before.len(),
            after.len()
        ))
    }
}

/// A record in which a file was written or added is not as it was.
#[test]
fn a_record_in_which_a_file_was_written_or_added_is_not_unchanged() {
    let file = |place: &str, text: &str| (PathBuf::from(place), text.to_owned());
    let before = vec![file("a.jsonl", "one\n")];
    assert!(record_unchanged(&before, &before.clone()).is_ok());
    assert!(record_unchanged(&before, &[file("a.jsonl", "one\ntwo\n")]).is_err());
    assert!(record_unchanged(&before, &[file("a.jsonl", "one\n"), file("b.jsonl", "x")]).is_err());
}

/// The conversation identifier of the file `place` holding `content`: the member of its first line
/// the entry names, else what its place says.
fn identifier_of(account: &Account, place: &Path, content: &str) -> String {
    account
        .conversation_id_member
        .as_deref()
        .and_then(|member| {
            let first: serde_json::Value = serde_json::from_str(content.lines().next()?).ok()?;
            first[member].as_str().map(str::to_owned)
        })
        .unwrap_or_else(|| conversation_id(place))
}

/// The conversation the one file of the record that holds `mark` in a prompt line is: its
/// identifier, how many files the record holds, and the file's place.
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
            return (
                identifier_of(&real.account, place, content),
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

/// Where the second process's question was recorded: the place and the conversation identifier of
/// the one file of the record that holds `needle` in a prompt line, or `None` where no file or
/// more than one holds it.
fn recorded_question(ctx: &Context, real: &Real, needle: &str) -> Option<(PathBuf, String)> {
    let mut holding: Vec<(PathBuf, String)> = Vec::new();
    read_record(
        ctx.run.root(),
        ctx.run.pin(),
        &conversations_relative(&real.account),
        &mut |place, content| {
            let content = String::from_utf8_lossy(content);
            if first_line_with(&content, None, &[needle, &real.account.prompt_line]).is_some() {
                let place = PathBuf::from(String::from_utf8_lossy(place).into_owned());
                let identifier = identifier_of(&real.account, &place, &content);
                holding.push((place, identifier));
            }
        },
    )
    .unwrap_or_else(|why| panic!("the agent's record is not whole: {why}"));
    match holding.as_slice() {
        [found] => Some(found.clone()),
        _ => None,
    }
}

/// Why a real route cannot run part 7 or 7f, or `None`: the entry names no start draft text
/// (`account.draft`). The agent's resume or fork start draws a composer beside its draft, and with no
/// text to tell the draft by the screen reads that composer as a running continuation, so the part
/// would charge B's turn and type at a start that is still a draft.
fn second_start_unreadable(draft: &[String]) -> Option<&'static str> {
    draft.is_empty().then_some(
        "the entry names no start draft texts (account.draft), so the screen of the second start \
         cannot tell the saved conversation's start draft from a running continuation",
    )
}

/// What part 7 or 7f records instead of a run, or `None` where it runs: `draft` is the entry's start
/// draft texts on a real route, and `None` on the stand-in route, which has no start draft.
fn second_start_not_run(draft: Option<&[String]>, arm: &str) -> Option<serde_json::Value> {
    let why = second_start_unreadable(draft?)?;
    Some(serde_json::json!({
        "arm": arm,
        "not_run": why,
        "turns_charged": 0,
    }))
}

/// A real route whose entry names no start draft text is not run for part 7 or 7f, because B's
/// resume draft reads as a running continuation on its screen; an entry that names the texts runs.
#[test]
fn a_real_route_with_no_start_draft_text_is_not_run_for_parts_7_and_7f() {
    let typed = "codex resume 0123-4567";
    let composer = "Ask Codex to do anything";
    let refusals = ["This conversation is open in another app".to_owned()];
    let resume_draft: Vec<String> = [
        "kr-session$ codex resume 0123-4567",
        "  Resuming session…",
        "> Ask Codex to do anything",
    ]
    .iter()
    .map(|row| (*row).to_owned())
    .collect();
    let named = ["Resuming session…".to_owned()];
    assert_eq!(
        second_screen(&resume_draft, typed, composer, &refusals, &[], false),
        Some((Started::Running, None)),
        "with no draft text, B's resume draft reads as a running continuation"
    );
    assert_eq!(
        second_screen(&resume_draft, typed, composer, &refusals, &named, false),
        None,
        "with the text named, it is no answer yet"
    );
    assert!(
        second_start_unreadable(&[]).is_some_and(|why| why.contains("account.draft")),
        "an entry that names no draft text is not run, and the line names the field"
    );
    assert_eq!(
        second_start_unreadable(&named),
        None,
        "one that names it runs"
    );
    assert_eq!(
        second_start_not_run(Some(&[]), "pinned build"),
        Some(serde_json::json!({
            "arm": "pinned build",
            "not_run": "the entry names no start draft texts (account.draft), so the screen of the \
                        second start cannot tell the saved conversation's start draft from a \
                        running continuation",
            "turns_charged": 0,
        })),
        "a real route with no draft text records the part as not run, with no turn charged"
    );
    assert_eq!(
        second_start_not_run(Some(&named), "pinned build"),
        None,
        "a real route that names the texts runs"
    );
    assert_eq!(
        second_start_not_run(None, "stand-in"),
        None,
        "the stand-in route has no start draft and runs"
    );
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
    let real_draft = match &ctx.route {
        Route::Real(real) => Some(real.account.draft.as_slice()),
        Route::StandIn => None,
    };
    if let Some(not_run) = second_start_not_run(real_draft, arm(ctx)) {
        return not_run;
    }
    let (a, b) = (seated(session, Seat::First), seated(session, Seat::Second));
    let agent_a = starts_by_hand(ctx, session, Seat::First, &[], true);
    let shown_a = detects(ctx, &a);
    detected(ctx, &agent_a, &shown_a, "session A's launch");
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
    let record_before = record_files(ctx, real);
    b.person.clears_the_screen();
    ctx.checks_the_placed_files();
    real.checks_the_route(&ctx.run);
    let line = real.typed(&extra);
    b.person.types(&line);
    let (started, refusal, agent_seen) = second_start(
        ctx,
        &b,
        &line,
        &account.composer,
        &account.resume_refused,
        &account.draft,
    );
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
        if started == Started::Refused {
            // The agent may refuse and end, or go on running with the conversation open read-only
            // and a notice in place of the composer: a refusal is an outcome either way, and the
            // process is recorded as it stands. Session A's conversation is as it was, since a
            // read-only view writes nothing.
            let standing = refusal_standing(match agent_seen {
                Some(identity) => Ok(Some(running(&identity))),
                None => agent_now(ctx, b.session_id).map(|found| found.as_ref().map(running)),
            });
            record_unchanged(&record_before, &record_files(ctx, real))
                .unwrap_or_else(|why| panic!("session A's conversation is as it was: {why}"));
            for (key, value) in standing_evidence(&standing) {
                evidence["session_b"][key] = value;
            }
        } else {
            // The agent's start ended: the host shows no instance for it.
            check_unchanged(None, &shown_now(ctx, &b)).unwrap_or_else(|why| {
                panic!("the ended start announces no instance of its own: {why}")
            });
        }
        let what = taken(started, None, None).unwrap_or_else(|why| panic!("{why}"));
        evidence["resume"] = serde_json::json!({ "outcome": what.word(), "shown": refusal });
        evidence["control"] = serde_json::json!({ "what": "session B's marker typed into session A", "breaks_property": false, "why_not": "no second execution ran, so there was no second session to type a marker from" });
        check_taken(forks, what).unwrap_or_else(|why| panic!("{why}"));
        evidence["turns_charged"] = turns.charged.into();
        return evidence;
    }
    // A second process runs: the host detects it as an instance of its own.
    let agent_b = HandAgent::found(ctx, b.session_id);
    let shown_b = detects(ctx, &b);
    detected(ctx, &agent_b, &shown_b, "session B's launch");
    assert_ne!(
        Held::of(&shown_a).map(|held| held.instance),
        Held::of(&shown_b).map(|held| held.instance),
        "the two launches are two instances"
    );
    let mut typing_b = Typing::attach(ctx, session, Seat::Second);
    // The second process is asked for what only session A's saved history holds: the code session A
    // was told to remember, which the question does not repeat and the mark of the question does
    // not contain. A process that has no such history cannot answer it.
    let mark_b = crate::mark();
    let recalled = mark.to_uppercase();
    typing_b.submits(
        &mut turns,
        "the second process's question",
        &format!(
            "({mark_b}) What code did I ask you to remember earlier? Reply with that code in \
             upper case and nothing else."
        ),
        &format!("({mark_b})"),
        &account.submit,
    );
    let _ = b.person.sees(
        &recalled,
        "session B recalls the code that only session A's saved history holds",
    );
    b.person.waits_for_the_composer(
        &account.composer,
        &account.busy,
        "session B is back at its composer",
    );
    settles(ctx, real, &[&mark_b, &account.prompt_line]);
    let (place_b, identifier_b) = recorded_question(ctx, real, &mark_b)
        .map_or((None, None), |(place, identifier)| {
            (Some(place), Some(identifier))
        });
    let what = taken(
        started,
        place_b.as_ref().map(|place| *place == first_place),
        identifier_b
            .as_ref()
            .map(|identifier| *identifier == conversation),
    )
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
    evidence["resume"] = serde_json::json!({ "outcome": what.word(), "recalled": recalled, "conversation_of_b": identifier_b, "conversation_of_a": conversation });
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
    detected(ctx, &agent_b, &shown_b, "session B's launch");
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
/// refuses, whether it ended or went on running read-only with a notice in place of the composer,
/// A's conversation and binding are as they were. The control breaks the property: B's marker typed
/// into A's session, and the isolation check fails on it. A real route whose entry names no start
/// draft text is not run, with no charge.
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
/// command, or no start draft text, is not run, with no charge.
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
    assert!(check_taken(false, taken(Started::Refused, None, None).unwrap()).is_ok());
    assert!(
        check_taken(
            false,
            taken(Started::Running, Some(true), Some(true)).unwrap()
        )
        .is_ok()
    );
    assert!(
        check_taken(
            false,
            taken(Started::Running, Some(false), Some(false)).unwrap()
        )
        .is_err(),
        "a conversation of its own is part 7f's"
    );
    assert!(
        check_taken(false, taken(Started::Ended, None, None).unwrap()).is_err(),
        "an end with no reason shows nothing"
    );
    assert!(
        taken(Started::Running, None, None).is_err(),
        "a question recorded in no file is no answer"
    );
}

/// A fork the agent refused or merged, and a start that ended with no text that says why, fail part
/// 7f.
#[test]
fn a_fork_that_the_agent_refused_or_merged_fails_the_check_of_7f() {
    assert!(
        check_taken(
            true,
            taken(Started::Running, Some(false), Some(false)).unwrap()
        )
        .is_ok()
    );
    assert!(
        check_taken(true, taken(Started::Refused, None, None).unwrap()).is_err(),
        "a refused fork shows no second history"
    );
    assert!(
        check_taken(
            true,
            taken(Started::Running, Some(true), Some(true)).unwrap()
        )
        .is_err(),
        "a merged fork is not a conversation of its own"
    );
    assert!(
        check_taken(true, taken(Started::Ended, None, None).unwrap()).is_err(),
        "an end with no reason shows nothing"
    );
}

/// A second file is a fork only under another conversation identifier, and the first file is a
/// continuation only under the first one: a file that copies the first conversation's identifier
/// is not a fork, and another identifier in the first file is not a continuation.
#[test]
fn a_question_whose_file_and_conversation_identifier_disagree_is_neither_a_fork_nor_a_merge() {
    assert!(taken(Started::Running, Some(false), Some(true)).is_err());
    assert!(taken(Started::Running, Some(true), Some(false)).is_err());
    assert!(taken(Started::Running, Some(true), None).is_err());
    assert!(taken(Started::Running, None, Some(true)).is_err());
    assert_eq!(
        taken(Started::Running, Some(false), Some(false)),
        Ok(Taken::Forked)
    );
    assert_eq!(
        taken(Started::Running, Some(true), Some(true)),
        Ok(Taken::Merged)
    );
}
