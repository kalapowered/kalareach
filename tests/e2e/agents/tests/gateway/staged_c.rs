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
use kr_e2e_agents::detect::{
    Detection, Held, Launched, Shown, announced_now, capabilities_of, check_detected,
    check_unchanged, wait_for_detection,
};
use kr_e2e_agents::observe::live_bindings;
use kr_e2e_agents::stage::Keyboard;
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

/// One of a case's sessions.
#[derive(Clone, Copy)]
enum Seat {
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

/// The turns a case charged to the budget and the ones it submitted.
struct Turns<'a> {
    ctx: &'a Context,
    real: &'a Real,
    part: &'a str,
    charged: u64,
    submitted: u64,
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
fn turns_as_planned(charged: u64, submitted: u64, planned: u64) -> Result<(), String> {
    if charged == submitted && charged == planned {
        Ok(())
    } else {
        Err(format!(
            "{charged} turn(s) charged, {submitted} submitted, {planned} planned"
        ))
    }
}

/// The device's keyboard on a session, and the person's screen it types at.
struct Typing<'a> {
    ctx: &'a Context,
    at: Seated<'a>,
    keys: Keyboard,
}

impl<'a> Typing<'a> {
    /// Attaches the device's keyboard to the session at `seat` and takes the input lease.
    fn attach(ctx: &'a Context, session: &'a Session<'_>, seat: Seat) -> Self {
        let at = seated(session, seat);
        let mut keys = Keyboard::attach(at.remote, &ctx.runtime, at.session_id)
            .unwrap_or_else(|why| panic!("the device's keyboard attaches: {why}"));
        keys.acquire(at.remote, &ctx.runtime)
            .unwrap_or_else(|why| panic!("the device takes the input lease: {why}"));
        Self { ctx, at, keys }
    }

    /// Types `text` from the device: every byte is forwarded to the terminal.
    fn types(&mut self, text: &str) {
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
    fn submits(&mut self, turns: &mut Turns<'_>, what: &str, text: &str, mark: &str, key: &str) {
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
    fn new(ctx: &'a Context, real: &'a Real, part: &'a str) -> Self {
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
