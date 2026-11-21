//! The parts of the qualification that need the person's login (1, 3 and 4), on the gateway
//! driver: the same host, managed shell, paired device and held ending as the gateway cases, with
//! the agent started from the managed shell so that the host's command integration serves it
//! through a gateway.
//!
//! After the agent started nothing runs `kr`: a device connects again with the paired host's own
//! connection, the host's processes are ended by the identities the run recorded, and every prompt
//! is charged to the ledger before it is sent. On the stand-in route the agent is the application
//! stand-in, which starts no model turn and charges nothing; on a real route it is the pinned build
//! with the person's login the build list entry names. A part that needs a real answer (the image's
//! colour, a command's run) checks it on the real route only; the stand-in route checks what the
//! host does with the frames it carries.

use super::*;

use kr_e2e_agents::conversation;
use kr_e2e_agents::transfer::{self, Caller, Transfer};

/// The colour that fills [`COLOUR_PNG`], as a one-word answer names it.
const COLOUR: &str = "red";

/// A 32 by 32 image filled with one colour, red.
const COLOUR_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfc, 0x18, 0xed,
    0xa3, 0x00, 0x00, 0x00, 0x27, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0xed, 0xcd, 0xb1, 0x09, 0x00,
    0x00, 0x08, 0xc0, 0xb0, 0xfe, 0xff, 0xb4, 0x5e, 0xe1, 0x20, 0x04, 0xb2, 0xa7, 0xa9, 0x53, 0x09,
    0x04, 0x02, 0x81, 0x40, 0x20, 0x10, 0x08, 0x04, 0x82, 0x2f, 0xc1, 0x02, 0x32, 0xc3, 0xfc, 0x2e,
    0x70, 0xfd, 0x23, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

/// The variants of the stand-in that part 1 and part 4 run: the terminal's own turn waits for its
/// approval to be answered, and goes on reading.
const HELD_TURN: &str = "answer-when-released,keep-reading,stay";

/// The variants of the stand-in that part 3 runs: the approval of the terminal's turn is left to
/// whoever answers it first.
const RACED_APPROVAL: &str = "answer-when-released,keep-reading,ping-when-released,stay";

/// How long a case lets what it did settle before it reads the counts a second time.
const SETTLE: Duration = Duration::from_secs(3);

/// The route as the case's own record names it, beside the host-side `route` every case writes.
fn arm(ctx: &Context) -> &'static str {
    match ctx.route {
        Route::StandIn => "stand-in",
        Route::Real(_) => "pinned build",
    }
}

/// A case of a part with the person's login: the ledger's case is the part's own name.
fn login_case(
    part: &str,
    test: &str,
    variants: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    run_case(&format!("staged-{part}"), part, test, variants, body);
}

/// The text that gives `file` to the agent as an image at its composer, as its build list says:
/// pasted as a terminal pastes a path, or typed in the agent's own syntax.
fn image_input(account: &Account, file: &Path) -> String {
    let path = file.display().to_string();
    if account.image == "paste" {
        format!("\u{1b}[200~{path}\u{1b}[201~")
    } else {
        account.image.replace("{path}", &path)
    }
}

/// The first line of `text` that holds every one of `needles`, by index.
fn line_of(text: &str, needles: &[&str]) -> Option<usize> {
    text.lines()
        .position(|line| needles.iter().all(|needle| line.contains(needle)))
}

/// The agent's record of its conversation, read whole, read again until it can be.
fn record(ctx: &Context, real: &Real) -> String {
    let started = Instant::now();
    loop {
        match real.conversations(&ctx.run) {
            Ok(text) => return text,
            Err(why) if started.elapsed() >= LIVENESS => {
                panic!("the agent's record cannot be read: {why}")
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// A new connection of the paired device, as it makes one after the old one went.
fn reconnects(ctx: &Context, session: &Session<'_>) -> Remote {
    ctx.runtime
        .block_on(session.device.connect(&session.paired))
        .unwrap_or_else(|why| panic!("the device connects again: {why}"))
}

/// The approval the host holds pending and has interpreted, read through `remote`: the one resource
/// in the state pending, where earlier ones may be listed as resolved.
fn pending_approval(
    ctx: &Context,
    remote: &Remote,
    session: &Session<'_>,
) -> kr_protocol::gateway::PendingResource {
    let pending = |read: &AgentInstancesResult| {
        read.agent_resources
            .resources
            .iter()
            .filter(|resource| {
                resource.state == PendingState::Pending && resource.interpretation_verified
            })
            .count()
            == 1
    };
    let read = ctx.instances_until(
        remote,
        session.session_id(),
        "a pending request is interpreted",
        pending,
    );
    read.agent_resources
        .resources
        .iter()
        .find(|resource| resource.state == PendingState::Pending)
        .cloned()
        .expect("the one pending resource")
}

/// How many approvals the host holds pending, read through `remote`.
fn pending_count(ctx: &Context, remote: &Remote, session: &Session<'_>) -> usize {
    ctx.instances(remote, session.session_id())
        .agent_resources
        .resources
        .iter()
        .filter(|resource| resource.state == PendingState::Pending)
        .count()
}

// ---------------------------------------------------------------------------------------------
// Part 1: a device prompts the agent and adds an image, and the local terminal shows the same
// execution.
// ---------------------------------------------------------------------------------------------

/// Whether the image the agent was given is the one the device transferred: the file the host
/// published for the transfer holds the sent bytes, and, where the agent's own record was read,
/// every image it holds is the sent one and it holds one.
///
/// # Errors
///
/// Returns what shows that the agent was given another image.
fn image_received_is_the_one_sent(
    sent: &str,
    published: Option<&str>,
    recorded: Option<&[Option<String>]>,
) -> Result<(), String> {
    let mut wrong = Vec::new();
    if published != Some(sent) {
        wrong.push(
            "the host's staging area holds no file with the sent image's bytes for the transfer, \
             so the agent was given another",
        );
    }
    if let Some(images) = recorded {
        if images.is_empty() {
            wrong.push("the agent's record holds no image");
        } else if images.iter().any(|digest| digest.as_deref() != Some(sent)) {
            wrong.push("an image the agent's record holds is not the one the device transferred");
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("; "))
    }
}

/// Whether a transfer was a paired device's: sent by the device, and on a lane a device reaches.
///
/// # Errors
///
/// Returns why the transfer was not shown to be the device's.
fn a_devices_transfer(caller: Caller, lane: transfer::Lane) -> Result<(), String> {
    if caller != Caller::Device {
        return Err(format!(
            "the image was transferred by the {}, not by a paired device",
            caller.word()
        ));
    }
    if !lane.is_a_devices() {
        return Err(format!(
            "the image's chunks travelled the {}, which a paired device does not reach",
            lane.word()
        ));
    }
    Ok(())
}

/// Whether a row of the screen holds the code beside a word that names the colour: the agent's
/// answer, which only the model writes.
///
/// # Errors
///
/// Returns that no row does.
fn answer_names_the_colour(rows: &[String], code: &str) -> Result<(), String> {
    let named = rows.iter().any(|row| {
        row.contains(code)
            && row
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == COLOUR)
    });
    if named {
        Ok(())
    } else {
        Err(format!(
            "no row holds the code {code} beside the colour {COLOUR}"
        ))
    }
}

/// The digests of the images the agent's record holds: for each line of `text` that holds
/// `marker`, the text after each `base64,` in it, decoded and hashed. A line with no image text
/// after it, or whose image cannot be decoded, gives `None`.
fn images_in(text: &str, marker: &str) -> Vec<Option<String>> {
    use base64::Engine as _;

    let mut found = Vec::new();
    for line in text.lines().filter(|line| line.contains(marker)) {
        let mut images = line.split("base64,").skip(1).peekable();
        if images.peek().is_none() {
            found.push(None);
        }
        for after in images {
            let encoded: String = after
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
                })
                .collect();
            found.push(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .ok()
                    .map(|bytes| transfer::hex_of(&kr_cbor::sha256(&bytes))),
            );
        }
    }
    found
}

/// Transfers `bytes` as the paired device does, with the client library's upload driver on the data
/// streams of the device's own connection: the device begins the upload, sends the bytes and
/// finishes it. Nothing runs `kr`.
fn device_transfer(
    ctx: &Context,
    session: &Session<'_>,
    bytes: &[u8],
) -> (Transfer, transfer::Lane) {
    let environment = session.host.environment();
    let (route, lane) = ctx
        .runtime
        .block_on(transfer::device_route(
            session.remote.session(),
            environment,
        ))
        .unwrap_or_else(|why| panic!("the paired device's data streams: {why}"));
    let target = kr_e2e_m1b::view::session_target(&session.remote, session.session_id());
    let subject = transfer::image_subject(environment, session.session_id(), "colour.png");
    let sent = ctx.runtime.block_on(transfer::send_image(
        session.remote.session(),
        &route,
        &target,
        subject,
        bytes.to_vec(),
    ));
    (sent, lane)
}

/// KR-REQ-12.32, case 1, part 1: the agent is started from the ordinary managed shell and the host
/// serves it through a gateway. The paired device's own transfer sends an image on the data streams
/// of its connection, and the host publishes it; the device sends a prompt the agent answers, which
/// the local terminal shows; the image the host published is given to the agent at its composer in
/// the agent's own syntax, with a question only the image answers, which carries the part's code in
/// upper case; and the agent's own record holds the image the device transferred and no other. The
/// local terminal shows the same execution: the same instance, still served through a gateway, on
/// the thread the device's prompt ran on. On the stand-in route the stand-in takes the device's
/// prompt and nothing is typed at it; the image's answer is the model's and is checked on a real
/// route only.
#[test]
fn gateway_a_device_prompts_the_agent_and_adds_an_image_and_the_local_terminal_shows_the_same_execution()
 {
    const TEST: &str = "gateway_a_device_prompts_the_agent_and_adds_an_image_and_the_local_terminal_shows_the_same_execution";
    login_case("1", TEST, HELD_TURN, |ctx, session| {
        let instance = session.starts_the_agent(&[], None, &[]);
        // The device's own transfer comes first, before anything is charged.
        let (sent, lane) = device_transfer(ctx, session, COLOUR_PNG);
        let sent_digest = transfer::hex_of(&kr_cbor::sha256(COLOUR_PNG));
        let Transfer::Sent(handle) = &sent else {
            panic!(
                "a paired device's transfer did not publish the image: {}",
                sent.evidence(Caller::Device, lane)
            );
        };
        assert!(
            transfer::hex_of(handle.content_digest.as_bytes()) == sent_digest
                && handle.byte_len.get() == COLOUR_PNG.len() as u64,
            "the host published an attachment that is not the image sent: {}",
            sent.evidence(Caller::Device, lane)
        );
        a_devices_transfer(Caller::Device, lane).unwrap_or_else(|why| panic!("{why}"));
        let staged = transfer::staged_file(session.host.environment(), &handle.transfer_id);
        let staged_digest = staged.as_deref().and_then(transfer::digest_of);
        match &ctx.route {
            Route::StandIn => {
                let _ = session.binding_until(
                    instance,
                    "the stream names the thread and the turn",
                    |binding| names(binding, "thread-1", Some("turn-1")),
                );
                releases(ctx);
                let idle = session.binding_until(instance, "the turn ends", |binding| {
                    names(binding, "thread-1", None)
                });
                let from = session.person.window.mark();
                let started = ctx
                    .prompts(
                        &session.remote,
                        session.session_id(),
                        instance,
                        &idle,
                        "run it again",
                    )
                    .unwrap_or_else(|why| {
                        panic!(
                            "the device's prompt is carried: {why:?}\n{}",
                            session.diagnosis()
                        )
                    });
                assert!(started.turn_id.0.is_some(), "the host started a turn");
                let _ = session.person.window.wait_for(
                    from,
                    b"TUI: turn/started",
                    "the terminal shows the turn the device's prompt started",
                );
                image_received_is_the_one_sent(&sent_digest, staged_digest.as_deref(), None)
                    .unwrap_or_else(|why| panic!("{why}"));
                session.gateway_serves(instance);
                serde_json::json!({
                    "arm": arm(ctx),
                    "transfer": sent.evidence(Caller::Device, lane),
                    "published_is_the_sent": staged_digest.as_deref() == Some(sent_digest.as_str()),
                    "turn_started_by_the_device": true,
                })
            }
            Route::Real(real) => {
                let idle = session.binding_until(
                    instance,
                    "the stream names a thread and no turn",
                    |binding| {
                        binding.thread_id.0.is_some()
                            && binding.turn_id.0.is_none()
                            && unsuspended(binding)
                    },
                );
                let marked = mark();
                let root = ctx.run.root().display().to_string();
                let (question, sum) = session.person.asks(&[&marked, &root]);
                real.charge(&ctx.run, "1", "a prompt from a device");
                let before = session.person.window.screen();
                let started = ctx
                    .prompts(
                        &session.remote,
                        session.session_id(),
                        instance,
                        &idle,
                        &format!("({marked}) {question}"),
                    )
                    .unwrap_or_else(|why| {
                        panic!(
                            "the device's prompt is carried: {why:?}\n{}",
                            session.diagnosis()
                        )
                    });
                assert!(started.turn_id.0.is_some(), "the host started a turn");
                let _ = session.person.sees_the_sum(
                    &sum,
                    &before,
                    "the terminal shows the turn the device started",
                );
                let first = thread_of(&idle).expect("the idle binding names a thread");
                let _ = session.binding_settled_until(
                    instance,
                    "the device's turn ends on the thread it ran on",
                    Some(&first),
                    |binding| binding.turn_id.0.is_none(),
                );
                // The image the host published, in the agent's own syntax, with a question only the
                // image answers.
                let file = staged
                    .clone()
                    .expect("the host published a file for the transfer");
                let upper = marked.to_uppercase();
                real.charge(&ctx.run, "1", "an image and its question");
                session
                    .person
                    .window
                    .type_text(image_input(&real.account, &file).as_bytes());
                std::thread::sleep(Duration::from_millis(500));
                // A mark of its own: the first prompt's is on the screen already.
                let image_mark = mark();
                session.person.composes(
                    &format!(
                        " What colour fills this image? ({image_mark}) Reply with one lowercase \
                         word, a space, and the code {marked} in upper case."
                    ),
                    &image_mark,
                );
                // A model's displayed reasoning can quote the code before its answer: the wait goes
                // on until a row holds the code beside the colour, which only the answer does.
                let mut rows = session
                    .person
                    .sees(&upper, "the agent answers from the image");
                let waited = Instant::now();
                while answer_names_the_colour(&rows, &upper).is_err() && waited.elapsed() < LIVENESS
                {
                    std::thread::sleep(Duration::from_millis(300));
                    rows = session.person.window.screen();
                }
                answer_names_the_colour(&rows, &upper).unwrap_or_else(|why| {
                    panic!(
                        "the answer names the image's colour: {why}:\n{}",
                        rows.join("\n")
                    )
                });
                // The agent's own record of the image it was given.
                let marker = real
                    .account
                    .image_line
                    .as_deref()
                    .expect("the build list names a marker for an image in the agent's record");
                let recorded = images_in(&record(ctx, real), marker);
                image_received_is_the_one_sent(
                    &sent_digest,
                    staged_digest.as_deref(),
                    Some(&recorded),
                )
                .unwrap_or_else(|why| panic!("{why}"));
                // The same execution: the instance is still the one the gateway serves, on the
                // thread the device's prompt ran on.
                session.gateway_serves(instance);
                let after = ctx.binding(&session.remote, session.session_id(), instance);
                assert_eq!(
                    thread_of(&after).as_deref(),
                    Some(first.as_str()),
                    "the binding names the thread the device's prompt ran on"
                );
                serde_json::json!({
                    "arm": arm(ctx),
                    "transfer": sent.evidence(Caller::Device, lane),
                    "published_is_the_sent": staged_digest.as_deref() == Some(sent_digest.as_str()),
                    "images_in_the_record": recorded.len(),
                    "image": { "syntax": real.account.image, "answer": COLOUR, "code": upper },
                    "prompt": { "question": question, "answer": sum },
                })
            }
        }
    });
}

#[test]
fn an_image_that_is_not_the_one_sent_fails_the_check_of_part_1() {
    let sent = "aa";
    assert!(image_received_is_the_one_sent(sent, Some(sent), None).is_ok());
    assert!(image_received_is_the_one_sent(sent, None, None).is_err());
    assert!(image_received_is_the_one_sent(sent, Some("bb"), None).is_err());
    let one = [Some(sent.to_owned())];
    assert!(image_received_is_the_one_sent(sent, Some(sent), Some(&one)).is_ok());
    assert!(image_received_is_the_one_sent(sent, Some(sent), Some(&[])).is_err());
    let other = [Some(sent.to_owned()), Some("bb".to_owned())];
    assert!(image_received_is_the_one_sent(sent, Some(sent), Some(&other)).is_err());
    let unread = [None];
    assert!(image_received_is_the_one_sent(sent, Some(sent), Some(&unread)).is_err());
}

#[test]
fn a_transfer_that_is_not_a_devices_fails_the_check_of_part_1() {
    assert!(a_devices_transfer(Caller::Device, transfer::Lane::Network).is_ok());
    assert!(a_devices_transfer(Caller::LocalOwner, transfer::Lane::Network).is_err());
    assert!(a_devices_transfer(Caller::Device, transfer::Lane::Local).is_err());
}

#[test]
fn an_answer_that_names_another_colour_or_lacks_the_code_fails_the_check_of_part_1() {
    let rows = |text: &str| vec![text.to_owned()];
    assert!(answer_names_the_colour(&rows("red KRABC123"), "KRABC123").is_ok());
    assert!(answer_names_the_colour(&rows("blue KRABC123"), "KRABC123").is_err());
    assert!(answer_names_the_colour(&rows("red"), "KRABC123").is_err());
    assert!(answer_names_the_colour(&rows("reddish KRABC123"), "KRABC123").is_err());
}

#[test]
fn the_digests_of_the_images_a_record_holds_are_read_from_its_marked_lines_only() {
    use base64::Engine as _;

    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let text = format!(
        "{{\"type\":\"input_image\",\"url\":\"data:image/png;base64,{}\"}}\nsomething else\n\
         {{\"type\":\"input_image\"}}\n",
        encode(COLOUR_PNG)
    );
    let found = images_in(&text, "\"type\":\"input_image\"");
    assert_eq!(
        found,
        vec![Some(transfer::hex_of(&kr_cbor::sha256(COLOUR_PNG))), None]
    );
}

// ---------------------------------------------------------------------------------------------
// Part 3: the device and the local terminal answer one approval at once.
// ---------------------------------------------------------------------------------------------

/// Whether the approval was resolved once: exactly one answer reached the server, and where the
/// command's runs were counted, it ran once if the device's answer, which allows it, was the one
/// carried, and not at all if the local terminal's, which refuses it, was.
///
/// # Errors
///
/// Returns what shows that more than one resolution happened.
fn one_answer_reached_the_server(
    answers: usize,
    ran: Option<usize>,
    device_carried: bool,
) -> Result<(), String> {
    if answers != 1 {
        return Err(format!(
            "{answers} answer(s) reached the server, where one resolution gives it one"
        ));
    }
    if let Some(ran) = ran {
        let expected = usize::from(device_carried);
        if ran != expected {
            return Err(format!(
                "the command ran {ran} time(s), where the answer that was carried (the device's \
                 allow: {device_carried}) runs it {expected}"
            ));
        }
    }
    Ok(())
}

/// Whether nothing either side typed was typed again after the device connected again: the counts
/// of the answers the server received and of the command's runs are what they were.
///
/// # Errors
///
/// Returns what changed.
fn nothing_typed_again(
    before: (usize, Option<usize>),
    after: (usize, Option<usize>),
    pending: usize,
) -> Result<(), String> {
    if before != after || pending != 0 {
        return Err(format!(
            "after the device connected again the server holds {} answer(s) and the command ran \
             {:?} time(s), where it was {} and {:?}, with {pending} approval(s) pending",
            after.0, after.1, before.0, before.1
        ));
    }
    Ok(())
}

/// How many answers the stand-in's server received.
fn responses(ctx: &Context) -> usize {
    received_lines(ctx)
        .iter()
        .filter(|line| line.starts_with("response "))
        .count()
}

/// The race: the local terminal's key that refuses the approval is written to its terminal, and at
/// once the device's answer, which allows it, is sent through the gateway.
fn race(
    ctx: &Context,
    session: &Session<'_>,
    instance: ApplicationInstanceId,
    binding: &AgentBindingState,
    resource: PendingResourceId,
    deny: &str,
) -> Result<AgentApprovalRespondResult, RequestError> {
    session.person.window.type_text(deny.as_bytes());
    ctx.answers(
        &session.remote,
        session.session_id(),
        instance,
        binding,
        resource,
        ACCEPT,
    )
}

/// How many answers to approvals the agent's record holds after the prompt that holds `mark`, as
/// the build list's marks count them, waiting until there are at least `least` and the count has
/// held for a second.
fn recorded_answers(ctx: &Context, real: &Real, mark: &str, least: usize) -> usize {
    let account = &real.account;
    let count = || {
        let text = record(ctx, real);
        let prompt_at = line_of(&text, &[mark, &account.prompt_line]);
        conversation::answers(
            &text,
            prompt_at,
            (
                &account.decision_line,
                &account.call_lines,
                &account.decision_calls,
            ),
        )
        .unwrap_or_else(|why| panic!("the answers to the approval cannot be counted: {why}"))
    };
    let started = Instant::now();
    let mut seen = count();
    while seen < least && started.elapsed() < LIVENESS {
        std::thread::sleep(Duration::from_millis(200));
        seen = count();
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let again = count();
        if again == seen {
            return seen;
        }
        seen = again;
    }
}

/// Reads the command's pipe until the turn on `instance` has ended, as read through `remote`: a
/// run of the command is a line in the pipe, and the reader stays open so that a second run would
/// find it open and write its line too.
fn until_the_turn_ends(
    ctx: &Context,
    remote: &Remote,
    session: &Session<'_>,
    instance: ApplicationInstanceId,
    reader: &mut FifoReader,
) {
    let started = Instant::now();
    loop {
        reader.poll();
        let binding = ctx.binding(remote, session.session_id(), instance);
        if binding.turn_id.0.is_none() && unsuspended(&binding) {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the turn does not end after {LIVENESS:?}: the binding is {binding:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    reader.poll();
}

/// The two markers of the part's two commands: each as long as the other, and different.
///
/// # Panics
///
/// Panics when the two are the same, which would let one command's marker stand for the other's.
fn approval_markers(mark: &str) -> (String, String) {
    let first = format!("kr{}", &mark[mark.len() - 6..]);
    let second = format!("kr{}", &mark[2..8]);
    assert_ne!(first, second, "the part's two markers are the same");
    (first, second)
}

/// How many lines of the pipe's reader are `tag`, and how many are anything else.
fn runs_of(reader: &FifoReader, tag: &str) -> (usize, usize) {
    let lines = reader.lines();
    let ran = lines.iter().filter(|line| line.as_str() == tag).count();
    (ran, lines.len() - ran)
}

/// KR-REQ-12.32, case 3, part 3: the agent raises its approval dialog for a shell command, and the
/// local terminal, which refuses it, and the paired device, whose rich answer allows it and is
/// dispatched through the gateway, answer it at the same moment. One resolution: exactly one answer
/// reaches the server, and the command runs once if the device's answer is the one carried and not
/// at all if the terminal's is, so the agent's own record holds one answer to it; the host holds no
/// approval pending after it. After the device connects again nothing either typed is typed again:
/// the counts are as they were. The control, on a real route, breaks the property: a second
/// approval is answered by the local terminal alone, the command never runs, and the check that
/// says the device's allow ran it fails on that command.
#[test]
fn gateway_a_local_and_a_remote_answer_raced_to_one_approval_resolve_it_once() {
    const TEST: &str = "gateway_a_local_and_a_remote_answer_raced_to_one_approval_resolve_it_once";
    login_case("3", TEST, RACED_APPROVAL, |ctx, session| {
        // The pipes are made before the agent first starts: nothing is written through a path of
        // the run after that.
        let pipes = matches!(ctx.route, Route::Real(_))
            .then(|| (Fifo::made_in(ctx, "f"), Fifo::made_in(ctx, "g")));
        let instance = session.starts_the_agent(&[], None, &[]);
        match &ctx.route {
            Route::StandIn => {
                let binding = session.binding_until(
                    instance,
                    "the stream names the thread and the turn",
                    |binding| names(binding, "thread-1", Some("turn-1")),
                );
                let pending = pending_approval(ctx, &session.remote, session);
                let answered = race(ctx, session, instance, &binding, pending.resource_id, "d");
                let _ = session.person.sees(
                    "TUI: serverRequest/resolved",
                    "the terminal reads the server's word that the request was answered",
                );
                let device_carried =
                    matches!(&answered, Ok(done) if done.state == PendingState::Resolved);
                let received = responses(ctx);
                one_answer_reached_the_server(received, None, device_carried)
                    .unwrap_or_else(|why| panic!("one resolution: {why}"));
                session.remote.close();
                let fresh = reconnects(ctx, session);
                std::thread::sleep(SETTLE);
                nothing_typed_again(
                    (received, None),
                    (responses(ctx), None),
                    pending_count(ctx, &fresh, session),
                )
                .unwrap_or_else(|why| panic!("{why}"));
                serde_json::json!({
                    "arm": arm(ctx),
                    "answers_the_server_received": received,
                    "device_answer": match &answered {
                        Ok(done) => format!("{:?}", done.state),
                        Err(refusal) => format!("refused: {refusal:?}"),
                    },
                    "device_won": device_carried,
                })
            }
            Route::Real(real) => {
                let marked = mark();
                let (tag, second) = approval_markers(&marked);
                let (pipe, second_pipe) =
                    pipes.expect("the real route made its pipes before the start");
                let command = format!("echo {tag} > {}", ctx.run.work().join("f").display());
                let second_command =
                    format!("echo {second} > {}", ctx.run.work().join("g").display());
                for line in [&command, &second_command] {
                    assert!(
                        real.account
                            .approval
                            .command_line
                            .as_deref()
                            .unwrap_or("")
                            .len()
                            + line.len()
                            + 8
                            <= usize::from(kr_e2e_m1b::window::COLUMNS),
                        "the case's command, {} characters, would not fit on one line of the \
                         agent's dialog",
                        line.len()
                    );
                }
                real.charge(&ctx.run, "3", "an approval-gated command");
                session.person.composes(
                    &format!(
                        "({marked}) Use your shell tool to run exactly this command and nothing \
                         else: {command}"
                    ),
                    &marked,
                );
                // The device answers only a dialog that asks to run the case's command and nothing
                // else: an accepted request runs outside the read-only sandbox.
                let _ = session.person.dialog_names(&real.account, &command);
                let binding = session.binding_until(
                    instance,
                    "the stream names the thread and the running turn",
                    |binding| {
                        binding.thread_id.0.is_some()
                            && binding.turn_id.0.is_some()
                            && unsuspended(binding)
                    },
                );
                let pending = pending_approval(ctx, &session.remote, session);
                let answered = race(
                    ctx,
                    session,
                    instance,
                    &binding,
                    pending.resource_id,
                    &real.account.approval.deny,
                );
                session.person.stops_seeing(
                    &real.account.approval.shows,
                    "the terminal's prompt goes once the approval is resolved",
                );
                let device_carried =
                    matches!(&answered, Ok(done) if done.state == PendingState::Resolved);
                let mut reader = pipe.reader(ctx);
                until_the_turn_ends(ctx, &session.remote, session, instance, &mut reader);
                let (ran, others) = runs_of(&reader, &tag);
                assert_eq!(
                    others, 0,
                    "the command wrote something else through its pipe"
                );
                let decided = recorded_answers(ctx, real, &marked, 1);
                one_answer_reached_the_server(decided, Some(ran), device_carried)
                    .unwrap_or_else(|why| panic!("one resolution: {why}"));
                assert_eq!(
                    pending_count(ctx, &session.remote, session),
                    0,
                    "the host holds an approval pending after the race"
                );
                // After the device connects again, nothing either typed is typed again.
                session.remote.close();
                let fresh = reconnects(ctx, session);
                std::thread::sleep(SETTLE);
                reader.poll();
                let rows = session.person.window.screen();
                assert!(
                    !rows
                        .iter()
                        .any(|row| row.contains(&real.account.approval.shows)),
                    "the agent shows an approval after the device connected again:\n{}",
                    rows.join("\n")
                );
                nothing_typed_again(
                    (decided, Some(ran)),
                    (
                        recorded_answers(ctx, real, &marked, 0),
                        Some(runs_of(&reader, &tag).0),
                    ),
                    pending_count(ctx, &fresh, session),
                )
                .unwrap_or_else(|why| panic!("{why}"));
                // The control: a second approval that the local terminal answers alone. The device's
                // allow is refused, the command never runs, and the check that says the device's
                // allow ran it fails on that command.
                real.charge(&ctx.run, "3", "the control's second approval");
                // A mark of its own: the first prompt's is on the screen already.
                let second_mark = format!("{marked}-2");
                session.person.composes(
                    &format!(
                        "({second_mark}) Use your shell tool to run exactly this command and \
                         nothing else: {second_command}"
                    ),
                    &second_mark,
                );
                let _ = session.person.dialog_names(&real.account, &second_command);
                let second_pending = pending_approval(ctx, &fresh, session);
                session
                    .person
                    .window
                    .type_text(real.account.approval.deny.as_bytes());
                session.person.stops_seeing(
                    &real.account.approval.shows,
                    "the local terminal's refusal closes the second dialog",
                );
                let now = ctx.binding(&fresh, session.session_id(), instance);
                let device_refused = ctx
                    .answers(
                        &fresh,
                        session.session_id(),
                        instance,
                        &now,
                        second_pending.resource_id,
                        ACCEPT,
                    )
                    .is_err();
                let mut second_reader = second_pipe.reader(ctx);
                until_the_turn_ends(ctx, &fresh, session, instance, &mut second_reader);
                let control_ran = runs_of(&second_reader, &second).0;
                let decided_control = recorded_answers(ctx, real, &marked, decided + 1);
                let control = one_answer_reached_the_server(
                    decided_control - decided,
                    Some(control_ran),
                    true,
                );
                assert!(
                    control.is_err() && control_ran == 0 && device_refused,
                    "the check fails once the local terminal alone answered: {control:?}; the \
                     command ran {control_ran} time(s) and the device's answer was refused: \
                     {device_refused}"
                );
                serde_json::json!({
                    "arm": arm(ctx),
                    "answers_in_the_record": decided,
                    "command_ran": ran,
                    "device_answer": match &answered {
                        Ok(done) => format!("{:?}", done.state),
                        Err(refusal) => format!("refused: {refusal:?}"),
                    },
                    "device_won": device_carried,
                    "control": {
                        "what": "a second approval answered by the local terminal alone",
                        "breaks_property": true,
                        "command_ran": control_ran,
                        "device_refused": device_refused,
                        "check": control.err(),
                    },
                })
            }
        }
    });
}

#[test]
fn a_second_answer_or_a_run_the_carried_answer_does_not_explain_fails_the_check_of_part_3() {
    assert!(one_answer_reached_the_server(1, None, true).is_ok());
    assert!(one_answer_reached_the_server(1, None, false).is_ok());
    assert!(one_answer_reached_the_server(2, None, true).is_err());
    assert!(one_answer_reached_the_server(0, None, false).is_err());
    assert!(one_answer_reached_the_server(1, Some(1), true).is_ok());
    assert!(one_answer_reached_the_server(1, Some(0), false).is_ok());
    assert!(one_answer_reached_the_server(1, Some(0), true).is_err());
    assert!(one_answer_reached_the_server(1, Some(1), false).is_err());
    assert!(one_answer_reached_the_server(1, Some(2), true).is_err());
}

#[test]
fn an_answer_typed_again_after_the_device_connected_again_fails_the_check_of_part_3() {
    assert!(nothing_typed_again((1, Some(1)), (1, Some(1)), 0).is_ok());
    assert!(nothing_typed_again((1, None), (1, None), 0).is_ok());
    assert!(nothing_typed_again((1, None), (2, None), 0).is_err());
    assert!(nothing_typed_again((1, Some(1)), (1, Some(2)), 0).is_err());
    assert!(nothing_typed_again((1, Some(1)), (1, Some(1)), 1).is_err());
}

#[test]
fn the_two_approval_markers_are_as_long_as_each_other_and_differ() {
    let (first, second) = approval_markers("kr0123456789ab");
    assert_eq!(first.len(), second.len());
    assert_ne!(first, second);
}
