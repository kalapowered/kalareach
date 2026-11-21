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
