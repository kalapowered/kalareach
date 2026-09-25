//! The legs of the cross-boundary checkpoint, in the order `scripts/e2e-m1b.sh` runs them.
//!
//! Each leg is a whole run of its own: its own directory on the internal disk, its own host, its
//! own devices with fresh keys. It closes what it opened, checks that nothing it started is still
//! running, and ends with two lines the report reads: what it left on the deployment, and what it
//! proved.

#![cfg(unix)]

use std::time::Duration;

use kr_e2e_m1b::host::{Host, HostOptions};
use kr_e2e_m1b::run::Run;
use kr_e2e_m1b::{Checkpoint, NO_RENDEZVOUS_ORIGIN, NO_RENDEZVOUS_VARIABLE, ceremony, room, site};
use kr_protocol::pairing::{Locator, QrPayload};

/// How long a candidate that is sent nothing waits before it concludes the room served it nothing.
///
/// A served candidate is sent the record before its upgrade is even answered.
const PROBE: Duration = Duration::from_secs(5);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime for the device and the site")
}

/// The origin the site leg's control is refused at.
fn no_rendezvous_origin() -> String {
    std::env::var(NO_RENDEZVOUS_VARIABLE)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| NO_RENDEZVOUS_ORIGIN.to_owned())
}

/// Ends a leg's host and checks that nothing the leg started is still running.
fn close(run: &Run, host: &Host<'_>) -> String {
    host.stop()
        .unwrap_or_else(|problem| panic!("the host did not stop cleanly: {problem}"));
    run.closing_check()
        .unwrap_or_else(|left| panic!("the {} leg left processes running: {left}", run.leg()))
}

/// The site: the deployed origin answers and names the build it runs; a real host reserves a code
/// invitation's locator at that origin, the room there serves the record, and withdrawing the
/// invitation releases it; and an HTTPS origin that serves no rendezvous is refused as a
/// configuration error rather than as a service that could not be reached (KR-REQ-10.19's
/// configuration-error kind, against a live origin).
#[test]
fn the_site_answers_and_a_host_reserves_its_invitations_there() {
    const LEG: &str = "site";
    let Some(checkpoint) = Checkpoint::from_environment(LEG) else {
        return;
    };
    let runtime = runtime();
    let origin = checkpoint.origin().clone();

    let health = runtime
        .block_on(site::health(checkpoint.gateway()))
        .unwrap_or_else(|why| panic!("the site's health: {why}"));
    println!(
        "the site is {} ({}, release {}) at commit {}",
        health.service, health.environment, health.version, health.commit
    );

    checkpoint.left(LEG, "nothing: the health route is a read");
    let run = Run::start(LEG);
    let host = Host::start(&run, &HostOptions::default());

    // The control first, while the host has no invitation open: the owner's ceremony completes and
    // the reservation it asks for is refused by what answered.
    let control = no_rendezvous_origin();
    let refused = ceremony::issue_first(&host, &["--owner", "--origin", &control]);
    assert_eq!(
        (refused.exit, refused.refusal()),
        (8, Some("RENDEZVOUS_CONFIG_ERROR")),
        "an origin that serves no rendezvous is a configuration error: {}",
        refused.withheld()
    );

    let invited = ceremony::issue_first(&host, &["--owner", "--origin", origin.as_str()]);
    assert_eq!(
        invited.exit,
        0,
        "the host issues a code invitation at the deployment: {}",
        invited.withheld()
    );
    assert_eq!(
        invited.document["rendezvous_origin"],
        origin.as_str(),
        "the invitation names the deployment as its rendezvous: {}",
        invited.withheld()
    );
    let code = invited.document["code"]
        .as_str()
        .expect("a code invitation shows its code")
        .to_owned();
    let invitation_id = invited.document["invitation_id"]
        .as_str()
        .expect("an invitation identifier")
        .to_owned();
    let qr = QrPayload::from_text(
        invited.document["qr_text"]
            .as_str()
            .expect("the invitation's QR text"),
    )
    .expect("the QR text is a payload");
    let QrPayload::Code(qr) = qr else {
        panic!("a code invitation's QR is a code-mode QR");
    };
    // Compared without being printed: the code's last six characters are the invitation's
    // secret, and a failure message is written to the leg's log.
    assert!(
        qr.rendezvous_origin.as_str() == origin.as_str() && qr.code.as_str() == code,
        "the QR names the deployment and the code the invitation shows"
    );
    let locator = Locator::new(&code[..4]).expect("the code's first four characters");
    checkpoint.left(
        LEG,
        &format!(
            "locator {} is reserved for one invitation, which expires within five minutes",
            locator.as_str()
        ),
    );

    // The deployment holds the host's reservation: a candidate in that locator's room is served
    // the record.
    let served = runtime
        .block_on(room::serves_record(&origin, &locator, PROBE))
        .unwrap_or_else(|why| panic!("the room could not be asked: {why}"));
    assert!(
        served,
        "the room at the deployment serves the host's record"
    );

    let withdrawn = host.kr_json(&["pair", "cancel", &invitation_id]);
    println!("the invitation was withdrawn: {}", withdrawn["status"]);
    let served = runtime
        .block_on(room::serves_record(&origin, &locator, PROBE))
        .unwrap_or_else(|why| panic!("the room could not be asked: {why}"));
    assert!(
        !served,
        "a withdrawn invitation's locator is released: its room serves no record"
    );

    let closing = close(&run, &host);
    println!("{closing}");
    checkpoint.left(
        LEG,
        &format!(
            "nothing: locator {} was reserved for one invitation and released when it was \
             withdrawn, and its room serves no record",
            locator.as_str()
        ),
    );
    checkpoint.proved(
        LEG,
        &format!(
            "the site answers at commit {}; a host reserves its code invitations there, and an \
             origin that serves no rendezvous is a configuration error",
            &health.commit[..12]
        ),
    );
}

/// A code with the right locator and a different secret: the last character changed to another
/// character of the alphabet.
fn wrong_code(code: &str) -> String {
    let mut characters: Vec<char> = code.chars().collect();
    let last = characters.last_mut().expect("a code has characters");
    *last = if *last == '2' { '3' } else { '2' };
    characters.into_iter().collect()
}

/// Pairing: a device pairs as the host's first owner by short code through the deployed
/// rendezvous, after a wrong code for the same invitation is refused and counted against it; a
/// second device pairs by direct QR over loopback iroh, each owner step confirmed by the first
/// device over its paired connection; and each pairing ends in a `kr-connect/1` connection whose
/// two proofs both sides checked.
///
/// KR-REQ-10.16 (only the four locator characters reach the service; the record is untrusted until
/// the PAKE confirms it), KR-REQ-10.23 (the client's tag first, the host's tag verified before any
/// host metadata is trusted), KR-REQ-10.27 (`pair.finish` binds the transcript to both live
/// endpoints), KR-REQ-10.30 (a wrong confirmation counts against the invitation), KR-REQ-10.35 to
/// 10.37 (a direct invitation redeemed over a connection pinned to the QR's endpoint and confirmed
/// by the owner), KR-REQ-10.52 (sensitive confirmation by a separately paired owner device).
#[test]
fn a_device_pairs_by_code_through_the_site_and_by_direct_qr_over_loopback() {
    use kr_e2e_m1b::device::{Device, PairingStopped};
    use kr_protocol::confirmation::ConfirmationDisplay;
    use kr_protocol::invitation::InviteModeKind;

    const LEG: &str = "pairing";
    let Some(checkpoint) = Checkpoint::from_environment(LEG) else {
        return;
    };
    let runtime = runtime();
    let origin = checkpoint.origin().clone();
    let run = Run::start(LEG);
    let host = Host::start(&run, &HostOptions::default());
    let first = runtime.block_on(Device::create("first device", &run.root().join("d1")));

    // The host's first owner invitation, offered through the deployment.
    let invited = ceremony::issue_first(&host, &["--owner", "--origin", origin.as_str()]);
    assert_eq!(invited.exit, 0, "the invitation: {}", invited.withheld());
    let code = invited.document["code"]
        .as_str()
        .expect("a code invitation shows its code")
        .to_owned();
    let invitation_id = invited.document["invitation_id"]
        .as_str()
        .expect("an invitation identifier")
        .to_owned();
    let locator = Locator::new(&code[..4]).expect("the code's locator");
    checkpoint.left(
        LEG,
        &format!(
            "locator {} is reserved for one invitation, which expires within five minutes",
            locator.as_str()
        ),
    );

    // A wrong code for the same locator reaches the host, fails the confirmation, and costs the
    // invitation one of its five.
    let refused = runtime
        .block_on(first.enter_code(&origin, &wrong_code(&code)))
        .expect_err("a wrong code does not pair");
    assert!(
        matches!(
            refused,
            PairingStopped::Refused {
                remaining: Some(4),
                ..
            }
        ),
        "a wrong code is refused with four confirmations left: {refused}"
    );
    let status = host.kr_json(&["pair", "status", &invitation_id]);
    assert_eq!(
        status["status"]["open"]["remaining_confirmations"], 4,
        "the host counted the wrong code against the invitation: {status}"
    );

    // The right code, through the same room.
    let mut exchange = runtime
        .block_on(first.enter_code(&origin, &code))
        .unwrap_or_else(|stopped| panic!("the right code: {stopped}"));
    let candidate = runtime
        .block_on(first.finish(&mut exchange))
        .unwrap_or_else(|why| panic!("pair.finish: {why}"));
    let approved = ceremony::approve_first(&host, &invitation_id, &candidate.verification_value);
    assert_eq!(
        approved.exit, 0,
        "the owner approves: {}",
        approved.document
    );
    let paired = runtime
        .block_on(candidate.committed(kr_e2e_m1b::LIVENESS))
        .unwrap_or_else(|why| panic!("the first device's pairing: {why}"));
    assert_eq!(
        approved.document["device_id"],
        paired.device_id.to_string(),
        "the device is told the identity the owner approved"
    );
    let owner = runtime
        .block_on(first.connect(&paired))
        .unwrap_or_else(|why| panic!("the first device's paired connection: {why}"));
    println!(
        "the first device paired by code and connected as {} ({})",
        paired.device_id,
        owner.connection()
    );

    // The deployment gave its locator back once the invitation was consumed.
    let served = runtime
        .block_on(room::serves_record(&origin, &locator, PROBE))
        .unwrap_or_else(|why| panic!("the room could not be asked: {why}"));
    assert!(
        !served,
        "a consumed invitation's locator is released: its room serves no record"
    );

    // A direct invitation on a host with an owner: each owner step is the first device's.
    let second = runtime.block_on(Device::create("second device", &run.root().join("d2")));
    let issuing = ceremony::issue_waiting(&host, &["--view", "60", "--direct"]);
    runtime
        .block_on(owner.confirm_pending(|display| {
            matches!(
                display,
                ConfirmationDisplay::IssueInvitation {
                    mode: InviteModeKind::Direct,
                    ..
                }
            )
        }))
        .unwrap_or_else(|why| panic!("the owner device confirms issuing: {why}"));
    let issued = ceremony::finished(issuing, "kr pair invite --direct");
    assert_eq!(
        issued.exit,
        0,
        "the direct invitation: {}",
        issued.withheld()
    );
    let direct_id = issued.document["invitation_id"]
        .as_str()
        .expect("an invitation identifier")
        .to_owned();
    let redeemed = runtime
        .block_on(
            second.redeem(
                issued.document["qr_text"]
                    .as_str()
                    .expect("a direct invitation's QR text"),
            ),
        )
        .unwrap_or_else(|why| panic!("the direct redemption: {why}"));
    let approving = ceremony::approve_waiting(&host, &direct_id);
    let shown = redeemed.verification_value.clone();
    runtime
        .block_on(owner.confirm_pending(|display| {
            matches!(
                display,
                ConfirmationDisplay::ConfirmDevice { candidate, .. }
                    if candidate.verification_value == shown
            )
        }))
        .unwrap_or_else(|why| panic!("the owner device confirms the device: {why}"));
    let approved = ceremony::finished(approving, "kr pair confirm");
    assert_eq!(
        approved.exit, 0,
        "the owner approves: {}",
        approved.document
    );
    let paired_directly = runtime
        .block_on(redeemed.committed(kr_e2e_m1b::LIVENESS))
        .unwrap_or_else(|why| panic!("the second device's pairing: {why}"));
    let viewer = runtime
        .block_on(second.connect(&paired_directly))
        .unwrap_or_else(|why| panic!("the second device's paired connection: {why}"));
    println!(
        "the second device paired by direct QR and connected as {} ({})",
        paired_directly.device_id,
        viewer.connection()
    );

    // The host holds both devices.
    let devices = host.kr_json(&["device", "list"]);
    let listed = devices.to_string();
    for device in [paired.device_id, paired_directly.device_id] {
        assert!(
            listed.contains(&device.to_string()),
            "the host lists device {device}: {devices}"
        );
    }

    owner.close();
    viewer.close();
    runtime.block_on(first.close());
    runtime.block_on(second.close());
    let closing = close(&run, &host);
    println!("{closing}");
    checkpoint.left(
        LEG,
        &format!(
            "nothing: locator {} was reserved for one invitation, reached by two candidate \
             sockets, and released when the pairing committed; its room serves no record",
            locator.as_str()
        ),
    );
    checkpoint.proved(
        LEG,
        "a device paired by code through the rendezvous after a wrong code was counted, a second \
         paired by direct QR on the first's confirmation, and both connected with kr-connect/1",
    );
}

/// What the session's shell prompts with, so a leg knows it is reading.
const PROMPT: &str = "kr-session$ ";

/// What the device answers the agent's question with.
const ANSWER: &str = "call it Kalareach one";

/// The person's own startup file for the session's shell. `kr shell install` adds the marked entry
/// that loads the package's integration after it.
const ZSHRC: &str =
    "PROMPT='kr-session$ '\nRPROMPT=''\nHISTFILE=''\nsetopt no_beep\nunsetopt prompt_sp\n";

/// The check `kr doctor` reports under `id`, wherever in its document it is.
fn check<'a>(document: &'a serde_json::Value, id: &str) -> Option<&'a serde_json::Value> {
    match document {
        serde_json::Value::Object(members) => {
            if members.get("id").and_then(serde_json::Value::as_str) == Some(id) {
                return Some(document);
            }
            members.values().find_map(|value| check(value, id))
        }
        serde_json::Value::Array(values) => values.iter().find_map(|value| check(value, id)),
        _ => None,
    }
}

/// The identity of the worker process that serves `session_id`, as the process table names it.
fn worker_of(run: &Run, session_id: &str) -> kr_protocol::identity::ProcessStartIdentity {
    let started = std::time::Instant::now();
    loop {
        if let Some((pid, _)) = kr_e2e_m1b::run::processes_under(run.root())
            .unwrap_or_default()
            .into_iter()
            .find(|(_, command)| {
                command.contains("kr-worker")
                    && command.contains(&format!("--session {session_id}"))
            })
            && let Some(identity) = run.record_pid(pid, "the session's worker")
        {
            return identity;
        }
        assert!(
            started.elapsed() < kr_e2e_m1b::LIVENESS,
            "no worker for session {session_id} is in the process table"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `read` answers with a process identifier, and records that process.
fn recorded(
    run: &Run,
    what: &str,
    read: impl Fn() -> Option<u32>,
) -> kr_protocol::identity::ProcessStartIdentity {
    let started = std::time::Instant::now();
    loop {
        if let Some(identity) = read().and_then(|pid| run.record_pid(pid, what)) {
            return identity;
        }
        assert!(
            started.elapsed() < kr_e2e_m1b::LIVENESS,
            "{what} never recorded a running process"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The question a device answers next: one still pending that is none of `seen`, at the revision
/// the host shows.
///
/// A device reads the questions it may answer with `question.read`. Where the host refuses that
/// read, the refusal is recorded in `defects` as a defect of the host, and the question is taken
/// from the device's own screen instead, where the agent printed its identity, at the revision a
/// new question starts at. That records what the rest of the leg can still check; it never makes
/// the leg pass, which fails at its end naming the refusal.
fn question_to_answer(
    runtime: &tokio::runtime::Runtime,
    remote: &kr_e2e_m1b::device::Remote,
    view: &mut kr_e2e_m1b::view::View,
    session_id: kr_protocol::ids::SessionId,
    seen: &[kr_protocol::ids::QuestionId],
    defects: &mut Vec<String>,
) -> (
    kr_protocol::ids::QuestionId,
    kr_protocol::ids::QuestionRevision,
) {
    use kr_e2e_m1b::view::pending_questions;
    let started = std::time::Instant::now();
    loop {
        match runtime.block_on(pending_questions(remote, session_id)) {
            Ok(pending) => {
                if let Some(question) = pending
                    .into_iter()
                    .find(|question| !seen.contains(&question.question_id))
                {
                    return (question.question_id, question.revision);
                }
            }
            Err(refusal) => {
                let defect = format!(
                    "the host's network read routing (crates/kr-controller/src/net/dispatch.rs) \
                     refuses question.read to a paired device, although the method table \
                     (crates/kr-protocol/src/method.rs) admits a paired device to it, so no \
                     device can read the questions it may answer ({refusal})"
                );
                if !defects.contains(&defect) {
                    defects.push(defect);
                }
                let shown = view
                    .rows()
                    .iter()
                    .rev()
                    .filter_map(|row| row.split(kr_e2e_m1b::agent::ASKED).nth(1))
                    .filter_map(|rest| rest.trim().parse().ok())
                    .find(|question| !seen.contains(question));
                if let Some(question) = shown {
                    return (question, kr_protocol::ids::QuestionRevision::new(1));
                }
            }
        }
        assert!(
            started.elapsed() < kr_e2e_m1b::LIVENESS,
            "no new question to answer appeared"
        );
        runtime
            .block_on(view.pump(remote, Duration::from_millis(200)))
            .unwrap_or_else(|why| panic!("{why}"));
    }
}

/// The terminal workflow, from a paired device: a person enters a managed shell with `kr new`,
/// launches an agent in it, and the device, attached over iroh, answers the agent's question and,
/// holding the input lease, types into it. The device detaches and the session lives on; the device
/// reattaches over a new connection and is drawn the screen as it now is, with nothing replayed.
/// The agent exits, shell commands run, a second agent launches and is used the same way, `kr
/// attach` from the command line draws the screen the device holds, and the session closes with
/// its shell.
///
/// KR-ACC-003 (enter an integrated shell, launch an agent, use it remotely, exit it, run shell
/// commands and launch another agent), KR-REQ-01.01 (the session survives its client's exit and is
/// attached again from the command line and from the app's client library).
#[test]
fn a_device_uses_an_agent_in_a_managed_shell_and_reattaches_to_the_screen_kr_attach_draws() {
    use kr_client::cursors::StreamCursors;
    use kr_client::reconnect::ClientState;
    use kr_e2e_m1b::agent::{ANSWERED, ASKED, Agent, ENDED, ERASED, WENT_ON};
    use kr_e2e_m1b::device::Device;
    use kr_e2e_m1b::host::quoted;
    use kr_e2e_m1b::run::{ended_within, running};
    use kr_e2e_m1b::screen::{Terminal, content};
    use kr_e2e_m1b::view::{View, answer_question};
    use kr_e2e_m1b::window::{COLUMNS, ROWS, Window, answered, contains};
    use kr_e2e_m1b::{LIVENESS, shells};
    use kr_protocol::method::Method;
    use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
    use kr_protocol::scalars::Nullable;

    const LEG: &str = "terminal";
    let Some(checkpoint) = Checkpoint::from_environment(LEG) else {
        return;
    };
    checkpoint.left(
        LEG,
        "nothing: this leg pairs directly and never contacts the site",
    );
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the terminal leg's managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping the terminal leg: {why}");
            return;
        }
    };
    let runtime = runtime();
    let run = Run::start(LEG);
    let host = Host::start(
        &run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );

    // The device pairs as the host's first owner, by direct QR over loopback.
    let device = runtime.block_on(Device::create("phone", &run.root().join("d")));
    let (paired, remote) = ceremony::pair_first_owner(&host, &device, &runtime);

    // The person's own startup, with the marked entry the product installs.
    let home = run.home();
    std::fs::write(home.join(".zshrc"), ZSHRC).expect("writes the startup file");
    let mut variables = host.variables();
    variables.push(("ZDOTDIR".to_owned(), home.display().to_string()));
    variables.push(("SHELL".to_owned(), shell.executable.display().to_string()));
    let mut install = host.command(&["shell", "install", "--json"]);
    install.envs(variables.iter().cloned());
    let installed = kr_e2e_m1b::run::output_within(install, LIVENESS)
        .unwrap_or_else(|why| panic!("kr shell install: {why}"));
    assert!(
        installed.status.success(),
        "kr shell install: {}{}",
        String::from_utf8_lossy(&installed.stdout),
        String::from_utf8_lossy(&installed.stderr)
    );
    let startup = std::fs::read_to_string(home.join(".zshrc")).expect("the startup file");
    assert!(
        startup.len() > ZSHRC.len() && startup.starts_with(ZSHRC),
        "kr shell install added its marked entry after the person's own lines: {}",
        String::from_utf8_lossy(&installed.stdout)
    );
    let first = Agent::place(&run, &host, "a1");
    let second = Agent::place(&run, &host, "a2");

    // Enter an integrated shell: `kr new` on a terminal of its own makes a managed session and
    // attaches it.
    let work = run.work();
    let mut local = Window::open(
        &run,
        "kr new",
        &run.binary("kr"),
        &[
            "new",
            "--attach",
            "--headless",
            "--shell",
            &shell.executable.display().to_string(),
            "--shell-mode",
            "managed",
            "--startup",
            "interactive",
            "--cwd",
            &work.display().to_string(),
        ],
        run.root(),
        &variables,
    );
    answered(&local, local.answer_capability_queries(0));
    let _ = local.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at the terminal");
    let sessions = host.live_sessions();
    assert_eq!(sessions.len(), 1, "one live session: {sessions:?}");
    let session_id: kr_protocol::ids::SessionId = sessions[0]["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("a session identifier");
    let display = sessions[0]["display_number"].to_string();
    let status = host.kr_json(&["status", &display]);
    assert_eq!(
        status["shell_mode"], "managed",
        "a managed session: {status}"
    );
    let worker = worker_of(&run, &session_id.to_string());
    let doctor = host.kr_json(&["doctor"]);
    println!(
        "the workers run under: {}",
        check(&doctor, "supervisor").map_or_else(
            || "a supervisor kr doctor does not name".to_owned(),
            |check| check["detail"].to_string()
        )
    );

    // Launch an agent, as a person does, by typing its name at the prompt.
    local.type_text(first.command_line("first").as_bytes());
    let _ = local.wait_for_screen(ASKED, "the first agent asks its question");
    let first_agent = recorded(&run, "the first agent", || first.pid());
    let first_tools = recorded(&run, "the first agent's tool server", || first.tools_pid());

    // Use it remotely: the device attaches over iroh and is drawn the session's screen.
    let snapshot: EventsSnapshotResult = runtime
        .block_on(remote.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|error| panic!("events.snapshot: {error}"));
    let root = snapshot
        .session
        .root_process
        .0
        .clone()
        .expect("the session names its root shell");
    run.record(root.clone(), "the session's root shell");
    let dimensions = snapshot.geometry.dimensions;
    let mut view = runtime
        .block_on(View::attach(
            &remote,
            session_id,
            dimensions,
            &StreamCursors::new(),
        ))
        .unwrap_or_else(|why| panic!("the device attaches: {why}"));
    let _ = runtime
        .block_on(view.wait_for(&remote, ASKED, LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    println!(
        "the device is drawn the session {}",
        if view.projected() {
            "as a projection"
        } else {
            "as its byte stream"
        }
    );

    // The device answers the agent's question, and the agent's wait returns exactly that answer.
    let mut defects = Vec::new();
    let (question, revision) =
        question_to_answer(&runtime, &remote, &mut view, session_id, &[], &mut defects);
    let resolved = runtime
        .block_on(answer_question(
            &remote, session_id, question, revision, ANSWER,
        ))
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        resolved
            .question
            .answer
            .0
            .as_ref()
            .map(|record| record.device_id),
        Some(Nullable::some(paired.device_id)),
        "the host records the answer as this device's"
    );
    let _ = runtime
        .block_on(view.wait_for(&remote, &format!("{ANSWERED}{ANSWER}"), LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        first
            .answered()
            .map(|kept| kept.to_string().contains(ANSWER)),
        Some(true),
        "the agent's wait returned the device's answer"
    );

    // The local terminal is detached from another command. The session, its shell and its agent
    // go on, and the terminal is put back.
    let local_attachment = snapshot
        .attachments
        .iter()
        .map(|attachment| attachment.attachment_id)
        .find(|attachment| *attachment != view.attachment_id())
        .expect("the local terminal's attachment");
    let detached = host.kr_json(&[
        "detach",
        &display,
        "--attachment",
        &local_attachment.to_string(),
    ]);
    assert_eq!(detached["detached"], local_attachment.to_string());
    assert_eq!(
        local.exit_code(LIVENESS),
        0,
        "kr new ends when its terminal is detached"
    );
    assert!(
        local.in_line_mode(),
        "the local terminal is put back in line mode"
    );

    // Holding the input lease, the device types into the agent.
    let acquired = runtime
        .block_on(view.acquire(&remote))
        .unwrap_or_else(|why| panic!("{why}"));
    let written = runtime
        .block_on(view.type_text(&remote, "go on\r"))
        .unwrap_or_else(|why| panic!("{why}"));
    assert!(
        written.forwarded_bytes.get() > 0,
        "the device's input reached the agent"
    );
    let _ = runtime
        .block_on(view.wait_for(&remote, WENT_ON, LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));

    // The device detaches. What it carries across is its client state: how far it applied the
    // session's output, and the outcome of every action it submitted, each of which the host
    // settled while it was attached. The session lives on, with its shell, its agent and its tool
    // server.
    runtime
        .block_on(view.pump(&remote, Duration::from_millis(500)))
        .unwrap_or_else(|why| panic!("{why}"));
    let before = content(&view.rows());
    let typed_before = view.acknowledged();
    let carried = runtime.block_on(ClientState::from_session(remote.session(), None));
    assert!(
        carried.unresolved_actions().is_empty(),
        "every action the device submitted was settled before it detached: {:?}",
        carried.unresolved_actions()
    );
    let _ = runtime
        .block_on(view.detach(&remote))
        .unwrap_or_else(|why| panic!("{why}"));
    remote.close();
    drop(view);
    let status = host.kr_json(&["status", &display]);
    assert_eq!(
        status["state"], "live",
        "the session outlives its clients: {status}"
    );
    for (identity, what) in [
        (&worker, "the worker"),
        (&root, "the root shell"),
        (&first_agent, "the agent"),
        (&first_tools, "the tool server"),
    ] {
        assert!(
            running(identity),
            "{what} goes on after the device detached"
        );
    }

    // The device reattaches over a new connection, resuming from what it had applied, and is
    // drawn the screen as it now is: the agent's current line, not the one it erased, and no
    // clipboard write or bell replayed.
    let remote = runtime
        .block_on(device.reconnect(&paired, carried.cursors.clone()))
        .unwrap_or_else(|why| panic!("the device reconnects: {why}"));
    let mut view = runtime
        .block_on(View::attach(
            &remote,
            session_id,
            dimensions,
            &carried.cursors,
        ))
        .unwrap_or_else(|why| panic!("the device reattaches: {why}"));
    let rows = runtime
        .block_on(view.wait_for(&remote, WENT_ON, LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    assert!(
        !rows.iter().any(|row| row.contains(ERASED)),
        "the reattached screen does not show a line the session erased:\n{}",
        rows.join("\n")
    );
    assert_eq!(
        content(&rows),
        before,
        "the reattached device is drawn the screen it detached from, which nothing has changed"
    );
    assert!(
        !contains(view.output(), b"\x1b]52;") && !contains(view.output(), b"\x07"),
        "nothing replays the clipboard write or the bell"
    );

    // The device ends the agent, runs shell commands, and launches a second agent. The new
    // connection is a new input stream: the lease starts it from nothing, and nothing typed on the
    // old connection is sent again.
    let reacquired = runtime
        .block_on(view.acquire(&remote))
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        reacquired.lease.next_sequence.get(),
        0,
        "a new connection's input starts afresh, with nothing replayed"
    );
    assert!(
        reacquired.lease.epoch > acquired.lease.epoch,
        "the reattached device holds a lease of a later epoch than the one it typed under before"
    );
    let _ = runtime
        .block_on(view.type_text(&remote, "finish\r"))
        .unwrap_or_else(|why| panic!("{why}"));
    let _ = runtime
        .block_on(view.wait_for(&remote, "first-ended-0", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    assert!(
        view.rows()
            .iter()
            .any(|row| row.contains(&format!("{ENDED}0"))),
        "the agent's tool server ended cleanly"
    );
    assert!(
        ended_within(&first_agent, LIVENESS),
        "the first agent has exited"
    );
    assert!(
        ended_within(&first_tools, LIVENESS),
        "its tool server has exited"
    );
    let _ = runtime
        .block_on(view.type_text(&remote, "printf 'kala%s-ran\\n' reach\r"))
        .unwrap_or_else(|why| panic!("{why}"));
    let _ = runtime
        .block_on(view.wait_for(&remote, "kalareach-ran", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    let _ = runtime
        .block_on(view.type_text(&remote, &second.command_line("second")))
        .unwrap_or_else(|why| panic!("{why}"));
    let second_agent = recorded(&run, "the second agent", || second.pid());
    let second_tools = recorded(&run, "the second agent's tool server", || {
        second.tools_pid()
    });
    let started = std::time::Instant::now();
    while second.asked().is_none() {
        assert!(
            started.elapsed() < LIVENESS,
            "the second agent asks its question"
        );
        runtime
            .block_on(view.pump(&remote, Duration::from_millis(100)))
            .unwrap_or_else(|why| panic!("{why}"));
    }
    let (next, revision) = question_to_answer(
        &runtime,
        &remote,
        &mut view,
        session_id,
        &[question],
        &mut defects,
    );
    let _ = runtime
        .block_on(answer_question(&remote, session_id, next, revision, ANSWER))
        .unwrap_or_else(|why| panic!("{why}"));
    let started = std::time::Instant::now();
    while second.answered().is_none() {
        assert!(started.elapsed() < LIVENESS, "the second agent is answered");
        std::thread::sleep(Duration::from_millis(50));
    }
    for line in ["go on\r", "finish\r"] {
        let _ = runtime
            .block_on(view.type_text(&remote, line))
            .unwrap_or_else(|why| panic!("{why}"));
    }
    let _ = runtime
        .block_on(view.wait_for(&remote, "second-ended-0", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    println!(
        "the host acknowledged each of the device's inputs: {typed_before} before it detached and \
         {} after it reattached",
        view.acknowledged()
    );
    assert!(
        ended_within(&second_agent, LIVENESS),
        "the second agent has exited"
    );
    assert!(
        ended_within(&second_tools, LIVENESS),
        "its tool server has exited"
    );
    let _ = runtime
        .block_on(view.wait_for(&remote, PROMPT.trim_end(), LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));

    // `kr attach` from the command line draws the screen the device holds.
    let mut attached = Window::open(
        &run,
        "kr attach",
        &run.binary("kr"),
        &["attach", &display],
        run.root(),
        &host.variables(),
    );
    answered(&attached, attached.answer_capability_queries(0));
    let started = std::time::Instant::now();
    let (drawn, held) = loop {
        runtime
            .block_on(view.pump(&remote, Duration::from_millis(200)))
            .unwrap_or_else(|why| panic!("{why}"));
        let mut terminal = Terminal::new(COLUMNS, ROWS);
        terminal.feed(&attached.collected().since(0));
        let drawn = content(&terminal.rows());
        let held = content(&view.rows());
        if drawn == held || started.elapsed() > LIVENESS {
            break (drawn, held);
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(
        drawn,
        held,
        "kr attach draws the screen the device holds.\nkr attach:\n{}\nthe device:\n{}",
        drawn.join("\n"),
        held.join("\n")
    );

    // The session closes with its shell.
    let mark = attached.mark();
    attached.type_text(b"exit\r");
    assert_eq!(
        attached.exit_code(LIVENESS),
        0,
        "kr attach ends cleanly with the session"
    );
    assert!(
        contains(
            &attached.collected().since(mark),
            b"the session closed: its shell exited with status 0"
        ),
        "kr attach says how the session closed: {}",
        String::from_utf8_lossy(&attached.collected().since(mark)).escape_debug()
    );
    let closure = runtime
        .block_on(view.wait_until_closed(&remote, LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        closure.root_exit_code.0.map(|code| code.get()),
        Some(0),
        "the device is told the shell exited with status 0: {closure:?}"
    );
    let closed = host.wait_until_closed(&display);
    println!("the session closed: {}", closed["closure"]);
    assert!(
        ended_within(&worker, LIVENESS),
        "the worker exits with its session"
    );
    remote.close();
    runtime.block_on(device.close());
    let _ = quoted(&work);

    let closing = close(&run, &host);
    println!("{closing}");
    assert!(
        defects.is_empty(),
        "every step of the workflow ran, and the host fell short in: {}",
        defects.join("; ")
    );
    checkpoint.proved(
        LEG,
        "a device attached over iroh answered an agent in a managed shell and typed into it, \
         detached and reattached to the current screen, kr attach drew that screen, and the \
         session closed with its shell",
    );
}

/// The catalogue: the host enrols the published catalogue release on the device's owner
/// confirmation of that exact root, `kr plugin repo sync` synchronises it, and `kr plugin install`
/// installs the bundled package from it at the hash `bundled-plugins.lock` pins, which the host
/// accepts only when the release's verified index names that exact package; and the bundled copy's
/// own bytes are the ones the lock names (`scripts/sync-bundled-plugins.sh --verify`).
///
/// The release is named by [`kr_e2e_m1b::RELEASE_VARIABLE`]; without one there is nothing to enrol
/// and the leg fails saying so.
#[test]
fn the_host_installs_the_published_catalogue_release_byte_for_byte_the_bundled_copy() {
    use kr_e2e_m1b::catalogue::{BundledLock, PLUGIN, enrol, pinned_root, workspace};
    use kr_e2e_m1b::device::Device;
    use kr_e2e_m1b::{LIVENESS, RELEASE_VARIABLE};
    use kr_protocol::catalogue::CatalogueKind;

    const LEG: &str = "catalogue";
    let Some(checkpoint) = Checkpoint::from_environment(LEG) else {
        return;
    };
    checkpoint.left(LEG, "nothing: this leg only reads the published release");
    let named = std::env::var(RELEASE_VARIABLE).unwrap_or_default();
    assert!(
        !named.is_empty(),
        "no published catalogue release is named: {RELEASE_VARIABLE} names the HTTPS address of \
         the release this leg enrols, and nothing was contacted"
    );
    let base = url::Url::parse(&format!("{}/", named.trim_end_matches('/')))
        .unwrap_or_else(|error| panic!("what {RELEASE_VARIABLE} names is not an address: {error}"));
    assert_eq!(
        base.scheme(),
        "https",
        "a published release is reached over https"
    );
    let metadata_url = base
        .join("metadata/")
        .expect("the metadata address")
        .to_string();
    let targets_url = base
        .join("targets/")
        .expect("the targets address")
        .to_string();
    let lock = BundledLock::read();
    let root = pinned_root(&lock);

    let runtime = runtime();
    let run = Run::start(LEG);
    let host = Host::start(&run, &HostOptions::default());
    let device = runtime.block_on(Device::create("owner", &run.root().join("d")));
    let (_, remote) = ceremony::pair_first_owner(&host, &device, &runtime);

    let added = runtime
        .block_on(enrol(
            &remote,
            "release",
            CatalogueKind::Official,
            &metadata_url,
            &targets_url,
            &root,
        ))
        .unwrap_or_else(|why| panic!("the owner device enrols the release: {why}"));
    println!(
        "enrolled {} under root {}",
        added.catalogue.catalogue_id, added.catalogue.root_digest
    );
    let synced = host.kr_json(&["plugin", "repo", "sync", "release"]);
    println!("synchronised: {synced}");
    let installed = host.kr_json(&[
        "plugin",
        "install",
        "release",
        PLUGIN,
        &lock.version,
        "--digest",
        &lock.manifest_digest,
    ]);
    let installed_digest = installed.to_string();
    assert!(
        installed_digest.contains(&lock.manifest_digest),
        "the release's {PLUGIN} is the bundled package, hash for hash: {installed}"
    );
    let mut verify = std::process::Command::new("bash");
    verify
        .arg(workspace().join("scripts/sync-bundled-plugins.sh"))
        .arg("--verify")
        .current_dir(workspace());
    let verified = kr_e2e_m1b::run::output_within(verify, LIVENESS)
        .unwrap_or_else(|why| panic!("scripts/sync-bundled-plugins.sh --verify: {why}"));
    assert!(
        verified.status.success(),
        "the bundled copy's bytes are the ones the lock names: {}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );

    remote.close();
    runtime.block_on(device.close());
    let closing = close(&run, &host);
    println!("{closing}");
    checkpoint.proved(
        LEG,
        &format!(
            "the published release was enrolled on the owner device's confirmation, synchronised, \
             and its {PLUGIN} installed at the bundled copy's hash {}",
            &lock.manifest_digest[..12]
        ),
    );
}

/// The plugin: the bundled package, installed and enabled from a generation the host verified, is
/// bound into the worker of a session running the application it matches, and the device invokes
/// the package's action through the session's broker; a device whose grant does not carry the
/// action's rights is refused the same action.
///
/// The generation is the committed development generation, served from the internal disk as a
/// local repository, so this leg depends on the binding and the broker alone and not on a release
/// being published. The application is the scripted agent under the name the package's match rule
/// recognises. The host is asked for each step in order, and the leg fails at the first one it
/// does not answer, naming it.
#[test]
fn the_installed_package_is_bound_into_the_session_and_acts_through_its_broker() {
    use kr_client::cursors::StreamCursors;
    use kr_e2e_m1b::LIVENESS;
    use kr_e2e_m1b::agent::Agent;
    use kr_e2e_m1b::catalogue::{
        BundledLock, PLUGIN, copy_tree, development_generation, directory_url, enrol, pinned_root,
    };
    use kr_e2e_m1b::device::Device;
    use kr_e2e_m1b::view::{View, pending_questions, session_target};
    use kr_protocol::agent::{
        AgentCapabilitiesParams, AgentCapabilitiesResult, AgentMutationTarget, AgentSubject,
        PluginActionInvokeParams, PluginActionInvokeResult,
    };
    use kr_protocol::catalogue::{CatalogueKind, PluginListParams, PluginListResult};
    use kr_protocol::method::Method;
    use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
    use kr_protocol::scalars::{Bytes, Nullable};

    const LEG: &str = "plugin";
    /// How long the package is given to be bound once its application is running.
    const BINDING: Duration = Duration::from_secs(30);
    /// The action the package registers.
    const ACTION: &str = "status.refresh";

    let Some(checkpoint) = Checkpoint::from_environment(LEG) else {
        return;
    };
    checkpoint.left(
        LEG,
        "nothing: this leg serves its generation from the internal disk and never contacts the site",
    );
    let lock = BundledLock::read();
    let root = pinned_root(&lock);
    let runtime = runtime();
    let run = Run::start(LEG);
    let host = Host::start(&run, &HostOptions::default());
    let device = runtime.block_on(Device::create("owner", &run.root().join("d")));
    let (_, remote) = ceremony::pair_first_owner(&host, &device, &runtime);

    // The package, from a generation the host verifies before it installs anything.
    let generation = run.root().join("generation");
    copy_tree(&development_generation(), &generation);
    let _ = runtime
        .block_on(enrol(
            &remote,
            "development",
            CatalogueKind::Local,
            &directory_url(&generation.join("metadata")),
            &directory_url(&generation.join("targets")),
            &root,
        ))
        .unwrap_or_else(|why| panic!("the owner device enrols the generation: {why}"));
    let _ = host.kr_json(&["plugin", "repo", "sync", "development"]);
    let _ = host.kr_json(&[
        "plugin",
        "install",
        "development",
        PLUGIN,
        &lock.version,
        "--digest",
        &lock.manifest_digest,
    ]);
    let _ = host.kr_json(&["plugin", "enable", PLUGIN]);

    // A session running the application the package matches: the scripted agent, under the name
    // the package's match rule recognises, launched from the session's shell by the device.
    let agent = Agent::place_as(&run, &host, "example", "example-agent");
    let work = run.work().display().to_string();
    let created = host.kr_json(&[
        "new",
        "--invisible",
        "--headless",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
        "--cwd",
        &work,
    ]);
    let session_id: kr_protocol::ids::SessionId = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("a session identifier");
    let snapshot: EventsSnapshotResult = runtime
        .block_on(remote.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|error| panic!("events.snapshot: {error}"));
    let mut view = runtime
        .block_on(View::attach(
            &remote,
            session_id,
            snapshot.geometry.dimensions,
            &StreamCursors::new(),
        ))
        .unwrap_or_else(|why| panic!("the device attaches: {why}"));
    let _ = runtime
        .block_on(view.acquire(&remote))
        .unwrap_or_else(|why| panic!("{why}"));
    let _ = runtime
        .block_on(view.type_text(&remote, &agent.command_line("example")))
        .unwrap_or_else(|why| panic!("{why}"));
    let started = std::time::Instant::now();
    while agent.asked().is_none() {
        assert!(
            started.elapsed() < LIVENESS,
            "the application starts and asks"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = run.record_pid(
        agent.pid().expect("the application's process"),
        "the application",
    );
    let _ = run.record_pid(
        agent.tools_pid().expect("its tool server's process"),
        "the application's tool server",
    );

    // The package is active in the running session's worker.
    let started = std::time::Instant::now();
    let bound = loop {
        let listed: PluginListResult = runtime
            .block_on(remote.read(
                Method::PluginList,
                &PluginListParams {
                    environment_id: remote.environment_id(),
                },
            ))
            .unwrap_or_else(|error| panic!("plugin.list: {error}"));
        let live = listed
            .plugins
            .iter()
            .find(|plugin| plugin.plugin_id.as_str() == PLUGIN)
            .map_or(0, |plugin| plugin.live_bindings.get());
        if live > 0 || started.elapsed() > BINDING {
            break live;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(
        bound > 0,
        "the installed and enabled {PLUGIN} is not active in the running session's worker: \
         plugin.list reports no live binding {BINDING:?} after its application started"
    );

    // The application instance the package is bound to, as the host names it: the source of the
    // question the application asked, and the binding revision in force for it.
    let question = runtime
        .block_on(pending_questions(&remote, session_id))
        .unwrap_or_else(|why| panic!("{why}"))
        .into_iter()
        .next()
        .expect("the application's question");
    let subject = AgentSubject {
        session_id,
        application_instance_id: question.source.application_instance_id,
    };
    let capabilities: AgentCapabilitiesResult = runtime
        .block_on(remote.read(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams { subject },
        ))
        .unwrap_or_else(|error| panic!("agent.capabilities: {error}"));
    let invoke = PluginActionInvokeParams {
        target: AgentMutationTarget {
            subject,
            binding_revision: capabilities.binding.binding_revision,
        },
        plugin_id: kr_protocol::ids::PluginId::new(PLUGIN).expect("a plugin identifier"),
        action: kr_protocol::broker::ActionName::new(ACTION).expect("an action name"),
        draft_id: Nullable::null(),
        resource_id: Nullable::null(),
        parameters: Bytes::new(
            kr_cbor::to_canonical_vec(&serde_json::json!({ "detail": "summary" }))
                .expect("the action's parameters"),
        ),
    };

    // The control first: a device whose grant does not carry the action's rights.
    let viewer = runtime.block_on(Device::create("viewer", &run.root().join("v")));
    let issuing = ceremony::issue_waiting(&host, &["--view", "60", "--direct"]);
    let _ = runtime
        .block_on(remote.confirm_pending(|_| true))
        .unwrap_or_else(|why| panic!("{why}"));
    let issued = ceremony::finished(issuing, "kr pair invite --view");
    let candidate = runtime
        .block_on(viewer.redeem(issued.document["qr_text"].as_str().expect("a QR text")))
        .unwrap_or_else(|why| panic!("{why}"));
    let approving = ceremony::approve_waiting(
        &host,
        issued.document["invitation_id"]
            .as_str()
            .expect("an invitation"),
    );
    let _ = runtime
        .block_on(remote.confirm_pending(|_| true))
        .unwrap_or_else(|why| panic!("{why}"));
    let _ = ceremony::finished(approving, "kr pair confirm");
    let paired_viewer = runtime
        .block_on(candidate.committed(LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    let watching = runtime
        .block_on(viewer.connect(&paired_viewer))
        .unwrap_or_else(|why| panic!("{why}"));
    let refused = runtime.block_on(watching.mutate::<_, PluginActionInvokeResult>(
        Method::PluginActionInvoke,
        session_target(&watching, session_id),
        &invoke,
    ));
    match refused {
        Err(error) if error.refusal() == Some(kr_protocol::error::ErrorCode::PermissionDenied) => {}
        other => panic!(
            "the action is refused to a device whose grant does not carry its rights, with \
             PERMISSION_DENIED: {other:?}"
        ),
    }
    let applied: PluginActionInvokeResult = runtime
        .block_on(remote.mutate(
            Method::PluginActionInvoke,
            session_target(&remote, session_id),
            &invoke,
        ))
        .unwrap_or_else(|error| panic!("plugin.action.invoke: {error}"));
    assert_eq!(applied.action.as_str(), ACTION);

    watching.close();
    remote.close();
    runtime.block_on(viewer.close());
    runtime.block_on(device.close());
    let closing = close(&run, &host);
    println!("{closing}");
    checkpoint.proved(
        LEG,
        &format!(
            "{PLUGIN} was bound into a running session's worker and its action ran through the \
             broker for the owner device and was refused to a device without its grant"
        ),
    );
}
