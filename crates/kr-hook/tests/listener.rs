//! The forwarder against the worker's own listener.
//!
//! Every case here but the last runs the real composition: the worker's gateway binds the endpoint,
//! launches a stand-in application through the same launch path production uses, and writes the
//! registration and the owner-only credential file into that application's environment. The
//! application then starts `kr-hook claude-code hook` itself, as Claude Code starts a hook, so the
//! process the kernel names on the accepted socket is a process the launched application started.
//!
//! The last case stands in for the worker's listener, on the private endpoint the platform gives a
//! launch: a socket on Unix, a named pipe on Windows. The application it launches is a shell of its
//! own, `/bin/sh` or a copy of `cmd.exe`.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.43 | every case: the registration file and the private exchange, never a session identifier alone |
//! | KR-REQ-12.14 | `kr_req_12_14_*`: the private endpoint, and the per-launch credential |
//! | KR-REQ-05.09 | `kr_req_05_09_*`: the installation is validated before anything is accepted |

mod common;

use tokio::io::AsyncWriteExt as _;

use common::{LIVENESS, Placed, StandIn, launched, read_line, run_with_input};

/// A `SessionStart` payload as Claude Code writes it on a hook's standard input.
const SESSION_START: &[u8] = br#"{"session_id":"4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}"#;

/// KR-REQ-11.43, KR-REQ-12.14: a hook the launched application starts reaches the private socket
/// the registration names, presents the launch's private exchange and its own process, and is
/// admitted as the installed bridge's hook; the process the kernel named is that hook, not the
/// application. The hook still answers exactly `{}` and exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_14_a_hook_the_launched_application_starts_is_admitted() {
    let placed = Placed::new();
    let mut launch = launched::Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed(
            &placed.forwarder,
            &[
                kr_worker::broker::BridgeSurface::Hook,
                kr_worker::broker::BridgeSurface::Channel,
            ],
        ),
    );
    assert!(
        launch
            .gateway
            .registration()
            .expect("the launch publishes a registration")
            .contains(if cfg!(windows) {
                r"endpoint=\\.\pipe\"
            } else {
                "endpoint=/"
            }),
        "the registration names the private endpoint the platform gives a launch"
    );
    assert_eq!(
        launch
            .broker
            .binding_state(launched::instance())
            .expect("the launch registered its instance")
            .mode,
        kr_protocol::broker::IntegrationMode::NativeBridge,
        "the application is integrated through a bridge beside its unchanged terminal"
    );
    let request = launch.hook(SESSION_START);
    let admitted = launch.accept().await.expect("the hook is admitted");
    assert_eq!(admitted.surface, kr_worker::broker::BridgeSurface::Hook);
    assert_ne!(
        admitted.process.identity.pid.get(),
        u64::from(launch.application.id()),
        "the admitted process is the hook the application started, not the application"
    );
    assert_eq!(
        admitted
            .process
            .starter
            .as_ref()
            .map(|starter| starter.pid.get()),
        Some(u64::from(launch.application.id())),
        "and the application started it itself"
    );
    assert!(
        admitted.process.started.is_some(),
        "the kernel's forward-only record of its start is read"
    );
    // The worker reads the observation the hook sent behind its hello and closes the connection,
    // which is what the hook waits for before it answers.
    let report = tokio::time::timeout(LIVENESS, launch.gateway.observe_hook(admitted))
        .await
        .expect("the observation arrives in time")
        .expect("its observation is applied");
    assert_eq!(
        report.observation.event,
        kr_worker::broker::ObservedEvent::ThreadStarted
    );
    let outcome = launched::outcome(&request);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, b"{}\n");
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
}

/// KR-REQ-11.43: the launch binding and the private exchange are both required. A hook that
/// presents a credential other than the launch's is refused, and so is the forwarder with the right
/// files when the launched application did not start it. Each still answers `{}` and exits 0, so a
/// refusal changes nothing about what the application does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_the_wrong_exchange_or_a_process_the_application_did_not_start_is_refused() {
    let placed = Placed::new();
    let mut launch = launched::Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed(&placed.forwarder, &[kr_worker::broker::BridgeSurface::Hook]),
    );

    // The forwarder, run by this test rather than by the application, with the launch's own
    // registration and credential in its environment.
    let registration = launch.runtime.join("registration");
    let deadline = std::time::Instant::now() + LIVENESS;
    while !registration.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the registration is written"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let mut outsider = placed.command(&["claude-code", "hook"]);
    outsider
        .env("KR_REGISTRATION", &registration)
        .env("KR_SESSION", "the-session-this-process-names");
    let running = std::thread::spawn(move || run_with_input(outsider, SESSION_START));
    let refused = launch
        .accept()
        .await
        .expect_err("a process the application did not start is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        refused.to_string().contains("was not started by"),
        "{refused}"
    );
    let ran = running.join().expect("the outsider ran");
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(ran.stdout, b"{}\n");

    // The application's own hook, with a credential other than the launch's.
    std::fs::write(launch.credential_file(), "0".repeat(64)).expect("the credential is replaced");
    let request = launch.hook(SESSION_START);
    let refused = launch
        .accept()
        .await
        .expect_err("the wrong private exchange is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        refused.to_string().contains("private exchange"),
        "{refused}"
    );
    let outcome = launched::outcome(&request);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, b"{}\n");
    assert!(
        outcome.stderr.contains("without admitting"),
        "the hook says why on standard error only: {}",
        outcome.stderr
    );
}

/// KR-REQ-11.43, KR-REQ-12.14: a connection that presents only an environment session
/// identifier, or presents another process's identity with the right exchange, is refused: the
/// kernel's naming of the peer and the private exchange decide, never what the environment says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_a_session_identifier_alone_or_a_borrowed_identity_is_refused() {
    use tokio::io::AsyncWriteExt as _;
    let placed = Placed::new();
    let launch = launched::Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed(&placed.forwarder, &[kr_worker::broker::BridgeSurface::Hook]),
    );
    let endpoint = launch.gateway.address().for_diagnostics();
    let application = kr_ipc::identity::process_start_identity(launch.application.id())
        .expect("the application's identity");
    let this = kr_ipc::identity::current_process_start_identity().expect("this process");
    let credential = std::fs::read_to_string(launch.credential_file()).expect("the credential");
    let bridge = serde_json::json!({"application": "claude-code", "surface": "hook"});
    let cases = [
        (
            "a session identifier and nothing else",
            serde_json::json!({"kr_hello": {
                "credential": "",
                "pid": this.pid.get(),
                "start": this.start_value.get(),
                "session": "the-session-this-process-names",
                "bridge": bridge,
            }}),
        ),
        (
            "the launched application's identity, borrowed",
            serde_json::json!({"kr_hello": {
                "credential": credential.trim(),
                "pid": application.pid.get(),
                "start": application.start_value.get(),
                "session": null,
                "bridge": bridge,
            }}),
        ),
    ];
    for (case, hello) in cases {
        let address = endpoint.clone();
        let connecting = tokio::spawn(async move {
            let mut stream = common::connect(&address).await;
            let mut line = hello.to_string().into_bytes();
            line.push(b'\n');
            stream.write_all(&line).await.expect("the hello is written");
            stream
        });
        let refused = launch.accept().await.expect_err(case);
        assert_eq!(
            refused.code(),
            kr_protocol::error::ErrorCode::PermissionDenied,
            "{case}: {refused}"
        );
        drop(connecting.await.expect("the connection was made"));
    }
}

/// KR-REQ-05.09: the host validates the integration's installation before it accepts anything
/// from it. The forwarder at a path the installation did not put in place is refused, and so is a
/// hook when the installed recipe registered no hooks, although the launch binding and the
/// private exchange are both right.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_05_09_a_bridge_the_installation_did_not_put_in_place_is_refused() {
    let placed = Placed::new();
    let elsewhere = placed
        .host
        .root()
        .join("bin")
        .join(format!("kr-hook-elsewhere{}", std::env::consts::EXE_SUFFIX));
    kr_ipc::testing::place_program(&placed.forwarder, &elsewhere);
    let mut launch = launched::Launch::start(
        &placed,
        &elsewhere,
        launched::installed(&placed.forwarder, &[kr_worker::broker::BridgeSurface::Hook]),
    );
    let request = launch.hook(SESSION_START);
    let refused = launch
        .accept()
        .await
        .expect_err("a forwarder the installation did not put in place is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        refused.to_string().contains("installed forwarder"),
        "{refused}"
    );
    let outcome = launched::outcome(&request);
    assert_eq!((outcome.code, outcome.stdout.as_slice()), (0, &b"{}\n"[..]));
    drop(launch);
    // One placed program is held at a time, so this one is let go of before the next is placed.
    drop(placed);

    let placed = Placed::new();
    let mut launch = launched::Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed(
            &placed.forwarder,
            &[kr_worker::broker::BridgeSurface::Channel],
        ),
    );
    let request = launch.hook(SESSION_START);
    let refused = launch
        .accept()
        .await
        .expect_err("a registration the installation does not have is refused");
    assert!(
        refused.to_string().contains("hook registration"),
        "{refused}"
    );
    let outcome = launched::outcome(&request);
    assert_eq!((outcome.code, outcome.stdout.as_slice()), (0, &b"{}\n"[..]));
}

/// KR-REQ-12.14, KR-REQ-11.43: the private exchange is what decides. This listener stands in for
/// the worker's on this platform's own private endpoint (a socket on Unix, a named pipe on
/// Windows): the forwarder reaches it there only, presents exactly the credential the owner-only
/// file holds and its own process as the operating system reads it, declares which bridge it is,
/// and waits for the admission before it answers `{}`. A listener that closes without admitting it,
/// or never answers at all, changes nothing about its answer, and the one that never answers
/// cannot hold it past its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_14_over_the_private_endpoint_the_forwarder_presents_the_launch_credential() {
    let placed = Placed::new();
    let credential = "5e".repeat(32);
    let files = placed.host.root().join("files");
    kr_ipc::paths::create_private_directory(&files).expect("a private directory");
    let credential_file = files.join("credential");
    kr_ipc::paths::create_new_owner_only_file(&credential_file, credential.as_bytes())
        .expect("the credential is written");

    for answer in ["admit", "close", "withhold"] {
        let stand_in = StandIn::bind(&files, answer);
        let registration = files.join(format!("registration.{answer}"));
        std::fs::write(
            &registration,
            format!(
                "endpoint={}\nprofile=lp-1\n\
                 instance=02020202-0202-0202-0202-020202020202\npid=1\nstart=1\n\
                 credential={}\nframing=json_lines\n",
                stand_in.address,
                credential_file.display()
            ),
        )
        .expect("the registration is written");
        let mut command = placed.command(&["claude-code", "hook"]);
        command.env("KR_REGISTRATION", &registration);
        let mut running =
            tokio::task::spawn_blocking(move || run_with_input(command, SESSION_START));

        let (mut stream, peer) = tokio::select! {
            // A connection already made is taken before the forwarder's end is looked at.
            biased;
            accepted = stand_in.listener.accept() => accepted.expect("the forwarder connects"),
            ran = &mut running => {
                let ran = ran.expect("the forwarder ran");
                panic!(
                    "{answer}: the forwarder ended without connecting, with {:?}: {}",
                    ran.code, ran.stderr
                );
            }
            () = tokio::time::sleep(LIVENESS) => panic!("{answer}: the forwarder did not connect"),
        };
        let hello = read_line(&mut stream).await;
        let hello: serde_json::Value = serde_json::from_slice(&hello).expect("the hello is JSON");
        let presented = &hello["kr_hello"];
        assert_eq!(presented["credential"], credential.as_str());
        assert_eq!(
            presented["bridge"],
            serde_json::json!({"application": "claude-code", "surface": "hook"})
        );
        // The process is the forwarder's own, as the operating system reads it now, while the
        // forwarder is waiting for this listener's answer.
        let pid = u32::try_from(presented["pid"].as_u64().expect("a process")).expect("a pid");
        let read = kr_ipc::identity::process_start_identity(pid).expect("the process is running");
        assert_eq!(presented["start"].as_u64(), Some(read.start_value.get()));
        // The process the operating system names on the connection is the one the hello presents.
        assert_eq!(
            peer.pid,
            Some(pid),
            "{answer}: the kernel names the process that presented itself"
        );
        // And the host's own comparison takes it as the launch's private exchange.
        let launch_credential = kr_worker::broker::Credential::from_registration_text(&credential)
            .expect("the launch credential");
        let bytes: Vec<u8> = (0..32)
            .map(|index| {
                u8::from_str_radix(&credential[index * 2..index * 2 + 2], 16).expect("hex")
            })
            .collect();
        assert!(launch_credential.authenticates(&bytes));

        let ran = match answer {
            "admit" => {
                stream
                    .write_all(b"{\"kr_bridge\":{\"admitted\":\"hook\"}}\n")
                    .await
                    .expect("admitted");
                // The observation comes behind the hello, and the forwarder waits for this end to
                // close once it has been read.
                let observation = read_line(&mut stream).await;
                let observation: serde_json::Value =
                    serde_json::from_slice(&observation).expect("the observation is JSON");
                assert_eq!(
                    observation,
                    serde_json::json!({"kr_observation": {
                        "event": "thread_started",
                        "thread": "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11",
                        "detail": "startup",
                    }})
                );
                drop(stream);
                running.await.expect("the forwarder ran")
            }
            "close" => {
                drop(stream);
                running.await.expect("the forwarder ran")
            }
            _ => {
                // The connection stays open and says nothing until the forwarder has ended.
                let ran = running.await.expect("the forwarder ran");
                drop(stream);
                assert!(
                    ran.took < std::time::Duration::from_secs(1),
                    "a listener that never answers held the hook for {:?}, past the one-second \
                     SessionEnd timeout",
                    ran.took
                );
                ran
            }
        };
        assert_eq!(ran.code, Some(0), "{answer}: {}", ran.stderr);
        assert_eq!(ran.stdout, b"{}\n", "{answer}");
        assert_eq!(
            ran.stderr.is_empty(),
            answer == "admit",
            "{answer}: anything but an admission is said on standard error only: {}",
            ran.stderr
        );
    }
}
