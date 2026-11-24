//! The frames this release reads from and writes to a plugin host of the release before, taken from
//! a real one.
//!
//! This release's control daemon adopts a plugin host that a daemon of the release before started,
//! and the daemon of the release before adopts one of this release's after a rollback. What either
//! says to such a host is a claim it reads (`HostRendezvous`), the acknowledgement it writes
//! (`RendezvousAccepted`), the descriptor it publishes and later reads, and `Hello` and `Verify`
//! with their answers. Only the protocol's name tells the two releases that these frames agree, so
//! the real program of the release before is run and its frames kept. One more frame reaches a
//! launcher: the start failure frame, which a host that could not start sends in place of its
//! claim; the launcher of the release before reads it, the recording does not hold it, and the case
//! of a host that cannot bind, below, shows it. Everything else of the protocol is spoken between a
//! worker and the host, and the daemon never sees it.
//!
//! The case runs the release before's real `kr-plugin-host` as its launcher would, keeps the
//! payload of every frame, and checks each one decodes with this build's types and encodes back to
//! the bytes it came from. With `KR_RECORD_PLUGIN_HOST_FRAMES` set it prints the record that
//! `retained/<level>/plugin-host-frames.json` holds, which `kr-plugin-service`'s cases read. The
//! claim, the answers and the descriptor file in it are what the release before's own program and
//! daemon wrote. The acknowledgement and the requests are the bytes this recorder wrote to that
//! program, which accepted them. What this build's launcher and daemon write is shown to be read by
//! the real program in the cases that start one and adopt one.

use std::time::Duration;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{
    Frame, HostDescriptor, HostProtocol, HostRendezvous, RendezvousAccepted, Request, RequestBody,
    ResponseBody,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Nonce256;

use super::{Host, Setup, Updated, previous, start_agent, terminal_for};
#[cfg(target_os = "linux")]
use super::{end_program, host_info_of, install_plugin, teardown};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: a plugin host of the release before, run as its
/// launcher runs it, presents a claim this build reads and verifies, accepts the acknowledgement
/// this build writes, answers `Hello` (and refuses another protocol's) and `Verify` in frames this
/// build reads, and a daemon of that release publishes a descriptor file this build reads and
/// writes back to the same bytes.
#[tokio::test(flavor = "multi_thread")]
async fn the_frames_of_the_plugin_host_of_the_release_before_are_read_and_written_back_as_they_were()
 {
    let before = previous();
    let program = before
        .programs
        .iter()
        .find(|(name, ..)| *name == "kr-plugin-host")
        .map(|(_, path, ..)| path.clone())
        .expect("the release before's plugin host");
    let host = Host::bare();
    let environment = host.tree.environment();
    environment.create().expect("the environment's directories");
    let limits = StreamKind::Control.cbor_limits();

    // The release before's program, started as its launcher starts it.
    let reservation_id = kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid());
    let rendezvous =
        launcher::rendezvous_endpoint(&environment, reservation_id).expect("an endpoint");
    let listener = Listener::bind(&rendezvous).expect("the rendezvous endpoint");
    let packages = host.scratch("plugin-packages");
    let working = host.scratch("plugin-host-directory");
    let arguments: Vec<(&str, String)> = vec![
        ("--reservation", reservation_id.to_string()),
        ("--environment", environment.environment_id().to_string()),
        ("--rendezvous", rendezvous.as_text()),
        (
            "--runtime-dir",
            environment.runtime_root().display().to_string(),
        ),
        (
            "--state-dir",
            environment.state_root().display().to_string(),
        ),
        ("--packages-dir", packages.display().to_string()),
    ];
    let mut command = std::process::Command::new(&program);
    for (flag, value) in &arguments {
        command.arg(flag).arg(value);
    }
    let mut child = command
        .current_dir(&working)
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("the release before's plugin host starts");

    // Its claim.
    let (connection, _peer) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
        .await
        .expect("the host presents a claim in time")
        .expect("the claim's connection");
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let claim_bytes = reader.read_payload().await.expect("the claim");
    let claim: HostRendezvous =
        kr_cbor::from_canonical_slice(&claim_bytes, &limits).expect("this build reads the claim");
    assert_eq!(
        kr_cbor::to_canonical_vec(&claim).expect("a claim encodes"),
        claim_bytes,
        "the claim encodes back to the bytes the release before wrote"
    );
    launcher::check_rendezvous(&claim).expect("the claim is signed by the key it presents");
    assert_eq!(claim.reservation_id, reservation_id);
    assert_eq!(
        claim.endpoint,
        launcher::host_endpoint(&environment, &HostProtocol::V3)
            .expect("an endpoint")
            .as_text(),
        "the host serves on the endpoint of the protocol both releases speak"
    );

    // The acknowledgement this build writes, which the program takes before it serves.
    let accepted = RendezvousAccepted {
        reservation_id,
        environment_id: environment.environment_id(),
        endpoint: claim.endpoint.clone(),
    };
    let accepted_bytes = kr_cbor::to_canonical_vec(&accepted).expect("an acknowledgement encodes");
    writer
        .write_message(&accepted)
        .await
        .expect("the acknowledgement");

    // `Hello`, a `Hello` for a protocol it does not speak, and `Verify`.
    let descriptor = HostDescriptor {
        protocol: HostProtocol::V3.name.to_owned(),
        environment_id: environment.environment_id(),
        reservation_id: claim.reservation_id,
        endpoint: claim.endpoint.clone(),
        boot_identity: claim.boot_identity.clone(),
        process_start_identity: claim.process_start_identity.clone(),
        host_public_key: claim.host_public_key,
    };
    let endpoint = Endpoint::from_path(&claim.endpoint).expect("the host's endpoint");
    let connection = Connection::connect(&endpoint)
        .await
        .expect("the host answers");
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let nonce = Nonce256::from_bytes([7; 32]);
    let mut exchange = Vec::new();
    for (request_id, body) in [
        (
            1,
            RequestBody::Hello {
                protocol: HostProtocol::V3.name.to_owned(),
            },
        ),
        (
            2,
            RequestBody::Hello {
                protocol: "kr-plugin-host/99".to_owned(),
            },
        ),
        (3, RequestBody::Verify { nonce }),
    ] {
        let request = Request { request_id, body };
        let request_bytes = kr_cbor::to_canonical_vec(&request).expect("a request encodes");
        writer.write_message(&request).await.expect("the request");
        let (response_bytes, answer) = loop {
            let payload = reader.read_payload().await.expect("the host answers");
            let frame: Frame = kr_cbor::from_canonical_slice(&payload, &limits)
                .expect("this build reads the host's frame");
            assert_eq!(
                kr_cbor::to_canonical_vec(&frame).expect("a frame encodes"),
                payload,
                "the frame encodes back to the bytes the release before wrote"
            );
            if let Frame::Response { reply_to, body } = frame
                && reply_to == request_id
            {
                break (payload, body);
            }
        };
        match (request_id, answer) {
            (
                1,
                ResponseBody::Hello {
                    protocol,
                    descriptor: told,
                },
            ) => {
                assert_eq!(protocol, HostProtocol::V3.name);
                // The host's own account of its descriptor names no reservation: the launcher's
                // is the one published.
                assert_eq!(told.reservation_id.to_string(), uuid_nil());
                assert_eq!(
                    HostDescriptor {
                        reservation_id: claim.reservation_id,
                        ..*told
                    },
                    descriptor
                );
            }
            (2, ResponseBody::Refused { request, .. }) => assert_eq!(request, "hello"),
            (3, ResponseBody::Verified(proof)) => {
                launcher::check_proof(&descriptor, &nonce, &proof)
                    .expect("the proof verifies against the descriptor the claim gives");
            }
            (id, other) => panic!("request {id} was answered {other:?}"),
        }
        exchange.push(serde_json::json!({
            "request": hex(&request_bytes),
            "response": hex(&response_bytes),
        }));
    }
    drop(writer);
    drop(reader);
    child.kill().expect("the host ends");
    let _ = child.wait();

    // The descriptor file the release before's own daemon publishes for such a host: this build
    // reads it and writes the same bytes back.
    let prepared = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await;
    let agent = prepared.host.plugin_agent();
    let terminal = terminal_for(
        &prepared.host,
        &prepared.kr_before(),
        &["attach", &prepared.display],
    );
    terminal.ready().await;
    let program = start_agent(&prepared.host, &terminal, &agent).await;
    prepared.host.plugin_holding(1).await;
    let published = std::fs::read(
        prepared
            .host
            .tree
            .environment()
            .runtime_dir()
            .join(HostProtocol::V3.descriptor),
    )
    .expect("the descriptor the release before published");
    let read: HostDescriptor =
        serde_json::from_slice(&published).expect("this build reads the descriptor");
    assert_eq!(read.protocol, HostProtocol::V3.name);
    assert_eq!(
        serde_json::to_vec(&read).expect("a descriptor encodes"),
        published,
        "the descriptor encodes back to the bytes the release before's daemon wrote"
    );
    super::end_program(&program);
    drop(terminal);
    prepared
        .host
        .close(&prepared.kr_before(), &prepared.display);
    prepared.host.worker_ended(&prepared.worker).await;
    prepared.host.end_the_plugin_host().await;

    if std::env::var_os("KR_RECORD_PLUGIN_HOST_FRAMES").is_some() {
        let record = serde_json::json!({
            "release": before.release.as_str(),
            "arguments": arguments.iter().map(|(flag, _)| *flag).collect::<Vec<_>>(),
            "nonce": hex(nonce.as_bytes()),
            "claim": hex(&claim_bytes),
            "accepted": hex(&accepted_bytes),
            "exchange": exchange,
            "descriptor_file": String::from_utf8(published).expect("a text file"),
        });
        println!(
            "PLUGIN-HOST-FRAMES-JSON-BEGIN\n{}\nPLUGIN-HOST-FRAMES-JSON-END",
            serde_json::to_string_pretty(&record).expect("a record")
        );
    }
}

/// The longest this case watches the daemon after the worker has asked for the plugin runtime: past
/// the thirty seconds the launcher of the release before waits for a host to report itself.
#[cfg(target_os = "linux")]
const WATCH: Duration = Duration::from_secs(45);

/// How many processes run as the plugin host `program`, by the command line the system reports.
#[cfg(target_os = "linux")]
fn hosts_running(program: &std::path::Path) -> usize {
    let output = std::process::Command::new("ps")
        .args(["-ww", "-axo", "args="])
        .output()
        .expect("ps runs");
    let program = program.display().to_string();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with(&program))
        .count()
}

/// Whether a job's diagnostics file in `jobs` holds what this build's plugin host writes as it ends
/// for an endpoint named `socket_name`.
fn a_host_said_why_it_could_not_start(jobs: &std::path::Path, socket_name: &str) -> bool {
    std::fs::read_dir(jobs)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "diagnostics")
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .any(|text| text.contains("kr-plugin-host: ") && text.contains(socket_name))
}

/// A plugin host of this build, started by the daemon of the release before in a layout that has no
/// store, whose endpoint has a file on it, does not hang the daemon: the host sends the frame that
/// says why it could not start, the launcher of the release before reads it as the host's reason
/// and ends its wait, and the host ends with the connection. No host is published, the daemon goes
/// on serving, and the session's worker is the one it was.
///
/// The case shows that the scenario happened: the plugin host of this build is seen to have been
/// started by the release before's launcher (it leaves its reason in a job's diagnostics), and is
/// seen to have ended by itself, while the daemon is watched. It does not read the binding's own report (`ComponentState::Unavailable`): nothing
/// in this suite reads a worker's bindings.
///
/// The daemon is the release before's real one, started with `--worker` naming a folder that holds
/// the release before's worker and this build's `kr-plugin-host`, which the daemon takes from beside
/// the worker; a daemon of an installed release refuses `--worker`, so the layout has no store. No
/// service manager is reachable: run by name on Linux as
/// `env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS cargo test --locked -p kr-cli --test
/// upgrade --features upgrade-suite -- --nocapture --ignored --exact
/// plugin_host_frames::a_host_that_cannot_bind_beside_the_daemon_of_the_release_before_leaves_it_serving`,
/// after `cargo build --locked -p kr-controller -p kr-worker -p kr-hook -p kr-plugin-host`,
/// `cargo build --locked -p kr-controller --features testing --bin kr-controller-held` and
/// `cargo build --locked -p kr-describe-model --bin kr-describe-inference`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by name on Linux with XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS removed from the environment"]
async fn a_host_that_cannot_bind_beside_the_daemon_of_the_release_before_leaves_it_serving() {
    for variable in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        assert!(
            std::env::var_os(variable).is_none(),
            "{variable} is set: run this case by name with \
             `env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS`"
        );
    }
    let before = previous();
    let mut host = Host::bare_in(teardown::Tree::create().without_service_manager());
    let environment = host.tree.environment();
    environment.create().expect("the environment's directories");
    install_plugin(&host).await;

    // The release before's programs, with this build's plugin host beside its worker.
    let programs = host.scratch("the-release-before");
    for (name, path, ..) in before.programs {
        if *name != "kr-plugin-host" {
            kr_ipc::testing::place_program(path, &programs.join(name));
        }
    }
    let this_builds_host = std::env::current_exe()
        .expect("this test's path")
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the directory the programs are built in")
        .join("kr-plugin-host");
    assert!(
        this_builds_host.is_file(),
        "{} is not built; run `cargo build --locked -p kr-plugin-host` first",
        this_builds_host.display()
    );
    kr_ipc::testing::place_program(&this_builds_host, &programs.join("kr-plugin-host"));

    // A file where the plugin host binds.
    let endpoint = launcher::host_endpoint(&environment, &HostProtocol::V3).expect("an endpoint");
    std::fs::write(endpoint.as_path(), b"").expect("a file where the plugin host binds");

    let mut arguments = host.daemon_arguments();
    arguments.push("--worker".to_owned());
    arguments.push(programs.join("kr-worker").display().to_string());
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    // The daemon is given the home and working folder of this tree and nothing of this test's
    // environment, and a folder of its own for its `PATH` that holds Git alone, so it finds no
    // other program of the system by name: every program it runs but Git is named by its whole
    // path.
    let tools = host.scratch("only-git");
    let git = std::env::var_os("PATH")
        .and_then(|search| {
            std::env::split_paths(&search)
                .map(|folder| folder.join("git"))
                .find(|candidate| candidate.is_file())
        })
        .expect("Git is on this test's path");
    std::os::unix::fs::symlink(&git, tools.join("git")).expect("Git in the daemon's tools folder");
    let mut command = std::process::Command::new(programs.join("kr-controller"));
    command.args(&arguments);
    kr_ipc::testing::started_environment::StartedEnvironment::within(host.tree.root())
        .apply(&mut command)
        .env("PATH", &tools)
        .env(
            "KR_RUNTIME_DIR",
            host.tree.paths().runtime_root().display().to_string(),
        )
        .env(
            "KR_STATE_DIR",
            host.tree.paths().state_root().display().to_string(),
        );
    host.start_daemon_as(command).await;

    let kr = programs.join("kr");
    let (display, session_id) = host.new_session(&kr);
    let worker = host.worker_process(session_id);
    let agent = host.plugin_agent();
    let terminal = terminal_for(&host, &kr, &["attach", &display]);
    terminal.ready().await;
    let program = start_agent(&host, &terminal, &agent).await;

    // The worker asks for the plugin runtime, and the release before's launcher starts this
    // build's host. The release before's launcher reads the frame and drops the connection, so the
    // host ends at once and lives for milliseconds: it is seen by what it leaves, the
    // job's diagnostics file, where it writes why it could not start (the service manager's own
    // record of a job's standard error stays after the job). The daemon is watched from the first
    // sight, for longer than the launcher's whole wait.
    let host_program = programs.join("kr-plugin-host");
    let jobs = environment.jobs_dir();
    let socket_name = endpoint
        .as_path()
        .file_name()
        .expect("the endpoint's name")
        .to_string_lossy()
        .into_owned();
    let mut began = None;
    let seen = std::time::Instant::now();
    while began.is_none() && seen.elapsed() < Duration::from_secs(120) {
        if a_host_said_why_it_could_not_start(&jobs, &socket_name) {
            began = Some(std::time::Instant::now());
        } else {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(
        began.is_some(),
        "the release before's launcher started this build's plugin host, which said why it could \
         not start in a job's diagnostics under {}",
        jobs.display()
    );
    let began = began.unwrap_or(seen);
    // One loop from the first sight to the end of the watch: the host is seen to have ended, no
    // host is published, and the daemon serves a status request, at every step.
    let mut ended = false;
    while began.elapsed() < WATCH {
        ended = ended || hosts_running(&host_program) == 0;
        assert_eq!(
            host.plugin_host(),
            None,
            "no plugin host is published beside a file at its endpoint"
        );
        assert_eq!(
            host_info_of(&host).await.environment_id,
            host.tree.environment_id(),
            "the daemon still serves a status request"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        ended,
        "the host ended by itself and did not hold the daemon"
    );
    assert_eq!(
        host.plugin_host(),
        None,
        "at the end of the watch no plugin host is published"
    );
    assert_eq!(
        host_info_of(&host).await.environment_id,
        host.tree.environment_id(),
        "at the end of the watch the daemon serves a status request"
    );
    assert_eq!(
        host.worker_process(session_id),
        worker,
        "the session's worker is the process it was"
    );
    assert!(
        endpoint.as_path().is_file(),
        "and the file kr did not make is where it was"
    );
    end_program(&program);
}

/// The nil identifier's text.
fn uuid_nil() -> String {
    kr_protocol::scalars::Uuid::from_bytes([0; 16]).to_string()
}
