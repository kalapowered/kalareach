//! The authorised-file read check against a host that is already running, asked by hand on a Mac.
//!
//! KR-REQ-03.02: the platform's file-access controls are honoured. The cases of `desktop_checks.rs`
//! run the worker inside the test's own process, so the platform decides about the file for the
//! test program. This case asks a host that is already running to perform the read check on a
//! nominated file, and writes what the host then holds. When the file is in a place the platform
//! guards (the Desktop, Documents and Downloads folders, or a removable volume) and the program
//! the platform holds responsible for the worker has no access, the platform asks the person at
//! the machine, and the read check reports what was decided. Which program is asked about is the
//! platform's choice: the terminal application for a host that terminal started, and the host
//! program itself for a host that is its own responsible process.
//!
//! It is ignored by default because it can raise a prompt on the screen of whoever is at the
//! machine. Run it by hand against a running host, as this process, with:
//!
//! * `KR_RUNTIME_DIR` and `KR_STATE_DIR` set to the host's.
//! * the host's default worker profile set to `headless_user` in its configuration document, and a
//!   session of that profile running. The checks run in the host's default profile: with another
//!   default they end without a session, and with a desktop profile they also take a screen
//!   image, read the accessibility tree and start an application. The case reads the profile
//!   before it asks and refuses to ask for any other.
//! * `KR_FILE_ACCESS_FILE`, the absolute path the read check is nominated.
//! * `KR_FILE_ACCESS_OUT`, where the host's findings are written, as JSON.
//!
//! The read check has five seconds, so a prompt nobody has answered shows as a check that had not
//! read the file in time; answering it and asking again shows what the platform decided.
#![cfg(target_os = "macos")]

use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::desktop::{
    CapabilityChecksState, CapabilityEvidenceSource, CapabilityState,
    EnvironmentCapabilitiesCheckParams, EnvironmentCapabilitiesParams,
    EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

const PATIENCE: Duration = Duration::from_secs(90);

/// What the host shows of its capabilities now.
async fn shown(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
) -> EnvironmentCapabilitiesResult {
    client
        .request(
            Method::EnvironmentCapabilities,
            &EnvironmentCapabilitiesParams { environment_id },
        )
        .await
        .expect("the call reaches the host")
        .expect("environment.capabilities succeeds")
        .to_typed()
        .expect("a result of the declared shape")
}

/// KR-REQ-03.02: asks the running host for the read check on a nominated file and writes what the
/// host then holds. It fails if the host's default profile is not headless, if a run of the checks
/// was already going, if any check other than the read was performed, or if the record it reads
/// is not this request's: taken before the request, in another session, for another file or not a
/// disclosed probe. It passes for every state the read check can end in, so a person reads the
/// written findings for what the platform decided.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "raises the platform's file-access prompt; run by hand against a running host with KR_FILE_ACCESS_FILE and KR_FILE_ACCESS_OUT"]
async fn the_read_check_of_a_running_host_names_what_the_platform_decided() {
    let file = std::env::var("KR_FILE_ACCESS_FILE").expect("KR_FILE_ACCESS_FILE names the file");
    let out = std::env::var("KR_FILE_ACCESS_OUT").expect("KR_FILE_ACCESS_OUT names where it goes");

    let host = HostPaths::discover().expect("this user's host paths");
    let environment_id = host
        .recorded_environment_id()
        .expect("the environment identity reads")
        .expect("the host has been started");
    let endpoint = host
        .environment(environment_id)
        .controller_endpoint()
        .expect("the control endpoint");
    let build = BuildId::new("kr-by-hand/0").expect("a build identifier");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build)
        .await
        .expect("connects to the running host");

    // The checks run in the host's default profile. In any other the request would be refused for
    // want of a session or, in a desktop profile, would also capture the screen, read the
    // accessibility tree and start an application: nothing is asked of such a host.
    let before = shown(&mut client, environment_id).await;
    assert_eq!(
        before.default_worker_profile,
        WorkerProfile::HeadlessUser,
        "set the host's default worker profile to headless_user before asking for the read check"
    );
    // A run that is already going would be joined by this request, and its record is not an
    // answer to the file nominated here.
    assert_ne!(
        before.checks.state,
        CapabilityChecksState::Running,
        "a run of the checks is already going on this host; ask again when it has ended"
    );
    let asked_at = kr_ipc::now_ms();

    let request = client
        .compose(
            Method::EnvironmentCapabilitiesCheck,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &EnvironmentCapabilitiesCheckParams {
                environment_id,
                authorised_file: Nullable::some(file.clone()),
            },
        )
        .await
        .expect("the request is built");
    client
        .repeat(&request)
        .await
        .expect("the call reaches the host")
        .expect("the host takes the request for the checks");

    let found = tokio::time::timeout(PATIENCE, async {
        loop {
            let found = shown(&mut client, environment_id).await;
            if matches!(
                found.checks.state,
                CapabilityChecksState::Current | CapabilityChecksState::Failed
            ) {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the checks end within the limit");

    std::fs::write(
        &out,
        serde_json::to_string_pretty(&found).expect("the findings serialise"),
    )
    .unwrap_or_else(|error| panic!("{out} could not be written: {error}"));

    // The findings are written above whatever they say. What is accepted is the record of this
    // request: a run that began after it was asked, that ended current, in the session whose
    // worker read the file nominated here, as a disclosed probe.
    let mut problems = Vec::new();
    if found.checks.state != CapabilityChecksState::Current {
        problems.push(format!(
            "the checks ended as {:?}, failure {:?}",
            found.checks.state, found.checks.failure
        ));
    }
    match found.checks.started_at_ms.as_ref() {
        Some(started) if started.get() >= asked_at.get() => {}
        other => problems.push(format!(
            "the run began at {other:?}, which is not at or after this request at {asked_at:?}"
        )),
    }
    if found.checks.session_id.as_ref().is_none() {
        problems.push("no session is named as having performed the checks".to_owned());
    }
    match found.desktop.record(capabilities::AUTHORISED_FILE_READ) {
        None => problems.push("the read check has no record".to_owned()),
        Some(read) => {
            if read.subject.session_id.as_ref() != found.checks.session_id.as_ref() {
                problems.push(format!(
                    "the read record is about session {:?}, not the run's session {:?}",
                    read.subject.session_id, found.checks.session_id
                ));
            }
            if read.identity.binary.as_ref() != Some(&file) {
                problems.push(format!(
                    "the read record is for {:?}, not the nominated file",
                    read.identity.binary
                ));
            }
            if read.evidence_source != CapabilityEvidenceSource::DisclosedProbe {
                problems.push(format!(
                    "the read record comes from {:?}, not a disclosed probe",
                    read.evidence_source
                ));
            }
            if read.observed_at_ms.get() < asked_at.get() {
                problems.push(format!(
                    "the read record was observed at {:?}, before this request at {asked_at:?}",
                    read.observed_at_ms
                ));
            }
            if read.state == CapabilityState::PermissionRequired
                && read.disabled_reason.as_ref().is_none()
            {
                problems.push("a refusal says why, and this one does not".to_owned());
            }
        }
    }
    // Only the read ran. A host whose sessions run in a desktop profile performs the screen,
    // accessibility and application checks as well, and each of those raises a prompt of its own.
    for record in &found.desktop.records {
        if record.capability.as_str() != capabilities::AUTHORISED_FILE_READ
            && record.evidence_source == CapabilityEvidenceSource::DisclosedProbe
        {
            problems.push(format!(
                "{} was performed, and this case asks for the read check alone",
                record.capability.as_str()
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "the findings written to {out} are not the answer to this request: {problems:#?}"
    );
}
