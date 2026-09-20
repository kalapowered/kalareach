//! What the archive refuses to read, and why it refuses on silence.
//!
//! A read of a closed session is safe only where this host can say the session's worker is gone.
//! Three things can say so and a closure erases two of them, so the daemon asks all three: the
//! registry's worker row, the closure's own record of a worker it never saw end, and the published
//! descriptor. This is about the fourth answer, which is no answer at all: a registry this host
//! cannot read says nothing, and nothing is not "no worker".

use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::{BuildId, SessionId};

/// A supervisor that starts nothing, because no test here needs a worker.
#[derive(Debug)]
struct NoSupervisor;

impl WorkerSupervisor for NoSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registry_this_host_cannot_read_refuses_the_archive_rather_than_serving_it() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let registry_path = environment.registry_database();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoSupervisor),
        terminal: Box::new(kr_controller::supervision::NoTerminal),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
    })
    .await
    .expect("the daemon starts");

    let session_id = SessionId::new(kr_ipc::new_uuid());
    // A session this daemon has no record of reads as an archive of what is left, which is
    // nothing. That is the answer when the registry can be read.
    controller
        .session_archive(session_id)
        .await
        .expect("a session with no record still reads");

    // Now the registry cannot answer. The rows it would have been asked for are gone, and the
    // daemon's own connection sees that the moment it asks.
    {
        let connection = rusqlite::Connection::open(&registry_path).expect("opens the registry");
        connection
            .execute_batch("DROP TABLE workers;")
            .expect("takes the worker table away");
    }
    // Give the daemon a moment to be between its own reads, so this is the archive's answer and
    // not a race with startup.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let refused = controller
        .session_archive(session_id)
        .await
        .expect_err("a registry that cannot answer is not an absence of workers");
    assert!(
        !refused.to_string().is_empty(),
        "the refusal says something: {refused}"
    );
}
