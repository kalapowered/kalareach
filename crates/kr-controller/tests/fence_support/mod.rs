//! A fence this host owes and could not raise, brought about the way a host comes to owe one.
//!
//! A configuration that narrows the rights a grant may carry withdraws authority, and the fence it
//! owes advances the authority revision. The registry is made to refuse that advance, as a full
//! disk or a damaged file would, so the acceptance cannot raise the fence and the host refuses
//! dispatch until it can. Everything is in the test's own temporary host tree.

use kr_controller::service::Controller;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;

/// Writes one configuration document where this host reads it.
fn write_configuration(
    environment: &kr_ipc::paths::EnvironmentPaths,
    document: &ConfigurationDocument,
) {
    let path = kr_worker::config::document_path(environment);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the state directory");
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(document).as_bytes(),
    )
    .expect("the document");
}

/// A configuration document that narrows the rights a grant may carry to `rights`, which withdraws
/// authority and owes a fence.
fn narrowing_document(rights: &[ActionRight]) -> ConfigurationDocument {
    let mut narrowed = ConfigurationDocument::empty();
    narrowed.revision = 1;
    narrowed.ceilings.grant_rights = Nullable::some(
        rights
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect(),
    );
    narrowed
}

/// Makes this environment's registry refuse the revision advance a fence needs, until the returned
/// connection drops the trigger.
fn refuse_fences(environment: &kr_ipc::paths::EnvironmentPaths) -> rusqlite::Connection {
    let registry =
        rusqlite::Connection::open(environment.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_fence BEFORE UPDATE OF authority_revision ON environment
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    registry
}

/// Puts a configuration that withdraws authority into force on a registry that refuses the fence
/// the withdrawal owes, so this host owes a fence it could not raise.
///
/// Every right the grants in these suites carry is still allowed, so the fence is the only thing
/// that can refuse what a test asks for afterwards. The returned connection holds the fault; drop
/// the trigger through it to clear it.
pub async fn owe_a_fence(
    controller: &Controller,
    environment: &kr_ipc::paths::EnvironmentPaths,
) -> rusqlite::Connection {
    let registry = refuse_fences(environment);
    write_configuration(
        environment,
        &narrowing_document(&[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::TerminalInput,
            ActionRight::VoiceUse,
        ]),
    );
    let effective = controller.effective_configuration().await;
    assert!(
        effective
            .not_in_force
            .as_ref()
            .is_some_and(|problem| problem.as_str().contains("dispatch could not be fenced")),
        "{:?}",
        effective.not_in_force
    );
    registry
}

/// Clears the fault [`owe_a_fence`] put in place.
pub fn clear_the_fault(registry: &rusqlite::Connection) {
    registry
        .execute_batch("DROP TRIGGER refuse_fence;")
        .expect("the fault is cleared");
}
