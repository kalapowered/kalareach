//! An organisation's signed policy applied on a host: the adapters it allows decide which adapters
//! the host admits.
//!
//! Everything here goes through the owner's local socket, on a real daemon enrolled in an
//! organisation the way a person enrols it, with a policy the organisation's own keys signed. The
//! catalogue is the daemon's own: the example package is installed in it, and `plugin.list` says
//! whether the admissions in force let a new binding use it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.06 | the cases named `kr_req_18_06_` |

#![cfg(unix)]

mod fence_support;
mod net_support;
mod organisation_fixture;
mod organisation_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_controller::grants::applied;
use kr_plugin_catalogue::RepositoryKind;
use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, InstallationGrant, RepositoryId};
use kr_protocol::account::{OrganisationPolicy, PolicyAuthority};
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActionId, AuthorityRevision, OrganisationId, OrganisationPolicyRevision, PluginId,
};
use kr_protocol::method::Method;
use kr_protocol::organisation::{OrganisationPolicyApplyParams, OrganisationPolicyApplyResult};
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};
use net_support::pairing as calls;
use organisation_fixture::*;
use organisation_support::{MINUTE_MS, Organisation};

const EXAMPLE: &str = "kalareach/example-declarative";
const CODEX: &str = "kalareach/codex";
const CLAUDE_CODE: &str = "kalareach/claude-code";

fn example() -> PluginId {
    PluginId::new(EXAMPLE).expect("a plugin identifier")
}

fn allowed(names: &[&str]) -> Nullable<CanonicalSet<PluginId>> {
    Nullable::some(
        names
            .iter()
            .map(|name| PluginId::new(*name).expect("a plugin identifier"))
            .collect(),
    )
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    let mut stack = vec![from.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("readable").flatten() {
            let source = entry.path();
            if source.is_dir() {
                stack.push(source);
                continue;
            }
            let relative = source.strip_prefix(from).expect("inside the tree");
            let destination = to.join(relative);
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
            std::fs::copy(&source, &destination).expect("copyable");
        }
    }
}

fn directory_url(path: &Path) -> url::Url {
    let absolute = std::fs::canonicalize(path).expect("an existing directory");
    url::Url::from_directory_path(absolute).expect("an absolute path")
}

/// Installs and enables the example package in the daemon's own catalogue, from a copy of the
/// published development generation. The copy lives as long as the returned directory.
async fn install_the_example(fixture: &Fixture) -> tempfile::TempDir {
    let repository = tempfile::tempdir().expect("a directory on the internal disk");
    let published = repository.path().join("development");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/catalogue/development"),
        &published,
    );
    let environment_id = fixture.host.environment_id;
    let module = fixture.host.controller().catalogue().catalogue();
    let mut catalogue = module.lock().await;
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&published.join("metadata")),
                directory_url(&published.join("targets")),
                std::fs::read(published.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&example(), &version)
        .expect("the example package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            environment_id,
            &example(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment_id, &example(), true)
        .await
        .expect("enabled");
    repository
}

/// What `plugin.list` says of the example package's admission now.
async fn admission(fixture: &Fixture) -> wire::PluginAdmission {
    let mut client = fixture.host.client().await;
    let listed: wire::PluginListResult = calls::read(
        &mut client,
        Method::PluginList,
        &wire::PluginListParams {
            environment_id: fixture.host.environment_id,
        },
    )
    .await
    .expect("the owner reads the list");
    listed
        .plugins
        .into_iter()
        .find(|summary| summary.plugin_id == example())
        .expect("the example package is installed")
        .admission
        .0
        .expect("the admissions say where the package stands")
}

fn is_admitted(admission: &wire::PluginAdmission) -> bool {
    matches!(admission, wire::PluginAdmission::Admitted)
}

fn is_left_out_by_the_allowlist(admission: &wire::PluginAdmission) -> bool {
    matches!(
        admission,
        wire::PluginAdmission::LeftOut {
            reason: wire::PluginLeftOutReason::NotAllowed,
            ..
        }
    )
}

/// Waits until `wanted` holds of the example package's admission. It fails when it never does.
async fn until_admission(fixture: &Fixture, wanted: fn(&wire::PluginAdmission) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let now = admission(fixture).await;
        if wanted(&now) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the admissions never came to hold: {now:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Applies `policy`, with `authority` beside it, on the owner's socket under a new action.
async fn apply(
    fixture: &Fixture,
    policy: OrganisationPolicy,
    authority: Option<PolicyAuthority>,
) -> Result<OrganisationPolicyApplyResult, ProtocolError> {
    let mut client = fixture.host.client().await;
    calls::mutate_as(
        fixture.host.environment_id,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        Method::OrganisationPolicyApply,
        &OrganisationPolicyApplyParams {
            policy,
            authority: Nullable(authority),
        },
    )
    .await
}

/// That the host refused with a bad argument that names `rule`.
fn refused_as(
    outcome: Result<OrganisationPolicyApplyResult, ProtocolError>,
    rule: &str,
) -> ProtocolError {
    let error = outcome.expect_err("the host refuses the policy");
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    assert!(
        error.message.contains(&format!("({rule})")),
        "the refusal names {rule}: {error:?}"
    );
    error
}

/// The list `organisation.list` says is in force.
async fn list_in_force(fixture: &Fixture) -> Nullable<CanonicalSet<PluginId>> {
    fixture.listed().await.adapter_allowlist_in_force
}

/// Whether the doctor's catalogue evidence says that the adapters the organisations allow could not
/// be confirmed in force.
async fn the_doctor_says_the_list_is_not_in_force(
    controller: &kr_controller::service::Controller,
) -> bool {
    controller.catalogue_warnings().await.iter().any(|warning| {
        warning.contains("could not confirm that the adapters its organisations allow are in force")
    })
}

/// The state directory of the fixture's daemon, where the store of applied policies is.
fn state_dir(fixture: &Fixture) -> PathBuf {
    fixture
        .host
        .registry_database()
        .parent()
        .expect("the state directory")
        .to_path_buf()
}

/// The policies the daemon's store of applied policies holds.
fn applied_policies(fixture: &Fixture) -> Vec<applied::StoredAppliedPolicy> {
    applied::read(&state_dir(fixture)).expect("the store of applied policies reads")
}

/// Stops the daemon, lets `change` alter what it left in the state directory, and starts another
/// on the same tree: what a stop between two writes leaves for the next start.
async fn restart_over(fixture: Fixture, change: impl FnOnce(&Path)) -> Fixture {
    let stopped = fixture.host.shut_down().await;
    change(stopped.tree().environment().state_dir());
    let settings = stopped.settings().clone();
    Fixture {
        host: stopped.start(settings).await,
        ..fixture
    }
}

/// KR-REQ-18.06: a policy the organisation signed under the key the host pinned decides which
/// adapters the host admits. Before it, the package is admitted; a policy that names another
/// adapter leaves it out, and one that names it admits it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_an_applied_policy_leaves_a_package_outside_its_allowlist_out() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "with no policy applied every adapter is admitted"
    );

    let applied = apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the organisation's policy");
    assert_eq!(
        applied.organisation_policy_revision,
        OrganisationPolicyRevision::new(1)
    );
    assert_eq!(applied.adapter_allowlist, allowed(&[CODEX]));
    assert_eq!(applied.effective_adapter_allowlist, allowed(&[CODEX]));
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "a package the policy does not name is left out"
    );

    let listed = fixture.listed().await;
    assert_eq!(listed.effective_adapter_allowlist, allowed(&[CODEX]));
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(1))
    );
    assert_eq!(listed.enrolments[0].adapter_allowlist, allowed(&[CODEX]));

    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 2, Some(&[CODEX, EXAMPLE]), fixture.now()),
        None,
    )
    .await
    .expect("a later revision that names the package");
    assert!(
        is_admitted(&admission(&fixture).await),
        "a package the policy names is admitted"
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: the policy a host applied is still in force after the host restarts, and so is
/// the floor under it: the same revision with another list, and a lower revision, are refused
/// by name, the same revision with the same list is a repeat that succeeds, and a higher one
/// applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_restart_keeps_the_applied_policy_and_its_floor() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 5, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the policy");
    assert_eq!(
        applied_policies(&fixture),
        vec![applied::StoredAppliedPolicy {
            organisation_id: fixture.organisation.organisation_id,
            enrolment_revision: fixture.revision,
            organisation_policy_revision: OrganisationPolicyRevision::new(5),
            adapter_allowlist: allowed(&[CODEX]),
        }],
        "the policy is kept in the store of applied policies, for this enrolment"
    );

    let fixture = fixture.restart().await;
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "the restarted host holds the list"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(5))
    );

    let same = |names: &[&str]| {
        fixture
            .organisation
            .policy(2, 5, Some(names), fixture.now())
    };
    apply(&fixture, same(&[CODEX]), None)
        .await
        .expect("the same revision with the same list is a repeat");
    refused_as(
        apply(&fixture, same(&[CODEX, EXAMPLE]), None).await,
        "not_newer",
    );
    refused_as(
        apply(
            &fixture,
            fixture
                .organisation
                .policy(2, 4, Some(&[CODEX, EXAMPLE]), fixture.now()),
            None,
        )
        .await,
        "not_newer",
    );
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "what was refused changed nothing"
    );

    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 6, Some(&[EXAMPLE]), fixture.now()),
        None,
    )
    .await
    .expect("a higher revision applies after the restart");
    assert!(is_admitted(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a policy the host cannot verify under the key its chain ends with is refused, by
/// the rule that refuses it, and nothing the host admits changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_policy_that_does_not_verify_changes_nothing() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let organisation = &fixture.organisation;

    // Signed by a key the host did not pin: the first revision's, under the second's name.
    let forged =
        organisation.signed_policy(1, organisation.policy_payload(2, 1, Some(&[CODEX]), now));
    refused_as(apply(&fixture, forged, None).await, "bad_signature");

    // A payload altered after it was signed.
    let mut tampered = organisation.policy(2, 1, Some(&[CODEX]), now);
    tampered.payload.adapter_allowlist = allowed(&[CODEX, EXAMPLE]);
    refused_as(apply(&fixture, tampered, None).await, "bad_signature");

    // Another organisation's policy, signed with its own keys.
    let other = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS);
    refused_as(
        apply(&fixture, other.policy(1, 1, Some(&[CODEX]), now), None).await,
        "not_enrolled",
    );

    // A policy that breaks a rule of its own: it names no adapter at all.
    refused_as(
        apply(&fixture, organisation.policy(2, 1, Some(&[]), now), None).await,
        "structure",
    );

    // Issued before the key that signs it took over: the second revision took over a day ago.
    refused_as(
        apply(
            &fixture,
            organisation.policy(2, 1, Some(&[CODEX]), now - 2 * 24 * 60 * MINUTE_MS),
            None,
        )
        .await,
        "issued_before_activation",
    );

    // An earlier key revision, properly signed: only the key the chain ends with signs a policy.
    refused_as(
        apply(
            &fixture,
            organisation.policy(1, 1, Some(&[CODEX]), now),
            None,
        )
        .await,
        "earlier_revision",
    );

    // A key revision the host does not hold: without a chain, with a chain that is not newer, with
    // a chain that does not verify, and with another organisation's chain.
    fixture.organisation.rotate(now - 1_000);
    let organisation = &fixture.organisation;
    let later = organisation.policy(3, 1, Some(&[CODEX]), now);
    refused_as(apply(&fixture, later.clone(), None).await, "later_revision");
    refused_as(
        apply(
            &fixture,
            later.clone(),
            Some(organisation.authority_at(2, now)),
        )
        .await,
        "later_revision",
    );
    let mut broken = organisation.authority(now);
    broken.head.signature = kr_protocol::scalars::Signature64::from_bytes([0x61; 64]);
    refused_as(apply(&fixture, later.clone(), Some(broken)).await, "chain");
    let elsewhere = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS).authority(now);
    refused_as(
        apply(&fixture, later, Some(elsewhere)).await,
        "foreign_chain",
    );

    assert!(
        is_admitted(&admission(&fixture).await),
        "nothing that was refused changed what the host admits"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].accepted_head.get(),
        2,
        "a chain that was refused with its policy is not kept"
    );
    assert!(
        applied_policies(&fixture).is_empty(),
        "a policy that was refused is kept nowhere"
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: after the organisation rotates its key, a policy under the new key applies with
/// the chain beside it, over a policy the host holds under the earlier key, and a policy under the
/// old key, issued before the rotation, does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_after_a_rotation_only_the_new_key_signs_a_policy() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX, EXAMPLE]), now),
        None,
    )
    .await
    .expect("the policy under the key the host follows applies");
    assert!(is_admitted(&admission(&fixture).await));
    fixture.organisation.rotate(now - 1_000);
    let organisation = &fixture.organisation;

    apply(
        &fixture,
        organisation.policy(3, 2, Some(&[CODEX]), now),
        Some(organisation.authority(now)),
    )
    .await
    .expect("the policy under the new key applies with the chain beside it");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 3);

    refused_as(
        apply(
            &fixture,
            organisation.policy(2, 3, Some(&[CODEX, EXAMPLE]), now - 2_000),
            None,
        )
        .await,
        "earlier_revision",
    );
    apply(
        &fixture,
        organisation.policy(3, 3, Some(&[CODEX, EXAMPLE]), now),
        None,
    )
    .await
    .expect("the new key signs the next revision with no chain beside it");
    assert!(is_admitted(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// What the managed service signed across a rotation of its policy-signing key, captured from its
/// own signing code: the chain and the policy before the rotation, and after it.
#[derive(serde::Deserialize)]
struct RotatedPolicy {
    authority_before_rotation: PolicyAuthority,
    policy_before_rotation: OrganisationPolicy,
    authority_after_rotation: PolicyAuthority,
    policy_after_rotation: OrganisationPolicy,
}

/// KR-REQ-18.06: the policy the managed service signs again when its organisation rotates the
/// policy-signing key applies to a host that holds the policy before. The records are the
/// service's own, not built here: the host enrols from the chain before the rotation, applies the
/// policy signed before it, follows the chain after it with the policy the service signed again
/// beside it, and holds the same list under the next revision; the policy before is then refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_the_policy_the_managed_service_signs_again_at_a_rotation_applies_to_a_host_that_holds_the_one_before()
 {
    let rotated: RotatedPolicy = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/accounts/rotated-policy.json"),
        )
        .expect("the captured records"),
    )
    .expect("records the host reads");
    // The host's clock reads a moment inside the life of both heads.
    let fixture = Fixture::start_unenrolled_at(
        rotated
            .authority_after_rotation
            .head
            .payload
            .issued_at_ms
            .get()
            + 500,
    )
    .await;
    fixture
        .enrol_from(rotated.authority_before_rotation.clone())
        .await;

    let before = apply(&fixture, rotated.policy_before_rotation.clone(), None)
        .await
        .expect("the policy signed before the rotation applies under the key the host followed");
    assert_eq!(before.organisation_policy_revision.get(), 1);
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 1);

    let after = apply(
        &fixture,
        rotated.policy_after_rotation.clone(),
        Some(rotated.authority_after_rotation.clone()),
    )
    .await
    .expect("the policy signed again under the new key applies with the new chain beside it");
    assert_eq!(after.organisation_policy_revision.get(), 2);
    assert_eq!(
        after.adapter_allowlist, before.adapter_allowlist,
        "the settings are the ones before"
    );
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 2);
    refused_as(
        apply(&fixture, rotated.policy_before_rotation.clone(), None).await,
        "earlier_revision",
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a chain that shows an installed lease was signed after its key was succeeded is
/// refused with its policy, and nothing is kept: dropping the lease owes a fence that presenting
/// the chain with a lease raises, and the lease stays in force until then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_that_would_drop_an_installed_lease_is_refused_with_its_policy() {
    let mut fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    read_host_info(&raw).await.expect("served under the lease");

    // The organisation's key was succeeded a minute before the host's lease was issued, and the
    // host has not heard of it.
    let now = fixture.now();
    fixture.organisation.rotate(now - MINUTE_MS);
    let organisation = &fixture.organisation;
    refused_as(
        apply(
            &fixture,
            organisation.policy(3, 1, Some(&[CODEX]), now),
            Some(organisation.authority(now)),
        )
        .await,
        "chain_drops_leases",
    );
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 2);
    read_host_info(&raw)
        .await
        .expect("the lease is still in force");

    // Once the lease has ended nothing answers to it, and the same chain is followed with the
    // policy: the lease that was in force is the only thing the refusal protected.
    raw.close();
    fixture.pass(Duration::from_secs(16 * 60));
    let now = fixture.now();
    let organisation = &fixture.organisation;
    apply(
        &fixture,
        organisation.policy(3, 1, Some(&[CODEX]), now),
        Some(organisation.authority(now)),
    )
    .await
    .expect("a chain that drops only a lease that has ended is followed");
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 3);
    fixture.host.stop().await;
}

/// KR-REQ-18.06: the host stops applying an organisation's list when it leaves the organisation,
/// and a new enrolment holds no policy until one is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_withdrawing_from_the_organisation_lifts_its_list() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let organisation_id = fixture.organisation.organisation_id;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the policy");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the owner withdraws the host");
    drop(client);
    assert!(
        is_admitted(&admission(&fixture).await),
        "the list went with the enrolment"
    );
    assert!(
        !applied::file_in(&state_dir(&fixture)).exists(),
        "the store of applied policies is removed when no policy is left"
    );
    assert_eq!(
        fixture.listed().await.effective_adapter_allowlist,
        Nullable::null()
    );

    fixture.enrol().await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "a new enrolment holds no policy"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: what the host admits is the intersection of the lists of every organisation it
/// is enrolled in that states one. An organisation with no list adds no constraint, lists that
/// share nothing admit nothing, and leaving an organisation widens what is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_the_effective_list_is_the_intersection_of_the_organisations_lists() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let second = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS);
    fixture.enrol_in(&second).await;

    // One organisation states a list, the other none.
    let first = apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CLAUDE_CODE, CODEX]), now),
        None,
    )
    .await
    .expect("the first organisation's policy");
    assert_eq!(
        first.effective_adapter_allowlist,
        allowed(&[CLAUDE_CODE, CODEX])
    );
    assert_eq!(
        list_in_force(&fixture).await,
        allowed(&[CLAUDE_CODE, CODEX]),
        "the list in force is the one the policy states"
    );
    let unlisted = apply(&fixture, second.policy(1, 1, None, now), None)
        .await
        .expect("the second organisation's policy, with no list");
    assert_eq!(
        unlisted.effective_adapter_allowlist,
        allowed(&[CLAUDE_CODE, CODEX]),
        "no list adds no constraint"
    );
    assert_eq!(
        list_in_force(&fixture).await,
        allowed(&[CLAUDE_CODE, CODEX])
    );

    // Both state one.
    let both = apply(
        &fixture,
        second.policy(1, 2, Some(&[CODEX, EXAMPLE]), now),
        None,
    )
    .await
    .expect("a list from the second organisation");
    assert_eq!(both.effective_adapter_allowlist, allowed(&[CODEX]));
    assert_eq!(
        list_in_force(&fixture).await,
        allowed(&[CODEX]),
        "the list in force is the intersection of the two lists"
    );
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    // Lists that share nothing.
    let nothing = apply(&fixture, second.policy(1, 3, Some(&[EXAMPLE]), now), None)
        .await
        .expect("a list that shares nothing with the first");
    assert_eq!(nothing.effective_adapter_allowlist, allowed(&[]));
    assert_eq!(list_in_force(&fixture).await, allowed(&[]));
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    assert_eq!(
        applied_policies(&fixture).len(),
        2,
        "the store holds the policy of each organisation"
    );

    // Leaving the first organisation leaves the second's list alone.
    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            fixture.organisation.organisation_id,
        )
        .await
        .expect("the owner withdraws the host from the first organisation");
    drop(client);
    assert_eq!(
        fixture.listed().await.effective_adapter_allowlist,
        allowed(&[EXAMPLE])
    );
    assert_eq!(list_in_force(&fixture).await, allowed(&[EXAMPLE]));
    assert!(is_admitted(&admission(&fixture).await));
    assert_eq!(
        applied_policies(&fixture)
            .into_iter()
            .map(|policy| policy.organisation_id)
            .collect::<Vec<_>>(),
        vec![second.organisation_id],
        "the store keeps the policy of the organisation the host is still in"
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a policy whose list cannot be put in force is recorded and told so, and the host
/// never reports it as applied while it is not in force. The catalogue is held here as a
/// synchronisation holds it. The same request made again, as the owner's tooling does, applies the
/// same policy again and puts the list in force once the catalogue is free; and the host's own pass
/// puts the list in force when nobody asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_list_that_could_not_be_put_in_force_is_told_and_then_put_in_force() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let environment_id = fixture.host.environment_id;
    let controller = Arc::clone(fixture.host.controller());

    // The catalogue is busy: the apply says so and the list is not in force.
    let policy = fixture
        .organisation
        .policy(2, 1, Some(&[CODEX]), fixture.now());
    let mut client = fixture.host.client().await;
    let request = client
        .compose(
            Method::OrganisationPolicyApply,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &OrganisationPolicyApplyParams {
                policy,
                authority: Nullable::null(),
            },
        )
        .await
        .expect("the request");
    {
        let held = controller.catalogue().catalogue().lock().await;
        // Every time the owner asks, the catalogue is still held and the answer says so: a policy
        // is never reported as applied while its list is not in force.
        for _ in 0..2 {
            let refused = client
                .repeat(&request)
                .await
                .expect("the daemon answers")
                .expect_err("the list could not be put in force");
            assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
        }
        let installation = held
            .installation(environment_id, &example())
            .expect("readable")
            .expect("installed");
        assert_eq!(
            held.standing(&installation, None),
            None,
            "the list is not in force"
        );
        // The owner sees the difference: the policy states a list that the catalogue does not
        // admit under yet.
        let listed = fixture.listed().await;
        assert_eq!(listed.effective_adapter_allowlist, allowed(&[CODEX]));
        assert_eq!(
            listed.adapter_allowlist_in_force,
            Nullable::null(),
            "the list the policies state is not the list in force"
        );
    }
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(1)),
        "the policy is recorded"
    );

    // The same request again, with the catalogue free, applies the same policy again.
    let answered: OrganisationPolicyApplyResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the policy again, with the list in force")
        .to_typed()
        .expect("an answer");
    assert_eq!(answered.adapter_allowlist, allowed(&[CODEX]));
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    assert_eq!(
        list_in_force(&fixture).await,
        allowed(&[CODEX]),
        "and the list is in force once it landed"
    );
    drop(client);

    // A later policy fails the same way. The host's own pass, which finds the catalogue held too,
    // says to the doctor that it could not put the list in force; once the catalogue is let go the
    // next pass puts the list in force and the note goes.
    let next = fixture
        .organisation
        .policy(2, 2, Some(&[EXAMPLE]), fixture.now());
    {
        let _held = controller.catalogue().catalogue().lock().await;
        let refused = apply(&fixture, next, None)
            .await
            .expect_err("the list could not be put in force");
        assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
        controller.ask_for_admissions_pass();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !the_doctor_says_the_list_is_not_in_force(&controller).await {
            assert!(
                Instant::now() < deadline,
                "the pass never said that the list is not in force"
            );
        }
    }
    controller.ask_for_admissions_pass();
    until_admission(&fixture, is_admitted).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    while the_doctor_says_the_list_is_not_in_force(&controller).await {
        assert!(
            Instant::now() < deadline,
            "the note outlived the put that landed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    fixture.host.stop().await;
}

/// A policy kept for an enrolment applies to that enrolment alone. A host that stopped after it
/// withdrew from an organisation and before it wrote the store of applied policies leaves the
/// entry of the enrolment that ended: it is dropped when the host starts without that enrolment,
/// and it applies to no enrolment in the same organisation made later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_kept_for_an_enrolment_that_ended_applies_to_no_later_enrolment() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let first_enrolment = fixture.revision;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the policy");
    let left_behind = applied_policies(&fixture);
    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            fixture.organisation.organisation_id,
        )
        .await
        .expect("the owner withdraws the host");
    drop(client);
    assert!(applied_policies(&fixture).is_empty());

    // The store is as the host that stopped before it wrote it left it: the entry of the
    // enrolment that ended. No enrolment holds it, so the next start drops it.
    let put_back = |directory: &Path| {
        applied::write(directory, &left_behind).expect("the entry is written back");
    };
    let mut fixture = restart_over(fixture, put_back).await;
    assert!(is_admitted(&admission(&fixture).await));
    assert!(
        applied_policies(&fixture).is_empty(),
        "an entry that names no enrolment the host holds is dropped"
    );

    // A later enrolment in the same organisation takes a later revision, and the entry of the
    // earlier one is left behind again.
    fixture.enrol().await;
    assert_ne!(fixture.revision, first_enrolment);
    let fixture = restart_over(fixture, put_back).await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "the new enrolment holds no policy"
    );
    let listed = fixture.listed().await;
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    assert_eq!(listed.effective_adapter_allowlist, Nullable::null());
    assert!(
        applied_policies(&fixture).is_empty(),
        "the entry of the earlier enrolment is dropped"
    );
    fixture.host.stop().await;
}

/// The policy is written to its store after the registry row of the request, so a stop between the
/// two leaves the policy the host last answered for in force, with the chain the request followed
/// recorded; the same policy applied again, with no chain beside it any more, writes the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_between_the_two_writes_leaves_the_earlier_policy_and_the_policy_again_completes_it()
{
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    fixture.organisation.rotate(now - 1_000);
    let policy = fixture.organisation.policy(3, 1, Some(&[CODEX]), now);
    let chain = fixture.organisation.authority(now);
    apply(&fixture, policy.clone(), Some(chain))
        .await
        .expect("the host applies the policy under the new key, with the chain beside it");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    // The store is as it was before the request: the host stopped after the registry row.
    let fixture = restart_over(fixture, |directory| {
        applied::write(directory, &[]).expect("the store is put back");
    })
    .await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "no policy the host did not write down is in force"
    );
    let listed = fixture.listed().await;
    assert_eq!(
        listed.enrolments[0].accepted_head.get(),
        3,
        "the chain the request followed is recorded"
    );
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );

    apply(&fixture, policy, None)
        .await
        .expect("the same policy again applies, the chain being held");
    assert_eq!(applied_policies(&fixture).len(), 1);
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// The part of the answer that says the request's chain is recorded, which a request whose chain
/// did not advance the host's, or that carried none, must not claim.
const CHAIN_RECORDED: &str = "newer chain";

/// The part of the answer that says the new policy is already in its file.
const IN_ITS_FILE: &str = "already in its file";

/// The chain a request followed is in the registry before the file of applied policies is written,
/// and it stays in force when that file cannot be written: the key it replaced signs nothing more,
/// while the file cannot be written, once it can, and after a restart. The policy in force is the
/// one the host answered for before the request, which is no policy when `earlier` is `None` and
/// that policy otherwise. A file that was there is moved aside for the failure and put back
/// afterwards, which is what a failed write leaves: the earlier bytes. The same policy applied
/// again writes the file.
async fn a_failed_write_keeps_the_chain_and_the_policy_answered_for(earlier: Option<&[&str]>) {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let file = applied::file_in(&state_dir(&fixture));
    let aside = file.with_extension("aside");
    let revision = if earlier.is_some() { 2 } else { 1 };
    if let Some(list) = earlier {
        apply(
            &fixture,
            fixture.organisation.policy(2, 1, Some(list), now),
            None,
        )
        .await
        .expect("the earlier policy applies under the key in force");
        assert_eq!(applied_policies(&fixture).len(), 1);
    }
    // What the host answered for before the request, as `organisation.list` says it, and the list
    // the catalogue admits under.
    let before = fixture.listed().await;
    let in_force_before = list_in_force(&fixture).await;
    assert_eq!(
        in_force_before,
        earlier.map_or_else(Nullable::null, allowed)
    );
    assert_eq!(
        before.enrolments[0].organisation_policy_revision,
        earlier.map_or_else(Nullable::null, |_| Nullable::some(
            OrganisationPolicyRevision::new(1)
        ))
    );

    fixture.organisation.rotate(now - 1_000);
    let policy = fixture
        .organisation
        .policy(3, revision, Some(&[CODEX]), now);
    let chain = fixture.organisation.authority(now);
    let old_key =
        fixture
            .organisation
            .policy(2, revision + 1, Some(&[CODEX, EXAMPLE]), now - 2_000);
    // A directory in the file's place: the registry takes the request, and the file is refused.
    if earlier.is_some() {
        std::fs::rename(&file, &aside).expect("the earlier file is put aside");
    }
    std::fs::create_dir(&file).expect("a directory in the file's place");

    let refused = apply(&fixture, policy.clone(), Some(chain.clone()))
        .await
        .expect_err("the file of applied policies cannot be written");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused:?}");
    assert!(
        refused.message.contains(CHAIN_RECORDED),
        "a chain that advanced the host's is said to be recorded: {refused:?}"
    );
    let listed = fixture.listed().await;
    assert_eq!(
        listed.enrolments[0].accepted_head.get(),
        3,
        "the chain the registry took is in force"
    );
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        before.enrolments[0].organisation_policy_revision,
        "the policy the file could not hold is not in force, and the one answered for before is"
    );
    assert_eq!(
        listed.enrolments[0].adapter_allowlist,
        before.enrolments[0].adapter_allowlist
    );
    assert_eq!(
        listed.effective_adapter_allowlist, before.effective_adapter_allowlist,
        "and so is the list it states"
    );
    assert_eq!(
        listed.adapter_allowlist_in_force, in_force_before,
        "and the catalogue keeps the list it admitted under"
    );
    assert!(is_admitted(&admission(&fixture).await));

    // The same policy with no chain beside it, and with the chain the host holds now, cannot be
    // written either, and neither says that a chain is recorded: none advanced.
    for beside in [None, Some(chain)] {
        let refused = apply(&fixture, policy.clone(), beside)
            .await
            .expect_err("the file of applied policies cannot be written");
        assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused:?}");
        assert!(
            !refused.message.contains(CHAIN_RECORDED),
            "no chain was recorded by this request: {refused:?}"
        );
        assert!(
            !refused.message.contains(IN_ITS_FILE),
            "and the file does not hold the policy: {refused:?}"
        );
    }
    refused_as(
        apply(&fixture, old_key.clone(), None).await,
        "earlier_revision",
    );
    std::fs::remove_dir(&file).expect("the way is clear");
    if earlier.is_some() {
        std::fs::rename(&aside, &file).expect("the earlier file is back");
    }
    assert_eq!(
        applied_policies(&fixture).len(),
        usize::from(earlier.is_some())
    );

    // Before any restart: the key the chain replaced still signs nothing.
    refused_as(
        apply(&fixture, old_key.clone(), None).await,
        "earlier_revision",
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        before.enrolments[0].organisation_policy_revision
    );

    let fixture = restart_over(fixture, |_| {}).await;
    let restarted = fixture.listed().await;
    assert_eq!(
        restarted.enrolments[0].accepted_head.get(),
        3,
        "a restart keeps the chain the registry took"
    );
    assert_eq!(
        restarted.enrolments[0].organisation_policy_revision,
        before.enrolments[0].organisation_policy_revision,
        "and the policy the file holds"
    );
    refused_as(apply(&fixture, old_key, None).await, "earlier_revision");
    assert!(is_admitted(&admission(&fixture).await));

    apply(&fixture, policy, None)
        .await
        .expect("the same policy again applies, the chain being held");
    assert_eq!(applied_policies(&fixture).len(), 1);
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// No policy was applied before the request: the host goes back to none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_the_registry_took_stays_in_force_when_the_file_of_applied_policies_cannot_be_written()
 {
    a_failed_write_keeps_the_chain_and_the_policy_answered_for(None).await;
}

/// A policy was applied before the request: the host goes back to it, and its list is the one in
/// force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_earlier_policy_stays_in_force_when_the_file_of_applied_policies_cannot_be_written() {
    a_failed_write_keeps_the_chain_and_the_policy_answered_for(Some(&[CODEX, EXAMPLE])).await;
}

/// A write that renames the file into place and fails when it flushes the directory leaves the new
/// policy in its file. The host keeps the policy it answered for in force, and the answer says
/// that the file holds the new one, so that a restart before the same policy is accepted may apply
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_whose_file_was_renamed_into_place_and_not_flushed_is_told_so() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let policy = fixture.organisation.policy(2, 1, Some(&[CODEX]), now);
    let refused = {
        let _flushes = kr_flush::testing::refuse_flushes_of(state_dir(&fixture));
        apply(&fixture, policy.clone(), None)
            .await
            .expect_err("the directory cannot be flushed")
    };
    assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused:?}");
    assert!(
        refused.message.contains(IN_ITS_FILE),
        "the answer says the file holds the new policy: {refused:?}"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::null(),
        "the policy answered for before is the one in force"
    );
    assert!(is_admitted(&admission(&fixture).await));

    let fixture = restart_over(fixture, |_| {}).await;
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(1)),
        "a restart applies the policy the file holds, as the answer said it may"
    );
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// Asks the host to apply `params`, lets the request reach the registry, passes `by` on both
/// clocks while it waits for the registry's lock, and returns the refusal it ends with.
async fn applied_while_time_passes(
    fixture: &Fixture,
    params: OrganisationPolicyApplyParams,
    by: Duration,
) -> ProtocolError {
    let (arrived, go) = fixture
        .host
        .controller()
        .sharing()
        .grants()
        .pause_before_effect();
    let environment = fixture.host.environment_id;
    let mut client = fixture.host.client().await;
    let asking = tokio::spawn(async move {
        let answer: Result<OrganisationPolicyApplyResult, ProtocolError> = calls::mutate_as(
            environment,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            Method::OrganisationPolicyApply,
            &params,
        )
        .await;
        (client, answer)
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the request reaches the registry");
    assert_eq!(
        applied_policies(fixture)
            .first()
            .map(|kept| kept.organisation_policy_revision),
        Some(OrganisationPolicyRevision::new(1)),
        "nothing is written to the store of applied policies before the registry accepts the request"
    );
    fixture.pass(by);
    go.send(()).expect("the request waits");
    let (client, answer) = asking.await.expect("the request ends");
    drop(client);
    answer.expect_err("the registry refuses the request")
}

/// A request the registry refuses writes nothing to the store of applied policies: the time the
/// request was admitted for runs out while it waits for the registry's lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_the_registry_refuses_leaves_the_store_of_applied_policies_as_it_was() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the first policy");
    let kept = applied_policies(&fixture);

    let refused = applied_while_time_passes(
        &fixture,
        OrganisationPolicyApplyParams {
            policy: fixture
                .organisation
                .policy(2, 2, Some(&[CODEX, EXAMPLE]), fixture.now()),
            authority: Nullable::null(),
        },
        Duration::from_secs(16 * 60),
    )
    .await;
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(applied_policies(&fixture), kept, "the store is as it was");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// An entry that names no enrolment the host holds is dropped when the host starts, and a host that
/// cannot drop it stops, naming the file: an entry that stays could meet an enrolment made later
/// that takes its revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_cannot_drop_an_entry_that_names_no_enrolment_stops() {
    let fixture = Fixture::start_unenrolled().await;
    let stopped = fixture.host.shut_down().await;
    let state_dir = stopped.tree().environment().state_dir().to_path_buf();
    applied::write(
        &state_dir,
        &[applied::StoredAppliedPolicy {
            organisation_id: fixture.organisation.organisation_id,
            enrolment_revision: AuthorityRevision::new(1),
            organisation_policy_revision: OrganisationPolicyRevision::new(1),
            adapter_allowlist: allowed(&[CODEX]),
        }],
    )
    .expect("the entry is written");
    let settings = stopped.settings().clone();
    let refused = {
        let _flushes = kr_flush::testing::refuse_flushes_of(state_dir.clone());
        let start = stopped.start(settings);
        match tokio::task::LocalSet::new()
            .run_until(async move { tokio::task::spawn_local(start).await })
            .await
        {
            Err(stopped) => stopped,
            Ok(_) => panic!("the daemon started with an entry it could not drop"),
        }
    };
    let said = match refused.into_panic().downcast::<String>() {
        Ok(text) => *text,
        Err(other) => other
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .unwrap_or_default(),
    };
    assert!(
        said.contains("organisation-policy.json"),
        "the refusal names the file: {said}"
    );
}

/// The store of applied policies is never written larger than a start reads: a record the host
/// cannot read back is refused before anything is written.
#[test]
fn a_store_of_applied_policies_is_never_written_larger_than_a_start_reads() {
    let entry = |byte: u16| applied::StoredAppliedPolicy {
        organisation_id: OrganisationId::new(Uuid::from_bytes([byte as u8; 16])),
        enrolment_revision: AuthorityRevision::new(u64::from(byte)),
        organisation_policy_revision: OrganisationPolicyRevision::new(1),
        adapter_allowlist: Nullable::some(
            (0..64)
                .map(|index| {
                    PluginId::new(format!("kalareach/an-adapter-with-a-long-name-{index:03}"))
                        .expect("a plugin identifier")
                })
                .collect(),
        ),
    };
    let directory = tempfile::tempdir().expect("a directory");
    let few: Vec<_> = (0..4).map(entry).collect();
    applied::write(directory.path(), &few).expect("a record a start reads is written");
    assert_eq!(applied::read(directory.path()).expect("reads back"), few);

    let many: Vec<_> = (0..255)
        .flat_map(|first| (0..2).map(move |second| (first, second)))
        .map(|(first, second)| {
            let mut one = entry(first);
            one.organisation_id = OrganisationId::new(Uuid::from_bytes([
                first as u8,
                second as u8,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
            ]));
            one
        })
        .collect();
    applied::write(directory.path(), &many).expect_err("a record a start would refuse is refused");
    assert_eq!(
        applied::read(directory.path()).expect("the record is as it was"),
        few,
        "nothing was written"
    );
}

/// What a start does with a store of applied policies it cannot read: it stops, naming the file.
/// A host that came back without the restrictions it was left with would run every adapter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_of_applied_policies_this_build_cannot_read_stops_the_start() {
    use kr_controller::service::{Controller, ControllerSetup};
    use kr_crypto::store::{StoreSelection, open_store_in};
    use kr_ipc::verify::ControllerIdentity;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    std::fs::create_dir_all(environment.state_dir()).expect("the state directory");
    let file = applied::file_in(environment.state_dir());
    for damaged in [
        &b"not a record"[..],
        // Another format: what a later build wrote is not read back without what it adds.
        &br#"{"version": 2, "policies": []}"#[..],
        // An organisation named twice: which of the two is in force is not known.
        &br#"{"version": 1, "policies": [
            {"organisation_id": "21212121-2121-2121-2121-212121212121", "enrolment_revision": "7",
             "organisation_policy_revision": "1", "adapter_allowlist": null},
            {"organisation_id": "21212121-2121-2121-2121-212121212121", "enrolment_revision": "8",
             "organisation_policy_revision": "2", "adapter_allowlist": null}]}"#[..],
    ] {
        kr_ipc::paths::write_owner_only_file(&file, damaged).expect("the file is written");
        let secrets = environment.secrets_dir();
        let started = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(kr_controller::supervision::DetachedSupervisor),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await;
        let Err(refused) = started else {
            panic!("the daemon started with a store of applied policies it cannot read");
        };
        assert!(
            refused.to_string().contains("organisation-policy.json"),
            "the refusal names the file: {refused}"
        );
    }
}

/// The store of applied policies as a host writes it: a record the host kept reads back, and is
/// written back as the same bytes.
#[test]
fn a_store_of_applied_policies_reads_back_the_bytes_the_host_wrote() {
    const KEPT: &str = r#"{
  "version": 1,
  "policies": [
    {
      "organisation_id": "21212121-2121-2121-2121-212121212121",
      "enrolment_revision": "7",
      "organisation_policy_revision": "3",
      "adapter_allowlist": [
        "kalareach/codex",
        "kalareach/example-declarative"
      ]
    },
    {
      "organisation_id": "22222222-2222-2222-2222-222222222222",
      "enrolment_revision": "9",
      "organisation_policy_revision": "1",
      "adapter_allowlist": null
    }
  ]
}"#;
    let directory = tempfile::tempdir().expect("a directory");
    let file = applied::file_in(directory.path());
    kr_ipc::paths::write_owner_only_file(&file, KEPT.as_bytes()).expect("the file is written");

    let read = applied::read(directory.path()).expect("the record reads");
    assert_eq!(
        read,
        vec![
            applied::StoredAppliedPolicy {
                organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
                enrolment_revision: AuthorityRevision::new(7),
                organisation_policy_revision: OrganisationPolicyRevision::new(3),
                adapter_allowlist: allowed(&[CODEX, EXAMPLE]),
            },
            applied::StoredAppliedPolicy {
                organisation_id: OrganisationId::new(Uuid::from_bytes([0x22; 16])),
                enrolment_revision: AuthorityRevision::new(9),
                organisation_policy_revision: OrganisationPolicyRevision::new(1),
                adapter_allowlist: Nullable::null(),
            },
        ]
    );
    applied::write(directory.path(), &read).expect("the record is written");
    assert_eq!(
        std::fs::read_to_string(&file).expect("the file reads"),
        KEPT
    );
}
