//! Repository sync, TUF verification, package activation and what an installed package may do.
//!
//! Every generation these tests verify is built here, signed with keys the test makes in memory.
//! Nothing reads a private key from the repository, because there is none to read: a committed
//! signing key is a key that has to be rotated, and a test that needed one would be a reason to
//! commit one.
//!
//! One test is the exception in the other direction. `the_development_generation_verifies` reads
//! the generation the plugins repository actually published, copied into
//! `fixtures/plugins/catalogue/development/` at a named commit. A suite that only ever verified
//! its own output would prove that this code agrees with itself.

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use kr_plugin_catalogue::budget::{Resource, Stage};
use kr_plugin_catalogue::{
    Authority, BudgetLedger, CapabilityCeiling, Catalogue, CatalogueError, CatalogueResult, Change,
    Claimed, Committed, DisablePolicy, Effect, Enrolment, FetchReason, Installation,
    InstallationGrant, MatchIndex, Observation, Owner, ReceiptClaim, ReceiptKey, Recording,
    RepositoryId, RepositoryKind, Resolution, Transition, capability_from_str,
};
use kr_plugin_sdk::capability::{CapabilityState, EvidenceSource, PluginCapability};
use kr_plugin_sdk::catalogue::{QualificationResult, RevocationReason, RevocationRecord};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_plugin_sdk::text::{Label, Summary};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, RepositoryGeneration};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use support::{Generation, GenerationSpec, KeySet};

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::NIL)
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("a valid plugin identifier")
}

fn version() -> PackageVersion {
    PackageVersion::parse("0.1.0").expect("a valid version")
}

fn repository() -> RepositoryId {
    RepositoryId::new("official").expect("a valid repository identifier")
}

/// Returns true when the package is here and every file its manifest declares checks out.
fn complete(store: &kr_plugin_catalogue::Store, digest: PayloadDigest) -> bool {
    matches!(
        store.check_package(digest).expect("a readable store"),
        kr_plugin_catalogue::PackageCheck::Complete(_)
    )
}

/// Returns true when nothing of the package was activated here.
fn absent(store: &kr_plugin_catalogue::Store, digest: PayloadDigest) -> bool {
    matches!(
        store.check_package(digest).expect("a readable store"),
        kr_plugin_catalogue::PackageCheck::Missing { .. }
    )
}

/// Opens a catalogue whose root is on the internal disk, and enrols one generation into it.
async fn enrolled(
    home: &std::path::Path,
    generation: &Generation,
    budgets: RepositoryBudgets,
    ceiling: CapabilityCeiling,
) -> Catalogue {
    let mut catalogue = Catalogue::open(&home.join("catalogue")).expect("an openable catalogue");
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        generation.metadata_url(),
        generation.targets_url(),
        generation.root_bytes(),
        budgets,
        ceiling,
    )
    .expect("an enrollable repository");
    catalogue
        .enrol(enrolment, true)
        .expect("the owner adopted the root");
    catalogue
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.07: root, timestamp, snapshot and targets through the qualified client
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_07_a_generation_verifies_through_the_qualified_client() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    assert_eq!(outcome.generation.get(), 1);
    assert_eq!(outcome.entries, 1);
    assert_eq!(
        outcome.mirrored_payloads, 0,
        "a sync fetches metadata, not payloads"
    );

    let index = catalogue.index(&repository()).expect("an activated index");
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.entries[0].plugin_id, plugin());
}

#[tokio::test]
async fn kr_req_11_07_metadata_signed_by_another_root_is_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    // A root this host adopted, over keys that signed nothing in this generation.
    let stranger =
        Generation::build(&home.path().join("stranger"), GenerationSpec::default()).await;

    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Community,
        generation.metadata_url(),
        generation.targets_url(),
        stranger.root_bytes(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("an enrollable repository");
    catalogue.enrol(enrolment, true).expect("adopted");

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("another root");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    assert!(
        catalogue.index(&repository()).is_err(),
        "nothing is activated when verification fails"
    );
}

#[tokio::test]
async fn kr_req_11_07_a_tampered_target_does_not_verify() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    // The bytes under a signed name are replaced after the metadata was written.
    let manifest = generation
        .targets_dir()
        .join("packages/kalareach/example-declarative/0.1.0/plugin.json");
    let original = std::fs::read(&manifest).expect("readable");
    let mut tampered = original.clone();
    tampered.extend_from_slice(b"\n");
    std::fs::write(&manifest, &tampered).expect("writable");

    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect_err("a tampered target");
    assert!(
        matches!(
            refusal,
            CatalogueError::Integrity { .. } | CatalogueError::Untrusted { .. }
        ),
        "{refusal}"
    );
    std::fs::write(&manifest, &original).expect("writable");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.08: delegation scope, pinning, terminating roles, bounded depth, revocation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_08_vendor_delegations_verify_and_each_names_one_publisher() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            delegations: vec![
                (
                    "vendor".to_owned(),
                    "packages/kalareach/*/*/*".to_owned(),
                    false,
                ),
                (
                    "vendor-stable".to_owned(),
                    "packages/kalareach/example-declarative/*/*".to_owned(),
                    true,
                ),
            ],
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    let roles: Vec<&str> = outcome
        .delegations
        .iter()
        .map(|(role, _)| role.as_str())
        .collect();
    assert!(roles.contains(&"vendor"), "{roles:?}");
    assert!(roles.contains(&"vendor-stable"), "{roles:?}");
    assert_eq!(outcome.delegations.len(), 2);
    for (_, publisher) in &outcome.delegations {
        assert_eq!(publisher, "kalareach");
    }

    // The generation still resolves its targets through the delegation search, so what the index
    // declares is what a read would actually reach.
    catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect("the package resolves through the delegations");
}

#[tokio::test]
async fn kr_req_11_08_nested_two_level_delegation_resolves_package_from_leaf() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            nested_delegation: true,
            empty_leaf: false,
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("a verified generation with nested delegations");

    let roles: Vec<&str> = outcome
        .delegations
        .iter()
        .map(|(role, _)| role.as_str())
        .collect();
    assert!(roles.contains(&"vendor"), "{roles:?}");
    assert!(roles.contains(&"vendor-leaf"), "{roles:?}");
    assert_eq!(outcome.delegations.len(), 2);

    catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect("the package resolves through two levels of delegation");
}

#[tokio::test]
async fn kr_req_11_08_terminating_miss_in_leaf_fails_package_resolution() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            nested_delegation: true,
            empty_leaf: true,
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    // Because the leaf role has no package targets and is terminating, the package target
    // cannot be resolved through delegation, so sync must reject the generation as untrusted.
    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("terminating miss in leaf must fail");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    assert!(
        refusal
            .to_string()
            .contains("could not be resolved through delegation"),
        "{refusal}"
    );
}

/// A delegation chain at the bound verifies and resolves its package through every level. One role
/// deeper is refused before the client asks for that role's document, so a repository cannot make
/// a host fetch and verify a level it would refuse anyway. Both hold whether or not the root
/// publishes consistent snapshots, which name every role's document with its version in front.
#[tokio::test]
async fn kr_req_11_08_a_role_past_the_depth_bound_is_refused_before_its_document_is_fetched() {
    for consistent_snapshot in [false, true] {
        for (depth, permitted) in [(3usize, true), (4, false)] {
            let home = tempfile::tempdir().expect("a temporary directory");
            let generation = Generation::build(
                home.path(),
                GenerationSpec {
                    delegation_chain: depth,
                    consistent_snapshot,
                    ..GenerationSpec::default()
                },
            )
            .await;
            let mut catalogue = enrolled(
                home.path(),
                &generation,
                RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .await;
            let watched = Watched::default();
            catalogue.set_transport(Arc::new(watched.clone()));
            let outcome = catalogue.sync(&repository()).await;
            let fetched = watched.fetched.lock().expect("the list").clone();
            let requested = |role: &str| {
                let file = if consistent_snapshot {
                    format!("/1.{role}.json")
                } else {
                    format!("/{role}.json")
                };
                fetched.iter().any(|url| url.path().ends_with(&file))
            };
            let case = format!("depth {depth}, consistent snapshots {consistent_snapshot}");
            let deepest = format!("level-{depth}");
            if permitted {
                let outcome = outcome.unwrap_or_else(|refusal| panic!("{case}: {refusal}"));
                assert_eq!(outcome.delegations.len(), depth, "{case}");
                assert!(requested(&deepest), "{case}: {fetched:?}");
                catalogue
                    .activate_package(
                        &repository(),
                        &plugin(),
                        &version(),
                        FetchReason::ExplicitInstall,
                    )
                    .await
                    .unwrap_or_else(|refusal| panic!("{case}: {refusal}"));
                continue;
            }
            let refusal = outcome.expect_err("a chain past the bound is refused");
            assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted, "{case}");
            assert!(
                refusal.to_string().contains("deeper than 3 roles"),
                "{case}: {refusal}"
            );
            assert!(requested("level-3"), "{case}: the chain was followed");
            assert!(
                !requested(&deepest),
                "{case}: the role past the bound was fetched: {fetched:?}"
            );
            assert_eq!(
                catalogue.active(&repository()).expect("enrolled"),
                None,
                "{case}"
            );
        }
    }
}

#[tokio::test]
async fn kr_req_11_07_root_key_rotation_advances_and_withholding_rotated_root_fails() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    // Sync generation 1 under root v1
    catalogue
        .sync(&repository())
        .await
        .expect("sync generation 1");

    let initial_root = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled")
        .root
        .clone();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&initial_root).expect("readable")["signed"]["version"],
        serde_json::json!(1)
    );

    // Rotate root to v2 cross-signed by root v1 and root v2 keys
    let new_keys = KeySet::generate();
    let root_v2_bytes = generation.rotate_root_to_v2(&new_keys).await;

    // A host enrolled with root v1 fails to sync if root v2 is withheld by the repository:
    let home2 = tempfile::tempdir().expect("tempdir");
    let mut catalogue2 = Catalogue::open(&home2.path().join("catalogue")).expect("openable");
    let enrolment2 = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        generation.metadata_url(),
        generation.targets_url(),
        initial_root.clone(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("enrollable");
    catalogue2
        .enrol(enrolment2, true)
        .expect("enrolled with root v1");

    generation.withhold_root_v2();
    let refusal = catalogue2
        .sync(&repository())
        .await
        .expect_err("withholding root v2 must fail");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);

    // Restore root v2 so the generation publishes properly
    generation.restore_root_v2(&root_v2_bytes);

    // Now catalogue2 with root v1 can sync and advance to root v2
    let outcome2 = catalogue2
        .sync(&repository())
        .await
        .expect("sync generation 2 advances root to v2");
    assert_eq!(outcome2.generation.get(), 2);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &catalogue2
                .repository(&repository())
                .expect("readable")
                .expect("enrolled")
                .root
        )
        .expect("readable"),
        serde_json::from_slice::<serde_json::Value>(&root_v2_bytes).expect("readable")
    );

    // Sync from root v1 advances to root v2
    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("sync generation 2 advances root to v2");
    assert_eq!(outcome.generation.get(), 2);

    let rotated_root = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled")
        .root
        .clone();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rotated_root).expect("readable"),
        serde_json::from_slice::<serde_json::Value>(&root_v2_bytes).expect("readable")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rotated_root).expect("readable")["signed"]["version"],
        serde_json::json!(2)
    );

    // Restart retains root v2
    let mut restarted = Catalogue::open(&home.path().join("catalogue")).expect("reopenable");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &restarted
                .repository(&repository())
                .expect("readable")
                .expect("enrolled")
                .root
        )
        .expect("readable"),
        serde_json::from_slice::<serde_json::Value>(&root_v2_bytes).expect("readable")
    );

    // A repository that tries to revert to generation 3 signed by old keys fails against a host on root v2
    generation.rewrite_as(3).await;
    let refusal = restarted
        .sync(&repository())
        .await
        .expect_err("metadata signed with old keys must fail on root v2 host");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
}

#[tokio::test]
async fn kr_req_11_07_the_verified_root_is_what_the_next_load_starts_from() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let adopted = generation.root_bytes();
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    // The root this host now holds is the one verification arrived at, written where the client
    // reads one from, so a restart starts from it rather than from the bytes first adopted.
    let held = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled")
        .root
        .clone();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&held).expect("readable")["signed"]["version"],
        serde_json::json!(1)
    );
    assert!(!adopted.is_empty());

    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    assert_eq!(
        reopened
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .root,
        held
    );
}

#[tokio::test]
async fn kr_req_11_05_a_payload_is_fetched_only_out_of_the_accepted_generation() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("generation one");

    // The repository publishes a second generation in place of the first, whose package files are
    // gone. This host has not accepted the second, so nothing is fetched out of it: the payload is
    // fetched as the first generation named it, and its absence is the answer, not a quiet
    // substitution.
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    first.replace_with(&second);

    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect_err("a generation this host has not accepted");
    assert_eq!(refusal.code(), ErrorCode::PackageUnavailableOffline);
    assert!(
        refusal
            .to_string()
            .contains("packages/kalareach/example-declarative/0.1.0/"),
        "the absence names the accepted generation's own target: {refusal}"
    );
    let store = catalogue.store(&repository()).expect("enrolled");
    assert!(absent(&store, first.manifest_digest()));
    assert!(absent(&store, second.manifest_digest()));
}

#[tokio::test]
async fn kr_req_11_05_a_matching_application_alone_authorises_no_fetch() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    // Nothing is installed, so an activation has nothing to be an activation of.
    let refusal = catalogue
        .activate_package_scoped(
            &repository(),
            Some(environment()),
            &plugin(),
            &version(),
            Some(generation.manifest_digest()),
            FetchReason::AuthorisedActivation,
        )
        .await
        .expect_err("not installed and enabled");
    assert_eq!(refusal.code(), ErrorCode::PackageUnavailableOffline);
    assert!(
        refusal.to_string().contains("does not authorise"),
        "{refusal}"
    );

    // An activation that names neither the environment nor the package hash claims an authority
    // it has not identified, and is refused before any installation is looked at.
    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::AuthorisedActivation,
        )
        .await
        .expect_err("an activation that names no installation");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        refusal.to_string().contains("exact package hash"),
        "{refusal}"
    );

    // Nor does a repository that does not keep a mirror fetch one as though it did.
    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::FullOfflineMirror,
        )
        .await
        .expect_err("no mirror setting");
    assert!(
        refusal.to_string().contains("full offline mirror"),
        "{refusal}"
    );
}

#[tokio::test]
async fn kr_req_11_09_an_installed_package_is_enabled_without_its_repository() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");

    generation.take_offline();

    // The package is here, at the hash it was installed at, so enabling it reads no metadata.
    let enabled = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("what is installed is enablable offline");
    assert!(enabled.enabled);
    // And what it may do is answered from what was recorded at installation.
    let decisions = catalogue
        .capabilities(environment(), &plugin())
        .expect("readable offline");
    assert!(!decisions.is_empty());
}

#[test]
fn a_repository_this_host_cannot_fetch_is_refused_by_name() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    assert!(catalogue.fetches_network());
    catalogue.set_fetches_network(false);
    assert!(!catalogue.fetches_network());
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        url("https://plugins.example/metadata/"),
        url("https://plugins.example/targets/"),
        b"a root".to_vec(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("enrollable");
    catalogue.enrol(enrolment, true).expect("adopted");

    let refusal = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(catalogue.sync(&repository()))
        .expect_err("no network transport");
    assert_eq!(refusal.code(), ErrorCode::PackageUnavailableOffline);
    assert!(refusal.to_string().contains("local mirror"), "{refusal}");
}

#[tokio::test]
async fn kr_req_11_08_a_delegation_outside_its_publisher_refuses_the_generation() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            // A vendor role that claims every target, including the index.
            delegations: vec![("greedy".to_owned(), "*".to_owned(), false)],
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("out of scope");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    assert!(refusal.to_string().contains("outside"), "{refusal}");
}

#[tokio::test]
async fn kr_req_11_08_an_older_generation_is_a_rollback_and_the_current_one_stays() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let second = Generation::build(
        home.path(),
        GenerationSpec {
            generation: 2,
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &second,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("generation two");
    assert_eq!(
        catalogue
            .index(&repository())
            .expect("activated")
            .generation
            .get(),
        2
    );

    // The repository is replaced in place by an earlier generation, keys and all.
    second.rewrite_as(1).await;
    let refusal = catalogue.sync(&repository()).await.expect_err("a rollback");
    assert!(
        refusal.to_string().contains("rollback") || refusal.to_string().contains("version"),
        "{refusal}"
    );
    assert_eq!(
        catalogue
            .index(&repository())
            .expect("activated")
            .generation
            .get(),
        2,
        "the current generation stays usable"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.09: expiry blocks new generations; pinned packages stay usable offline
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_09_expired_metadata_blocks_a_new_generation_and_leaves_the_old_one_usable() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
        .pin_package(environment(), &plugin(), Some(generation.manifest_digest()))
        .expect("pinnable");

    // The repository publishes a newer generation whose metadata has already expired.
    generation.rewrite_expired(2).await;
    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("expired metadata");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    assert!(
        matches!(refusal, CatalogueError::MetadataExpired { .. }),
        "{refusal}"
    );

    // Everything already here still works, with no network and no metadata read at all.
    let index = catalogue.index(&repository()).expect("the previous index");
    assert_eq!(index.generation.get(), 1);
    assert_eq!(
        catalogue
            .search(&repository(), "", 10)
            .expect("offline search")
            .len(),
        1
    );
    let installation = catalogue
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("still installed");
    assert!(installation.pinned);
    assert_eq!(installation.package_digest, generation.manifest_digest());
    let store = catalogue.store(&repository()).expect("enrolled");
    assert!(complete(&store, generation.manifest_digest()));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.05: an uncached payload is unavailable offline, never a fictitious capability
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_05_an_uncached_payload_is_unavailable_offline() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    // The metadata is here and searchable; the payloads are not, and the repository is gone.
    assert_eq!(
        catalogue
            .search(&repository(), "", 10)
            .expect("offline")
            .len(),
        1
    );
    generation.take_offline();

    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect_err("nothing to fetch from");
    assert_eq!(
        refusal.code(),
        ErrorCode::PackageUnavailableOffline,
        "the refusal is an absence of bytes, not a capability this host invented: {refusal}"
    );

    // The index is still whole. The absence is of bytes, not of the catalogue.
    let index = catalogue
        .index(&repository())
        .expect("the index is still here");
    assert_eq!(index.entries.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.06: full mirror, atomic activation, interrupted fetch
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_06_the_full_offline_mirror_setting_fetches_every_payload() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut budgets = RepositoryBudgets::defaults();
    budgets.full_offline_mirror = true;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        budgets,
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    assert!(
        outcome.mirrored_payloads >= 2,
        "a mirror fetches the manifest and every payload: {}",
        outcome.mirrored_payloads
    );

    // With every payload cached, the repository can go away and an activation still succeeds.
    generation.take_offline();
    catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect("every payload is already here");
}

#[tokio::test]
async fn kr_req_11_06_a_corrupt_cached_payload_is_fetched_again_and_never_counts_as_mirrored() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut budgets = RepositoryBudgets::defaults();
    budgets.full_offline_mirror = true;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        budgets,
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    let index = catalogue.index(&repository()).expect("an activated index");
    let entry = index.entries.first().expect("one indexed package").clone();
    let payload = entry.payloads.first().expect("one payload").clone();
    let object = catalogue
        .store(&repository())
        .expect("enrolled")
        .payload_path(payload.digest);
    let cached = std::fs::read(&object).expect("a mirrored payload");

    // An interrupted write leaves the content hash's own name with the wrong bytes behind it.
    std::fs::write(&object, &cached[..cached.len() / 2]).expect("a truncated object");
    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    assert!(
        outcome.mirrored_payloads >= 1,
        "a corrupt object is fetched again rather than skipped: {}",
        outcome.mirrored_payloads
    );
    assert_eq!(
        std::fs::read(&object).expect("a repaired payload"),
        cached,
        "the mirror replaces the object with the bytes the generation names"
    );

    // With the object corrupt and the repository no longer able to supply it, the sync refuses
    // rather than leaving a file of the right name in a set it calls complete.
    std::fs::write(&object, &cached[..cached.len() / 2]).expect("a truncated object");
    std::fs::remove_dir_all(generation.targets_dir().join("packages")).expect("removable packages");
    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("an incomplete mirror");
    assert_eq!(refusal.code(), ErrorCode::PackageUnavailableOffline);
}

#[tokio::test]
async fn kr_req_11_06_a_mirror_past_its_budget_leaves_the_last_generation_usable() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("the first generation, with no mirror");

    // The owner turns the mirror on with a payload budget that cannot hold this generation.
    let mut budgets = RepositoryBudgets::defaults();
    budgets.full_offline_mirror = true;
    budgets.payload_cache_bytes = U64::new(64);
    let mut narrowed = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled")
        .clone();
    narrowed.budgets = budgets;
    catalogue
        .update_enrolment(narrowed, false)
        .expect("a mirror setting enlarges no trust");

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("over the cache budget");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    let message = refusal.to_string();
    assert!(message.contains("payload_cache_bytes"), "{message}");
    assert!(
        message.contains("last generation stays usable"),
        "{message}"
    );

    // A mirror that cannot be completed activates nothing, so the generation this host already
    // accepted is the one it is still on, and it is still searchable.
    assert_eq!(
        catalogue
            .search(&repository(), "", 10)
            .expect("offline")
            .len(),
        1
    );
    assert_eq!(
        catalogue
            .index(&repository())
            .expect("activated")
            .generation
            .get(),
        1
    );
}

#[tokio::test]
async fn kr_req_11_06_an_interrupted_package_activation_leaves_the_installed_one_usable() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            first.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    let installed = first.manifest_digest();

    // The repository publishes a second release whose presentation payload is missing.
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            drop_payload: Some("plugin.json".to_owned()),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    first.replace_with(&second);

    catalogue
        .sync(&repository())
        .await
        .expect("the second generation verifies");
    let refusal = catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &PackageVersion::parse("0.2.0").expect("a valid version"),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect_err("a payload that is not there");
    assert!(
        matches!(
            refusal,
            CatalogueError::UnavailableOffline { .. }
                | CatalogueError::NotFound { .. }
                | CatalogueError::UnsafePackage { .. }
        ),
        "{refusal}"
    );

    // The installed package is untouched, on the hash it was installed at.
    let store = catalogue.store(&repository()).expect("enrolled");
    assert!(complete(&store, installed));
    assert_eq!(
        catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .expect("still installed")
            .package_digest,
        installed
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.10: extraction safety and no installation scripts
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_10_case_colliding_declared_names_are_refused_before_a_fetch() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/invalid/case-colliding-names/package");
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            package: Some(fixtures),
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("a case collision");
    assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    assert!(
        refusal.to_string().contains("case-insensitive"),
        "{refusal}"
    );
}

#[test]
fn kr_req_11_10_an_unsafe_path_never_reaches_an_index_or_a_target_name() {
    // The closed schema is where this is settled. A manifest that declares a traversing path does
    // not parse, so an index cannot carry one, so no fetch is ever started for one.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/invalid/unsafe-extraction-path/package/plugin.json");
    let bytes = std::fs::read(manifest).expect("the fixture");
    let refusal = serde_json::from_slice::<kr_plugin_sdk::plugin::PluginManifest>(&bytes)
        .expect_err("a traversing path");
    assert!(refusal.to_string().contains("traverse"), "{refusal}");

    // And a target name that traverses is refused even though whoever built the generation chose
    // it, because the remainder is checked against the package path rules rather than trusted.
    let prefix = "packages/kalareach/example-declarative/0.1.0";
    for name in [
        "packages/kalareach/example-declarative/0.1.0/../../../etc/passwd",
        "packages/kalareach/example-declarative/0.1.0/assets/../../escape",
        "packages/other/tool/0.1.0/plugin.json",
    ] {
        assert!(
            kr_plugin_catalogue::extract::relative_target(prefix, name).is_err(),
            "{name} should be refused"
        );
    }
}

#[tokio::test]
async fn kr_req_11_10_activation_writes_data_and_runs_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::ExplicitInstall,
        )
        .await
        .expect("activatable");

    let store = catalogue.store(&repository()).expect("enrolled");
    let directory = store.package_dir(generation.manifest_digest());
    let mut seen = 0usize;
    for entry in walk(&directory) {
        seen += 1;
        let metadata = std::fs::symlink_metadata(&entry).expect("readable");
        assert!(
            metadata.file_type().is_file(),
            "{} is not a regular file",
            entry.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                metadata.permissions().mode() & 0o111,
                0,
                "{} was written executable, and sync executes nothing",
                entry.display()
            );
        }
    }
    assert!(seen >= 2, "the package's files are there");
}

fn walk(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.11: the repository capability ceiling
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_11_the_default_ceiling_permits_the_three_passive_capabilities_only() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            capabilities: vec![
                PluginCapability::MetadataMatch,
                PluginCapability::DeclarativePresentation,
                PluginCapability::BrokerSemanticEvents,
                PluginCapability::TranscriptTail,
                PluginCapability::TerminalInput,
                PluginCapability::NativeBridgeInstall,
            ],
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");

    // Nothing beyond the three passive capabilities installs without a grant.
    let refusal = catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect_err("no grant");
    assert_eq!(refusal.code(), ErrorCode::PluginGrantRequired);

    // A native bridge runs outside the component sandbox and needs the owner's confirmation of
    // this exact package, which an installation does not carry, so even a grant that names it
    // does not install it.
    let grant = InstallationGrant::with([
        PluginCapability::TranscriptTail,
        PluginCapability::TerminalInput,
        PluginCapability::NativeBridgeInstall,
    ]);
    let refusal = catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            grant.clone(),
        )
        .await
        .expect_err("a native bridge is not installed");
    assert!(
        matches!(
            refusal,
            CatalogueError::GrantRequired {
                capability: PluginCapability::NativeBridgeInstall,
                ..
            }
        ),
        "{refusal:?}"
    );
    assert!(
        catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .is_none()
    );

    // What each capability needs, decided under the default ceiling.
    let entry = catalogue
        .index(&repository())
        .expect("an activated index")
        .find(&plugin(), &version())
        .expect("the package")
        .clone();
    let decisions = kr_plugin_catalogue::ceiling::decide(
        &entry.capabilities,
        &CapabilityCeiling::default_ceiling(),
        &grant,
    );
    assert_eq!(decisions.len(), 6);
    for decision in &decisions {
        use kr_plugin_catalogue::GrantRequirement as Requirement;
        let expected = match decision.capability {
            PluginCapability::MetadataMatch
            | PluginCapability::DeclarativePresentation
            | PluginCapability::BrokerSemanticEvents => Requirement::WithinCeiling,
            PluginCapability::TranscriptTail => Requirement::RepositoryGrant,
            PluginCapability::NativeBridgeInstall => Requirement::ConfirmedInstallationGrant,
            _ => Requirement::InstallationGrant,
        };
        assert_eq!(
            decision.requirement, expected,
            "{} decided {:?}",
            decision.capability, decision.requirement
        );
    }
}

#[tokio::test]
async fn kr_req_11_11_a_capability_answer_uses_the_ceiling_the_package_came_from() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            capabilities: vec![
                PluginCapability::MetadataMatch,
                PluginCapability::DeclarativePresentation,
                PluginCapability::BrokerSemanticEvents,
                PluginCapability::TranscriptTail,
            ],
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    // A second enrolment of the same generation, trusted with more: a transcript tail needs a
    // repository grant, and this repository has one.
    let wider = RepositoryId::new("wide").expect("a valid repository identifier");
    let enrolment = Enrolment::new(
        wider.clone(),
        RepositoryKind::Community,
        generation.metadata_url(),
        generation.targets_url(),
        generation.root_bytes(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::with([PluginCapability::TranscriptTail]),
    )
    .expect("an enrollable repository");
    catalogue
        .enrol(enrolment, true)
        .expect("the owner adopted the root");

    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::with([PluginCapability::TranscriptTail]),
        )
        .await
        .expect("installable");

    // The owner withdraws the grant. Under the narrow repository's ceiling that leaves the
    // transcript tail unpermitted, and the wider enrolment beside it does not answer for this
    // installation: the ceiling is the one the package came from.
    catalogue
        .set_grant(environment(), &plugin(), InstallationGrant::none())
        .expect("an owner may withdraw what they granted");
    let tail = catalogue
        .capabilities(environment(), &plugin())
        .expect("readable")
        .into_iter()
        .find(|decision| decision.capability == PluginCapability::TranscriptTail)
        .expect("the package asks for a transcript tail");
    assert!(
        !tail.permitted,
        "another repository's ceiling answered for this installation"
    );
    assert!(
        catalogue.repository(&wider).expect("readable").is_some(),
        "the wider repository is enrolled all the same"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.12: budgets, and never evicting a live-bound or pinned payload
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_12_a_metadata_budget_bounds_the_bytes_a_load_holds() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    // The budget is narrowed to one byte under the index's own signed length, so the refusal is
    // the declared check: the index's length is read from the metadata and compared before a byte
    // of the document itself is fetched.
    let index_bytes = std::fs::metadata(generation.targets_dir().join("index.json"))
        .expect("the index")
        .len();
    let mut budgets = RepositoryBudgets::defaults();
    budgets.metadata_bytes = U64::new(index_bytes - 1);
    let mut narrowed = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled")
        .clone();
    narrowed.budgets = budgets;
    catalogue
        .update_enrolment(narrowed, false)
        .expect("narrowing a budget enlarges nothing");

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("over the metadata budget");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    let message = refusal.to_string();
    assert!(message.contains("metadata_bytes"), "{message}");
    assert!(message.contains("metadata budget"), "{message}");
    assert!(
        message.contains("last generation stays usable"),
        "{message}"
    );
}

#[tokio::test]
async fn kr_req_11_12_an_entry_budget_names_its_own_resource() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut budgets = RepositoryBudgets::defaults();
    budgets.metadata_entries = U64::new(0);
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        budgets,
        CapabilityCeiling::default_ceiling(),
    )
    .await;

    let refusal = catalogue
        .sync(&repository())
        .await
        .expect_err("over the entry budget");
    assert!(
        refusal.to_string().contains("metadata_entries"),
        "{refusal}"
    );
}

#[test]
fn kr_req_11_12_the_defaults_are_sixty_four_mebibytes_a_hundred_thousand_entries_and_a_gibibyte() {
    let ledger = BudgetLedger::new(RepositoryBudgets::defaults());
    assert!(
        ledger
            .check_metadata_bytes(64 * 1024 * 1024, Stage::Declared, "index.json")
            .is_ok()
    );
    assert!(
        ledger
            .check_metadata_bytes(64 * 1024 * 1024 + 1, Stage::Declared, "index.json")
            .is_err()
    );
    assert!(
        ledger
            .check_metadata_entries(100_000, Stage::Declared, "index.json")
            .is_ok()
    );
    assert!(
        ledger
            .check_metadata_entries(100_001, Stage::Declared, "index.json")
            .is_err()
    );
    assert!(
        ledger
            .check_payload_bytes(1024 * 1024 * 1024, Stage::Declared, "component.wasm")
            .is_ok()
    );
    assert!(
        ledger
            .check_payload_bytes(1024 * 1024 * 1024 + 1, Stage::Declared, "component.wasm")
            .is_err()
    );
}

#[tokio::test]
async fn kr_req_11_12_a_pinned_payload_is_never_evicted_to_finish_a_sync() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
        .pin_package(environment(), &plugin(), Some(generation.manifest_digest()))
        .expect("pinnable");

    // The repository publishes a second release, and the cache budget is narrowed to exactly
    // what the pinned package already holds. Fetching the second release then needs room that
    // only evicting the pinned package would make.
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(generation.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    generation.replace_with(&second);
    catalogue
        .sync(&repository())
        .await
        .expect("the second generation verifies");
    let store = catalogue.store(&repository()).expect("enrolled");
    let held: u64 = store.cached_payloads().expect("readable").values().sum();
    let mut narrowed = catalogue
        .repository(&repository())
        .expect("readable")
        .expect("enrolled");
    narrowed.budgets.payload_cache_bytes = U64::new(held);
    catalogue
        .update_enrolment(narrowed, false)
        .expect("narrowing a budget enlarges nothing");

    let elsewhere = EnvironmentId::new(Uuid::from_bytes([1; 16]));
    let refusal = catalogue
        .install(
            &repository(),
            elsewhere,
            &plugin(),
            &PackageVersion::parse("0.2.0").expect("a version"),
            second.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect_err("nothing may be evicted to make room");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded, "{refusal}");
    assert!(refusal.to_string().contains("never evicted"), "{refusal}");

    // The pinned package is still here, whole.
    let manifest = generation.manifest_digest();
    let length = store
        .cached_payloads()
        .expect("readable")
        .get(&manifest)
        .copied()
        .expect("the pinned manifest is cached");
    assert!(store.holds_payload(manifest, length).expect("readable"));
    assert!(complete(&store, manifest));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.13 and KR-REQ-25.22: matching, activation, bindings and revocation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_11_13_only_a_matching_enabled_package_binds() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");

    let index = catalogue.index(&repository()).expect("activated");
    let lookup = MatchIndex::build(&index);
    let observed = Observation {
        executable_path: "/usr/local/bin/example-agent".to_owned(),
        distribution: None,
    };
    let candidates = lookup.candidates(&observed);
    assert_eq!(candidates.len(), 1);

    let entry = index
        .find(&plugin(), &version())
        .expect("in the index")
        .clone();

    // Installed and not enabled: nothing is instantiated.
    let refusal = catalogue
        .bind(environment(), &entry, &observed.executable_path)
        .expect_err("disabled");
    assert_eq!(refusal.code(), ErrorCode::PluginDisabled);

    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enablable");
    let binding = catalogue
        .bind(environment(), &entry, &observed.executable_path)
        .expect("enabled");
    assert_eq!(binding.package_digest, generation.manifest_digest());

    // A package nothing recognises is not a candidate at all.
    assert!(
        lookup
            .candidates(&Observation {
                executable_path: "/usr/local/bin/unrelated".to_owned(),
                distribution: None,
            })
            .is_empty()
    );
}

#[tokio::test]
async fn kr_req_25_22_a_revoked_release_stops_new_bindings_and_warns_the_live_one() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enablable");

    let index = catalogue.index(&repository()).expect("activated");
    let entry = index
        .find(&plugin(), &version())
        .expect("in the index")
        .clone();
    let binding = catalogue
        .bind(environment(), &entry, "/usr/local/bin/example-agent")
        .expect("enabled");

    let mut revoked = entry.clone();
    revoked.revocation = Nullable(Some(RevocationRecord {
        reason: RevocationReason::Vulnerable,
        revoked_at: TimestampMs::new(1_760_000_100_000),
        statement: Summary::new("Replaced by 0.1.1").expect("a valid statement"),
    }));

    // No new binding.
    let refusal = catalogue
        .bind(environment(), &revoked, "/usr/local/bin/example-agent")
        .expect_err("revoked");
    assert!(
        refusal.to_string().contains("stops new bindings"),
        "{refusal}"
    );

    // The live one warns and keeps serving under the default policy.
    let notices = catalogue.revocation_notices(&revoked).expect("readable");
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].binding_id, binding.binding_id);
    assert!(notices[0].keeps_serving);
    assert_eq!(notices[0].policy, DisablePolicy::WarnOnly);

    // Under an explicit administrator policy it stops at the next admission, not mid-request.
    catalogue
        .set_disable_policy(DisablePolicy::DisableAtOnce)
        .expect("recorded");
    let notices = catalogue.revocation_notices(&revoked).expect("readable");
    assert!(!notices[0].keeps_serving);
    assert_eq!(
        catalogue.bindings().len(),
        1,
        "the binding is not torn down by the notice itself"
    );

    // A revoked release also stops matching, so nothing new is offered it.
    let mut revoked_index = index.clone();
    revoked_index.entries[0] = revoked;
    let lookup = MatchIndex::build(&revoked_index);
    assert!(
        lookup
            .candidates(&Observation {
                executable_path: "/usr/local/bin/example-agent".to_owned(),
                distribution: None,
            })
            .is_empty()
    );
}

#[tokio::test]
async fn kr_req_11_13_an_upgrade_leaves_a_live_binding_on_its_exact_package_hash() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            first.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enablable");
    let index = catalogue.index(&repository()).expect("activated");
    let entry = index
        .find(&plugin(), &version())
        .expect("in the index")
        .clone();
    catalogue
        .bind(environment(), &entry, "/usr/local/bin/example-agent")
        .expect("enabled");

    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    first.replace_with(&second);
    catalogue
        .sync(&repository())
        .await
        .expect("the second generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &PackageVersion::parse("0.2.0").expect("a valid version"),
            second.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");

    assert_eq!(
        catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .expect("installed")
            .package_digest,
        second.manifest_digest()
    );
    assert_eq!(
        catalogue.bindings()[0].package_digest,
        first.manifest_digest(),
        "the live binding stays on the hash it was made against"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.14 and KR-ACC-017: ten thousand definitions, offline lookup, no input delay
// ---------------------------------------------------------------------------------------------

#[test]
fn kr_req_11_14_ten_thousand_definitions_are_searched_and_matched_offline() {
    let index = support::synthetic_index(10_000);
    assert_eq!(index.entries.len(), 10_000);

    let started = std::time::Instant::now();
    let lookup = MatchIndex::build(&index);
    assert_eq!(lookup.executable_count(), 10_000);

    // Matching is a lookup in one bucket rather than a scan of ten thousand rules. The count is
    // what makes that structural rather than a claim about a clock: one candidate out of ten
    // thousand entries, from a bucket holding one entry.
    let found = lookup.candidates(&Observation {
        executable_path: "/usr/local/bin/agent-7421".to_owned(),
        distribution: None,
    });
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].plugin_id.as_str(), "kalareach/agent-7421");

    for ordinal in 0..10_000u32 {
        let found = lookup.candidates(&Observation {
            executable_path: format!("/usr/local/bin/agent-{ordinal}"),
            distribution: None,
        });
        assert_eq!(found.len(), 1, "agent-{ordinal}");
    }

    // Offline search reads the whole index and nothing else.
    assert_eq!(support::search_len(&index, "agent-7421"), 1);
    assert_eq!(support::search_len(&index, "agent"), 10_000);
    assert_eq!(support::search_len(&index, "nothing here"), 0);

    // A generous bound. The point is that a catalogue this size is not a reason to wait: ten
    // thousand lookups and three searches over ten thousand entries, well inside a second on any
    // machine this runs on, and measured with enough margin that a loaded one still passes.
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "ten thousand definitions took {elapsed:?}"
    );
}

#[tokio::test]
async fn kr_ac_017_catalogue_search_does_not_hold_the_runtime_a_terminal_shares() {
    // A task that ticks while the catalogue is searched, on the same runtime, with the search on
    // a blocking task exactly as a host would run one. What this establishes is that the search
    // does not take the reactor away from something that has to keep ticking; it does not measure
    // a terminal's input latency, which needs the terminal.
    let index = Arc::new(support::synthetic_index(10_000));
    let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });

    let searching = Arc::clone(&index);
    let searched = tokio::task::spawn_blocking(move || {
        let lookup = MatchIndex::build(&searching);
        let mut total = 0usize;
        for ordinal in 0..2_000u32 {
            total += lookup
                .candidates(&Observation {
                    executable_path: format!("/usr/local/bin/agent-{ordinal}"),
                    distribution: None,
                })
                .len();
        }
        total
    });

    assert_eq!(searched.await.expect("the search finished"), 2_000);
    ticker.await.expect("the ticker finished");
    assert_eq!(ticks.load(std::sync::atomic::Ordering::Relaxed), 200);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.15 and KR-REQ-11.18: capability evidence and signed qualification
// ---------------------------------------------------------------------------------------------

#[test]
fn kr_req_11_15_the_runtime_state_vocabulary_is_one_vocabulary() {
    // The protocol's wire vocabulary and the SDK's evidence vocabulary are the same seven states,
    // spelled the same way. A host cannot report a state a client has no name for.
    let sdk = [
        CapabilityState::QualifiedAvailable,
        CapabilityState::VersionQualified,
        CapabilityState::MissingInstallation,
        CapabilityState::PermissionRequired,
        CapabilityState::Incompatible,
        CapabilityState::TemporarilyUnavailable,
        CapabilityState::NotTested,
    ];
    let wire = kr_protocol::catalogue::PluginCapabilityState::ALL;
    assert_eq!(sdk.len(), wire.len());
    for (sdk_state, wire_state) in sdk.iter().zip(wire) {
        let sdk_name = serde_json::to_string(sdk_state).expect("serialisable");
        assert_eq!(sdk_name.trim_matches('"'), wire_state.as_str());
    }

    let sdk_sources = [
        EvidenceSource::HostProbe,
        EvidenceSource::LiveBinding,
        EvidenceSource::SignedRecord,
        EvidenceSource::PackageDeclaration,
    ];
    let wire_sources = kr_protocol::catalogue::PluginEvidenceSource::ALL;
    assert_eq!(sdk_sources.len(), wire_sources.len());
    for (sdk_source, wire_source) in sdk_sources.iter().zip(wire_sources) {
        let sdk_name = serde_json::to_string(sdk_source).expect("serialisable");
        assert_eq!(sdk_name.trim_matches('"'), wire_source.as_str());
    }
}

#[test]
fn kr_req_11_18_a_qualification_creates_no_effect_and_raises_no_grant() {
    use kr_plugin_catalogue::evidence;

    let entry = support::example_entry();
    // An installation of the package this entry describes, recorded with what its manifest asks
    // for.
    let installation = Installation {
        plugin_id: entry.plugin_id.clone(),
        publisher_id: entry.publisher_id.clone(),
        plugin_name: entry.plugin_name.clone(),
        version: entry.version.clone(),
        package_digest: entry.manifest_digest,
        enrolment: kr_plugin_catalogue::EnrolmentKey::generate().expect("a key"),
        repository: repository(),
        environment_id: environment(),
        enabled: false,
        pinned: false,
        grant: InstallationGrant::none(),
        requested: entry.capabilities.clone(),
        payloads: entry
            .payloads
            .iter()
            .map(|payload| payload.digest)
            .collect(),
        ceiling: CapabilityCeiling::default_ceiling(),
    };
    let requested = entry.capabilities[0].capability;

    let good = QualificationResult {
        capability_id: evidence::capability_id(requested).expect("an identifier"),
        capability_version: PackageVersion::parse("1.0.0").expect("a valid version"),
        subject: Label::new("ExternalApp 1.4").expect("a valid label"),
        state: CapabilityState::VersionQualified,
        source: EvidenceSource::SignedRecord,
        profile_digest: PayloadDigest::of(b"profile"),
        statement: Summary::new("Qualified against ExternalApp 1.4").expect("a valid statement"),
    };
    let record = evidence::from_qualification(
        &entry,
        &installation,
        &good,
        kr_protocol::ids::CapabilityRevision::new(1),
        TimestampMs::new(1_760_000_000_000),
    )
    .expect("readable");
    assert_eq!(record.state, CapabilityState::VersionQualified);
    assert!(
        !record.state.is_usable(),
        "a signed artifact describes a release, not this host"
    );

    // A capability the package never requested is an effect the artifact would be creating.
    let unrequested = PluginCapability::ALL
        .iter()
        .copied()
        .find(|capability| {
            !entry
                .capabilities
                .iter()
                .any(|r| r.capability == *capability)
        })
        .expect("some capability the example does not request");
    let mut inventing = good.clone();
    inventing.capability_id = evidence::capability_id(unrequested).expect("an identifier");
    assert!(
        evidence::from_qualification(
            &entry,
            &installation,
            &inventing,
            kr_protocol::ids::CapabilityRevision::new(1),
            TimestampMs::new(1_760_000_000_000)
        )
        .is_err()
    );

    // A record outside the effective grant raises nothing: it is refused.
    let nothing: BTreeSet<PluginCapability> = BTreeSet::new();
    assert!(
        evidence::check_grants_nothing(std::slice::from_ref(&record), &nothing, "acme/tool")
            .is_err()
    );
    let granted: BTreeSet<PluginCapability> = [requested].into_iter().collect();
    assert!(evidence::check_grants_nothing(&[record], &granted, "acme/tool").is_ok());

    // And a record for another release never becomes this installation's.
    let mut moved = installation;
    moved.package_digest = PayloadDigest::of(b"another release");
    assert!(
        evidence::from_qualification(
            &entry,
            &moved,
            &good,
            kr_protocol::ids::CapabilityRevision::new(1),
            TimestampMs::new(1_760_000_000_000),
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------------------------
// The generation the plugins repository actually published
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_development_generation_verifies_and_is_searchable_offline() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/catalogue/development");
    let home = tempfile::tempdir().expect("a temporary directory");
    // The generation is copied to the internal disk before it is read, so nothing a test starts
    // opens a path on the workspace volume.
    let working = home.path().join("development");
    support::copy_tree(&fixture, &working);

    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        support::directory_url(&working.join("metadata")),
        support::directory_url(&working.join("targets")),
        std::fs::read(working.join("root.json")).expect("a trust root"),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("an enrollable repository");
    catalogue.enrol(enrolment, true).expect("adopted");

    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("the published generation verifies");
    assert_eq!(outcome.generation.get(), 1);
    assert_eq!(outcome.entries, 7, "seven packages at 0.1.0");

    let index = catalogue.index(&repository()).expect("activated");
    assert_eq!(
        support::search_len(&index, "codex"),
        1,
        "offline search finds a package by name"
    );

    // One of them installs, with every payload verified against what the index declares.
    let declarative = PluginId::new("kalareach/example-declarative").expect("a valid identifier");
    let entry = index
        .find(&declarative, &version())
        .expect("the example package")
        .clone();
    let installation = catalogue
        .install(
            &repository(),
            environment(),
            &declarative,
            &version(),
            entry.manifest_digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installable under the default ceiling");
    assert_eq!(installation.package_digest, entry.manifest_digest);

    let store = catalogue.store(&repository()).expect("enrolled");
    assert!(complete(&store, entry.manifest_digest));
}

#[test]
fn the_development_fixture_names_the_commit_it_was_copied_from() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/catalogue/development/README.md");
    let text = std::fs::read_to_string(readme).expect("the fixture's README");
    assert!(
        text.contains("44084fc058106bca25bfb4f2118cc349187419df"),
        "the fixture names the commit it came from"
    );

    // And the files themselves carry no key material, which is checked by reading them rather
    // than by believing the sentence above that says so.
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/catalogue/development");
    let mut seen = 0usize;
    for path in walk(&directory) {
        seen += 1;
        let bytes = std::fs::read(&path).expect("readable");
        let text = String::from_utf8_lossy(&bytes);
        for marker in [
            "PRIVATE KEY",
            "BEGIN RSA",
            "BEGIN EC PARAMETERS",
            "BEGIN OPENSSH",
        ] {
            assert!(
                !text.contains(marker),
                "{} carries {marker}",
                path.display()
            );
        }
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("readable")
                .file_type()
                .is_file(),
            "{} is not a regular file",
            path.display()
        );
    }
    assert_eq!(seen, 30, "the generation's files and its README");
}

// ---------------------------------------------------------------------------------------------
// Enrolment: the owner's decisions, and a branch that is never update authority
// ---------------------------------------------------------------------------------------------

#[test]
fn kr_req_11_11_a_wider_ceiling_or_a_new_root_is_the_owners_decision() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        url("file:///var/lib/kalareach/mirror/metadata/"),
        url("file:///var/lib/kalareach/mirror/targets/"),
        b"a root".to_vec(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("enrollable");

    let refusal = catalogue
        .enrol(enrolment.clone(), false)
        .expect_err("unconfirmed");
    assert_eq!(refusal.code(), ErrorCode::OwnerConfirmationRequired);
    catalogue.enrol(enrolment.clone(), true).expect("confirmed");

    let mut wider = enrolment;
    wider.ceiling = CapabilityCeiling::with([PluginCapability::TranscriptTail]);
    let refusal = catalogue
        .update_enrolment(wider.clone(), false)
        .expect_err("a wider ceiling");
    assert_eq!(refusal.code(), ErrorCode::OwnerConfirmationRequired);
    catalogue.update_enrolment(wider, true).expect("confirmed");
}

#[test]
fn a_version_control_branch_is_never_update_authority() {
    for location in [
        "git+https://example.invalid/plugins.git",
        "https://example.invalid/plugins?ref=main",
    ] {
        let refusal = Enrolment::new(
            repository(),
            RepositoryKind::Vendor,
            url(location),
            url("https://example.invalid/targets/"),
            b"a root".to_vec(),
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .expect_err("a moving reference");
        assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
        assert!(
            refusal.to_string().contains("never update authority"),
            "{location}: {refusal}"
        );
    }
}

#[test]
fn an_independent_root_is_kept_separate_from_the_official_one() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    for (name, root) in [
        ("official", b"official root".as_slice()),
        ("vendor", b"vendor root"),
    ] {
        let enrolment = Enrolment::new(
            RepositoryId::new(name).expect("a valid identifier"),
            RepositoryKind::Vendor,
            url("file:///var/lib/kalareach/mirror/metadata/"),
            url("file:///var/lib/kalareach/mirror/targets/"),
            root.to_vec(),
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .expect("enrollable");
        catalogue.enrol(enrolment, true).expect("adopted");
    }
    let roots: Vec<PayloadDigest> = catalogue
        .repositories()
        .expect("readable")
        .iter()
        .map(|enrolment| enrolment.root_digest())
        .collect();
    assert_eq!(roots.len(), 2);
    assert_ne!(roots[0], roots[1], "one repository's root is not another's");

    // And a restart finds both, each against the root it adopted.
    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    let after: Vec<PayloadDigest> = reopened
        .repositories()
        .expect("readable")
        .iter()
        .map(|enrolment| enrolment.root_digest())
        .collect();
    assert_eq!(roots, after);
}

#[test]
fn every_capability_name_round_trips() {
    for capability in PluginCapability::ALL {
        assert_eq!(
            capability_from_str(capability.as_str()).expect("a known capability"),
            *capability
        );
    }
}

#[test]
fn an_explicit_selection_wins_a_conflict() {
    let index = support::conflicting_index();
    let lookup = MatchIndex::build(&index);
    let found = lookup.candidates(&Observation {
        executable_path: "/usr/local/bin/agent".to_owned(),
        distribution: None,
    });
    assert_eq!(found.len(), 2);
    assert!(matches!(
        kr_plugin_catalogue::search::resolve(found.clone(), None),
        Resolution::Conflict(_)
    ));
    let chosen = index.entries[1].plugin_id.clone();
    match kr_plugin_catalogue::search::resolve(found, Some(&chosen)) {
        Resolution::Selected(candidate) => assert_eq!(candidate.plugin_id, chosen),
        other => panic!("the selection should win: {other:?}"),
    }
}

#[tokio::test]
async fn failed_index_fetch_must_keep_rotated_root() {
    let home = tempfile::tempdir().expect("tempdir");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("initial sync");
    let new_root = generation.rotate_root_to_v2(&KeySet::generate()).await;
    std::fs::remove_file(generation.targets_dir().join("index.json")).expect("removed index");
    assert!(catalogue.sync(&repository()).await.is_err());
    let actual: serde_json::Value = serde_json::from_slice(
        &catalogue
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .root,
    )
    .expect("json");
    let expected: serde_json::Value = serde_json::from_slice(&new_root).expect("json");
    assert_eq!(
        actual["signed"]["version"], expected["signed"]["version"],
        "rotation must survive later index failure"
    );
}

#[tokio::test]
async fn failed_timestamp_fetch_must_keep_rotated_root() {
    let home = tempfile::tempdir().expect("tempdir");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("initial sync");
    let new_root = generation.rotate_root_to_v2(&KeySet::generate()).await;
    std::fs::remove_file(generation.metadata_dir().join("timestamp.json"))
        .expect("removed timestamp");
    assert!(catalogue.sync(&repository()).await.is_err());
    let actual: serde_json::Value = serde_json::from_slice(
        &catalogue
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .root,
    )
    .expect("json");
    let expected: serde_json::Value = serde_json::from_slice(&new_root).expect("json");
    assert_eq!(
        actual["signed"]["version"], expected["signed"]["version"],
        "rotation during load must survive timestamp failure"
    );
}

#[tokio::test]
async fn failed_index_fetch_must_reject_subsequent_old_keys() {
    let home = tempfile::tempdir().expect("tempdir");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("initial sync");
    generation.rotate_root_to_v2(&KeySet::generate()).await;
    std::fs::remove_file(generation.targets_dir().join("index.json")).expect("removed index");
    assert!(catalogue.sync(&repository()).await.is_err());
    generation.rewrite_as(3).await;
    generation.withhold_root_v2();
    assert!(
        catalogue.sync(&repository()).await.is_err(),
        "metadata signed by replaced keys must be refused"
    );
}

#[tokio::test]
async fn installed_hash_must_not_authorise_another_version() {
    let home = tempfile::tempdir().expect("tempdir");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("sync");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            first.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enabled");
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    first.replace_with(&second);
    catalogue.sync(&repository()).await.expect("sync 2");
    let result = catalogue
        .activate_package_scoped(
            &repository(),
            Some(environment()),
            &plugin(),
            &PackageVersion::parse("0.2.0").expect("version"),
            Some(first.manifest_digest()),
            FetchReason::AuthorisedActivation,
        )
        .await;
    assert!(
        result.is_err(),
        "an installed v1 hash authorised v2 fetch: {result:?}"
    );
}

#[tokio::test]
async fn old_installed_package_must_enable_after_index_drops_it() {
    let home = tempfile::tempdir().expect("tempdir");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("sync");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            first.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    first.replace_with(&second);
    catalogue.sync(&repository()).await.expect("sync 2");
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("verified local v1 must stay usable");
}

/// Every installed operation still answers after the repository is actually unenrolled.
///
/// `catalogue.remove` stops this host trusting a root. It does not uninstall what came from it, so
/// the package stays installed on the hash it was installed at, and enable, pin, grant, capability
/// queries and uninstall all have to keep working with no enrolment behind them.
#[tokio::test]
async fn kr_req_11_09_installed_operations_survive_the_repository_being_removed() {
    let home = tempfile::tempdir().expect("a temporary directory");
    // The package asks for the transcript tail, which only the wider ceiling permits, so what a
    // restart reads back is an effective permission and not only a stored ceiling.
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            capabilities: vec![
                PluginCapability::MetadataMatch,
                PluginCapability::DeclarativePresentation,
                PluginCapability::BrokerSemanticEvents,
                PluginCapability::TranscriptTail,
            ],
            ..GenerationSpec::default()
        },
    )
    .await;
    // A ceiling wider than the default, so what a restart reads back can be told apart from the
    // narrowest one a repository can have.
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::with([PluginCapability::TranscriptTail]),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");

    catalogue
        .remove_repository(&repository())
        .expect("the owner stopped trusting this root");
    assert!(
        catalogue
            .repository(&repository())
            .expect("readable")
            .is_none(),
        "the enrolment is gone"
    );

    // What it may do is answered from what the installation recorded, not from an enrolment.
    let decisions = catalogue
        .capabilities(environment(), &plugin())
        .expect("a capability answer without an enrolment");
    assert!(!decisions.is_empty());
    let effective = catalogue
        .effective_capabilities(environment(), &plugin())
        .expect("effective capabilities");
    assert!(effective.contains(&PluginCapability::DeclarativePresentation));
    assert!(
        effective.contains(&PluginCapability::TranscriptTail),
        "the ceiling it was installed under still permits what it asks for: {effective:?}"
    );

    // Enabling reads no metadata: the payloads are in the directory the enrolment left behind.
    let enabled = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("an installed package is enablable without its repository");
    assert!(enabled.enabled);

    let pinned = catalogue
        .pin_package(environment(), &plugin(), Some(generation.manifest_digest()))
        .expect("pinnable without its repository");
    assert!(pinned.pinned);

    // A grant is still held to what the package asked for and what its repository permitted.
    let withdrawn = catalogue
        .set_grant(environment(), &plugin(), InstallationGrant::none())
        .expect("a grant can be withdrawn without its repository");
    assert!(withdrawn.grant.capabilities().is_empty());
    let refused = catalogue.set_grant(
        environment(),
        &plugin(),
        InstallationGrant::with([PluginCapability::FilesystemRead]),
    );
    assert!(
        matches!(refused, Err(CatalogueError::GrantRequired { .. })),
        "the recorded ceiling still decides: {refused:?}"
    );

    // And what a restart reads back says the same thing, from the ceiling it recorded rather than
    // from the default one: the repository is gone and the wider ceiling it had is still here.
    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    let effective = reopened
        .effective_capabilities(environment(), &plugin())
        .expect("effective capabilities after a restart");
    assert!(!effective.contains(&PluginCapability::FilesystemRead));
    assert!(
        effective.contains(&PluginCapability::TranscriptTail),
        "and so does a restart, with no enrolment behind it: {effective:?}"
    );
    let installed = reopened
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("still installed after a restart");
    assert!(
        installed.ceiling.permits(PluginCapability::TranscriptTail),
        "the wider ceiling this package was installed under survives the restart"
    );
    assert!(!installed.ceiling.permits(PluginCapability::FilesystemRead));

    let closed = catalogue
        .uninstall(environment(), &plugin())
        .expect("uninstallable without its repository");
    assert_eq!(closed, 0);
}

// ---------------------------------------------------------------------------------------------
// Trust progress: a private copy for every verification, and a checkpoint only a verified load moves
// ---------------------------------------------------------------------------------------------

/// Every file of the accepted trust checkpoint, with its bytes.
fn checkpoint(catalogue: &Catalogue) -> std::collections::BTreeMap<String, Vec<u8>> {
    let directory = catalogue
        .store(&repository())
        .expect("enrolled")
        .datastore();
    std::fs::read_dir(&directory)
        .expect("a checkpoint")
        .flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).expect("readable"),
            )
        })
        .collect()
}

/// Lower role versions under new keys are accepted after the sync that reached the new root failed
/// and the host restarted.
///
/// A root that changes the timestamp and snapshot keys lets those roles start again from lower
/// versions. The sync here keeps the new root and then fails at its index, so the next sync starts
/// from the new root. The floors the old keys set no longer apply: the client applies a stored
/// floor only where it still verifies under the current root, and the reset recorded with the kept
/// root drops the floors from the working copy for a key change the client would otherwise not see.
/// A second floor of this host's own, compared whatever the keys, refuses these versions.
#[tokio::test]
async fn lower_role_versions_under_new_keys_are_accepted_after_a_failed_sync_and_a_restart() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            generation: 5,
            ..GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("generation five, every role at version five");

    // New keys for every role, every role's metadata at version two, and a newer generation.
    let new_root = generation
        .rotate_root_to_v2_publishing(&KeySet::generate(), 6)
        .await;
    let index = generation.targets_dir().join("index.json");
    let published = std::fs::read(&index).expect("an index");
    std::fs::remove_file(&index).expect("removable");
    assert!(
        catalogue.sync(&repository()).await.is_err(),
        "the index is missing"
    );
    let kept: serde_json::Value = serde_json::from_slice(
        &catalogue
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .root,
    )
    .expect("json");
    let rotated: serde_json::Value = serde_json::from_slice(&new_root).expect("json");
    assert_eq!(kept["signed"]["version"], rotated["signed"]["version"]);

    // A restart in between changes nothing: the reset is kept with the root.
    drop(catalogue);
    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    std::fs::write(&index, &published).expect("writable");
    let outcome = catalogue
        .sync(&repository())
        .await
        .expect("lower versions under the new keys are accepted");
    assert_eq!(outcome.generation.get(), 6);
}

/// A verification that fails, is interrupted or is refused at its commit leaves the accepted
/// trust checkpoint exactly as it was, and one that verifies replaces it.
///
/// The client works in a private copy. The accepted checkpoint changes only through its own
/// commit, under the admission, after the metadata verified.
#[tokio::test]
async fn a_verification_that_does_not_finish_leaves_the_accepted_checkpoint_as_it_was() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a first generation");
    let accepted = checkpoint(&catalogue);
    assert!(
        accepted.contains_key("timestamp.json"),
        "{:?}",
        accepted.keys()
    );
    generation.rewrite_as(2).await;

    // Refused at its commit: the metadata verified, and none of it was accepted.
    let withdrawn = WithdrawnAtCommit::default();
    let refused = catalogue
        .sync_with(&repository(), &mut Change::new(&withdrawn))
        .await;
    assert!(
        matches!(refused, Err(CatalogueError::PermissionDenied { .. })),
        "{refused:?}"
    );
    assert_eq!(checkpoint(&catalogue), accepted, "refused at the commit");

    // Interrupted part way through the metadata.
    catalogue.set_transport(Arc::new(Damaging {
        suffix: "snapshot.json",
        damage: Damage::DropsPartWay,
    }));
    assert!(catalogue.sync(&repository()).await.is_err());
    assert_eq!(checkpoint(&catalogue), accepted, "interrupted");

    // Verified: the checkpoint is the new metadata, and no working copy is left behind.
    catalogue.set_transport(Arc::new(tough::FilesystemTransport));
    catalogue
        .sync(&repository())
        .await
        .expect("the second generation");
    assert_ne!(checkpoint(&catalogue), accepted);
    let staging = catalogue
        .store(&repository())
        .expect("enrolled")
        .datastore()
        .with_file_name("staging");
    assert_eq!(
        std::fs::read_dir(&staging).expect("readable").count(),
        0,
        "no working copy is left in staging"
    );
}

/// Reads the local repository and takes its time over every package file, so time passes while a
/// mirror fetches.
#[derive(Clone, Debug)]
struct Slow {
    absent: Option<&'static str>,
    called: Arc<std::sync::Mutex<Vec<jiff::Timestamp>>>,
}

#[tough::async_trait]
impl tough::Transport for Slow {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        if url.path().contains("/packages/") {
            self.called
                .lock()
                .expect("the list")
                .push(jiff::Timestamp::now());
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            if self
                .absent
                .is_some_and(|suffix| url.path().ends_with(suffix))
            {
                return Err(tough::TransportError::new(
                    tough::TransportErrorKind::FileNotFound,
                    url,
                ));
            }
        }
        tough::FilesystemTransport.fetch(url).await
    }
}

/// The latest time the client saw while a mirror fetched is kept in the accepted checkpoint,
/// whether the mirror finished or not.
///
/// The client refuses a clock set back behind the latest time it knows, and it moves that time on
/// every time it reads a target. The checkpoint is published before the mirror starts, so the
/// times the mirror saw are kept by a commit of their own; without it the accepted time would be
/// the one from before the mirror, and a clock set back to a time in between would pass.
#[tokio::test]
async fn the_time_a_mirror_saw_is_kept_with_the_trust_checkpoint() {
    for absent in [None, Some("presentation.json")] {
        let home = tempfile::tempdir().expect("a temporary directory");
        let generation = Generation::build(home.path(), GenerationSpec::default()).await;
        let mut budgets = RepositoryBudgets::defaults();
        budgets.full_offline_mirror = true;
        let mut catalogue = enrolled(
            home.path(),
            &generation,
            budgets,
            CapabilityCeiling::default_ceiling(),
        )
        .await;
        let slow = Slow {
            absent,
            called: Arc::default(),
        };
        catalogue.set_transport(Arc::new(slow.clone()));
        let outcome = catalogue.sync(&repository()).await;
        assert_eq!(outcome.is_ok(), absent.is_none(), "{absent:?}: {outcome:?}");
        // The client reads its clock just before it asks for each file.
        let last_fetch = *slow
            .called
            .lock()
            .expect("the list")
            .last()
            .expect("the mirror fetched");
        let kept: jiff::Timestamp = serde_json::from_slice(
            &std::fs::read(
                catalogue
                    .store(&repository())
                    .expect("enrolled")
                    .datastore()
                    .join("latest_known_time.json"),
            )
            .expect("a time checkpoint"),
        )
        .expect("a time");
        assert!(
            last_fetch.duration_since(kept) < jiff::SignedDuration::from_millis(100),
            "{absent:?}: the kept time {kept} is from before the mirror's last fetch at \
             {last_fetch}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// What is installed is the package this host checked, fetched as its accepted generation named it
// ---------------------------------------------------------------------------------------------

/// Reads the local repository and keeps the location of every fetch.
#[derive(Clone, Debug, Default)]
struct Watched {
    fetched: Arc<std::sync::Mutex<Vec<url::Url>>>,
}

#[tough::async_trait]
impl tough::Transport for Watched {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        self.fetched.lock().expect("the list").push(url.clone());
        tough::FilesystemTransport.fetch(url).await
    }
}

/// A generation this host accepted stays installable after the repository publishes a newer one,
/// and installing from it reads no metadata at all.
///
/// The payloads are fetched as the accepted generation named them, from where it said they are.
/// Reading the current metadata instead would find generation 2 and refuse, which would make an
/// accepted, or pinned, generation uninstallable while its exact bytes are still there.
#[tokio::test]
async fn an_accepted_generation_stays_installable_after_the_repository_moves_on() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let first = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &first,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("the first generation");
    drop(catalogue);

    // The repository moves on to generation 2, and the first generation's package files are still
    // where it named them.
    let second = Generation::build(
        &home.path().join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    support::copy_tree(&second.metadata_dir(), &first.metadata_dir());
    support::copy_tree(&second.targets_dir(), &first.targets_dir());

    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    let watched = Watched::default();
    catalogue.set_transport(Arc::new(watched.clone()));
    let installation = catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            first.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable from the generation this host accepted");
    assert_eq!(installation.package_digest, first.manifest_digest());

    let fetched = watched.fetched.lock().expect("the list").clone();
    let metadata = first.metadata_url();
    assert!(!fetched.is_empty(), "the payloads were fetched");
    assert!(
        fetched
            .iter()
            .all(|url| !url.as_str().starts_with(metadata.as_str())),
        "no metadata was read: {fetched:?}"
    );
}

/// One change an index can make to what it says about a package.
type EntryEdit = fn(&mut kr_plugin_sdk::catalogue::IndexEntry);

fn one_capability_fewer(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
    entry.capabilities.pop();
}

fn no_match_rules(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
    entry.match_rules.clear();
}

fn no_platforms(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
    entry.platforms.clear();
}

fn the_other_component_answer(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
    entry.has_component = !entry.has_component;
}

/// A package already here is installed only when the entry that names it agrees with its manifest.
///
/// A later signed index can say something about a hash that the manifest the hash names does not.
/// The package is reused without a fetch, and what is installed is read from its own manifest, so
/// the disagreement is refused rather than installed under the index's version of it.
#[tokio::test]
async fn a_package_already_here_is_installed_only_when_its_entry_agrees_with_its_manifest() {
    let edits: [(&str, EntryEdit); 4] = [
        ("requested capabilities", one_capability_fewer),
        ("match rules", no_match_rules),
        ("platform support", no_platforms),
        ("component", the_other_component_answer),
    ];
    for (field, edit) in edits {
        let home = tempfile::tempdir().expect("a temporary directory");
        let first = Generation::build(home.path(), GenerationSpec::default()).await;
        let mut catalogue = enrolled(
            home.path(),
            &first,
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .await;
        catalogue.sync(&repository()).await.expect("a generation");
        catalogue
            .install(
                &repository(),
                environment(),
                &plugin(),
                &version(),
                first.manifest_digest(),
                InstallationGrant::none(),
            )
            .await
            .expect("installable");

        let second = Generation::build(
            &home.path().join("second"),
            GenerationSpec {
                generation: 2,
                keys: Some(first.keys()),
                edit_entry: Some(edit),
                ..GenerationSpec::default()
            },
        )
        .await;
        assert_eq!(second.manifest_digest(), first.manifest_digest());
        first.replace_with(&second);
        catalogue
            .sync(&repository())
            .await
            .expect("the index verifies; it only disagrees with the manifest");

        let elsewhere = EnvironmentId::new(kr_ipc::new_uuid());
        let refusal = catalogue
            .install(
                &repository(),
                elsewhere,
                &plugin(),
                &version(),
                first.manifest_digest(),
                InstallationGrant::none(),
            )
            .await
            .expect_err("the entry disagrees with the manifest its hash names");
        assert!(
            matches!(refusal, CatalogueError::Integrity { .. })
                && refusal.to_string().contains(field),
            "{field}: {refusal}"
        );
        assert!(
            catalogue
                .installation(elsewhere, &plugin())
                .expect("readable")
                .is_none(),
            "{field}: nothing was installed"
        );
    }
}

/// A package whose files were removed or altered is fetched and checked again before it is
/// enabled, and one that cannot be fetched again is refused.
///
/// The directory's name is not the package. Enabling asks whether every file the manifest declares
/// is here in the bytes declared, and repairs what is not from the generation the package was
/// installed from; with the repository gone there is nothing to repair from, and the refusal says
/// so.
#[tokio::test]
async fn a_package_that_lost_or_changed_a_file_is_repaired_before_it_is_enabled() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;
    let store = catalogue.store(&repository()).expect("enrolled");
    let package = store.package_dir(generation.manifest_digest());
    let presentation = package.join(kr_plugin_sdk::package::PRESENTATION_FILE);

    for damage in ["removed", "altered"] {
        if damage == "removed" {
            std::fs::remove_file(&presentation).expect("removable");
        } else {
            std::fs::write(&presentation, b"not the declared bytes").expect("writable");
        }
        assert!(!complete(&store, generation.manifest_digest()), "{damage}");
        catalogue
            .set_enabled(environment(), &plugin(), true)
            .await
            .expect("repaired from the accepted generation and enabled");
        assert!(
            complete(&store, generation.manifest_digest()),
            "{damage}: the package is whole again"
        );
        catalogue
            .set_enabled(environment(), &plugin(), false)
            .await
            .expect("disabled");
    }

    // With the repository removed, there is nothing to fetch it again from.
    catalogue
        .remove_repository(&repository())
        .expect("the owner stopped trusting this root");
    std::fs::write(&presentation, b"not the declared bytes").expect("writable");
    let refusal = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect_err("an altered package with nothing to repair it from");
    assert!(
        matches!(refusal, CatalogueError::UnavailableOffline { .. }),
        "{refusal}"
    );
    assert!(
        !catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .expect("still installed")
            .enabled
    );
}

// ---------------------------------------------------------------------------------------------
// One owner for the catalogue's records, and the admission asked where a change becomes durable
// ---------------------------------------------------------------------------------------------

/// An authority that admits every early check and refuses at the commit, as an admission
/// withdrawn while the change waited for a lock or a download does.
#[derive(Debug, Default)]
struct WithdrawnAtCommit {
    commits: std::sync::atomic::AtomicUsize,
}

impl Authority for WithdrawnAtCommit {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        _effect: &Effect,
        _commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.commits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(CatalogueError::PermissionDenied {
            detail: "the authority behind this action was withdrawn".to_owned(),
        })
    }

    fn owner_confirmed(&self) -> bool {
        true
    }
}

/// An authority whose commit runs the change and then cannot confirm its own order.
#[derive(Debug, Default)]
struct FailsAfterCommit;

impl Authority for FailsAfterCommit {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        _effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        commit()?;
        Err(CatalogueError::StorageUnavailable {
            detail: "the order the change ran under could not be released".to_owned(),
        })
    }

    fn owner_confirmed(&self) -> bool {
        true
    }
}

/// Enrols, synchronises and installs the example package, returning the catalogue.
async fn installed_catalogue(home: &std::path::Path, generation: &Generation) -> Catalogue {
    let mut catalogue = enrolled(
        home,
        generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue.sync(&repository()).await.expect("a generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
}

/// A change refused at its commit changes nothing, in memory or on disk.
///
/// The admission is asked again where the change becomes durable, because everything between the
/// first check and the commit can wait: for the repository's lock, for a download, for the disk.
/// Every kind of change is refused there: the repository's, the installation's, and a sync's.
#[tokio::test]
async fn a_change_refused_at_its_commit_changes_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;
    let withdrawn = WithdrawnAtCommit::default();

    let pin = catalogue.pin_with(
        &repository(),
        Some(RepositoryGeneration::new(1)),
        &mut Change::new(&withdrawn),
    );
    assert!(
        matches!(pin, Err(CatalogueError::PermissionDenied { .. })),
        "{pin:?}"
    );
    let removal = catalogue.remove_repository_with(&repository(), &mut Change::new(&withdrawn));
    assert!(
        matches!(removal, Err(CatalogueError::PermissionDenied { .. })),
        "{removal:?}"
    );
    let grant = catalogue.pin_package_with(
        environment(),
        &plugin(),
        Some(generation.manifest_digest()),
        &mut Change::new(&withdrawn),
    );
    assert!(
        matches!(grant, Err(CatalogueError::PermissionDenied { .. })),
        "{grant:?}"
    );
    let enable = catalogue
        .set_enabled_with(environment(), &plugin(), true, &mut Change::new(&withdrawn))
        .await;
    assert!(
        matches!(enable, Err(CatalogueError::PermissionDenied { .. })),
        "{enable:?}"
    );
    let uninstall =
        catalogue.uninstall_with(environment(), &plugin(), &mut Change::new(&withdrawn));
    assert!(
        matches!(uninstall, Err(CatalogueError::PermissionDenied { .. })),
        "{uninstall:?}"
    );
    assert!(
        withdrawn.commits.load(std::sync::atomic::Ordering::SeqCst) >= 5,
        "every change asked at its commit"
    );

    for catalogue in [
        &catalogue,
        &Catalogue::open(&home.path().join("catalogue")).expect("reopens"),
    ] {
        let enrolment = catalogue
            .repository(&repository())
            .expect("readable")
            .expect("still enrolled");
        assert_eq!(enrolment.pinned_generation, None);
        let installation = catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .expect("still installed");
        assert!(!installation.pinned);
        assert!(!installation.enabled);
    }
}

/// A sync and an installation refused at their commit publish nothing: no generation, no cached
/// payload and no package directory.
#[tokio::test]
async fn a_sync_and_an_install_refused_at_their_commit_leave_no_trace_on_disk() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    let withdrawn = WithdrawnAtCommit::default();

    let sync = catalogue
        .sync_with(&repository(), &mut Change::new(&withdrawn))
        .await;
    assert!(
        matches!(sync, Err(CatalogueError::PermissionDenied { .. })),
        "{sync:?}"
    );
    assert_eq!(catalogue.active(&repository()).expect("enrolled"), None);

    catalogue.sync(&repository()).await.expect("a generation");
    let store = catalogue.store(&repository()).expect("enrolled");
    let cached_before = store.cached_payloads().expect("readable");
    let install = catalogue
        .install_with(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
            &mut Change::new(&withdrawn),
        )
        .await;
    assert!(
        matches!(install, Err(CatalogueError::PermissionDenied { .. })),
        "{install:?}"
    );
    assert_eq!(
        store.cached_payloads().expect("readable"),
        cached_before,
        "no payload was cached under a withdrawn admission"
    );
    assert!(absent(&store, generation.manifest_digest()));
    assert!(
        catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .is_none()
    );
}

/// A change that committed under an authority that then failed is an unknown outcome, never a
/// refusal, and what every reader sees afterwards is the change.
///
/// The records are the only copy of the state, so there is no second copy in memory to disagree
/// with them: this catalogue and a reopened one read the same thing.
#[tokio::test]
async fn a_change_that_committed_under_a_failing_authority_is_uncertain_and_is_what_readers_see() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;

    let pin = catalogue.pin_with(
        &repository(),
        Some(RepositoryGeneration::new(1)),
        &mut Change::new(&FailsAfterCommit),
    );
    assert!(
        matches!(pin, Err(CatalogueError::PublicationUncertain { .. })),
        "{pin:?}"
    );
    assert_eq!(
        pin.expect_err("uncertain").code(),
        ErrorCode::OutcomeUnknown
    );
    let enabled = catalogue
        .set_enabled_with(
            environment(),
            &plugin(),
            true,
            &mut Change::new(&FailsAfterCommit),
        )
        .await;
    assert!(
        matches!(enabled, Err(CatalogueError::PublicationUncertain { .. })),
        "{enabled:?}"
    );

    for catalogue in [
        &catalogue,
        &Catalogue::open(&home.path().join("catalogue")).expect("reopens"),
    ] {
        assert_eq!(
            catalogue
                .repository(&repository())
                .expect("readable")
                .expect("enrolled")
                .pinned_generation,
            Some(RepositoryGeneration::new(1))
        );
        assert!(
            catalogue
                .installation(environment(), &plugin())
                .expect("readable")
                .expect("installed")
                .enabled
        );
    }
}

/// Two catalogues on one directory lose nothing of each other's.
///
/// Each change reads what it changes inside its own transaction and changes rows rather than
/// writing back a copy of everything it read earlier, so a catalogue opened before another one's
/// change does not undo that change with its own.
#[tokio::test]
async fn two_catalogues_on_one_directory_lose_nothing_of_each_other() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut first = installed_catalogue(home.path(), &generation).await;
    let mut second = Catalogue::open(&home.path().join("catalogue")).expect("a second catalogue");

    // Each installs into its own environment and changes its own installation, interleaved.
    let elsewhere = EnvironmentId::new(Uuid::from_bytes([2; 16]));
    second
        .install(
            &repository(),
            elsewhere,
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable from the second catalogue");
    first
        .pin_package(environment(), &plugin(), Some(generation.manifest_digest()))
        .expect("pinned by the first");
    second
        .set_enabled(elsewhere, &plugin(), true)
        .await
        .expect("enabled by the second");
    first
        .pin(&repository(), Some(RepositoryGeneration::new(1)))
        .expect("the repository pinned by the first");

    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    let here = reopened
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("installed here");
    let there = reopened
        .installation(elsewhere, &plugin())
        .expect("readable")
        .expect("installed there");
    assert!(
        here.pinned,
        "the first catalogue's pin survives the second's changes"
    );
    assert!(
        there.enabled,
        "the second catalogue's enable survives the first's changes"
    );
    assert_eq!(
        reopened
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .pinned_generation,
        Some(RepositoryGeneration::new(1))
    );

    // A repository the second removes is not recreated by the first acting on what it read before.
    second
        .remove_repository(&repository())
        .expect("removed by the second");
    let stale = first.pin(&repository(), None);
    assert!(
        matches!(stale, Err(CatalogueError::NotFound { .. })),
        "{stale:?}"
    );
    assert!(
        reopened
            .repository(&repository())
            .expect("readable")
            .is_none()
    );
}

/// A name enrolled again is a new enrolment, and what was installed through the old one stays
/// with the old one.
///
/// The repository's name is the owner's choice and can be removed and enrolled again under
/// another root. An installation belongs to the enrolment it came through, so a new root under an
/// old name never picks it up, and its files stay in the directory that enrolment left.
#[tokio::test]
async fn a_name_enrolled_again_does_not_inherit_what_the_old_enrolment_installed() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;
    let before = catalogue
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("installed");

    catalogue.remove_repository(&repository()).expect("removed");
    let other = Generation::build(&home.path().join("other"), GenerationSpec::default()).await;
    let enrolment = Enrolment::new(
        repository(),
        RepositoryKind::Official,
        other.metadata_url(),
        other.targets_url(),
        other.root_bytes(),
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("an enrollable repository");
    catalogue
        .enrol(enrolment, true)
        .expect("the same name under another root");

    let after = catalogue
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("still installed");
    assert_eq!(
        after.enrolment, before.enrolment,
        "it stays with the enrolment it came through"
    );
    assert_ne!(
        catalogue
            .store(&repository())
            .expect("enrolled")
            .package_dir(before.package_digest),
        catalogue
            .store_of(&after)
            .package_dir(before.package_digest),
        "the new enrolment has a directory of its own"
    );
    // Enabling it reads the files the old enrolment left, not the new repository.
    other.take_offline();
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("the package the old enrolment installed is still whole");
}

/// The catalogue's installation state is committed with full durability and survives a restart
/// (KR-REQ-24.01, the plugin and catalogue installation state of section 24).
#[tokio::test]
async fn kr_req_24_01_the_catalogue_keeps_its_installation_state_durably_across_a_restart() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;
    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enabled");
    catalogue
        .pin_package(environment(), &plugin(), Some(generation.manifest_digest()))
        .expect("pinned");
    catalogue
        .pin(&repository(), Some(RepositoryGeneration::new(1)))
        .expect("the repository pinned");
    catalogue
        .set_disable_policy(DisablePolicy::DisableAtNextAdmission)
        .expect("recorded");

    let durability = catalogue.durability().expect("readable");
    assert_eq!(durability.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(durability.synchronous, 2, "full synchronisation");

    let installed = catalogue.installations().expect("readable");
    let repositories = catalogue.repository_views().expect("readable");
    drop(catalogue);
    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    assert_eq!(reopened.installations().expect("readable"), installed);
    assert_eq!(reopened.repository_views().expect("readable"), repositories);
    assert_eq!(
        reopened.disable_policy().expect("readable"),
        DisablePolicy::DisableAtNextAdmission
    );
    let installation = &installed[0];
    assert!(installation.enabled && installation.pinned);
    assert_eq!(installation.package_digest, generation.manifest_digest());
}

/// An action's claim, its effect and the answer it gave are one record, and an interrupted one is
/// never reported as refused.
#[tokio::test]
async fn an_action_is_claimed_once_settled_with_its_effect_and_recovered_as_unknown() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = installed_catalogue(home.path(), &generation).await;
    let claim = |action: &str| ReceiptClaim {
        key: ReceiptKey::new("kr:local", action),
        digest: vec![7; 32],
        method: "plugin.pin".to_owned(),
        method_version: 1,
        deadline_ms: None,
    };

    // Claimed, then settled in the same transaction as the pin it performed.
    assert_eq!(
        catalogue.claim(&claim("one"), 1).expect("recorded"),
        Claimed::Fresh
    );
    let mut rendered = 0u32;
    let mut render = |transition: &kr_plugin_catalogue::Transition| {
        rendered += 1;
        assert!(matches!(
            transition,
            kr_plugin_catalogue::Transition::Changed(_)
        ));
        Ok(b"the answer".to_vec())
    };
    catalogue
        .pin_package_with(
            environment(),
            &plugin(),
            Some(generation.manifest_digest()),
            &mut Change::settling(
                &Owner::acting(),
                ReceiptKey::new("kr:local", "one"),
                2,
                &mut render,
            ),
        )
        .expect("pinned");
    assert_eq!(rendered, 1);
    let Claimed::Retained(record) = catalogue.claim(&claim("one"), 3).expect("readable") else {
        panic!("a second claim of the same action finds its receipt");
    };
    assert_eq!(record.state, kr_protocol::receipt::ReceiptState::Applied);
    assert_eq!(record.result.as_deref(), Some(b"the answer".as_slice()));

    // A change refused at its commit leaves its claim dispatching, and is settled from what it
    // committed, which is nothing: refused, with the refusal it answered with.
    assert_eq!(
        catalogue.claim(&claim("two"), 4).expect("recorded"),
        Claimed::Fresh
    );
    let withdrawn = WithdrawnAtCommit::default();
    let recording = Recording::new(&withdrawn);
    let mut never = |_: &Transition| -> CatalogueResult<Vec<u8>> {
        unreachable!("a change refused at its commit renders no answer")
    };
    let refusal = catalogue
        .pin_package_with(
            environment(),
            &plugin(),
            None,
            &mut Change::settling(
                &recording,
                ReceiptKey::new("kr:local", "two"),
                5,
                &mut never,
            ),
        )
        .expect_err("withdrawn at the commit");
    let failure = recording.failure(&refusal.clone().into());
    assert_eq!(failure.state(), kr_protocol::receipt::ReceiptState::Refused);
    assert_eq!(failure.answer().code, refusal.code());
    catalogue
        .settle_failure(&ReceiptKey::new("kr:local", "two"), &failure, 5)
        .expect("recorded");
    let two = catalogue
        .receipt(&ReceiptKey::new("kr:local", "two"))
        .expect("readable")
        .expect("held");
    assert_eq!(two.state, kr_protocol::receipt::ReceiptState::Refused);
    assert_eq!(two.error.as_ref(), Some(failure.answer()));

    // An error that is itself an uncertain outcome is never recorded as a refusal.
    assert_eq!(
        catalogue.claim(&claim("three"), 6).expect("recorded"),
        Claimed::Fresh
    );
    let owner = Owner::acting();
    let uncertain = Recording::new(&owner).failure(&kr_protocol::error::ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        "not confirmed",
    ));
    catalogue
        .settle_failure(&ReceiptKey::new("kr:local", "three"), &uncertain, 7)
        .expect("recorded");
    assert_eq!(
        catalogue
            .receipt(&ReceiptKey::new("kr:local", "three"))
            .expect("readable")
            .expect("held")
            .state,
        kr_protocol::receipt::ReceiptState::Unknown
    );

    // A claim a stopped daemon left dispatching is settled as unknown when the next one opens it,
    // and never performed again.
    assert_eq!(
        catalogue.claim(&claim("four"), 8).expect("recorded"),
        Claimed::Fresh
    );
    drop(catalogue);
    let mut reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    assert_eq!(reopened.recover_interrupted(9).expect("recorded"), 1);
    let recovered = reopened
        .receipt(&ReceiptKey::new("kr:local", "four"))
        .expect("readable")
        .expect("held");
    assert_eq!(recovered.state, kr_protocol::receipt::ReceiptState::Unknown);
    assert_eq!(
        recovered.error.expect("a reason").code,
        ErrorCode::OutcomeUnknown
    );
    let Claimed::Retained(again) = reopened.claim(&claim("four"), 10).expect("readable") else {
        panic!("an interrupted action is not claimed afresh");
    };
    assert_eq!(again.state, kr_protocol::receipt::ReceiptState::Unknown);
}

/// A sync that kept a new root and then could not fetch its index is unknown, never refused.
///
/// Section 9 reserves refused for an action proved to have had no effect, and this one had one:
/// the rotation is kept the moment verification reaches it, and it stays kept. Its receipt says so,
/// the answer a resubmission gets says so, and the action is not performed again. A sync that
/// stopped at the same place without committing anything is the contrast, and it is refused.
#[tokio::test]
async fn a_sync_that_kept_a_new_root_and_then_failed_is_unknown_and_says_what_it_left() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a first generation");
    let claim = |action: &str| ReceiptClaim {
        key: ReceiptKey::new("kr:local", action),
        digest: vec![3; 32],
        method: "catalogue.sync".to_owned(),
        method_version: 1,
        deadline_ms: None,
    };
    let mut never = |_: &Transition| -> CatalogueResult<Vec<u8>> {
        unreachable!("a sync that stopped renders no answer")
    };
    let owner = Owner::acting();
    let index = generation.targets_dir().join("index.json");

    // The index is missing and nothing else changed: nothing commits, and the sync is refused.
    std::fs::remove_file(&index).expect("removable");
    assert_eq!(
        catalogue.claim(&claim("before"), 1).expect("recorded"),
        Claimed::Fresh
    );
    let recording = Recording::new(&owner);
    let stopped = catalogue
        .sync_with(
            &repository(),
            &mut Change::settling(
                &recording,
                ReceiptKey::new("kr:local", "before"),
                2,
                &mut never,
            ),
        )
        .await
        .expect_err("there is no index to fetch");
    assert_eq!(recording.committed(), Vec::new());
    let failure = recording.failure(&stopped.clone().into());
    assert_eq!(failure.state(), kr_protocol::receipt::ReceiptState::Refused);
    assert_eq!(failure.answer().code, stopped.code());
    catalogue
        .settle_failure(&ReceiptKey::new("kr:local", "before"), &failure, 3)
        .expect("recorded");

    // A rotation, then the same missing index: the root commits before the index is fetched.
    let new_root = generation.rotate_root_to_v2(&KeySet::generate()).await;
    std::fs::remove_file(&index).expect("removable");
    assert_eq!(
        catalogue.claim(&claim("after"), 4).expect("recorded"),
        Claimed::Fresh
    );
    let recording = Recording::new(&owner);
    let stopped = catalogue
        .sync_with(
            &repository(),
            &mut Change::settling(
                &recording,
                ReceiptKey::new("kr:local", "after"),
                5,
                &mut never,
            ),
        )
        .await
        .expect_err("there is no index to fetch");
    assert_eq!(
        recording.committed(),
        vec![Committed {
            effect: Effect::Root(repository()),
            confirmed: true,
        }]
    );
    let failure = recording.failure(&stopped.clone().into());
    assert_eq!(failure.state(), kr_protocol::receipt::ReceiptState::Unknown);
    let answer = failure.answer().clone();
    assert_eq!(answer.code, ErrorCode::OutcomeUnknown);
    assert!(
        answer.message.contains("a new trust root for official"),
        "{answer:?}"
    );
    assert!(
        answer.message.contains(stopped.code().as_str()),
        "the answer names what stopped it: {answer:?}"
    );
    catalogue
        .settle_failure(&ReceiptKey::new("kr:local", "after"), &failure, 6)
        .expect("recorded");
    let kept: serde_json::Value = serde_json::from_slice(
        &catalogue
            .repository(&repository())
            .expect("readable")
            .expect("enrolled")
            .root,
    )
    .expect("json");
    let rotated: serde_json::Value = serde_json::from_slice(&new_root).expect("json");
    assert_eq!(kept["signed"]["version"], rotated["signed"]["version"]);

    // A resubmission finds the receipt and its answer, here and after a restart, and nothing is
    // performed again.
    drop(catalogue);
    let mut reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
    assert_eq!(reopened.recover_interrupted(7).expect("recorded"), 0);
    for (action, state, error) in [
        (
            "before",
            kr_protocol::receipt::ReceiptState::Refused,
            stopped_before(&reopened),
        ),
        (
            "after",
            kr_protocol::receipt::ReceiptState::Unknown,
            answer.clone(),
        ),
    ] {
        let Claimed::Retained(record) = reopened.claim(&claim(action), 8).expect("readable") else {
            panic!("{action} is not claimed afresh");
        };
        assert_eq!(record.state, state, "{action}");
        assert_eq!(record.error, Some(error), "{action}");
    }
}

/// Reads the answer the refused sync recorded, which the test compares with itself after a
/// restart.
fn stopped_before(catalogue: &Catalogue) -> kr_protocol::error::ProtocolError {
    catalogue
        .receipt(&ReceiptKey::new("kr:local", "before"))
        .expect("readable")
        .expect("held")
        .error
        .expect("a refusal")
}

/// Reads the local repository, and holds the first fetch until the test lets it go.
///
/// A sync that reaches its first fetch has already read the enrolment it started from, so what
/// another catalogue commits while the fetch is held is something that sync did not see then.
#[derive(Clone, Debug)]
struct Held {
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    first: Arc<std::sync::atomic::AtomicBool>,
}

impl Held {
    fn new() -> Self {
        Self {
            reached: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            first: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

#[tough::async_trait]
impl tough::Transport for Held {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.reached.notify_one();
            self.release.notified().await;
        }
        tough::FilesystemTransport.fetch(url).await
    }
}

/// Every payload an index names, with its size.
fn payloads_of(generation: &Generation) -> std::collections::BTreeMap<PayloadDigest, u64> {
    let index: kr_plugin_sdk::catalogue::CatalogueIndex = serde_json::from_slice(
        &std::fs::read(generation.targets_dir().join("index.json")).expect("an index"),
    )
    .expect("a readable index");
    let mut payloads = std::collections::BTreeMap::new();
    for entry in &index.entries {
        payloads.insert(entry.manifest_digest, entry.manifest_size_bytes.get());
        for payload in &entry.payloads {
            payloads.insert(payload.digest, payload.size_bytes.get());
        }
    }
    payloads
}

/// A mirrored first generation whose cache is one byte short of taking the next one as well,
/// and the next generation, published at the same location.
async fn mirrored_at_its_limit(
    home: &std::path::Path,
) -> (
    Catalogue,
    Generation,
    std::collections::BTreeMap<PayloadDigest, u64>,
) {
    let first = Generation::build(home, GenerationSpec::default()).await;
    let second = Generation::build(
        &home.join("second"),
        GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            keys: Some(first.keys()),
            ..GenerationSpec::default()
        },
    )
    .await;
    let held = payloads_of(&first);
    let mut budgets = RepositoryBudgets::defaults();
    budgets.full_offline_mirror = true;
    budgets.payload_cache_bytes = U64::new(held.values().sum::<u64>() + 1);
    let mut catalogue = enrolled(home, &first, budgets, CapabilityCeiling::default_ceiling()).await;
    catalogue
        .sync(&repository())
        .await
        .expect("the first generation, mirrored");
    let store = catalogue.store(&repository()).expect("enrolled");
    for (digest, size) in &held {
        assert!(store.holds_payload(*digest, *size).expect("readable"));
    }
    first.replace_with(&second);
    (catalogue, first, held)
}

/// A pin another catalogue commits while a sync runs keeps every payload it pins.
///
/// The sync read its enrolment before the pin existed. What it protects when it makes room is read
/// again under the database's write lock, so the pin is seen there, and the payloads of the pinned
/// generation are not what the new generation is made room with.
#[tokio::test]
async fn a_generation_pinned_while_a_sync_ran_keeps_every_payload_it_pins() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let (mut catalogue, _generation, pinned) = mirrored_at_its_limit(home.path()).await;
    let held = Held::new();
    catalogue.set_transport(Arc::new(held.clone()));
    let pin = async {
        held.reached.notified().await;
        let mut other =
            Catalogue::open(&home.path().join("catalogue")).expect("a second catalogue");
        other
            .pin(&repository(), Some(RepositoryGeneration::new(1)))
            .expect("pinned");
        held.release.notify_one();
    };
    let id = repository();
    let (outcome, ()) = tokio::join!(catalogue.sync(&id), pin);

    assert!(
        matches!(outcome, Err(CatalogueError::ResourceLimit(_))),
        "making room would take pinned payloads: {outcome:?}"
    );
    let store = catalogue.store(&repository()).expect("enrolled");
    for (digest, size) in &pinned {
        assert!(
            store.holds_payload(*digest, *size).expect("readable"),
            "{digest} is pinned"
        );
    }
    assert_eq!(
        catalogue
            .active(&repository())
            .expect("enrolled")
            .map(|active| active.generation),
        Some(1)
    );
}

/// An installation keeps its payloads when room is made, whether or not it is pinned or enabled.
///
/// Evicting an installed package's files would leave it installed with nothing to run, so every
/// installation is protected, and a sync that could make room only by evicting one refuses.
#[tokio::test]
async fn an_installation_keeps_its_payloads_when_room_is_made() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let (mut catalogue, _generation, installed) = mirrored_at_its_limit(home.path()).await;
    let installation = catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            catalogue.index(&repository()).expect("an index").entries[0].manifest_digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installable from the mirror");
    assert!(!installation.pinned && !installation.enabled);

    let outcome = catalogue.sync(&repository()).await;
    assert!(
        matches!(outcome, Err(CatalogueError::ResourceLimit(_))),
        "making room would take an installation's payloads: {outcome:?}"
    );
    let store = catalogue.store(&repository()).expect("enrolled");
    for (digest, size) in &installed {
        assert!(
            store.holds_payload(*digest, *size).expect("readable"),
            "{digest} belongs to an installation"
        );
    }
}

/// Returns the bytes a sync of `generation` fetches while it loads the metadata, and the index's.
///
/// The client asks for the next root and finds none, then fetches the timestamp, the snapshot and
/// the targets metadata once each.
fn metadata_and_index(generation: &Generation) -> (u64, u64) {
    let size = |path: std::path::PathBuf| std::fs::metadata(path).expect("a file").len();
    let metadata: u64 = ["timestamp.json", "snapshot.json", "targets.json"]
        .into_iter()
        .map(|name| size(generation.metadata_dir().join(name)))
        .sum();
    (metadata, size(generation.targets_dir().join("index.json")))
}

/// Enrols `generation` from the given locations under a metadata allowance of `allowance` bytes,
/// in a catalogue of its own that fetches through `transport`.
fn enrolled_at(
    root: &std::path::Path,
    generation: &Generation,
    metadata_url: url::Url,
    targets_url: url::Url,
    allowance: u64,
    transport: &Watched,
) -> Catalogue {
    let mut budgets = RepositoryBudgets::defaults();
    budgets.metadata_bytes = U64::new(allowance);
    let mut catalogue = Catalogue::open(root).expect("an openable catalogue");
    catalogue
        .enrol(
            Enrolment::new(
                repository(),
                RepositoryKind::Official,
                metadata_url,
                targets_url,
                generation.root_bytes(),
                budgets,
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.set_transport(Arc::new(transport.clone()));
    catalogue
}

/// The metadata and the index are held under one allowance, and the index is counted once
/// wherever the targets are published: apart from the metadata, in the metadata location itself,
/// or inside it. A generation that fits exactly is accepted. One byte past it is refused against
/// the declared length before the index is asked for, and activates nothing.
#[tokio::test]
async fn the_index_is_counted_once_in_every_layout_and_refused_before_it_is_fetched() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    support::copy_tree(&generation.targets_dir(), &generation.metadata_dir());
    support::copy_tree(
        &generation.targets_dir(),
        &generation.metadata_dir().join("targets"),
    );
    let (metadata, index) = metadata_and_index(&generation);
    for (layout, targets_url) in [
        ("separate", generation.targets_url()),
        ("identical", generation.metadata_url()),
        (
            "nested",
            support::directory_url(&generation.metadata_dir().join("targets")),
        ),
    ] {
        for (allowance, fits) in [(metadata + index, true), (metadata + index - 1, false)] {
            assert!(metadata < allowance && index < allowance);
            let watched = Watched::default();
            let mut catalogue = enrolled_at(
                &home.path().join(format!("catalogue-{layout}-{allowance}")),
                &generation,
                generation.metadata_url(),
                targets_url.clone(),
                allowance,
                &watched,
            );
            let outcome = catalogue.sync(&repository()).await;
            let index_requested = watched
                .fetched
                .lock()
                .expect("the list")
                .iter()
                .any(|url| url.path().ends_with("/index.json"));
            if fits {
                outcome.unwrap_or_else(|refusal| panic!("{layout}: {refusal}"));
                assert!(index_requested, "{layout}");
                continue;
            }
            let refusal = outcome.expect_err("together they are past the allowance");
            let CatalogueError::ResourceLimit(limit) = &refusal else {
                panic!("{layout}: {refusal:?}");
            };
            assert_eq!(limit.resource, Resource::MetadataBytes, "{layout}");
            assert_eq!(limit.stage, Stage::Declared, "{layout}");
            assert_eq!(limit.requested, metadata + index, "{layout}");
            assert!(!index_requested, "{layout}: the index was asked for");
            assert_eq!(
                catalogue.active(&repository()).expect("enrolled"),
                None,
                "{layout}"
            );
        }
    }
}

/// Metadata is counted by what the client fetches it for, not by where it lives.
///
/// The client drops a location's fragment when it resolves a document against it, so documents
/// fetched from `metadata/#x` are not under that text at all. They are still metadata, and a
/// generation whose metadata and index together pass the allowance is refused.
#[tokio::test]
async fn metadata_under_a_location_with_a_fragment_is_counted_all_the_same() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let (metadata, index) = metadata_and_index(&generation);
    let mut located = generation.metadata_url();
    located.set_fragment(Some("x"));
    for (allowance, fits) in [(metadata + index, true), (metadata + index - 1, false)] {
        let watched = Watched::default();
        let mut catalogue = enrolled_at(
            &home.path().join(format!("catalogue-{allowance}")),
            &generation,
            located.clone(),
            generation.targets_url(),
            allowance,
            &watched,
        );
        let outcome = catalogue.sync(&repository()).await;
        if fits {
            outcome.expect("the generation fits its allowance exactly");
            continue;
        }
        let refusal = outcome.expect_err("together they are past the allowance");
        assert!(
            matches!(&refusal, CatalogueError::ResourceLimit(limit)
                if limit.resource == Resource::MetadataBytes
                    && limit.requested == metadata + index),
            "{refusal:?}"
        );
        assert_eq!(catalogue.active(&repository()).expect("enrolled"), None);
    }
}

/// An installation another catalogue pins while a sync runs keeps its payloads.
#[tokio::test]
async fn an_installation_pinned_while_a_sync_ran_keeps_its_payloads() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let (mut catalogue, _generation, installed) = mirrored_at_its_limit(home.path()).await;
    let installation = catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            catalogue.index(&repository()).expect("an index").entries[0].manifest_digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installable from the mirror");
    assert!(!installation.pinned);

    let held = Held::new();
    catalogue.set_transport(Arc::new(held.clone()));
    let pin = async {
        held.reached.notified().await;
        let mut other =
            Catalogue::open(&home.path().join("catalogue")).expect("a second catalogue");
        other
            .pin_package(environment(), &plugin(), Some(installation.package_digest))
            .expect("pinned");
        held.release.notify_one();
    };
    let id = repository();
    let (outcome, ()) = tokio::join!(catalogue.sync(&id), pin);

    assert!(
        matches!(outcome, Err(CatalogueError::ResourceLimit(_))),
        "making room would take a pinned installation's payloads: {outcome:?}"
    );
    let store = catalogue.store(&repository()).expect("enrolled");
    for (digest, size) in &installed {
        assert!(
            store.holds_payload(*digest, *size).expect("readable"),
            "{digest} belongs to a pinned installation"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// A failure keeps its own class, whatever stage it happens at
// ---------------------------------------------------------------------------------------------

/// What a damaging transport does to one target on its way in.
#[derive(Clone, Copy, Debug)]
enum Damage {
    /// The link drops after the first half of the document arrived.
    DropsPartWay,
    /// More bytes arrive than the signed metadata pins.
    Longer,
    /// The right number of bytes arrive, one of them altered.
    Altered,
    /// The repository answers that it holds no such file.
    Absent,
}

/// Reads the local repository and damages every document whose name ends in `suffix`.
#[derive(Clone, Debug)]
struct Damaging {
    suffix: &'static str,
    damage: Damage,
}

#[tough::async_trait]
impl tough::Transport for Damaging {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        use tough::IntoVec as _;
        if !url.path().ends_with(self.suffix) {
            return tough::FilesystemTransport.fetch(url).await;
        }
        if matches!(self.damage, Damage::Absent) {
            return Err(tough::TransportError::new(
                tough::TransportErrorKind::FileNotFound,
                url,
            ));
        }
        let bytes = tough::FilesystemTransport
            .fetch(url.clone())
            .await?
            .into_vec()
            .await?;
        let chunks: Vec<Result<tough::Bytes, tough::TransportError>> = match self.damage {
            Damage::DropsPartWay => vec![
                Ok(tough::Bytes::copy_from_slice(&bytes[..bytes.len() / 2])),
                Err(tough::TransportError::new_with_cause(
                    tough::TransportErrorKind::Other,
                    url,
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "the peer reset the connection",
                    ),
                )),
            ],
            Damage::Longer => vec![Ok(tough::Bytes::from(
                [bytes.as_slice(), b"and more than was signed"].concat(),
            ))],
            Damage::Altered => {
                let mut altered = bytes;
                altered[0] ^= 0x01;
                vec![Ok(tough::Bytes::from(altered))]
            }
            Damage::Absent => Vec::new(),
        };
        Ok(Box::pin(futures::stream::iter(chunks)))
    }
}

/// A payload fetch that fails reports why, in a class a person can act on.
///
/// A link that dropped part way is an availability failure: retrying later can succeed. More bytes
/// than the signed metadata allows, and bytes whose digest is not the signed one, are the
/// repository sending what it did not sign, which is integrity. The client wraps all four the same
/// way, as a transport error, so the class has to be read from what caused it.
#[tokio::test]
async fn kr_req_11_05_a_fetch_failure_keeps_its_own_class() {
    for damage in [
        Damage::DropsPartWay,
        Damage::Longer,
        Damage::Altered,
        Damage::Absent,
    ] {
        let home = tempfile::tempdir().expect("a temporary directory");
        let generation = Generation::build(home.path(), GenerationSpec::default()).await;
        let mut catalogue = enrolled(
            home.path(),
            &generation,
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .await;
        catalogue
            .sync(&repository())
            .await
            .expect("a verified generation");

        catalogue.set_transport(Arc::new(Damaging {
            suffix: "presentation.json",
            damage,
        }));
        let refusal = catalogue
            .activate_package(
                &repository(),
                &plugin(),
                &version(),
                FetchReason::ExplicitInstall,
            )
            .await
            .expect_err("a damaged payload does not activate");
        match (damage, &refusal) {
            (Damage::DropsPartWay | Damage::Absent, CatalogueError::UnavailableOffline { .. })
            | (Damage::Longer | Damage::Altered, CatalogueError::Integrity { .. }) => {}
            _ => panic!("{damage:?} was reported as {refusal:?}"),
        }
        let store = catalogue.store(&repository()).expect("enrolled");
        assert!(
            absent(&store, generation.manifest_digest()),
            "{damage:?}: nothing is activated from a fetch that failed"
        );
    }
}

/// A datastore this host cannot write is its own disk failing, not a repository it cannot reach.
#[cfg(unix)]
#[tokio::test]
async fn a_datastore_this_host_cannot_write_is_a_storage_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    let datastore = catalogue
        .store(&repository())
        .expect("enrolled")
        .datastore();
    std::fs::set_permissions(&datastore, std::fs::Permissions::from_mode(0o500))
        .expect("the datastore can be made read-only");
    let outcome = catalogue.sync(&repository()).await;
    std::fs::set_permissions(&datastore, std::fs::Permissions::from_mode(0o700))
        .expect("the datastore is writable again");
    let refusal = outcome.expect_err("the client cannot record what it trusts");
    assert!(
        matches!(refusal, CatalogueError::StorageUnavailable { .. }),
        "{refusal:?}"
    );
    assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);
}

/// An installed package whose repository is gone is enabled only when every file it declares is
/// here, in the bytes it declares.
///
/// With no repository there is nothing to fetch a missing file from, so a file that is gone or
/// altered is section 11's own answer. A file this host cannot read is a failure of its own disk
/// and is reported as that. In each case nothing changes: the package stays disabled.
#[tokio::test]
async fn kr_req_11_09_a_package_without_its_repository_enables_only_when_every_file_is_here() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut catalogue = enrolled(
        home.path(),
        &generation,
        RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .await;
    catalogue
        .sync(&repository())
        .await
        .expect("a verified generation");
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            InstallationGrant::none(),
        )
        .await
        .expect("installable");
    catalogue
        .remove_repository(&repository())
        .expect("the owner stopped trusting this root");

    let installed = catalogue
        .installation(environment(), &plugin())
        .expect("readable")
        .expect("still installed");
    let package = catalogue
        .store_of(&installed)
        .package_dir(generation.manifest_digest());
    let presentation = package.join(kr_plugin_sdk::package::PRESENTATION_FILE);
    let original = std::fs::read(&presentation).expect("the activated presentation");

    // A declared file that is gone, with its directory still in place.
    std::fs::remove_file(&presentation).expect("removable");
    let refusal = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect_err("a file the package declares is missing");
    assert_eq!(
        refusal.code(),
        ErrorCode::PackageUnavailableOffline,
        "{refusal}"
    );

    // The same number of bytes, one of them altered.
    let mut altered = original.clone();
    altered[0] ^= 0x01;
    std::fs::write(&presentation, &altered).expect("writable");
    let refusal = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect_err("a file the package declares holds other bytes");
    assert_eq!(
        refusal.code(),
        ErrorCode::PackageUnavailableOffline,
        "{refusal}"
    );

    // A file this host cannot read is its own disk's failure.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(&presentation, &original).expect("writable");
        std::fs::set_permissions(&presentation, std::fs::Permissions::from_mode(0o000))
            .expect("the file can be made unreadable");
        let outcome = catalogue.set_enabled(environment(), &plugin(), true).await;
        std::fs::set_permissions(&presentation, std::fs::Permissions::from_mode(0o600))
            .expect("readable again");
        let refusal = outcome.expect_err("an unreadable file");
        assert_eq!(refusal.code(), ErrorCode::StorageUnavailable, "{refusal}");
    }

    assert!(
        !catalogue
            .installation(environment(), &plugin())
            .expect("readable")
            .expect("still installed")
            .enabled,
        "no refusal changed the installation"
    );

    // The bytes it declared are back, and it enables.
    std::fs::write(&presentation, &original).expect("writable");
    let enabled = catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("every declared file is here");
    assert!(enabled.enabled);
}

fn url(text: &str) -> url::Url {
    url::Url::parse(text).expect("a parsable location")
}
