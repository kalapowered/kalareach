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

use kr_plugin_runtime::catalogue::budget::Stage;
use kr_plugin_runtime::catalogue::{
    BudgetLedger, CapabilityCeiling, Catalogue, CatalogueError, DisablePolicy, Enrolment,
    FetchReason, Installation, InstallationGrant, MatchIndex, Observation, RepositoryId,
    RepositoryKind, Resolution, Store, capability_from_str,
};
use kr_plugin_sdk::capability::{CapabilityState, EvidenceSource, PluginCapability};
use kr_plugin_sdk::catalogue::{QualificationResult, RevocationReason, RevocationRecord};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_plugin_sdk::text::{Label, Summary};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use support::{Generation, GenerationSpec};

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
        .expect("enrolled")
        .root
        .clone();
    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
    assert_eq!(store.read_root().expect("a root on disk"), held);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&held).expect("readable")["signed"]["version"],
        serde_json::json!(1)
    );
    assert!(!adopted.is_empty());

    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    assert_eq!(
        reopened.repository(&repository()).expect("enrolled").root,
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

    // The repository publishes a second generation. This host has not accepted it, so a payload
    // is not fetched out of it: the answer is an absence, not a quiet substitution.
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
    assert!(refusal.to_string().contains("synchronise"), "{refusal}");
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
        .activate_package(
            &repository(),
            &plugin(),
            &version(),
            FetchReason::AuthorisedActivation,
        )
        .await
        .expect_err("not installed and enabled");
    assert_eq!(refusal.code(), ErrorCode::PackageUnavailableOffline);
    assert!(
        refusal.to_string().contains("does not authorise"),
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
        .capabilities(&repository(), environment(), &plugin())
        .expect("readable offline");
    assert!(!decisions.is_empty());
}

#[test]
fn a_repository_this_host_cannot_fetch_is_refused_by_name() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
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
        .installations()
        .get(environment(), &plugin())
        .expect("still installed");
    assert!(installation.pinned);
    assert_eq!(installation.package_digest, generation.manifest_digest());
    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
    assert!(store.has_package(generation.manifest_digest()));
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
    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
    assert!(store.has_package(installed));
    assert_eq!(
        catalogue
            .installations()
            .get(environment(), &plugin())
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
            kr_plugin_runtime::catalogue::extract::relative_target(prefix, name).is_err(),
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

    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
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

    let grant = InstallationGrant::with([
        PluginCapability::TranscriptTail,
        PluginCapability::TerminalInput,
        PluginCapability::NativeBridgeInstall,
    ]);
    catalogue
        .install(
            &repository(),
            environment(),
            &plugin(),
            &version(),
            generation.manifest_digest(),
            grant,
        )
        .await
        .expect("granted");

    let decisions = catalogue
        .capabilities(&repository(), environment(), &plugin())
        .expect("readable");
    for decision in &decisions {
        use kr_plugin_runtime::catalogue::GrantRequirement as Requirement;
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

    assert_eq!(
        catalogue.installations().protected_packages(),
        vec![generation.manifest_digest()],
        "a pinned installation protects its own package hash"
    );

    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
    let mut budgets = RepositoryBudgets::defaults();
    budgets.payload_cache_bytes = U64::new(1);
    let mut ledger = BudgetLedger::new(budgets);
    for size in store.cached_payloads().expect("readable").values() {
        ledger.add_payload_bytes(*size);
    }
    let protected: BTreeSet<PayloadDigest> = catalogue
        .installations()
        .protected_packages()
        .into_iter()
        .collect();
    let refusal = store
        .reclaim(1024, &mut ledger, &protected, "component.wasm")
        .expect_err("nothing may be evicted");
    assert!(refusal.to_string().contains("never evicted"), "{refusal}");
    assert!(store.has_payload(generation.manifest_digest()));
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
        .installations_mut()
        .bind(environment(), &entry, &observed.executable_path)
        .expect_err("disabled");
    assert_eq!(refusal.code(), ErrorCode::PluginDisabled);

    catalogue
        .set_enabled(environment(), &plugin(), true)
        .await
        .expect("enablable");
    let binding = catalogue
        .installations_mut()
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
        .installations_mut()
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
        .installations_mut()
        .bind(environment(), &revoked, "/usr/local/bin/example-agent")
        .expect_err("revoked");
    assert!(
        refusal.to_string().contains("stops new bindings"),
        "{refusal}"
    );

    // The live one warns and keeps serving under the default policy.
    let notices = catalogue.installations().revocation_notices(&revoked);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].binding_id, binding.binding_id);
    assert!(notices[0].keeps_serving);
    assert_eq!(notices[0].policy, DisablePolicy::WarnOnly);

    // Under an explicit administrator policy it stops at the next admission, not mid-request.
    catalogue
        .installations_mut()
        .set_policy(DisablePolicy::DisableAtOnce);
    let notices = catalogue.installations().revocation_notices(&revoked);
    assert!(!notices[0].keeps_serving);
    assert_eq!(
        catalogue.installations().bindings().len(),
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
        .installations_mut()
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
            .installations()
            .get(environment(), &plugin())
            .expect("installed")
            .package_digest,
        second.manifest_digest()
    );
    assert_eq!(
        catalogue.installations().bindings()[0].package_digest,
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
    use kr_plugin_runtime::catalogue::evidence;

    let entry = support::example_entry();
    let installation = Installation::from_entry(
        &entry,
        repository(),
        environment(),
        InstallationGrant::none(),
    );
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

    let store = Store::open(&home.path().join("catalogue"), &repository()).expect("openable");
    assert!(store.has_package(entry.manifest_digest));
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
        .iter()
        .map(|enrolment| enrolment.root_digest())
        .collect();
    assert_eq!(roots.len(), 2);
    assert_ne!(roots[0], roots[1], "one repository's root is not another's");

    // And a restart finds both, each against the root it adopted.
    let reopened = Catalogue::open(&home.path().join("catalogue")).expect("openable");
    let after: Vec<PayloadDigest> = reopened
        .repositories()
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
        kr_plugin_runtime::catalogue::search::resolve(found.clone(), None),
        Resolution::Conflict(_)
    ));
    let chosen = index.entries[1].plugin_id.clone();
    match kr_plugin_runtime::catalogue::search::resolve(found, Some(&chosen)) {
        Resolution::Selected(candidate) => assert_eq!(candidate.plugin_id, chosen),
        other => panic!("the selection should win: {other:?}"),
    }
}

fn url(text: &str) -> url::Url {
    url::Url::parse(text).expect("a parsable location")
}
