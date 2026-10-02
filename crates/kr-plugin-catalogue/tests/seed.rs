//! Seeding the catalogue from the generation compiled into the host.
//!
//! The generations here are signed in memory, as the rest of the suite's are, and each becomes a
//! bundle with the lock a bundle has. The committed bundle itself is read once, by the case that
//! seeds from what this build compiles in: it is the development lineage's, so it is trusted by a
//! build with debug assertions and by no release.

// Each suite that includes the support module uses what it needs of it.
#[allow(dead_code)]
mod support;

use std::sync::Arc;

use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, CatalogueError, Change, Enrolment, InstallationGrant, Owner,
    Permitted, Refusal, RepositoryKind, SeedBundle, SeedPoint, SeedTrust, permitted_root,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Uuid;

use support::{Generation, GenerationSpec, KeySet, seed_bundle, seed_bundle_trusting, seed_files};

fn local() -> Arc<dyn tough::Transport + Send + Sync> {
    Arc::new(RepositoryTransport::local_only(
        "a test reads its repositories from disk",
    ))
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::NIL)
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("a valid plugin identifier")
}

fn version() -> PackageVersion {
    PackageVersion::parse("0.1.0").expect("a valid version")
}

/// A catalogue on the internal disk that cannot reach a network, as a fresh installation with none.
fn offline(home: &std::path::Path) -> Catalogue {
    let mut catalogue = Catalogue::open(&home.join("catalogue"), local()).expect("a catalogue");
    catalogue.set_fetches_network(false);
    catalogue
}

/// A generation whose package asks for capabilities past the default ceiling, the way an
/// adapter's does.
async fn adapter(home: &std::path::Path) -> Generation {
    Generation::build(
        home,
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
    .await
}

fn budgets() -> RepositoryBudgets {
    RepositoryBudgets::defaults()
}

fn installed(catalogue: &Catalogue) -> Option<kr_plugin_catalogue::Installation> {
    catalogue
        .installation(environment(), &plugin())
        .expect("readable records")
}

fn records(catalogue: &Catalogue) -> Vec<(String, String)> {
    catalogue.seed_records().expect("readable records")
}

fn has_record(catalogue: &Catalogue, prefix: &str) -> bool {
    records(catalogue)
        .iter()
        .any(|(name, _)| name.starts_with(prefix))
}

// ---------------------------------------------------------------------------------------------
// What a build trusts
// ---------------------------------------------------------------------------------------------

/// A root is trusted from its root role's key identifiers and nothing it says about itself: a
/// production root needs a production set that is not empty, every key in it and the threshold; a
/// development root needs a build that admits the development set and every key in it; an empty
/// list, a key in neither and one key of each are refused.
#[test]
fn a_root_is_trusted_by_its_keys_alone() {
    let production = ["aa", "bb"];
    let development = ["dd"];
    let trusted = |keys: &[&str], threshold, production: &[&str], development: Option<&[&str]>| {
        permitted_root(keys, threshold, production, 2, development)
    };

    assert_eq!(
        trusted(&["aa", "bb"], 2, &production, Some(&development)),
        Ok(Permitted::Production)
    );
    assert_eq!(
        trusted(&["dd"], 1, &production, Some(&development)),
        Ok(Permitted::Development)
    );
    // A build without debug assertions admits no development key.
    assert_eq!(
        trusted(&["dd"], 1, &production, None),
        Err(Refusal::UnknownKey("dd".to_owned()))
    );
    // One key of each is neither a production root nor a development one.
    assert_eq!(
        trusted(&["aa", "dd"], 2, &production, Some(&development)),
        Err(Refusal::Mixed)
    );
    assert!(trusted(&["aa", "zz"], 2, &production, Some(&development)).is_err());
    // A production root with fewer signatures than the production threshold.
    assert_eq!(
        trusted(&["aa", "bb"], 1, &production, Some(&development)),
        Err(Refusal::BelowThreshold { have: 1, need: 2 })
    );
    // No keys, and no production set yet.
    assert_eq!(
        trusted(&[], 1, &production, Some(&development)),
        Err(Refusal::NoKeys)
    );
    assert_eq!(
        trusted(&["dd"], 1, &[], None),
        Err(Refusal::NoProductionRoot)
    );
    // A release trusts no development key whatever the root is called.
    assert!(trusted(&["dd"], 1, &[], None).is_err());
}

/// A marker in a root's signed members, whatever it says, changes nothing: only the keys decide.
#[tokio::test]
async fn a_root_marked_production_is_trusted_for_its_keys_and_never_as_production() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = Generation::build(home.path(), GenerationSpec::default()).await;
    let mut root: serde_json::Value =
        serde_json::from_slice(&generation.root_bytes_highest()).expect("a root");
    root["signed"]["production"] = serde_json::json!(true);
    let marked = serde_json::to_vec(&root).expect("a root");
    let keys = support::seed_trust_of(&generation.root_bytes_highest());
    // The development lineage's own keys, admitted: a development root, marker or no marker.
    assert_eq!(
        keys.permit(&marked).expect("trusted"),
        Permitted::Development
    );
    // The same keys where no development set is admitted, as a release is: refused.
    let release = SeedTrust::named(Vec::new(), 1, None);
    assert!(release.permit(&marked).is_err());
    assert!(release.permit(&generation.root_bytes_highest()).is_err());
}

/// The development lineage's key identifiers this repository commits are the ones the published
/// phrase derives, and are disjoint from the production set.
#[test]
fn the_committed_development_keys_are_the_ones_the_phrase_derives() {
    use aws_lc_rs::signature::Ed25519KeyPair;
    use tough::sign::Sign as _;

    let seed = kr_plugin_sdk::digest::PayloadDigest::of(b"kalareach-plugins development key root");
    let pair = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes()).expect("a key");
    let identifier = pair.tuf_key().key_id().expect("an identifier");
    let derived: String = identifier
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let bundle = SeedBundle::embedded().expect("the committed bundle is whole");
    let trust = SeedTrust::compiled();
    // The committed root's role key is the derived one, so a build with debug assertions trusts it.
    let root = bundle.highest_root();
    let committed: serde_json::Value = serde_json::from_slice(root).expect("a root");
    let named = committed["signed"]["roles"]["root"]["keyids"][0]
        .as_str()
        .expect("a key identifier")
        .to_owned();
    assert_eq!(named, derived);
    if cfg!(debug_assertions) {
        assert_eq!(trust.permit(root).expect("trusted"), Permitted::Development);
    } else {
        assert!(
            trust.permit(root).is_err(),
            "a release trusts no development root"
        );
    }
}

/// A release trusts no bundled root until the production root exists: with this build's trust
/// narrowed to a release's, the committed bundle is refused and nothing is written.
#[tokio::test]
async fn a_release_refuses_every_bundle_and_writes_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = offline(home.path());
    // A release's trust: no production keys committed, and no development set.
    let (lock, files) = {
        let committed = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bundled-plugins.lock"),
        )
        .expect("the lock");
        let files: std::collections::BTreeMap<String, Vec<u8>> =
            bundle_files().into_iter().collect();
        (committed, files)
    };
    let release = SeedBundle::from_files(&lock, files, SeedTrust::named(Vec::new(), 1, None))
        .expect("the bundle is whole");

    let outcome = catalogue.seed(&release, environment(), budgets()).await;

    assert!(!outcome.committed, "{}", outcome.report());
    assert!(
        outcome
            .notes
            .iter()
            .any(|note| note.contains("trusts no bundled root"))
    );
    assert!(catalogue.repositories().expect("records").is_empty());
    assert!(records(&catalogue).is_empty());
}

/// Every file of the committed bundle, as the host compiles them in.
fn bundle_files() -> Vec<(String, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bundled-plugins");
    let mut found = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .expect("a directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path
                    .strip_prefix(&root)
                    .expect("inside the bundle")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((relative, std::fs::read(&path).expect("a file")));
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------------------------
// The bundle is what its lock says
// ---------------------------------------------------------------------------------------------

/// A bundle whose files are not what its lock names is not a bundle: a byte changed after the
/// lock, a file the lock does not name, a root missing from the chain, a root.json that is not the
/// highest root, a lock that names another root, and a lock that disagrees with its manifest.
#[tokio::test]
async fn a_bundle_that_is_not_what_its_lock_names_is_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let (lock, files) = seed_files(&generation);
    let trust = support::seed_trust_of(&generation.root_bytes_highest());
    let build = |lock: &str, files: std::collections::BTreeMap<String, Vec<u8>>| {
        SeedBundle::from_files(lock.as_bytes(), files, trust.clone())
    };
    build(&lock, files.clone()).expect("the control: the files as they were locked");

    let mut edited = files.clone();
    let manifest = edited
        .keys()
        .find(|path| path.ends_with("/plugin.json"))
        .expect("a manifest")
        .clone();
    edited.get_mut(&manifest).expect("the manifest")[0] ^= 1;
    let error = build(&lock, edited).expect_err("a byte edited after the lock");
    assert!(
        error
            .to_string()
            .contains("is not what the bundled lock names"),
        "{error}"
    );

    let mut extra = files.clone();
    extra.insert("targets/extra.json".to_owned(), b"{}".to_vec());
    let error = build(&lock, extra).expect_err("a file the lock does not name");
    assert!(
        error.to_string().contains("which its lock does not name"),
        "{error}"
    );

    let mut missing = files.clone();
    missing.remove("metadata/1.root.json");
    let mut lock_value: serde_json::Value = serde_json::from_str(&lock).expect("a lock");
    lock_value["metadata"]
        .as_array_mut()
        .expect("metadata")
        .retain(|entry| entry["path"] != "metadata/1.root.json");
    let error = build(&lock_value.to_string(), missing).expect_err("a root missing from the chain");
    assert!(error.to_string().contains("run from version 1"), "{error}");

    let mut other = files.clone();
    let mut changed: serde_json::Value = serde_json::from_str(&lock).expect("a lock");
    changed["trust_root"]["digest"] =
        serde_json::json!(kr_plugin_sdk::digest::PayloadDigest::of(b"another root").to_string());
    let error = build(&changed.to_string(), std::mem::take(&mut other))
        .expect_err("a lock that names another root");
    assert!(
        error.to_string().contains("does not name the highest root")
            || error.to_string().contains("does not carry"),
        "{error}"
    );

    let mut disagree: serde_json::Value = serde_json::from_str(&lock).expect("a lock");
    disagree["packages"][0]["version"] = serde_json::json!("0.9.0");
    let error = build(&disagree.to_string(), files).expect_err("a lock that disagrees");
    assert!(error.to_string().contains("disagree"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// A fresh installation
// ---------------------------------------------------------------------------------------------

/// KR-REQ-04.15, 12.01: with no repository and no network, the seed enrols the official
/// repository against the bundle's root, activates the bundled generation, and installs the
/// bundled package enabled with an empty grant: nothing past the default ceiling is effective,
/// and nothing was confirmed by an owner.
#[tokio::test]
async fn a_fresh_store_is_seeded_with_nothing_granted() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    assert!(
        installed(&catalogue).is_none(),
        "the control: at the base nothing is installed"
    );

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(outcome.enrolled && outcome.committed);
    assert_eq!(outcome.activated, Some(bundle.generation()));
    assert_eq!(outcome.installed, [plugin()]);
    let enrolments = catalogue.repositories().expect("records");
    assert_eq!(enrolments.len(), 1);
    let official = &enrolments[0];
    assert_eq!(official.id.as_str(), "official");
    assert_eq!(official.kind, RepositoryKind::Official);
    assert_eq!(official.root, bundle.highest_root());
    assert!(!official.budgets.full_offline_mirror);
    assert!(official.pinned_generation.is_none());

    let installation = installed(&catalogue).expect("the bundled package is installed");
    assert!(installation.enabled);
    assert!(
        installation.grant.capabilities().is_empty(),
        "an empty grant"
    );
    assert_eq!(installation.version, version());
    let effective = catalogue
        .effective_capabilities(environment(), &plugin())
        .expect("effective capabilities");
    for capability in [
        PluginCapability::TerminalInput,
        PluginCapability::NativeBridgeInstall,
        PluginCapability::TranscriptTail,
    ] {
        assert!(
            !effective.contains(&capability),
            "{capability} is past the default ceiling and stays the owner's decision"
        );
    }
    assert!(effective.contains(&PluginCapability::MetadataMatch));

    // The package is the bundle's own bytes, activated with no fetch.
    let store = catalogue.store(&official.id).expect("a store");
    assert!(matches!(
        store
            .check_package(
                installation.package_digest,
                kr_plugin_catalogue::PackageLimits::format()
            )
            .expect("a readable store"),
        kr_plugin_catalogue::PackageCheck::Complete(_)
    ));

    // What is recorded: the enrolment the seed made, where its generation came from and what it did
    // with the package.
    let names: Vec<String> = records(&catalogue)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(names.iter().any(|name| name.starts_with("seeded:")));
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("seed_provenance:"))
    );
    assert!(names.contains(&format!("seed_installed:{}", plugin())));
}

/// A second seed does nothing durable: nothing commits and the admission revision stays.
#[tokio::test]
async fn a_second_seed_changes_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue.seed(&bundle, environment(), budgets()).await;
    let before = records(&catalogue);
    let revision = catalogue.admission_revision().expect("a revision");

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(!outcome.committed, "{}", outcome.report());
    assert!(outcome.installed.is_empty() && outcome.left.is_empty());
    assert_eq!(records(&catalogue), before);
    assert_eq!(
        catalogue.admission_revision().expect("a revision"),
        revision
    );
}

/// The bundle this build compiles in seeds a fresh store, on a build that trusts the development
/// lineage, with every adapter's package installed.
#[tokio::test]
async fn the_committed_bundle_seeds_a_fresh_store() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let mut catalogue = offline(home.path());
    let bundle = SeedBundle::embedded().expect("the committed bundle is whole");

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    if cfg!(debug_assertions) {
        assert!(outcome.failure.is_none(), "{}", outcome.report());
        assert_eq!(
            outcome.installed.len(),
            bundle.packages().len(),
            "{}",
            outcome.report()
        );
        for package in bundle.packages() {
            let installation = catalogue
                .installation(environment(), &package.plugin_id)
                .expect("records")
                .expect("installed");
            assert!(installation.enabled);
            assert!(installation.grant.capabilities().is_empty());
        }
    } else {
        assert!(
            outcome.installed.is_empty(),
            "a release trusts no development root"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The owner's decisions are never undone
// ---------------------------------------------------------------------------------------------

/// An owner's uninstall stays uninstalled and an owner's disable stays disabled, at every later
/// seed.
#[tokio::test]
async fn an_owners_uninstall_and_disable_are_never_undone() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue.seed(&bundle, environment(), budgets()).await;

    catalogue
        .set_enabled(environment(), &plugin(), false)
        .await
        .expect("the owner disables it");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.installed.is_empty(), "{}", outcome.report());
    assert!(!installed(&catalogue).expect("still installed").enabled);

    catalogue
        .uninstall(environment(), &plugin())
        .expect("the owner uninstalls it");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.installed.is_empty(), "{}", outcome.report());
    assert!(installed(&catalogue).is_none(), "the uninstall stays");
}

/// An installation the owner made before the first seed, from another repository, with a grant and
/// in any state, is left as it is, whatever the seed's bundle carries; and removing it later
/// installs nothing.
#[tokio::test]
async fn an_installation_made_before_the_seed_is_left_as_it_is() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("a temporary directory");
    let mine = adapter(other.path()).await;
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    // The owner's own repository, which holds the same plugin under other keys.
    catalogue
        .enrol(
            Enrolment::new(
                kr_plugin_catalogue::RepositoryId::new("mine").expect("an identifier"),
                RepositoryKind::Community,
                mine.metadata_url(),
                mine.targets_url(),
                mine.root_bytes(),
                budgets(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment"),
            true,
        )
        .expect("the owner adopts the root");
    let id = kr_plugin_catalogue::RepositoryId::new("mine").expect("an identifier");
    catalogue.sync(&id).await.expect("the owner syncs");
    let grant = InstallationGrant::with([
        PluginCapability::TerminalInput,
        PluginCapability::TranscriptTail,
        PluginCapability::NativeBridgeInstall,
    ]);
    catalogue
        .install_with(
            &id,
            environment(),
            &plugin(),
            &version(),
            mine.manifest_digest(),
            grant,
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("the owner installs it");
    catalogue
        .set_enabled(environment(), &plugin(), false)
        .await
        .expect("the owner disables it");
    let before = installed(&catalogue).expect("installed");

    for _ in 0..2 {
        let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
        assert!(outcome.failure.is_none(), "{}", outcome.report());
        assert!(outcome.installed.is_empty(), "{}", outcome.report());
    }

    assert_eq!(
        installed(&catalogue).expect("installed"),
        before,
        "release, grant and state"
    );
    assert_eq!(before.repository.as_str(), "mine");
    assert!(!before.enabled);
    catalogue
        .uninstall(environment(), &plugin())
        .expect("the owner removes it");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.installed.is_empty(), "{}", outcome.report());
    assert!(installed(&catalogue).is_none());
}

/// A seed that stopped after its enrolment, before it reached a package the owner had installed,
/// cannot undo the owner's uninstall of it: once the seed has made its enrolment, an uninstall
/// settles the package in its own commit.
#[tokio::test]
async fn an_uninstall_after_a_seed_that_stopped_is_never_undone() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("a temporary directory");
    let mine = Generation::build(other.path(), GenerationSpec::default()).await;
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    let id = kr_plugin_catalogue::RepositoryId::new("mine").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Community,
                mine.metadata_url(),
                mine.targets_url(),
                mine.root_bytes(),
                budgets(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment"),
            true,
        )
        .expect("the owner adopts the root");
    catalogue.sync(&id).await.expect("the owner syncs");
    catalogue
        .install_with(
            &id,
            environment(),
            &plugin(),
            &version(),
            mine.manifest_digest(),
            InstallationGrant::none(),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("the owner installs it");

    catalogue.stop_seed_at(Some(SeedPoint::AfterEnrolment));
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.failure.is_some(), "the seed was stopped");
    assert!(outcome.enrolled);
    assert!(
        !has_record(&catalogue, "seed_installed:"),
        "nothing of the package is recorded yet"
    );

    catalogue
        .uninstall(environment(), &plugin())
        .expect("the owner uninstalls it");
    catalogue.stop_seed_at(None);
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(outcome.installed.is_empty(), "{}", outcome.report());
    assert!(installed(&catalogue).is_none(), "the uninstall stays");
    assert!(has_record(&catalogue, "seed_installed:"));
}

// ---------------------------------------------------------------------------------------------
// Stops and pins
// ---------------------------------------------------------------------------------------------

/// A stop right after the generation is active leaves a state the next start finishes: the
/// package is installed once, from the bundle's bytes.
#[tokio::test]
async fn a_stop_after_activation_is_finished_at_the_next_start() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue.stop_seed_at(Some(SeedPoint::AfterActivation));

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_some());
    assert_eq!(outcome.activated, Some(bundle.generation()));
    assert!(installed(&catalogue).is_none());
    assert!(!has_record(&catalogue, "seed_installed:"));

    catalogue.stop_seed_at(None);
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(
        outcome.activated.is_none(),
        "the generation is already active"
    );
    assert_eq!(outcome.installed, [plugin()]);
    assert!(installed(&catalogue).expect("installed").enabled);
}

/// A stop between the enrolment and the sync is finished at the next start, which resumes the
/// enrolment the seed made and enrols nothing again.
#[tokio::test]
async fn a_stop_between_the_enrolment_and_the_sync_is_resumed() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue.stop_seed_at(Some(SeedPoint::AfterEnrolment));
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.failure.is_some() && outcome.enrolled);

    catalogue.stop_seed_at(None);
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(!outcome.enrolled, "{}", outcome.report());
    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert_eq!(outcome.activated, Some(bundle.generation()));
    assert_eq!(outcome.installed, [plugin()]);
    assert_eq!(catalogue.repositories().expect("records").len(), 1);
}

/// A pin skips the sync only: the generation, the trust checkpoint and the floors do not move, and
/// the package the seed had not reached is still installed.
#[tokio::test]
async fn a_pin_skips_the_sync_and_not_the_installs() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue.stop_seed_at(Some(SeedPoint::AfterActivation));
    catalogue.seed(&bundle, environment(), budgets()).await;
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    catalogue
        .pin(&id, Some(bundle.generation()))
        .expect("the owner pins the generation");
    let active = catalogue.active(&id).expect("records");
    let floors = (catalogue.repository(&id).expect("records"), active);

    catalogue.stop_seed_at(None);
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(outcome.activated.is_none());
    assert_eq!(outcome.installed, [plugin()]);
    assert_eq!(
        (
            catalogue.repository(&id).expect("records"),
            catalogue.active(&id).expect("records")
        ),
        floors,
        "the pinned repository is unchanged"
    );
}

/// A repository pinned with every package recorded is skipped with no commit at all.
#[tokio::test]
async fn a_pinned_repository_with_every_package_recorded_commits_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue.seed(&bundle, environment(), budgets()).await;
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    catalogue
        .pin(&id, Some(bundle.generation()))
        .expect("the owner pins the generation");
    let revision = catalogue.admission_revision().expect("a revision");
    let before = records(&catalogue);

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(!outcome.committed, "{}", outcome.report());
    assert_eq!(records(&catalogue), before);
    assert_eq!(
        catalogue.admission_revision().expect("a revision"),
        revision
    );
}

// ---------------------------------------------------------------------------------------------
// The owner's repositories
// ---------------------------------------------------------------------------------------------

/// The seed never enrols again after the owner removed what it made, and a removal is recorded.
#[tokio::test]
async fn a_removed_seed_enrolment_is_never_enrolled_again() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue.seed(&bundle, environment(), budgets()).await;
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    catalogue
        .remove_repository(&id)
        .expect("the owner removes it");
    assert!(has_record(&catalogue, "removed:"));
    assert!(
        has_record(&catalogue, "seeded:"),
        "the record that it was made stays"
    );
    assert!(
        !has_record(&catalogue, "seed_provenance:"),
        "its provenance goes"
    );

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(
        !outcome.enrolled && !outcome.committed,
        "{}",
        outcome.report()
    );
    assert!(catalogue.repositories().expect("records").is_empty());
}

/// An enrolment of the owner's own, named `official` with other keys, is untouched, and the seed
/// declines durably; so does one that holds the bundle's root under another name.
#[tokio::test]
async fn an_enrolment_of_the_owners_is_untouched_and_the_seed_declines_durably() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("a temporary directory");
    let mine = adapter(other.path()).await;
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue
        .enrol(
            Enrolment::new(
                kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier"),
                RepositoryKind::Official,
                mine.metadata_url(),
                mine.targets_url(),
                mine.root_bytes(),
                budgets(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment"),
            true,
        )
        .expect("the owner adopts the root");
    let before = catalogue.repositories().expect("records");

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(!outcome.enrolled, "{}", outcome.report());
    assert!(outcome.committed, "the decline is the one record it keeps");
    assert_eq!(catalogue.repositories().expect("records"), before);
    assert!(has_record(&catalogue, "declined:"));
    // Declined for good: removing the owner's own does not let the seed in.
    catalogue
        .remove_repository(
            &kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier"),
        )
        .expect("the owner removes it");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(
        !outcome.enrolled && !outcome.committed,
        "{}",
        outcome.report()
    );

    // The same root under another name.
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue
        .enrol(
            Enrolment::new(
                kr_plugin_catalogue::RepositoryId::new("mirror-of-it").expect("an identifier"),
                RepositoryKind::Mirror,
                generation.metadata_url(),
                generation.targets_url(),
                generation.root_bytes(),
                budgets(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment"),
            true,
        )
        .expect("the owner adopts the root");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(!outcome.enrolled, "{}", outcome.report());
    assert!(has_record(&catalogue, "declined:"));
}

// ---------------------------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------------------------

/// A bundle whose metadata has expired is activated all the same and reported expired; a later
/// sync, with expiry enforced, refuses expired metadata and takes a fresh generation.
#[tokio::test]
async fn an_expired_seed_is_reported_and_a_fresh_sync_replaces_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let expired = Generation::build(
        home.path(),
        GenerationSpec {
            expired: true,
            ..GenerationSpec::default()
        },
    )
    .await;
    let bundle = seed_bundle(&expired);
    let mut catalogue = offline(home.path());

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert!(outcome.expired.is_some(), "{}", outcome.report());
    assert_eq!(outcome.activated, Some(bundle.generation()));
    assert_eq!(outcome.installed, [plugin()]);

    // The same repository, fetched from its own location now: expired metadata is refused, and a
    // fresh generation of the same root is taken.
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let mut official = catalogue
        .repository(&id)
        .expect("records")
        .expect("enrolled");
    official.metadata_url = expired.metadata_url();
    official.targets_url = expired.targets_url();
    catalogue
        .update_enrolment(official, false)
        .expect("the owner points it at a mirror");
    expired.rewrite_expired(2).await;
    let error = catalogue
        .sync(&id)
        .await
        .expect_err("expired metadata is refused");
    assert!(
        matches!(error, CatalogueError::MetadataExpired { .. }),
        "{error}"
    );
    expired
        .rewrite_with(GenerationSpec {
            generation: 3,
            ..GenerationSpec::default()
        })
        .await;
    catalogue
        .sync(&id)
        .await
        .expect("a fresh generation is taken");
}

// ---------------------------------------------------------------------------------------------
// A network that moved on
// ---------------------------------------------------------------------------------------------

/// A store a network sync moved past the bundle finishes the packages the seed had not reached,
/// from the active index and the bundle's bytes; an index that no longer lists the package, or
/// lists it revoked or at another digest, skips it with a reason and records nothing, so a later
/// index that lists it is taken.
#[tokio::test]
async fn a_store_moved_past_the_bundle_finishes_what_it_can() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue.stop_seed_at(Some(SeedPoint::AfterActivation));
    catalogue.seed(&bundle, environment(), budgets()).await;
    catalogue.stop_seed_at(None);
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let mut official = catalogue
        .repository(&id)
        .expect("records")
        .expect("enrolled");
    official.metadata_url = generation.metadata_url();
    official.targets_url = generation.targets_url();
    catalogue
        .update_enrolment(official, false)
        .expect("the owner points it at a mirror");

    // The network moves on to a generation that no longer lists the package.
    generation
        .rewrite_with(GenerationSpec {
            generation: 2,
            package_version: "0.2.0".to_owned(),
            ..GenerationSpec::default()
        })
        .await;
    catalogue.sync(&id).await.expect("the network moved on");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert!(outcome.installed.is_empty(), "{}", outcome.report());
    assert_eq!(outcome.skipped.len(), 1, "{}", outcome.report());
    assert!(
        !has_record(&catalogue, "seed_installed:"),
        "nothing is recorded for a skip"
    );

    // A later generation lists it again, at the digest the bundle carries, and it is installed
    // from the bundle's bytes with the network unreachable.
    generation
        .rewrite_with(GenerationSpec {
            generation: 3,
            capabilities: vec![
                PluginCapability::MetadataMatch,
                PluginCapability::DeclarativePresentation,
                PluginCapability::BrokerSemanticEvents,
                PluginCapability::TranscriptTail,
                PluginCapability::TerminalInput,
                PluginCapability::NativeBridgeInstall,
            ],
            ..GenerationSpec::default()
        })
        .await;
    catalogue.sync(&id).await.expect("a later generation");
    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;
    assert_eq!(outcome.installed, [plugin()], "{}", outcome.report());
    assert!(outcome.activated.is_none(), "the sync is not repeated");
}

// ---------------------------------------------------------------------------------------------
// Nothing is evicted for what cannot arrive
// ---------------------------------------------------------------------------------------------

/// A host that cannot reach its repository is told so before it has made room for a package it
/// could not fetch: what was cached and is protected by nothing is still there.
#[tokio::test]
async fn nothing_is_evicted_for_a_package_that_cannot_arrive() {
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_protocol::scalars::U64;

    let home = tempfile::tempdir().expect("a temporary directory");
    // A release the index lists and the bundle does not carry: only a network could supply it, and
    // it is large enough that fetching it would mean making room.
    let mut other = support::synthetic_index(1).entries.remove(0);
    other.plugin_id = plugin();
    other.plugin_name = kr_plugin_sdk::ids::PluginName::new("example-declarative").expect("a name");
    other.version = PackageVersion::parse("9.9.9").expect("a version");
    let mut total = other.manifest_size_bytes.get();
    for payload in &mut other.payloads {
        payload.digest = PayloadDigest::of(payload.path.as_str().as_bytes());
        payload.size_bytes = U64::new(4_000);
        total += 4_000;
    }
    other.total_size_bytes = U64::new(total);
    let generation = Generation::build(
        home.path(),
        GenerationSpec {
            listed_only: vec![other],
            ..GenerationSpec::default()
        },
    )
    .await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    let mut tight = budgets();
    tight.payload_cache_bytes = U64::new(40_000);
    catalogue.seed(&bundle, environment(), tight).await;
    assert!(
        installed(&catalogue).is_some(),
        "the control: the bundled package was installed"
    );
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let store = catalogue.store(&id).expect("a store");
    // The package is uninstalled, so what it cached is protected by nothing.
    catalogue
        .uninstall(environment(), &plugin())
        .expect("the owner uninstalls it");
    let held_before = store.cached_payloads().expect("a readable store");
    assert!(!held_before.is_empty());

    let error = catalogue
        .activate_package(
            &id,
            &plugin(),
            &PackageVersion::parse("9.9.9").expect("a version"),
            kr_plugin_catalogue::FetchReason::ExplicitInstall,
        )
        .await
        .expect_err("the repository cannot be reached");

    assert!(
        matches!(error, CatalogueError::UnavailableOffline { .. }),
        "{error}"
    );
    assert_eq!(
        store.cached_payloads().expect("a readable store"),
        held_before,
        "nothing was evicted for a package that could not arrive"
    );
}

// ---------------------------------------------------------------------------------------------
// The grant path
// ---------------------------------------------------------------------------------------------

/// `plugin.grant` no longer widens an installation whose release asks for a native bridge: it
/// refuses naming `plugin.install`, which is where the owner is shown the publisher's own words,
/// and narrowing stays.
#[tokio::test]
async fn a_seeded_bridge_is_granted_only_by_installing_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue.seed(&bundle, environment(), budgets()).await;
    let installation = installed(&catalogue).expect("installed");

    for added in [
        PluginCapability::NativeBridgeInstall,
        PluginCapability::TerminalInput,
    ] {
        let error = catalogue
            .set_grant_with(
                environment(),
                &plugin(),
                installation.package_digest,
                InstallationGrant::with([added]),
                &mut Change::new(&Owner::confirming()),
            )
            .expect_err("a widening of a bridge package is refused");
        assert!(
            matches!(error, CatalogueError::GrantRequired { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("plugin.install"), "{error}");
    }
    assert!(
        installed(&catalogue)
            .expect("installed")
            .grant
            .capabilities()
            .is_empty()
    );

    // The install path takes the whole grant, with the owner's confirmation, and then a narrower
    // grant is allowed.
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let all = InstallationGrant::with([
        PluginCapability::TranscriptTail,
        PluginCapability::TerminalInput,
        PluginCapability::NativeBridgeInstall,
    ]);
    let refused = catalogue
        .install_with(
            &id,
            environment(),
            &plugin(),
            &version(),
            installation.package_digest,
            all.clone(),
            None,
            &mut Change::new(&Owner::acting()),
        )
        .await
        .expect_err("without the owner's confirmation it changes nothing");
    assert!(
        matches!(refused, CatalogueError::OwnerConfirmationRequired { .. }),
        "{refused}"
    );
    assert!(
        installed(&catalogue)
            .expect("installed")
            .grant
            .capabilities()
            .is_empty()
    );
    catalogue
        .install_with(
            &id,
            environment(),
            &plugin(),
            &version(),
            installation.package_digest,
            all,
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("the confirmed install grants it");
    assert_eq!(
        installed(&catalogue)
            .expect("installed")
            .grant
            .capabilities()
            .len(),
        3
    );
    catalogue
        .set_grant_with(
            environment(),
            &plugin(),
            installation.package_digest,
            InstallationGrant::with([PluginCapability::TranscriptTail]),
            &mut Change::new(&Owner::acting()),
        )
        .expect("narrowing stays");
    assert_eq!(
        installed(&catalogue)
            .expect("installed")
            .grant
            .capabilities()
            .len(),
        1
    );
    let _ = (seed_bundle_trusting, KeySet::generate);
}

// ---------------------------------------------------------------------------------------------
// What the seed guards
// ---------------------------------------------------------------------------------------------

/// The identifier of a key set's root key, as the client writes it.
fn root_key_id(keys: &KeySet) -> String {
    keys.root
        .tuf_key()
        .key_id()
        .expect("a key identifier")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A resume under a root this build does not trust changes nothing: the enrolment has been moved by
/// the network to a root of other keys, and a bundle of the first root, which this build trusts,
/// neither syncs nor installs.
#[tokio::test]
async fn a_resume_under_a_root_this_build_does_not_trust_changes_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());
    catalogue.stop_seed_at(Some(SeedPoint::AfterActivation));
    catalogue.seed(&bundle, environment(), budgets()).await;
    catalogue.stop_seed_at(None);

    // The network rotates the root to keys this build does not trust, and the owner's host follows.
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let mut official = catalogue
        .repository(&id)
        .expect("records")
        .expect("enrolled");
    official.metadata_url = generation.metadata_url();
    official.targets_url = generation.targets_url();
    catalogue
        .update_enrolment(official, false)
        .expect("the owner points it at a mirror");
    generation.rotate_root_to_v2(&KeySet::generate()).await;
    catalogue
        .sync(&id)
        .await
        .expect("the host follows the rotation");
    let moved = catalogue
        .repository(&id)
        .expect("records")
        .expect("enrolled");
    assert_ne!(moved.root, bundle.highest_root());
    let before = (
        records(&catalogue),
        catalogue.admission_revision().expect("a revision"),
    );

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(
        outcome
            .notes
            .iter()
            .any(|note| note.contains("did not resume")),
        "{}",
        outcome.report()
    );
    assert!(outcome.installed.is_empty() && !outcome.committed);
    assert!(
        installed(&catalogue).is_none(),
        "no install under a root this build does not trust"
    );
    assert_eq!(
        (
            records(&catalogue),
            catalogue.admission_revision().expect("a revision")
        ),
        before
    );
    assert_eq!(catalogue.repository(&id).expect("records"), Some(moved));
}

/// A root the client reaches along a chain is one this build trusts before it is kept: with a
/// first root, an intermediate root of other keys and a last root the client cannot verify, the
/// intermediate root is not kept; where this build trusts it too, it is.
#[tokio::test]
async fn an_intermediate_root_this_build_does_not_trust_is_never_kept() {
    for trusting_the_middle in [false, true] {
        let home = tempfile::tempdir().expect("a temporary directory");
        let generation = adapter(home.path()).await;
        let (second, third) = (KeySet::generate(), KeySet::generate());
        let mut trusted = vec![root_key_id(&generation.keys()), root_key_id(&third)];
        if trusting_the_middle {
            trusted.push(root_key_id(&second));
        }
        let trust = SeedTrust::named(Vec::new(), 1, Some(trusted));
        let first_bundle = seed_bundle_trusting(&generation, trust.clone());
        let mut catalogue = offline(home.path());
        catalogue.stop_seed_at(Some(SeedPoint::AfterActivation));
        catalogue
            .seed(&first_bundle, environment(), budgets())
            .await;
        catalogue.stop_seed_at(None);
        let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
        let first_root = catalogue
            .repository(&id)
            .expect("records")
            .expect("enrolled")
            .root;

        // Root 2 is signed by the first keys and its own. Root 3 names the third keys and is signed
        // only by them, so a client that trusts root 2 cannot verify it.
        generation.rotate_root_to_v2(&second).await;
        let second_root = generation.root_bytes_highest();
        generation.rotate_root_to(3, &third, &third, 3).await;
        let later = seed_bundle_trusting(&generation, trust);
        let outcome = catalogue.seed(&later, environment(), budgets()).await;

        assert!(
            outcome.failure.is_some(),
            "the last root cannot be verified: {}",
            outcome.report()
        );
        let kept = catalogue
            .repository(&id)
            .expect("records")
            .expect("enrolled")
            .root;
        let version = |root: &[u8]| {
            serde_json::from_slice::<serde_json::Value>(root).expect("a root")["signed"]["version"]
                .as_u64()
                .expect("a version")
        };
        if trusting_the_middle {
            assert_eq!(
                version(&kept),
                version(&second_root),
                "a root this build trusts is kept on the way"
            );
        } else {
            assert_eq!(
                kept, first_root,
                "an intermediate root this build does not trust is not kept"
            );
        }
    }
}

/// A root that could not start a load, because it does not verify against itself, leaves no record
/// that would hold the store.
#[tokio::test]
async fn a_root_that_cannot_start_a_load_leaves_no_record() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    for path in [
        generation.directory().join("metadata").join("1.root.json"),
        generation.directory().join("metadata").join("root.json"),
    ] {
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("a root")).expect("a root");
        // A signature that is not the root's own.
        let signature = document["signatures"][0]["sig"]
            .as_str()
            .expect("a signature");
        let mut flipped = signature.to_owned();
        flipped.replace_range(0..1, if flipped.starts_with('0') { "1" } else { "0" });
        document["signatures"][0]["sig"] = serde_json::json!(flipped);
        std::fs::write(&path, serde_json::to_vec(&document).expect("a root")).expect("writable");
    }
    let bundle = seed_bundle(&generation);
    let mut catalogue = offline(home.path());

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(outcome.failure.is_some(), "{}", outcome.report());
    assert!(!outcome.enrolled);
    assert!(catalogue.repositories().expect("records").is_empty());
    assert!(records(&catalogue).is_empty(), "no record holds the store");
}

/// The first decline commits its record and nothing else: the admission revision does not move.
#[tokio::test]
async fn the_first_decline_moves_no_admission_revision() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("a temporary directory");
    let mine = adapter(other.path()).await;
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    catalogue
        .enrol(
            Enrolment::new(
                kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier"),
                RepositoryKind::Official,
                mine.metadata_url(),
                mine.targets_url(),
                mine.root_bytes(),
                budgets(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment"),
            true,
        )
        .expect("the owner adopts the root");
    let revision = catalogue.admission_revision().expect("a revision");

    let outcome = catalogue.seed(&bundle, environment(), budgets()).await;

    assert!(
        outcome.committed && !outcome.enrolled,
        "{}",
        outcome.report()
    );
    assert_eq!(
        catalogue.admission_revision().expect("a revision"),
        revision
    );
}

/// The seed enrols with the budgets it is given and never a full mirror, which the bundle could not
/// supply.
#[tokio::test]
async fn the_seed_enrols_without_a_mirror_whatever_budgets_say() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let bundle = seed_bundle(&adapter(home.path()).await);
    let mut catalogue = offline(home.path());
    let mut asked = budgets();
    asked.full_offline_mirror = true;
    asked.retained_generations = kr_protocol::scalars::U64::new(3);

    catalogue.seed(&bundle, environment(), asked).await;

    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let official = catalogue
        .repository(&id)
        .expect("records")
        .expect("enrolled");
    assert!(!official.budgets.full_offline_mirror);
    assert_eq!(official.budgets.retained_generations.get(), 3);
    assert_eq!(official.ceiling, CapabilityCeiling::default_ceiling());
}

/// The bundle is served at the repository's own addresses, and only what it carries: a file it does
/// not have is absent in the stream, as a 404 is, and a name that leaves its directory is not
/// served.
#[tokio::test]
async fn the_bundle_is_served_at_the_repositorys_addresses_and_nowhere_else() {
    use futures::StreamExt as _;
    use tough::Transport as _;

    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = adapter(home.path()).await;
    let bundle = seed_bundle(&generation);
    let enrolment = Enrolment::new(
        kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier"),
        RepositoryKind::Official,
        url::Url::parse("https://plugins.example.test/metadata").expect("an address"),
        url::Url::parse("https://plugins.example.test/targets/").expect("an address"),
        bundle.highest_root().to_vec(),
        budgets(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("an enrolment");
    let transport = kr_plugin_catalogue::transport::EmbeddedTransport::new(&bundle, &enrolment);
    let read = |address: &'static str| {
        let transport = transport.clone();
        async move {
            let mut stream = transport
                .fetch(url::Url::parse(address).expect("an address"))
                .await
                .expect("a stream");
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => bytes.extend_from_slice(&chunk),
                    Err(error) => return Err(error.kind()),
                }
            }
            Ok(bytes)
        }
    };

    assert_eq!(
        read("https://plugins.example.test/metadata/root.json")
            .await
            .expect("served"),
        bundle.highest_root()
    );
    assert_eq!(
        read("https://plugins.example.test/targets/index.json")
            .await
            .expect("served"),
        bundle.file("targets/index.json").expect("the index")
    );
    for address in [
        "https://plugins.example.test/metadata/9.root.json",
        "https://plugins.example.test/elsewhere/root.json",
        "https://other.example.test/metadata/root.json",
    ] {
        assert_eq!(
            read(address).await.expect_err("not served"),
            tough::TransportErrorKind::FileNotFound,
            "{address}"
        );
    }
}
