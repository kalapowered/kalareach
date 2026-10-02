//! First use of the bundled generation, with nothing reachable.
//!
//! A fresh installation has no repository. Section 11 still requires it to activate what it was
//! shipped with: bundled, installed, pinned and live-bound payloads remain available offline, a
//! package activates atomically once all its payloads verify, and a payload that is not there
//! answers `PACKAGE_UNAVAILABLE_OFFLINE` rather than a capability nobody could perform.
//!
//! The host carries a signed catalogue generation: the metadata that verifies it, its index and the
//! adapters' packages. Seeding enrols the official repository against the highest root that
//! generation ships, activates the generation through the ordinary update client over a transport
//! made of the bundle's own bytes, and installs each bundled package once, enabled, with nothing
//! granted. These cases run that over the committed bundle.
//!
//! # What this suite establishes about the network, and what it does not
//!
//! Not that the code "did not happen to need" the network. Three things, each with its own limit.
//!
//! 1. **The run is made unable to reach it.** The whole test binary is run a second time inside a
//!    kernel denial: on macOS `sandbox-exec` with a profile that denies `network*` to remote and
//!    local IP addresses (`(deny network* (remote ip))(deny network* (local ip))`), which refuses
//!    the IP sockets outright and leaves a Unix socket alone, and on Linux
//!    `bwrap --unshare-net --dev-bind / /`, which puts the process in a network namespace with no
//!    interface and no route. Both are unprivileged, and the acceptance evidence records one run of
//!    each beside an ordinary run.
//! 2. **The suite proves the denial rather than trusting the wrapper.** Those runs set
//!    `KR_REQUIRE_NO_NETWORK=1`. Every case that claims an offline result then opens two outbound
//!    TCP connections to literal addresses and sends one datagram, before it does anything else,
//!    and requires all three to fail. A wrapper that was not denying anything fails the suite here
//!    instead of letting it pass quietly; with the variable unset the suite makes no offline claim
//!    at all. The negative control for this is a run with the network available and the variable
//!    set, which fails.
//! 3. **The path under test has no way to reach it.** The catalogue's seed reads the bundle's bytes
//!    through an in-memory transport and installs from them: the catalogue is built with no
//!    network transport at all here, so there is no address, no client and no socket on it.
//!
//! The limits, stated rather than glossed. The wrappers cut off the external IP network; neither
//! forbids every socket operation, and `--dev-bind / /` leaves Unix sockets on the filesystem
//! reachable. The probes are IPv4 and cover two destinations. A denial that the code under test
//! caught and ignored would not show up here; a filter that killed the process on a socket call
//! would catch that, and is not what these wrappers do. What is established is that the bundled
//! generation seeds, and answers for what it does not carry, with the external network
//! kernel-denied to the process doing it.

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_plugin_catalogue::{Catalogue, PackageCheck, PackageLimits, SeedBundle, SeedTrust};
use kr_plugin_sdk::bundle::{BundleLock, LOCK_FILE};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Uuid;

/// The variable that turns "this run claims to be offline" into something the suite checks.
const REQUIRE_NO_NETWORK: &str = "KR_REQUIRE_NO_NETWORK";

/// Proves that this process cannot reach the network, when the run says it should not be able to.
///
/// Two families, because the two wrappers refuse at different points: macOS refuses to create the
/// socket, and a network namespace creates one and has nowhere to send it. Either way the attempt
/// has to fail, and a reachable address here is a failed run rather than a passed one.
fn establish_that_nothing_reaches_the_network() {
    let Ok(required) = std::env::var(REQUIRE_NO_NETWORK) else {
        eprintln!(
            "{REQUIRE_NO_NETWORK} is not set: this run exercises the offline path and does not \
             claim the network was unreachable"
        );
        return;
    };
    assert_eq!(
        required, "1",
        "{REQUIRE_NO_NETWORK} is set to {required:?}; it is set to 1 or left unset"
    );

    for address in ["1.1.1.1:443", "8.8.8.8:53"] {
        let parsed: SocketAddr = address
            .parse()
            .expect("a literal address needs no resolver");
        let outcome = TcpStream::connect_timeout(&parsed, Duration::from_secs(2));
        assert!(
            outcome.is_err(),
            "{REQUIRE_NO_NETWORK}=1 and {address} answered, so this run was not offline"
        );
    }

    let sent = UdpSocket::bind("0.0.0.0:0").and_then(|socket| {
        socket.connect("8.8.8.8:53")?;
        socket.send(b"kalareach")
    });
    assert!(
        sent.is_err(),
        "{REQUIRE_NO_NETWORK}=1 and a datagram left this process, so this run was not offline"
    );
}

/// The repository this test binary was built from.
fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The committed lock.
fn lock_text() -> String {
    std::fs::read_to_string(repository().join(LOCK_FILE)).expect("the committed lock reads")
}

/// Every file under a directory, by its path relative to it.
fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .expect("a directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.insert(
                    path.strip_prefix(root)
                        .expect("inside the tree")
                        .to_string_lossy()
                        .replace('\\', "/"),
                    std::fs::read(&path).expect("a file"),
                );
            }
        }
    }
    found
}

/// The committed bundle's files, as the host compiles them in.
fn committed_files() -> BTreeMap<String, Vec<u8>> {
    read_tree(&repository().join("bundled-plugins"))
}

/// A bundle of `files` under the committed lock, trusting the development lineage as this build
/// does.
fn bundle_of(
    lock: &str,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<SeedBundle, kr_plugin_catalogue::CatalogueError> {
    SeedBundle::from_files(lock.as_bytes(), files, SeedTrust::compiled())
}

/// A catalogue on the internal disk with no network transport at all.
fn offline_catalogue(home: &Path) -> Catalogue {
    let mut catalogue = Catalogue::open(
        &home.join("catalogue"),
        std::sync::Arc::new(
            kr_plugin_catalogue::transport::RepositoryTransport::local_only(
                "this host has no network",
            ),
        ),
    )
    .expect("a catalogue");
    catalogue.set_fetches_network(false);
    catalogue
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::NIL)
}

/// Flips one byte of a file of the bundle.
fn flip_one_byte(files: &mut BTreeMap<String, Vec<u8>>, path: &str) {
    files.get_mut(path).expect("a bundled file")[0] ^= 1;
}

#[tokio::test]
async fn the_bundled_generation_seeds_a_fresh_installation_with_nothing_reachable() {
    establish_that_nothing_reaches_the_network();

    let home = tempfile::tempdir().expect("a directory");
    let mut catalogue = offline_catalogue(home.path());
    let bundle = SeedBundle::embedded().expect("the committed bundle is whole");
    assert!(
        catalogue.repositories().expect("records").is_empty(),
        "at the base nothing is enrolled and nothing is installed"
    );

    let outcome = catalogue
        .seed(
            &bundle,
            environment(),
            kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
        )
        .await;

    if !cfg!(debug_assertions) {
        // A release trusts no development root: the bundle is refused and nothing is written.
        assert!(outcome.installed.is_empty(), "{}", outcome.report());
        assert!(catalogue.repositories().expect("records").is_empty());
        return;
    }
    assert!(outcome.failure.is_none(), "{}", outcome.report());
    assert_eq!(
        outcome.installed.len(),
        bundle.packages().len(),
        "{}",
        outcome.report()
    );
    let id = kr_plugin_catalogue::RepositoryId::new("official").expect("an identifier");
    let store = catalogue.store(&id).expect("a store");
    for package in bundle.packages() {
        let installation = catalogue
            .installation(environment(), &package.plugin_id)
            .expect("records")
            .expect("the package is installed");
        assert!(installation.enabled);
        assert!(
            installation.grant.capabilities().is_empty(),
            "nothing is granted by the seed"
        );
        assert_eq!(installation.package_digest, package.manifest.digest);
        // Usable rather than merely present: the package is whole where it is installed, and its
        // manifest names the executable it recognises.
        let PackageCheck::Complete(ready) = store
            .check_package(installation.package_digest, PackageLimits::format())
            .expect("a readable store")
        else {
            panic!("{} is not a whole package", package.plugin_id);
        };
        assert!(
            !ready.manifest().match_rules.is_empty(),
            "{} recognises the application it declares",
            package.plugin_id
        );
    }
    // The declarative package presents through the document it carries.
    let example = bundle
        .packages()
        .iter()
        .find(|package| package.plugin_id.as_str() == "kalareach/example-declarative")
        .expect("the example package is bundled");
    let presentation = store
        .package_dir(example.manifest.digest)
        .join("presentation.json");
    let document: kr_plugin_sdk::presentation::PresentationManifest =
        serde_json::from_slice(&std::fs::read(presentation).expect("the document"))
            .expect("the presentation parses");
    assert!(!document.nodes.is_empty());
}

#[test]
fn every_bundled_file_is_the_file_the_lock_names() {
    establish_that_nothing_reaches_the_network();

    let bundle = bundle_of(&lock_text(), committed_files()).expect("the committed bundle is whole");
    let mut total = 0usize;
    for package in bundle.packages() {
        let mut sum = 0u64;
        for file in package.files() {
            let bytes = bundle
                .file(&format!("{}/{}", package.directory, file.path))
                .expect("a bundled file");
            assert_eq!(
                kr_plugin_sdk::digest::PayloadDigest::of(bytes),
                file.digest,
                "{} is the file the lock names",
                file.path
            );
            sum += bytes.len() as u64;
            total += 1;
        }
        assert_eq!(sum, package.total_size_bytes.get(), "{}", package.plugin_id);
    }
    assert!(total > 0);
}

/// A byte changed after the lock was written is refused, in each kind of file a bundle holds, and
/// the bundle that refuses it seeds nothing: the packages stay uninstalled.
#[tokio::test]
async fn a_byte_edited_after_the_lock_is_refused_and_the_package_stays_unactivated() {
    establish_that_nothing_reaches_the_network();

    let lock = lock_text();
    let files = committed_files();
    bundle_of(&lock, files.clone()).expect("the control: the bundle as it was locked");
    let kinds = [
        ("a metadata file", "metadata/timestamp.json"),
        ("the index", "targets/index.json"),
        (
            "a manifest",
            "targets/packages/kalareach/example-declarative/0.1.0/plugin.json",
        ),
        (
            "a payload",
            "targets/packages/kalareach/example-declarative/0.1.0/README.md",
        ),
    ];
    for (what, path) in kinds {
        let mut edited = files.clone();
        flip_one_byte(&mut edited, path);
        let error = bundle_of(&lock, edited).expect_err(what);
        assert!(
            error
                .to_string()
                .contains("is not what the bundled lock names"),
            "{what}: {error}"
        );
    }
}

/// The digest is checked before anything is read as a document: a manifest replaced by the same
/// number of bytes that are not JSON is refused for its digest, not for its syntax.
#[test]
fn the_digest_is_checked_before_anything_is_read_as_a_document() {
    establish_that_nothing_reaches_the_network();

    let path = "targets/packages/kalareach/example-declarative/0.1.0/plugin.json";
    let mut files = committed_files();
    let length = files[path].len();
    files.insert(path.to_owned(), vec![b'{'; length]);

    let error = bundle_of(&lock_text(), files).expect_err("the manifest was changed");

    assert!(
        error
            .to_string()
            .contains("is not what the bundled lock names"),
        "the refusal is about the digest and not about the syntax: {error}"
    );
}

/// A file the lock does not name, a root missing from the chain and a lock that disagrees with its
/// manifest are each refused.
#[test]
fn a_bundle_that_does_not_match_its_lock_is_refused() {
    establish_that_nothing_reaches_the_network();

    let lock = lock_text();
    let mut extra = committed_files();
    extra.insert("targets/extra.json".to_owned(), b"{}".to_vec());
    assert!(
        bundle_of(&lock, extra)
            .expect_err("an undeclared file")
            .to_string()
            .contains("which its lock does not name")
    );

    let mut gone = committed_files();
    gone.remove("targets/packages/kalareach/example-declarative/0.1.0/README.md");
    assert!(
        bundle_of(&lock, gone)
            .expect_err("a payload that is gone")
            .to_string()
            .contains("does not carry")
    );

    let disagreeing = lock.replace("\"0.1.0\"", "\"0.2.0\"");
    let error = bundle_of(&disagreeing, committed_files()).expect_err("a lock that disagrees");
    assert!(error.to_string().contains("0.1.0"), "{error}");
}

#[test]
fn a_lock_that_names_a_path_outside_the_package_does_not_read() {
    let text = lock_text();
    for unsafe_path in [
        "../escape.md",
        "/etc/hosts",
        "fixtures/../../escape.md",
        "a\\b.md",
    ] {
        let escaped = unsafe_path.replace('\\', "\\\\");
        let altered = text.replacen("\"README.md\"", &format!("\"{escaped}\""), 1);
        assert!(
            BundleLock::from_slice(altered.as_bytes(), "lock").is_err(),
            "{unsafe_path} is not a path a package may name"
        );
    }
}

/// The synchronisation script's offline half, run over the committed bundle and over copies of it
/// that have been changed. This is the check continuous integration runs, and the rejections
/// section 11 asks for at the point where a bundle is made rather than where it is read.
#[cfg(unix)]
#[test]
fn the_script_verifies_the_committed_bundle_and_refuses_a_changed_one() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 is not on this machine, and the script needs it");
        return;
    }

    let repository = repository();
    let script = repository.join("scripts/sync-bundled-plugins.sh");
    let copy = || {
        let directory = tempfile::tempdir().expect("a directory");
        let bundle_root = directory.path().join("bundled-plugins");
        for (path, bytes) in committed_files() {
            let target = bundle_root.join(&path);
            std::fs::create_dir_all(target.parent().expect("a parent")).expect("a directory");
            std::fs::write(&target, bytes).expect("a file");
        }
        let lock = directory.path().join(LOCK_FILE);
        std::fs::copy(repository.join(LOCK_FILE), &lock).expect("the lock copies");
        (directory, bundle_root, lock)
    };
    let verify = |bundle_root: &Path, lock: &Path, extra: &[&str]| -> std::process::Output {
        Command::new("bash")
            .arg(&script)
            .arg("--verify")
            .args(extra)
            .arg("--bundle-root")
            .arg(bundle_root)
            .arg("--lock")
            .arg(lock)
            .current_dir(&repository)
            .output()
            .expect("the script runs")
    };

    let committed = verify(
        &repository.join("bundled-plugins"),
        &repository.join(LOCK_FILE),
        &[],
    );
    assert!(
        committed.status.success(),
        "the committed bundle matches the committed lock: {}",
        String::from_utf8_lossy(&committed.stderr)
    );
    // A release trusts no root yet, so the release reading refuses the committed bundle.
    let release = verify(
        &repository.join("bundled-plugins"),
        &repository.join(LOCK_FILE),
        &["--release"],
    );
    assert!(
        !release.status.success()
            && String::from_utf8_lossy(&release.stderr).contains("a release trusts no root yet"),
        "{}",
        String::from_utf8_lossy(&release.stderr)
    );

    // One byte, an undeclared file, a link in place of a payload, a missing payload, a missing
    // root, a root.json that is not the highest root: each is a thing a bundle has to refuse, and
    // each has to be refused by the check that runs where no repository is reachable.
    /// One way a bundle can drift from the lock that names it.
    type Drift = (&'static str, Box<dyn Fn(&Path)>);
    let example = "targets/packages/kalareach/example-declarative/0.1.0";
    let cases: Vec<Drift> = vec![
        (
            "a changed byte",
            Box::new(move |root: &Path| {
                let path = root.join(example).join("README.md");
                let mut bytes = std::fs::read(&path).expect("a payload");
                bytes[0] ^= 1;
                std::fs::write(path, bytes).expect("a payload");
            }),
        ),
        (
            "an undeclared file",
            Box::new(move |root: &Path| {
                std::fs::write(root.join(example).join("extra.json"), b"{}").expect("a file");
            }),
        ),
        (
            "a link in place of a payload",
            Box::new(move |root: &Path| {
                let payload = root.join(example).join("presentation.json");
                std::fs::remove_file(&payload).expect("a removable payload");
                symlink("/etc/hosts", &payload).expect("a link");
            }),
        ),
        (
            "a payload that is gone",
            Box::new(move |root: &Path| {
                std::fs::remove_file(root.join(example).join("fixtures/visibility.json"))
                    .expect("a removable payload");
            }),
        ),
        (
            "an undeclared directory",
            Box::new(move |root: &Path| {
                std::fs::create_dir(root.join(example).join("spare")).expect("a directory");
            }),
        ),
        (
            "a numbered root that is gone",
            Box::new(|root: &Path| {
                std::fs::remove_file(root.join("metadata/1.root.json")).expect("a root");
            }),
        ),
        (
            "a root.json that is not the highest root",
            Box::new(|root: &Path| {
                std::fs::write(root.join("metadata/root.json"), b"{}").expect("a root");
            }),
        ),
    ];

    for (what, change) in cases {
        let (_directory, bundle_root, lock_path) = copy();
        change(&bundle_root);
        let outcome = verify(&bundle_root, &lock_path, &[]);
        assert!(
            !outcome.status.success(),
            "{what} is drift and the check has to say so"
        );
    }

    // A lock that names another generation than the index carries is refused.
    let (_directory, bundle_root, lock_path) = copy();
    let mut lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).expect("a lock"))
            .expect("a readable lock");
    lock["source"]["generation"] = serde_json::json!("1");
    std::fs::write(&lock_path, lock.to_string()).expect("a lock");
    let outcome = verify(&bundle_root, &lock_path, &[]);
    assert!(
        !outcome.status.success()
            && String::from_utf8_lossy(&outcome.stderr).contains("the lock names generation 1"),
        "{}",
        String::from_utf8_lossy(&outcome.stderr)
    );

    // A file that is a private key, locked consistently with what it now holds, is refused by the
    // release scan's own checks, whatever the file is called.
    let (_directory, bundle_root, lock_path) = copy();
    let path = bundle_root.join(example).join("README.md");
    let secret = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        "A".repeat(64)
    );
    std::fs::write(&path, &secret).expect("a payload");
    let mut lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).expect("a lock"))
            .expect("a readable lock");
    let digest = kr_plugin_sdk::digest::PayloadDigest::of(secret.as_bytes()).to_string();
    let package = lock["packages"]
        .as_array_mut()
        .expect("packages")
        .iter_mut()
        .find(|package| package["plugin_id"] == "kalareach/example-declarative")
        .expect("the example package");
    let old_total: u64 = package["total_size_bytes"]
        .as_str()
        .expect("a total")
        .parse()
        .expect("a number");
    let readme = package["payloads"]
        .as_array_mut()
        .expect("payloads")
        .iter_mut()
        .find(|payload| payload["path"] == "README.md")
        .expect("the README");
    let old_size: u64 = readme["size_bytes"]
        .as_str()
        .expect("a size")
        .parse()
        .expect("a number");
    readme["digest"] = serde_json::json!(digest);
    readme["size_bytes"] = serde_json::json!(secret.len().to_string());
    package["total_size_bytes"] =
        serde_json::json!((old_total - old_size + secret.len() as u64).to_string());
    std::fs::write(&lock_path, lock.to_string()).expect("a lock");
    let outcome = verify(&bundle_root, &lock_path, &[]);
    assert!(
        !outcome.status.success()
            && String::from_utf8_lossy(&outcome.stderr).contains("holds a PEM private key"),
        "{}",
        String::from_utf8_lossy(&outcome.stderr)
    );
}

/// The cleanup the script runs when it is interrupted, taken from the script's own text: from the
/// function that names the lock's owner, through the traps, to the line that takes the lock.
fn cleanup_block() -> String {
    let text = std::fs::read_to_string(repository().join("scripts/sync-bundled-plugins.sh"))
        .expect("the script reads");
    let start = text
        .find("owner_of_publish_lock() {")
        .expect("the script names the lock's owner");
    let end = text
        .find("mkdir \"$publish_lock\"")
        .expect("the script takes the lock after its traps");
    assert!(start < end && text[start..end].contains("trap "));
    text[start..end].to_owned()
}

/// What the cleanup leaves on disk when a signal ends a run that has published its bundle and not
/// yet its lock, and when it ends one that has published nothing. A signal runs the cleanup once:
/// the pending lock is the only copy of the lock that describes the new bundle, so a second pass
/// that took the run for an unpublished one would delete it.
#[test]
fn an_interrupted_sync_keeps_what_it_published_and_puts_back_what_it_did_not() {
    use std::process::Command;

    if Command::new("bash").arg("--version").output().is_err()
        || Command::new("python3").arg("--version").output().is_err()
    {
        eprintln!("skipping: bash and python3 are needed to run the script's cleanup");
        return;
    }
    let block = cleanup_block();
    let run = |published: bool, signal: &str| {
        let directory = tempfile::tempdir().expect("a directory");
        let root = directory.path();
        let harness = format!(
            r#"set -euo pipefail
root="$1"
work="$root/work"; mkdir -p "$work"
bundle_root="$root/bundled-plugins"
lock_file="$root/bundled-plugins.lock"
publish_lock="$root/.sync.lock"; held_lock=false
stage_root="$root/stage"; staged_bundle="$stage_root/bundle"
pending_lock="$root/.bundled-plugins.lock.pending"
retiring="$root/.bundled-plugins.retiring"
rename_path() {{ python3 -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' "$1" "$2"; }}
{block}
mkdir -p "$stage_root"
echo previous > "$lock_file"
if [ "$2" = published ]; then
  mkdir -p "$retiring" "$bundle_root"; echo previous > "$retiring/file"; echo new > "$bundle_root/file"
  echo new > "$pending_lock"
else
  mkdir -p "$staged_bundle" "$retiring"; echo previous > "$retiring/file"; echo new > "$pending_lock"
fi
kill -{signal} $$
sleep 5
"#
        );
        let output = Command::new("bash")
            .arg("-c")
            .arg(&harness)
            .arg("harness")
            .arg(root)
            .arg(if published {
                "published"
            } else {
                "unpublished"
            })
            .output()
            .expect("bash runs");
        (
            directory,
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.code(),
        )
    };

    let (directory, stderr, code) = run(true, "TERM");
    let root = directory.path();
    assert_eq!(code, Some(143), "{stderr}");
    assert!(
        root.join(".bundled-plugins.lock.pending").is_file(),
        "the pending lock is the only copy of the lock for the new bundle: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("bundled-plugins/file")).expect("the new bundle"),
        "new\n",
        "{stderr}"
    );
    assert!(
        root.join(".bundled-plugins.retiring/file").is_file(),
        "the previous bundle is kept: {stderr}"
    );
    assert!(!root.join("stage").exists(), "{stderr}");
    assert!(stderr.contains("the new lock is at"), "{stderr}");

    let (directory, stderr, code) = run(false, "INT");
    let root = directory.path();
    assert_eq!(code, Some(130), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(root.join("bundled-plugins/file")).expect("the old bundle"),
        "previous\n",
        "the previous bundle is put back: {stderr}"
    );
    assert!(
        !root.join(".bundled-plugins.lock.pending").exists(),
        "an unpublished run drops its pending lock: {stderr}"
    );
    assert!(!root.join("stage").exists(), "{stderr}");
}
