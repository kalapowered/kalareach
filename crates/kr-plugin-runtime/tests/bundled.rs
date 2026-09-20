//! First use of the bundled package, with nothing reachable.
//!
//! A fresh installation has no repository. Section 11 still requires it to activate what it was
//! shipped with: bundled, installed, pinned and live-bound payloads remain available offline, a
//! package activates atomically once all its payloads verify, and a payload that is not there
//! answers `PACKAGE_UNAVAILABLE_OFFLINE` rather than a capability nobody could perform.
//!
//! # How this suite establishes that nothing reached the network
//!
//! Not by observing that it did not need to. Two things together:
//!
//! 1. **The run is made unable to.** The whole test binary is run a second time inside a kernel
//!    denial of the network: on macOS `sandbox-exec -p '(version 1)(allow default)(deny
//!    network*)'`, which refuses the socket outright, and on Linux `bwrap --unshare-net --dev-bind
//!    / /`, which puts it in a network namespace with no interface and no route. Both are
//!    unprivileged, and the acceptance evidence records one run of each beside the ordinary run.
//! 2. **The suite proves the denial rather than trusting the wrapper.** Those runs set
//!    `KR_REQUIRE_NO_NETWORK=1`. Every case below that claims an offline result then opens one
//!    outbound connection to a literal address before it does anything else and requires the
//!    attempt to fail. A run under a wrapper that was not actually denying anything fails here
//!    rather than passing quietly, and a run with no wrapper makes no offline claim at all.
//!
//! What the activation itself can reach is narrower than either: `kr_plugin_sdk::bundle` opens
//! every file relative to one `cap_std::fs::Dir` handle the caller supplies, and digests the bytes
//! with `sha2`. There is no address, no client and no socket anywhere on that path.

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cap_std::fs::Dir;
use kr_plugin_sdk::bundle::{BundleLock, BundleSource, BundledPackage, LOCK_FILE};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, RepositoryGeneration};
use kr_plugin_sdk::paths::PackagePath;
use kr_plugin_sdk::plugin::PayloadRole;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::error::ErrorCode;

/// The variable that turns "this run claims to be offline" into something the suite checks.
const REQUIRE_NO_NETWORK: &str = "KR_REQUIRE_NO_NETWORK";

/// The bundled package this repository ships.
const BUNDLED_PLUGIN: &str = "kalareach/example-declarative";

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
fn lock() -> BundleLock {
    BundleLock::read(&repository().join(LOCK_FILE)).expect("the committed lock reads")
}

/// A handle on the committed bundle directory, opened once, exactly as a host opens its packages
/// directory. Every payload below is opened relative to this and to nothing else.
fn open_bundle(root: &Path) -> Dir {
    Dir::open_ambient_dir(root, cap_std::ambient_authority()).expect("the bundle directory opens")
}

fn bundled_plugin() -> PluginId {
    PluginId::new(BUNDLED_PLUGIN).expect("a bounded identifier")
}

fn path(value: &str) -> PackagePath {
    PackagePath::new(value).expect("a package path")
}

/// Copies the committed bundle and lock into a directory of their own, so a case can change one
/// byte without touching the repository.
fn copy_of_the_bundle() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let bundle_root = directory.path().join("bundled-plugins");
    let source = repository().join("bundled-plugins");
    copy_tree(&source, &bundle_root);
    let lock_path = directory.path().join(LOCK_FILE);
    std::fs::copy(repository().join(LOCK_FILE), &lock_path).expect("the lock copies");
    (directory, bundle_root, lock_path)
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("a readable directory") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a file copies");
        }
    }
}

/// Replaces a file with the same number of different bytes.
fn flip_one_byte(path: &Path) {
    let mut bytes = std::fs::read(path).expect("a readable file");
    bytes[0] ^= 1;
    std::fs::write(path, bytes).expect("a writable file");
}

fn package<'a>(lock: &'a BundleLock, plugin: &PluginId) -> &'a BundledPackage {
    lock.package(plugin).expect("the lock carries the package")
}

fn source(lock: &BundleLock) -> &BundleSource {
    &lock.source
}

#[test]
fn the_bundled_package_activates_from_the_lock_with_nothing_reachable() {
    establish_that_nothing_reaches_the_network();

    let lock = lock();
    let bundle = open_bundle(&repository().join("bundled-plugins"));
    let activated = lock
        .activate(&bundle, &bundled_plugin())
        .expect("the bundled package activates");

    // The identity a binding would pin: the plugin, the version, the bytes and the generation the
    // copy was made from.
    let identity = activated.identity();
    assert_eq!(identity.plugin_id, bundled_plugin());
    assert_eq!(
        identity.version,
        PackageVersion::parse("0.1.0").expect("a version")
    );
    assert_eq!(
        identity.package_hash,
        package(&lock, &bundled_plugin()).manifest.digest
    );
    assert_eq!(identity.repository_generation, source(&lock).generation);
    assert_eq!(source(&lock).generation, RepositoryGeneration::new(1));

    // The manifest is the package the lock named, and it is usable rather than merely present: it
    // recognises the application it was written for, which is what a host with no repository needs
    // out of a bundled package.
    let manifest = activated.manifest();
    assert_eq!(manifest.plugin_id(), bundled_plugin());
    assert!(
        manifest
            .match_rules
            .iter()
            .any(|rule| rule.executable.matches_path("/usr/local/bin/example-agent")),
        "the bundled package recognises the application it declares"
    );

    // And the declarative half a package with no component presents through.
    let presentation = activated.presentation().expect("the presentation parses");
    assert!(
        !presentation.nodes.is_empty(),
        "the bundled presentation carries a document"
    );
    assert!(
        !manifest.has_component(),
        "this package carries no component"
    );
}

#[test]
fn every_bundled_payload_is_the_payload_the_lock_names() {
    establish_that_nothing_reaches_the_network();

    let lock = lock();
    let bundle = open_bundle(&repository().join("bundled-plugins"));
    let activated = lock
        .activate(&bundle, &bundled_plugin())
        .expect("the bundled package activates");
    let package = package(&lock, &bundled_plugin());

    let mut total = 0u64;
    for file in std::iter::once((&package.manifest.path, package.manifest.digest))
        .chain(package.payloads.iter().map(|p| (&p.path, p.digest)))
    {
        let bytes = activated.file(file.0).expect("a verified payload");
        assert_eq!(
            PayloadDigest::of(bytes),
            file.1,
            "{} is the payload the lock names",
            file.0
        );
        total += bytes.len() as u64;
    }
    assert_eq!(total, package.total_size_bytes.get());
    assert_eq!(activated.paths().count(), package.payloads.len() + 1);

    // The roles the package declares, so the bundle is a package rather than a bag of files.
    assert!(package.payload(PayloadRole::Presentation).is_some());
    assert!(package.payload(PayloadRole::Component).is_none());
}

#[test]
fn a_payload_the_lock_does_not_name_is_unavailable_offline() {
    establish_that_nothing_reaches_the_network();

    let lock = lock();
    let bundle = open_bundle(&repository().join("bundled-plugins"));
    let activated = lock
        .activate(&bundle, &bundled_plugin())
        .expect("the bundled package activates");

    // A file this package does not carry. There is no repository to fetch it from, so the answer
    // is that it is unavailable rather than a capability that would fail the moment it was used.
    let error = activated
        .file(&path("connector.json"))
        .expect_err("the package carries no connector table");
    assert_eq!(error.code(), ErrorCode::PackageUnavailableOffline);

    // And a package the bundle does not carry at all.
    let other = PluginId::new("kalareach/codex").expect("a bounded identifier");
    let error = lock
        .activate(&bundle, &other)
        .expect_err("the bundle carries one package");
    assert_eq!(error.code(), ErrorCode::PackageUnavailableOffline);

    // Absence is the only thing that answers that way. A payload that is there and is not what the
    // lock names is a trust answer, not a fetch answer, and the two must not be confused: a host
    // that reported tampering as "try again when you are online" would retry for ever.
    let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
    flip_one_byte(&bundle_root.join("fixture/README.md"));
    let copied = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = copied
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("a changed payload does not activate");
    assert_eq!(error.code(), ErrorCode::RepositoryUntrusted);
}

#[test]
fn a_package_whose_payloads_do_not_all_verify_does_not_activate_at_all() {
    establish_that_nothing_reaches_the_network();

    // One payload of four, changed without changing its length. Activation is independently atomic
    // after all its payloads verify, so this package does not become half usable.
    for name in [
        "plugin.json",
        "presentation.json",
        "README.md",
        "fixtures/visibility.json",
    ] {
        let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
        let target = bundle_root.join("fixture").join(name);
        let before = std::fs::read(&target).expect("a readable payload");
        flip_one_byte(&target);
        assert_eq!(
            std::fs::metadata(&target).expect("a payload").len(),
            before.len() as u64,
            "the case changes the bytes and not the length"
        );

        let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
        let error = lock
            .activate(&open_bundle(&bundle_root), &bundled_plugin())
            .expect_err("{name} was changed, so the package does not activate");
        assert_eq!(
            error.code(),
            ErrorCode::RepositoryUntrusted,
            "{name}: {error}"
        );
        assert!(
            error.to_string().contains(name),
            "the refusal names the payload it was about: {error}"
        );
    }

    // A truncated payload is refused on its length before a byte of it is read.
    let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
    std::fs::write(bundle_root.join("fixture/README.md"), b"short").expect("a writable payload");
    let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("a truncated payload does not activate");
    assert!(
        error.to_string().contains("5 bytes"),
        "the refusal says what it found: {error}"
    );

    // A payload that is simply gone is the offline answer.
    let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
    std::fs::remove_file(bundle_root.join("fixture/presentation.json")).expect("a removable file");
    let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("a payload that is not there does not activate");
    assert_eq!(error.code(), ErrorCode::PackageUnavailableOffline);
}

#[test]
fn the_digest_is_checked_before_anything_is_read_as_a_document() {
    establish_that_nothing_reaches_the_network();

    // The manifest, replaced by the same number of bytes that are not JSON at all. A host that
    // parsed first and checked afterwards would report a syntax error here, which would mean it had
    // already fed unverified bytes to a parser. The refusal has to be about the digest.
    let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
    let manifest = bundle_root.join("fixture/plugin.json");
    let length = std::fs::metadata(&manifest).expect("a manifest").len();
    std::fs::write(
        &manifest,
        vec![b'{'; usize::try_from(length).expect("a length")],
    )
    .expect("a writable manifest");

    let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("the manifest was changed, so the package does not activate");
    assert!(
        error
            .to_string()
            .contains("is not the payload the lock names"),
        "the refusal is about the digest and not about the syntax: {error}"
    );
    assert_eq!(error.code(), ErrorCode::RepositoryUntrusted);
}

#[cfg(unix)]
#[test]
fn a_payload_that_leaves_the_package_directory_is_refused() {
    use std::os::unix::fs::symlink;

    establish_that_nothing_reaches_the_network();

    // A payload replaced by a link out of the bundle. Every file is opened relative to the bundle
    // directory's own handle with links refused, so the open decides this rather than a comparison
    // made before it, and there is no window between the two.
    let (directory, bundle_root, lock_path) = copy_of_the_bundle();
    let outside = directory.path().join("outside.md");
    std::fs::write(&outside, b"somewhere else").expect("a writable file");
    let payload = bundle_root.join("fixture/README.md");
    std::fs::remove_file(&payload).expect("a removable payload");
    symlink(&outside, &payload).expect("a link");

    let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("a link is not a payload");
    assert_eq!(error.code(), ErrorCode::RepositoryUntrusted);

    // And the package directory itself, replaced by a link to somewhere that holds the same names.
    let (directory, bundle_root, lock_path) = copy_of_the_bundle();
    let elsewhere = directory.path().join("elsewhere");
    std::fs::rename(bundle_root.join("fixture"), &elsewhere).expect("a movable package");
    symlink(&elsewhere, bundle_root.join("fixture")).expect("a link");

    let lock = BundleLock::read(&lock_path).expect("the copied lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("a link is not a package directory");
    assert_eq!(error.code(), ErrorCode::RepositoryUntrusted);
}

#[test]
fn a_lock_that_names_a_path_outside_the_package_does_not_read() {
    let text = std::fs::read_to_string(repository().join(LOCK_FILE)).expect("the lock reads");
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

/// The lock and the manifest are two documents about one package, and they have to agree.
#[test]
fn a_lock_that_disagrees_with_the_manifest_does_not_activate() {
    establish_that_nothing_reaches_the_network();

    let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
    let text = std::fs::read_to_string(&lock_path).expect("the lock reads");
    std::fs::write(&lock_path, text.replace("\"0.1.0\"", "\"0.2.0\"")).expect("a writable lock");

    let lock = BundleLock::read(&lock_path).expect("the altered lock reads");
    let error = lock
        .activate(&open_bundle(&bundle_root), &bundled_plugin())
        .expect_err("the lock says one version and the manifest another");
    assert!(
        error.to_string().contains("0.1.0"),
        "the refusal says what the manifest actually is: {error}"
    );
    assert_eq!(error.code(), ErrorCode::RepositoryUntrusted);
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

    let verify = |bundle_root: &Path, lock: &Path| -> std::process::Output {
        Command::new("bash")
            .arg(&script)
            .arg("--verify")
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
    );
    assert!(
        committed.status.success(),
        "the committed bundle matches the committed lock: {}",
        String::from_utf8_lossy(&committed.stderr)
    );

    // One byte, an undeclared file, a link in place of a payload and a missing payload. Each is a
    // thing section 11 requires a bundle to refuse, and each has to be refused by the check that
    // runs where no repository is reachable.
    /// One way a bundle can drift from the lock that names it.
    type Drift = (&'static str, Box<dyn Fn(&Path)>);

    let cases: Vec<Drift> = vec![
        (
            "a changed byte",
            Box::new(|root: &Path| flip_one_byte(&root.join("fixture/README.md"))),
        ),
        (
            "an undeclared file",
            Box::new(|root: &Path| {
                std::fs::write(root.join("fixture/extra.json"), b"{}").expect("a writable file");
            }),
        ),
        (
            "a link in place of a payload",
            Box::new(|root: &Path| {
                let payload = root.join("fixture/presentation.json");
                std::fs::remove_file(&payload).expect("a removable payload");
                symlink("/etc/hosts", &payload).expect("a link");
            }),
        ),
        (
            "a payload that is gone",
            Box::new(|root: &Path| {
                std::fs::remove_file(root.join("fixture/fixtures/visibility.json"))
                    .expect("a removable payload");
            }),
        ),
        (
            "an undeclared directory",
            Box::new(|root: &Path| {
                std::fs::create_dir(root.join("fixture/spare")).expect("a directory");
            }),
        ),
    ];

    for (what, change) in cases {
        let (_directory, bundle_root, lock_path) = copy_of_the_bundle();
        change(&bundle_root);
        let outcome = verify(&bundle_root, &lock_path);
        assert!(
            !outcome.status.success(),
            "{what} is drift and the check has to say so"
        );
    }
}
