//! KR-REQ-11.42: a package's native bridge recipe applied in an application's own directory, and
//! exactly what it applied taken out again.
//!
//! The recipe is the Claude Code package's, release 0.3.0, built here from the three registration
//! files this repository pins in `fixtures/bridges/claude-code/`, which carry the digests that
//! release names. Every test works in a directory of its own on the internal disk: an application
//! directory with somebody's settings in it, a search path holding a stand-in for the application's
//! executable and for the forwarder, and a package directory holding the recipe's files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_controller::catalogue::native_bridge::{
    ApplicationDirectory, BridgeHost, BridgeSurface, BridgeTarget, NativeBridges,
    QualifiedExecutable, Settled,
};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::matching::MatchRule;
use kr_plugin_sdk::plugin::NativeBridge;
use kr_protocol::ids::PluginId;
use kr_protocol::scalars::Digest256;

/// The digests release 0.3.0's recipe names for its three files.
const MANIFEST_DIGEST: &str = "1cb6238953bafc5e2872e8af3a430d94ca8452c11e51dc43946889f7268b126c";
const SERVERS_DIGEST: &str = "13e39e82aee3be2710c49a6f38f5558e20d18416a0a18e07b72f5dff9de1c4ea";
const HOOKS_DIGEST: &str = "bbf177109cbca2bdcbf995fcf06f9cc434df898c86c0272461de0c10e5baf727";

const MANIFEST_PATH: &str = "skills/kalareach-channels/.claude-plugin/plugin.json";
const SERVERS_PATH: &str = "skills/kalareach-channels/.mcp.json";
const HOOKS_PATH: &str = "skills/kalareach-channels/hooks/hooks.json";

/// Somebody's settings, in their own layout, with a number a rewrite would spell differently.
const SETTINGS: &str = "{\n  \"model\": \"opus\",\n  \"cleanupPeriodDays\": 1e3,\n  \"permissions\": {\"allow\": [\"Bash(ls:*)\"]},\n  \"enabledPlugins\": {\n    \"other@market\": false\n  }\n}\n";

/// The same settings with the key in them, as the installation leaves them.
const SETTINGS_WITH_KEY: &str = "{\n  \"model\": \"opus\",\n  \"cleanupPeriodDays\": 1e3,\n  \"permissions\": {\"allow\": [\"Bash(ls:*)\"]},\n  \"enabledPlugins\": {\n    \"other@market\": false,\n    \"kalareach-channels@skills-dir\": true\n  }\n}\n";

/// The stand-in for the application's executable. The version check hashes it and never runs it.
const EXECUTABLE: &[u8] = b"\x7fELF a stand-in for Claude Code, hashed and never run";

fn plugin() -> PluginId {
    PluginId::new("kalareach/claude-code").expect("a plugin identifier")
}

/// The bytes of one pinned registration file.
fn pinned(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/bridges/claude-code")
            .join(name),
    )
    .expect("a pinned registration file")
}

/// The recipe of release 0.3.0, with the hooks file's digest given.
fn recipe_with_hooks(hooks_digest: &str) -> NativeBridge {
    serde_json::from_value(serde_json::json!({
        "application": "Claude Code",
        "application_range": ">=2.1.234, <3.0.0",
        "install": [
            {"type": "install_file", "source": "bridge/plugin-manifest.json",
             "destination": MANIFEST_PATH, "digest": MANIFEST_DIGEST},
            {"type": "install_file", "source": "bridge/mcp-servers.json",
             "destination": SERVERS_PATH, "digest": SERVERS_DIGEST},
            {"type": "install_file", "source": "bridge/hooks.json",
             "destination": HOOKS_PATH, "digest": hooks_digest},
            {"type": "add_configuration_key", "file": "settings.json",
             "key": "enabledPlugins.kalareach-channels@skills-dir", "value": "true"}
        ],
        "remove": [
            {"type": "remove_configuration_key", "file": "settings.json",
             "key": "enabledPlugins.kalareach-channels@skills-dir"},
            {"type": "remove_file", "destination": HOOKS_PATH, "digest": hooks_digest},
            {"type": "remove_file", "destination": SERVERS_PATH, "digest": SERVERS_DIGEST},
            {"type": "remove_file", "destination": MANIFEST_PATH, "digest": MANIFEST_DIGEST}
        ],
        "grant_statement": "Installs three registration files under your own Claude Code directory, where they apply to every project and every later session, and adds one settings key that enables them. Claude Code then starts the KalaReach forwarder itself, so the forwarder runs under Claude Code's own permissions and outside the KalaReach plugin sandbox, outside Wasmtime."
    }))
    .expect("the recipe of release 0.3.0")
}

fn recipe() -> NativeBridge {
    recipe_with_hooks(HOOKS_DIGEST)
}

fn match_rules() -> Vec<MatchRule> {
    serde_json::from_value(serde_json::json!([
        {"id": "claude-code-npm",
         "executable": {"file_stem": "claude", "path_suffix": [], "version_range": null},
         "distribution": {"registry": "npm", "package": "@anthropic-ai/claude-code"},
         "confidence": "exact"},
        {"id": "claude-code-executable",
         "executable": {"file_stem": "claude", "path_suffix": [], "version_range": null},
         "distribution": null,
         "confidence": "inferred"}
    ]))
    .expect("the release's match rules")
}

fn hex_digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// One test's own directories.
struct Site {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Site {
    fn new() -> Self {
        Self::with_settings(Some(SETTINGS))
    }

    fn with_settings(settings: Option<&str>) -> Self {
        let temp = tempfile::tempdir().expect("a temporary directory");
        let root = temp.path().to_path_buf();
        let site = Self { _temp: temp, root };
        std::fs::create_dir_all(site.application()).expect("the application's directory");
        if let Some(settings) = settings {
            std::fs::write(site.application().join("settings.json"), settings).expect("settings");
        }
        // Somebody's own skill, beside where the bridge goes.
        std::fs::create_dir_all(site.application().join("skills/theirs")).expect("a skill");
        std::fs::write(site.application().join("skills/theirs/SKILL.md"), "theirs")
            .expect("a skill");
        std::fs::create_dir_all(site.root.join("bin")).expect("a search path");
        std::fs::write(site.executable(), EXECUTABLE).expect("an executable");
        std::fs::write(site.forwarder(), b"a stand-in for the forwarder").expect("a forwarder");
        for (name, source) in [
            ("plugin-manifest.json", "plugin-manifest.json"),
            ("mcp-servers.json", "mcp-servers.json"),
            ("hooks.json", "hooks.json"),
        ] {
            let path = site.package("a").join("bridge").join(name);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a package");
            std::fs::write(path, pinned(source)).expect("a package file");
        }
        site
    }

    fn application(&self) -> PathBuf {
        self.root.join("home/.claude")
    }

    fn executable(&self) -> PathBuf {
        self.root.join("bin/claude")
    }

    fn forwarder(&self) -> PathBuf {
        self.root.join("bin/kr-hook")
    }

    fn package(&self, release: &str) -> PathBuf {
        self.root.join("packages").join(release)
    }

    fn host(&self) -> BridgeHost {
        BridgeHost {
            journals: self.root.join("state/native-bridges"),
            applications: vec![ApplicationDirectory {
                application: "Claude Code".to_owned(),
                directory: self.application(),
            }],
            search_path: vec![self.root.join("bin")],
            forwarder: Some(self.forwarder()),
            signed_records: Vec::new(),
        }
    }

    fn bridges(&self) -> NativeBridges {
        NativeBridges::new(self.host())
    }

    /// Release 0.3.0's recipe, its package here, and a signed record naming the stand-in
    /// executable at `version`.
    fn target(&self, version: &str) -> BridgeTarget {
        BridgeTarget {
            plugin_id: plugin(),
            package_digest: PayloadDigest::of(b"release a"),
            package_dir: self.package("a"),
            recipe: recipe(),
            match_rules: match_rules(),
            qualified: vec![QualifiedExecutable {
                digest: hex_digest(EXECUTABLE),
                version: version.to_owned(),
            }],
        }
    }

    fn release(&self) -> BridgeTarget {
        self.target("2.1.278")
    }

    /// A second release whose hooks file differs, with its own package.
    fn next_release(&self) -> BridgeTarget {
        let hooks = String::from_utf8(pinned("hooks.json"))
            .expect("text")
            .replace("\"timeout\": 1", "\"timeout\": 2");
        for (name, bytes) in [
            ("plugin-manifest.json", pinned("plugin-manifest.json")),
            ("mcp-servers.json", pinned("mcp-servers.json")),
            ("hooks.json", hooks.clone().into_bytes()),
        ] {
            let path = self.package("b").join("bridge").join(name);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a package");
            std::fs::write(path, bytes).expect("a package file");
        }
        BridgeTarget {
            plugin_id: plugin(),
            package_digest: PayloadDigest::of(b"release b"),
            package_dir: self.package("b"),
            recipe: recipe_with_hooks(&PayloadDigest::of(hooks.as_bytes()).to_string()),
            match_rules: match_rules(),
            qualified: vec![QualifiedExecutable {
                digest: hex_digest(EXECUTABLE),
                version: "2.1.278".to_owned(),
            }],
        }
    }

    /// Everything under the application's directory.
    fn tree(&self) -> BTreeMap<String, Node> {
        snapshot(&self.application())
    }
}

/// One thing in a directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Directory,
    File(Vec<u8>),
    Link(PathBuf),
}

/// Every file, directory and link under `root`, by relative path, without following a link.
fn snapshot(root: &Path) -> BTreeMap<String, Node> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("an entry").path();
            let relative = path
                .strip_prefix(root)
                .expect("inside the tree")
                .to_string_lossy()
                .into_owned();
            let metadata = std::fs::symlink_metadata(&path).expect("metadata");
            if metadata.file_type().is_symlink() {
                found.insert(
                    relative,
                    Node::Link(std::fs::read_link(&path).expect("a link")),
                );
            } else if metadata.is_dir() {
                found.insert(relative, Node::Directory);
                pending.push(path);
            } else {
                found.insert(relative, Node::File(std::fs::read(&path).expect("a file")));
            }
        }
    }
    found
}

/// The tree an application directory holding [`SETTINGS`] has once the recipe is applied.
fn applied_tree(before: &BTreeMap<String, Node>) -> BTreeMap<String, Node> {
    let mut expected = before.clone();
    for directory in [
        "skills/kalareach-channels",
        "skills/kalareach-channels/.claude-plugin",
        "skills/kalareach-channels/hooks",
    ] {
        expected.insert(directory.to_owned(), Node::Directory);
    }
    expected.insert(
        MANIFEST_PATH.to_owned(),
        Node::File(pinned("plugin-manifest.json")),
    );
    expected.insert(
        SERVERS_PATH.to_owned(),
        Node::File(pinned("mcp-servers.json")),
    );
    expected.insert(HOOKS_PATH.to_owned(), Node::File(pinned("hooks.json")));
    expected.insert(
        "settings.json".to_owned(),
        Node::File(SETTINGS_WITH_KEY.as_bytes().to_vec()),
    );
    expected
}

fn refused(settled: &Settled) -> &str {
    match settled {
        Settled::Refused(reason) => reason,
        other => panic!("applied instead of refusing: {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Installing and removing
// ---------------------------------------------------------------------------------------------

/// KR-REQ-11.42: installing writes the recipe's three files and its one key and nothing else, and
/// every other setting keeps its bytes.
#[test]
fn kr_req_11_42_installing_writes_the_three_files_and_the_key_and_nothing_else() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert_eq!(settled, Settled::Applied);
    assert_eq!(
        site.tree(),
        applied_tree(&before),
        "exactly the recipe's changes"
    );
    let facts = bridges
        .facts(&plugin(), site.release().package_digest)
        .expect("reads")
        .expect("applied");
    assert_eq!(
        facts.application, "claude-code",
        "the name the registration invokes the forwarder for"
    );
    assert_eq!(
        facts.surfaces,
        [BridgeSurface::Hook, BridgeSurface::Channel]
            .into_iter()
            .collect()
    );
    assert_eq!(facts.forwarder, site.forwarder());
    // Negative control: the record answers for the release it applied, and no other.
    assert!(
        bridges
            .facts(&plugin(), PayloadDigest::of(b"another release"))
            .expect("reads")
            .is_none()
    );
}

/// KR-REQ-11.42: removal takes the key back out and deletes the three files, and the application's
/// directory is again byte for byte what it was.
#[test]
fn kr_req_11_42_removing_restores_the_tree() {
    for settings in [Some(SETTINGS), None, Some("{}")] {
        let site = Site::with_settings(settings);
        let before = site.tree();
        let bridges = site.bridges();
        assert_eq!(
            bridges
                .reconcile(&plugin(), Some(&site.release()))
                .expect("applies"),
            Settled::Applied
        );
        assert_ne!(
            site.tree(),
            before,
            "{settings:?}: the recipe changed something"
        );

        let settled = bridges.reconcile(&plugin(), None).expect("removes");

        assert_eq!(settled, Settled::Removed);
        assert_eq!(site.tree(), before, "{settings:?}: the tree is what it was");
        assert!(
            bridges.reports().expect("reads").is_empty(),
            "nothing is left to report"
        );
        assert!(
            bridges
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_none()
        );
    }
}

/// A second reconciliation of an applied release changes nothing, and a new host reads the same
/// record back.
#[test]
fn an_applied_release_is_read_back_and_left_as_it_is() {
    let site = Site::new();
    site.bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let after = site.tree();

    let restarted = site.bridges();
    assert_eq!(
        restarted
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles"),
        Settled::Unchanged
    );
    assert_eq!(site.tree(), after);
    assert!(
        restarted
            .facts(&plugin(), site.release().package_digest)
            .expect("reads")
            .is_some(),
        "the record answers after a restart"
    );
}

/// A release applied in one directory, and wanted again once this host keeps the application's
/// plugins in another, is taken out of the first and applied in the second.
#[test]
fn a_release_follows_the_application_directory_to_another_place() {
    let site = Site::new();
    let before = site.tree();
    site.bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let other = site.root.join("other/.claude");
    std::fs::create_dir_all(&other).expect("another directory");
    std::fs::write(other.join("settings.json"), SETTINGS).expect("settings");
    let other_before = snapshot(&other);
    let moved = NativeBridges::new(BridgeHost {
        applications: vec![ApplicationDirectory {
            application: "Claude Code".to_owned(),
            directory: other.clone(),
        }],
        ..site.host()
    });

    let settled = moved
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert_eq!(settled, Settled::Applied);
    assert_eq!(site.tree(), before, "taken out of the first directory");
    let mut expected = applied_tree(&other_before);
    expected.insert("skills".to_owned(), Node::Directory);
    assert_eq!(snapshot(&other), expected, "and applied in the second");
}

/// KR-REQ-11.42: a file somebody changed after it was installed is kept by removal and reported;
/// the rest goes.
#[test]
fn kr_req_11_42_a_file_somebody_changed_is_kept_and_reported() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let edited = site.application().join(HOOKS_PATH);
    std::fs::write(&edited, b"{\"hooks\": {}}").expect("somebody edits it");

    // Reported while it is installed.
    let reports = bridges.reports().expect("reads");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.contains(HOOKS_PATH) && note.contains("changed")),
        "{reports:?}"
    );

    bridges.reconcile(&plugin(), None).expect("removes");

    assert_eq!(std::fs::read(&edited).expect("kept"), b"{\"hooks\": {}}");
    let mut expected = before.clone();
    expected.insert("skills/kalareach-channels".to_owned(), Node::Directory);
    expected.insert(
        "skills/kalareach-channels/hooks".to_owned(),
        Node::Directory,
    );
    expected.insert(
        HOOKS_PATH.to_owned(),
        Node::File(b"{\"hooks\": {}}".to_vec()),
    );
    assert_eq!(
        site.tree(),
        expected,
        "only the changed file and what holds it stay"
    );
    let reports = bridges.reports().expect("reads");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.contains(HOOKS_PATH)),
        "{reports:?}"
    );
}

/// KR-REQ-11.42: a key somebody else set is never replaced, whatever its value, and nothing is
/// written.
#[test]
fn kr_req_11_42_a_key_somebody_else_set_is_never_replaced() {
    for value in ["true", "false"] {
        let settings =
            format!("{{\"enabledPlugins\": {{\"kalareach-channels@skills-dir\": {value}}}}}");
        let site = Site::with_settings(Some(&settings));
        let before = site.tree();
        let bridges = site.bridges();

        let settled = bridges
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles");

        assert!(refused(&settled).contains("already set"), "{settled:?}");
        assert_eq!(site.tree(), before, "{value}: nothing was written");
        assert!(
            bridges
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_none()
        );
    }
}

/// A key this host added and somebody then changed is kept by removal.
#[test]
fn a_key_somebody_changed_after_the_installation_is_kept() {
    let site = Site::new();
    let bridges = site.bridges();
    assert_eq!(
        bridges
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles"),
        Settled::Applied
    );
    let changed = SETTINGS_WITH_KEY.replace(
        "\"kalareach-channels@skills-dir\": true",
        "\"kalareach-channels@skills-dir\": false",
    );
    std::fs::write(site.application().join("settings.json"), &changed).expect("somebody edits it");

    bridges.reconcile(&plugin(), None).expect("removes");

    assert_eq!(
        std::fs::read_to_string(site.application().join("settings.json")).expect("kept"),
        changed
    );
    assert!(
        !site.application().join(HOOKS_PATH).exists(),
        "the files still go"
    );
}

/// KR-REQ-11.42: a file already at a destination that this host did not write stops the
/// installation before anything is written, even when it holds the same bytes.
#[test]
fn kr_req_11_42_a_file_this_host_did_not_write_is_refused() {
    let site = Site::new();
    let existing = site.application().join(SERVERS_PATH);
    std::fs::create_dir_all(existing.parent().expect("a parent")).expect("a directory");
    std::fs::write(&existing, pinned("mcp-servers.json")).expect("the same bytes");
    let before = site.tree();
    let bridges = site.bridges();

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("did not write"), "{settled:?}");
    assert_eq!(site.tree(), before, "nothing was written");
}

/// KR-REQ-11.42: an executable whose signed record places it outside the recipe's range refuses the
/// recipe before anything is written; one inside it does not.
#[test]
fn kr_req_11_42_a_version_outside_the_range_is_refused_before_anything_is_written() {
    for (version, applies) in [
        ("2.1.233", false),
        ("3.0.0", false),
        ("2.1.234", true),
        ("2.1.278", true),
    ] {
        let site = Site::new();
        let before = site.tree();
        let bridges = site.bridges();

        let settled = bridges
            .reconcile(&plugin(), Some(&site.target(version)))
            .expect("reconciles");

        if applies {
            assert_eq!(settled, Settled::Applied, "{version}");
        } else {
            let reason = refused(&settled);
            assert!(
                reason.contains(version) && reason.contains("outside"),
                "{reason}"
            );
            assert_eq!(site.tree(), before, "{version}: nothing was written");
        }
    }
}

/// A version is known only from a signed record naming the executable's digest. Without one, and
/// for a script, the recipe is refused and nothing is written.
#[test]
fn a_version_no_signed_record_establishes_is_refused() {
    let unsigned = |site: &Site| BridgeTarget {
        qualified: Vec::new(),
        ..site.release()
    };
    let another = |site: &Site| BridgeTarget {
        qualified: vec![QualifiedExecutable {
            digest: hex_digest(b"another executable"),
            version: "2.1.278".to_owned(),
        }],
        ..site.release()
    };
    type Target = dyn Fn(&Site) -> BridgeTarget;
    type Prepare = dyn Fn(&Site);
    let cases: [(&str, &Target, &Prepare); 4] = [
        ("no signed qualification record", &unsigned, &|_| {}),
        ("not an executable any signed", &another, &|_| {}),
        ("script", &|site: &Site| site.release(), &|site: &Site| {
            std::fs::write(site.executable(), b"#!/bin/sh\necho 2.1.278\n").expect("a script");
        }),
        (
            "search path",
            &|site: &Site| site.release(),
            &|site: &Site| {
                std::fs::remove_file(site.executable()).expect("no executable");
            },
        ),
    ];
    for (why, target, prepare) in cases {
        let site = Site::new();
        prepare(&site);
        let before = site.tree();

        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&target(&site)))
            .expect("reconciles");

        assert!(refused(&settled).contains(why), "{why}: {settled:?}");
        assert_eq!(site.tree(), before, "{why}: nothing was written");
    }
}

/// A forwarder the host cannot name, and an application it does not know, refuse the recipe.
#[test]
fn a_recipe_the_host_cannot_place_is_refused() {
    let site = Site::new();
    let before = site.tree();
    let no_forwarder = NativeBridges::new(BridgeHost {
        forwarder: None,
        ..site.host()
    });
    let settled = no_forwarder
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(refused(&settled).contains("kr-hook"), "{settled:?}");

    let unknown = NativeBridges::new(BridgeHost {
        applications: Vec::new(),
        ..site.host()
    });
    let settled = unknown
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(refused(&settled).contains("Claude Code"), "{settled:?}");
    assert_eq!(site.tree(), before);
}

/// A package whose file is not the bytes its recipe names is refused.
#[test]
fn a_package_file_that_is_not_what_the_recipe_names_is_refused() {
    let site = Site::new();
    std::fs::write(site.package("a").join("bridge/hooks.json"), b"{}").expect("changes it");
    let before = site.tree();

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(
        refused(&settled).contains("bridge/hooks.json"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before);
}

// ---------------------------------------------------------------------------------------------
// What protects the application's directory
// ---------------------------------------------------------------------------------------------

/// A directory on a destination's way that is a link is refused before anything is written, and
/// nothing is written where it points.
#[cfg(unix)]
#[test]
fn a_link_on_the_way_to_a_destination_is_refused() {
    let site = Site::new();
    let elsewhere = site.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("another directory");
    std::os::unix::fs::symlink(
        &elsewhere,
        site.application().join("skills/kalareach-channels"),
    )
    .expect("a link");
    let before = site.tree();

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("link"), "{settled:?}");
    assert_eq!(site.tree(), before);
    assert!(
        snapshot(&elsewhere).is_empty(),
        "nothing was written through the link"
    );
}

/// A directory the installation made, replaced by a link afterwards, cannot send a removal into
/// another directory: the file there is not the installed one, whatever it holds.
#[cfg(unix)]
#[test]
fn a_removal_is_not_sent_through_a_link_into_another_directory() {
    let site = Site::new();
    let bridges = site.bridges();
    bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let elsewhere = site.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("another directory");
    std::fs::write(elsewhere.join("hooks.json"), pinned("hooks.json")).expect("the same bytes");
    let hooks = site.application().join("skills/kalareach-channels/hooks");
    std::fs::remove_dir_all(&hooks).expect("somebody removes it");
    std::os::unix::fs::symlink(&elsewhere, &hooks).expect("and puts a link there");

    bridges.reconcile(&plugin(), None).expect("removes");

    assert_eq!(
        std::fs::read(elsewhere.join("hooks.json")).expect("still there"),
        pinned("hooks.json"),
        "the file the link leads to is not touched"
    );
    let reports = bridges.reports().expect("reads");
    assert!(
        reports[0].notes.iter().any(|note| note.contains("hooks")),
        "{reports:?}"
    );
    assert!(
        !site.application().join(SERVERS_PATH).exists(),
        "the rest goes"
    );
}

/// A settings document that is a link, repeats a member or is not JSON this host can edit exactly
/// is refused before anything is written.
#[test]
fn a_settings_document_that_cannot_be_edited_exactly_is_refused() {
    let site = Site::with_settings(Some("{\"a\": 1, \"a\": 2}"));
    let before = site.tree();
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(refused(&settled).contains("more than once"), "{settled:?}");
    assert_eq!(site.tree(), before);

    let site = Site::with_settings(Some("{\"a\": 1,}"));
    let before = site.tree();
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(refused(&settled).contains("settings.json"), "{settled:?}");
    assert_eq!(site.tree(), before);

    #[cfg(unix)]
    {
        let site = Site::with_settings(None);
        let real = site.root.join("dotfiles-settings.json");
        std::fs::write(&real, SETTINGS).expect("settings kept elsewhere");
        std::os::unix::fs::symlink(&real, site.application().join("settings.json"))
            .expect("a link");
        let before = site.tree();
        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles");
        assert!(refused(&settled).contains("settings.json"), "{settled:?}");
        assert_eq!(site.tree(), before);
        assert_eq!(std::fs::read_to_string(&real).expect("reads"), SETTINGS);
    }
}

/// A settings document protected by an access-control list is not replaced.
#[cfg(target_os = "macos")]
#[test]
fn a_settings_document_protected_by_an_access_control_list_is_refused() {
    let site = Site::new();
    let document = site.application().join("settings.json");
    let _restriction = Restriction(document.clone());
    exacl::setfacl(
        &[&document],
        &[exacl::AclEntry::deny_group(
            "everyone",
            exacl::Perm::DELETE,
            None,
        )],
        None,
    )
    .expect("restricts the document");
    let before = site.tree();

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(
        refused(&settled).contains("access-control list"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before);
}

/// The access-control list a test put on a document, taken off again when this is dropped.
#[cfg(target_os = "macos")]
struct Restriction(PathBuf);

#[cfg(target_os = "macos")]
impl Drop for Restriction {
    fn drop(&mut self) {
        let _ = exacl::setfacl(&[&self.0], &[], None);
    }
}

/// A settings document that changes between the read and the replacement is read again, and the
/// change somebody made survives.
#[test]
fn a_settings_document_edited_meanwhile_is_read_again() {
    let site = Site::new();
    let bridges = site.bridges();
    let edited = Arc::new(AtomicBool::new(false));
    let document = site.application().join("settings.json");
    {
        let edited = Arc::clone(&edited);
        let document = document.clone();
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") && !edited.swap(true, Ordering::SeqCst) {
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(&document, text.replace("\"opus\"", "\"sonnet\""))
                    .expect("somebody edits it meanwhile");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert_eq!(settled, Settled::Applied);
    assert!(
        edited.load(Ordering::SeqCst),
        "the edit came between the read and the rename"
    );
    assert_eq!(
        std::fs::read_to_string(&document).expect("reads"),
        SETTINGS_WITH_KEY.replace("\"opus\"", "\"sonnet\""),
        "both the edit and the key are there"
    );
}

/// A settings document that keeps changing refuses the recipe part way, and the files already put
/// in place are taken out again: an application finishes or is undone.
#[test]
fn a_document_that_keeps_changing_refuses_the_recipe_and_leaves_nothing_of_it() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    let document = site.application().join("settings.json");
    {
        let document = document.clone();
        let edits = std::sync::atomic::AtomicUsize::new(0);
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") {
                let edit = edits.fetch_add(1, Ordering::SeqCst);
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(
                    &document,
                    text.replacen('{', &format!("{{\"edit{edit}\": 1, "), 1),
                )
                .expect("somebody edits it again");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("kept changing"), "{settled:?}");
    let mut after = site.tree();
    let edited = after.remove("settings.json").expect("the document");
    let mut expected = before.clone();
    expected.remove("settings.json");
    assert_eq!(after, expected, "the files put in place were taken out");
    assert_eq!(
        edited,
        Node::File(std::fs::read(&document).expect("reads")),
        "and the document holds the edits and not the key"
    );
    assert!(
        !std::fs::read_to_string(&document)
            .expect("reads")
            .contains("kalareach-channels@skills-dir"),
        "the key is not in it"
    );
}

/// A refusal whose undo has to leave a file in place, because somebody changed it after this host
/// placed it, is not reported as clean: the file is named as left.
#[test]
fn a_refusal_that_has_to_leave_a_changed_file_is_not_reported_as_clean() {
    let site = Site::new();
    let bridges = site.bridges();
    let hooks = site.application().join(HOOKS_PATH);
    {
        let document = site.application().join("settings.json");
        let hooks = hooks.clone();
        let edits = std::sync::atomic::AtomicUsize::new(0);
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") {
                let edit = edits.fetch_add(1, Ordering::SeqCst);
                if edit == 0 {
                    std::fs::write(&hooks, b"{\"hooks\": {}}").expect("somebody edits the hooks");
                }
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(
                    &document,
                    text.replacen('{', &format!("{{\"edit{edit}\": 1, "), 1),
                )
                .expect("somebody edits it again");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    let Settled::Unsettled(reason) = &settled else {
        panic!("reported as clean: {settled:?}");
    };
    assert!(
        reason.contains("kept changing")
            && reason.contains("left in place")
            && reason.contains(HOOKS_PATH),
        "{reason}"
    );
    assert_eq!(std::fs::read(&hooks).expect("left"), b"{\"hooks\": {}}");
    assert!(
        !site.application().join(SERVERS_PATH).exists(),
        "the rest is taken out"
    );
}

/// A refusal names the file its undo had to leave even when, in the same run, something an earlier
/// removal left is found gone.
#[test]
fn a_refusal_names_what_it_left_when_an_earlier_leftover_goes_in_the_same_run() {
    let site = Site::new();
    site.bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    // Somebody edits the hooks file installed in the first directory, so its removal leaves it.
    let first_hooks = site.application().join(HOOKS_PATH);
    std::fs::write(&first_hooks, b"{\"hooks\": {}}").expect("somebody edits it");
    // The host now keeps Claude Code's plugins in another directory.
    let other = site.root.join("other/.claude");
    std::fs::create_dir_all(&other).expect("another directory");
    std::fs::write(other.join("settings.json"), SETTINGS).expect("settings");
    let other_hooks = other.join(HOOKS_PATH);
    let moved = NativeBridges::new(BridgeHost {
        applications: vec![ApplicationDirectory {
            application: "Claude Code".to_owned(),
            directory: other.clone(),
        }],
        ..site.host()
    });
    {
        let first_hooks = first_hooks.clone();
        let other_hooks = other_hooks.clone();
        let document = other.join("settings.json");
        let edits = std::sync::atomic::AtomicUsize::new(0);
        moved.before_publishing(move |destination: &Path| {
            // Only the second directory's document: the first one's is edited by its removal.
            if destination == document {
                let edit = edits.fetch_add(1, Ordering::SeqCst);
                if edit == 0 {
                    // What the first removal left is removed by its owner, and the hooks file just
                    // placed in the second directory is edited.
                    std::fs::remove_file(&first_hooks).expect("its owner removes it");
                    std::fs::write(&other_hooks, b"{\"hooks\": {}}").expect("somebody edits it");
                }
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(
                    &document,
                    text.replacen('{', &format!("{{\"edit{edit}\": 1, "), 1),
                )
                .expect("somebody edits it again");
            }
        });
    }

    let settled = moved
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    let Settled::Unsettled(reason) = &settled else {
        panic!("reported as clean: {settled:?}");
    };
    assert!(
        reason.contains("left in place") && reason.contains(&other_hooks.display().to_string()),
        "{reason}"
    );
}

// ---------------------------------------------------------------------------------------------
// Stopped at each boundary
// ---------------------------------------------------------------------------------------------

/// A run stopped before one of its steps: the site it ran in, and the steps it took.
struct Stopped {
    site: Site,
    steps: Vec<String>,
}

impl Stopped {
    /// True when the run stopped after making something under a temporary name and before
    /// recording what it made: the one boundary that leaves an object the next run cannot show is
    /// the host's.
    fn left_unrecorded(&self) -> bool {
        self.steps
            .last()
            .is_some_and(|step| step.starts_with("stage ") || step.starts_with("make "))
    }
}

/// Runs `first` on a fresh site stopped before step `step`, and returns what it left when the run
/// stopped, or `None` when it finished before reaching that step.
fn stopped_at(
    step: usize,
    prepare: &dyn Fn(&Site),
    first: &dyn Fn(&Site, &NativeBridges) -> kr_controller::Result<Settled>,
) -> Option<Stopped> {
    let site = Site::new();
    prepare(&site);
    let bridges = site.bridges();
    bridges.stop_before(step);
    match first(&site, &bridges) {
        Err(_) => Some(Stopped {
            steps: bridges.steps(),
            site,
        }),
        Ok(_) => None,
    }
}

/// Every name under the application's directory that is a temporary one.
fn temporaries(site: &Site) -> Vec<String> {
    site.tree()
        .into_keys()
        .filter(|name| name.contains(".kalareach"))
        .collect()
}

/// Checks that a reconciliation after a run stopped between making something and recording it
/// left that one thing in place, named it, and reported the bridge as unsettled; then removes it,
/// as its owner would.
fn left_and_named(site: &Site, settled: &Settled, step: usize) {
    let Settled::Unsettled(reason) = settled else {
        panic!("step {step}: {settled:?}");
    };
    let left = temporaries(site);
    assert_eq!(left.len(), 1, "step {step}: {left:?}");
    let name = Path::new(&left[0])
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    assert!(reason.contains(&name), "step {step}: {reason}");
    let reports = site.bridges().reports().expect("reads");
    assert_eq!(reports[0].state, "unsettled", "step {step}: {reports:?}");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("not settled") && note.contains(&name)),
        "step {step}: {reports:?}"
    );
    let path = site.application().join(&left[0]);
    if path.is_dir() {
        std::fs::remove_dir(&path).expect("the owner removes it");
    } else {
        std::fs::remove_file(&path).expect("the owner removes it");
    }
}

/// KR-REQ-11.42: an installation stopped before any of its steps is never reported as applied, and
/// the next reconciliation finishes it when the release is still wanted and takes it out when it is
/// not. Something made and not yet recorded is neither taken nor claimed: it is named, and the
/// bridge is not reported as applied until its owner removes it.
#[test]
fn kr_req_11_42_an_installation_stopped_at_each_boundary_is_finished_or_undone() {
    let reference = Site::new();
    let before = reference.tree();
    let applied = applied_tree(&before);
    let mut boundaries = 0;
    let mut unrecorded = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        boundaries += 1;
        let site = &stopped.site;
        assert!(
            site.bridges()
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_none(),
            "step {step}: never reported as applied while unfinished"
        );
        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&site.release()))
            .expect("finishes");
        if stopped.left_unrecorded() {
            unrecorded += 1;
            left_and_named(site, &settled, step);
            assert_eq!(
                site.bridges()
                    .reconcile(&plugin(), Some(&site.release()))
                    .expect("finishes"),
                Settled::Unchanged,
                "step {step}"
            );
        } else {
            assert_eq!(settled, Settled::Applied, "step {step}");
        }
        assert_eq!(site.tree(), applied, "step {step}: finished exactly");
        assert!(
            site.bridges()
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_some(),
            "step {step}"
        );

        let stopped = stopped_at(step, &|_| {}, &apply).expect("stops again");
        let site = &stopped.site;
        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("takes it out");
        if stopped.left_unrecorded() {
            left_and_named(site, &settled, step);
            assert_eq!(
                site.bridges().reconcile(&plugin(), None).expect("finishes"),
                Settled::Removed,
                "step {step}"
            );
        } else if step == 1 {
            // Stopped before its first record: nothing was begun, so nothing needs undoing.
            assert_eq!(settled, Settled::Unchanged, "step {step}");
        } else {
            assert_eq!(settled, Settled::Removed, "step {step}");
        }
        assert_eq!(site.tree(), before, "step {step}: undone exactly");
        assert!(
            site.bridges().reports().expect("reads").is_empty(),
            "step {step}"
        );
    }
    assert!(boundaries > 20, "every step was a boundary: {boundaries}");
    assert_eq!(
        unrecorded, 7,
        "three directories, three files and the settings document were each made unrecorded once"
    );
}

/// KR-REQ-11.42: a removal stopped before any of its steps is finished by the next
/// reconciliation.
#[test]
fn kr_req_11_42_a_removal_stopped_at_each_boundary_is_finished() {
    let reference = Site::new();
    let before = reference.tree();
    let mut boundaries = 0;
    let mut unrecorded = 0;
    for step in 1.. {
        let install = |site: &Site| {
            site.bridges()
                .reconcile(&plugin(), Some(&site.release()))
                .expect("applies");
        };
        let remove = |_: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), None);
        let Some(stopped) = stopped_at(step, &install, &remove) else {
            break;
        };
        boundaries += 1;
        let site = &stopped.site;
        // Before its first step the removal has not begun, and the release is applied.
        assert!(
            step == 1
                || site
                    .bridges()
                    .facts(&plugin(), site.release().package_digest)
                    .expect("reads")
                    .is_none(),
            "step {step}: a release being removed is not reported as applied"
        );
        let settled = site.bridges().reconcile(&plugin(), None).expect("finishes");
        if stopped.left_unrecorded() {
            unrecorded += 1;
            left_and_named(site, &settled, step);
            assert_eq!(
                site.bridges().reconcile(&plugin(), None).expect("finishes"),
                Settled::Removed,
                "step {step}"
            );
        } else {
            assert_eq!(settled, Settled::Removed, "step {step}");
        }
        assert_eq!(site.tree(), before, "step {step}: removed exactly");
        assert!(
            site.bridges().reports().expect("reads").is_empty(),
            "step {step}"
        );
    }
    assert!(boundaries > 10, "every step was a boundary: {boundaries}");
    assert_eq!(unrecorded, 1, "the edit taking the key out");
}

/// An upgrade stopped before any of its steps ends with the new release applied and nothing of the
/// old one left.
#[test]
fn an_upgrade_stopped_at_each_boundary_ends_with_the_new_release() {
    let mut boundaries = 0;
    for step in 1.. {
        let install = |site: &Site| {
            site.bridges()
                .reconcile(&plugin(), Some(&site.release()))
                .expect("applies");
        };
        let upgrade = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.next_release()))
        };
        let Some(stopped) = stopped_at(step, &install, &upgrade) else {
            break;
        };
        boundaries += 1;
        let site = &stopped.site;
        let next = site.next_release();
        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&next))
            .expect("finishes");
        if stopped.left_unrecorded() {
            left_and_named(site, &settled, step);
            assert_eq!(
                site.bridges()
                    .reconcile(&plugin(), Some(&next))
                    .expect("finishes"),
                Settled::Unchanged,
                "step {step}"
            );
        } else {
            assert_eq!(settled, Settled::Applied, "step {step}");
        }
        assert_eq!(
            std::fs::read(site.application().join(HOOKS_PATH)).expect("the new file"),
            std::fs::read(site.package("b").join("bridge/hooks.json")).expect("reads"),
            "step {step}"
        );
        assert!(
            site.bridges()
                .facts(&plugin(), next.package_digest)
                .expect("reads")
                .is_some(),
            "step {step}"
        );
        assert!(
            site.bridges()
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_none(),
            "step {step}: the old release is not the one applied"
        );
        assert!(
            temporaries(site).is_empty(),
            "step {step}: no temporary file is left"
        );
    }
    assert!(boundaries > 20, "every step was a boundary: {boundaries}");
}

/// A note is not ownership: what the owner put at a noted place before the change was made is
/// theirs, and a removal leaves it.
#[test]
fn a_change_noted_and_not_made_does_not_claim_what_somebody_put_there() {
    let mut checked = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let site = &stopped.site;
        let theirs = site.application().join(MANIFEST_PATH);
        if theirs.exists() || !theirs.parent().is_some_and(Path::is_dir) {
            continue;
        }
        // Stopped with the file noted or staged and not in place. The owner writes the bytes the
        // recipe would have written, where it would have.
        std::fs::write(&theirs, pinned("plugin-manifest.json")).expect("the owner's copy");

        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert_eq!(
            std::fs::read(&theirs).expect("kept"),
            pinned("plugin-manifest.json"),
            "step {step}: the owner's file is left"
        );
        if stopped.left_unrecorded() {
            left_and_named(site, &settled, step);
        }
        assert!(
            temporaries(site).is_empty(),
            "step {step}: no temporary file is left"
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "the noted, the unrecorded and the staged boundaries were each reached: {checked}"
    );
}

/// The key noted before the settings document was replaced is not claimed when the owner sets it.
#[test]
fn a_key_noted_and_not_written_is_not_taken_when_the_owner_sets_it() {
    let mut checked = false;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let site = &stopped.site;
        let document = site.application().join("settings.json");
        let text = std::fs::read_to_string(&document).expect("reads");
        if text != SETTINGS || !site.application().join(HOOKS_PATH).exists() {
            continue;
        }
        // Every file is in place and the key is not: the owner sets it themselves.
        std::fs::write(&document, SETTINGS_WITH_KEY).expect("the owner sets the key");

        site.bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert_eq!(
            std::fs::read_to_string(&document).expect("reads"),
            SETTINGS_WITH_KEY,
            "step {step}: the owner's key stays"
        );
        checked = true;
    }
    assert!(checked, "a boundary before the key was written was reached");
}

/// A key published and then carried through a rewrite of the document by somebody else cannot be
/// shown to be this host's: it is neither taken nor claimed, and the bridge is reported as
/// unsettled rather than applied. A key recorded as published before the rewrite is this host's.
#[test]
fn a_key_whose_document_was_rewritten_meanwhile_stays_unsettled() {
    let mut unsettled = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let site = &stopped.site;
        let document = site.application().join("settings.json");
        let text = std::fs::read_to_string(&document).expect("reads");
        if text != SETTINGS_WITH_KEY || !temporaries(site).is_empty() {
            continue;
        }
        // The key is in place. Another program rewrites the document as a new file, keeping it.
        let replacement = site.root.join("replacement.json");
        std::fs::write(&replacement, SETTINGS_WITH_KEY).expect("a rewrite");
        std::fs::rename(&replacement, &document).expect("replaces the document");

        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles");

        match settled {
            Settled::Unsettled(_) => {
                unsettled += 1;
                assert!(
                    site.bridges()
                        .facts(&plugin(), site.release().package_digest)
                        .expect("reads")
                        .is_none(),
                    "step {step}"
                );
                let reports = site.bridges().reports().expect("reads");
                assert_eq!(reports[0].state, "unsettled", "step {step}: {reports:?}");
                site.bridges()
                    .reconcile(&plugin(), None)
                    .expect("reconciles");
                assert_eq!(
                    std::fs::read_to_string(&document).expect("reads"),
                    SETTINGS_WITH_KEY,
                    "step {step}: the key is not taken"
                );
            }
            // Recorded as published before it stopped: the key is this host's.
            Settled::Applied => {}
            other => panic!("step {step}: {other:?}"),
        }
    }
    assert!(
        unsettled >= 1,
        "a boundary after the key's publication and before its record was reached"
    );
}

/// Something staged and recorded, then replaced at its temporary name while the run was stopped,
/// is not the object the host staged: it is left and named, not removed.
#[test]
fn a_staged_file_replaced_while_the_run_was_stopped_is_left() {
    let mut checked = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        // Stopped with a staged file recorded, before its rename.
        let [.., staged, last] = stopped.steps.as_slice() else {
            continue;
        };
        let Some(temporary) = staged.strip_prefix("stage ") else {
            continue;
        };
        if !last.starts_with("save ") {
            continue;
        }
        // Another file with the same bytes takes its place. It is written first and renamed over
        // the staged one, so it is a new file rather than one reusing the staged file's inode.
        let temporary = PathBuf::from(temporary);
        let bytes = std::fs::read(&temporary).expect("staged");
        let another = temporary.with_extension("another");
        std::fs::write(&another, &bytes).expect("another file");
        std::fs::rename(&another, &temporary).expect("put in its place");
        let site = &stopped.site;

        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert_eq!(
            std::fs::read(&temporary).expect("left"),
            bytes,
            "step {step}: the file that is not the one staged is left"
        );
        left_and_named(site, &settled, step);
        checked += 1;
    }
    assert_eq!(checked, 4, "three files and the settings document");
}

/// A publication the next run finds renamed into place is recorded only after its directory is
/// flushed, and so is a removal it finds already done.
#[test]
fn what_a_stopped_run_did_is_recorded_only_after_its_directory_is_flushed() {
    // The run that installs, stopped between renaming the settings document into place and
    // flushing the application's directory.
    let traced = Site::new();
    let bridges = traced.bridges();
    bridges
        .reconcile(&plugin(), Some(&traced.release()))
        .expect("applies");
    let settings = format!(
        "rename {}",
        traced.application().join("settings.json").display()
    );
    let renamed = bridges
        .steps()
        .iter()
        .position(|step| *step == settings)
        .expect("the settings document is renamed");
    assert!(
        bridges.steps()[renamed + 1].starts_with("flush "),
        "a flush follows the rename"
    );
    let stopped = stopped_at(renamed + 2, &|_| {}, &|site, bridges| {
        bridges.reconcile(&plugin(), Some(&site.release()))
    })
    .expect("stops before the flush");
    let site = &stopped.site;
    let next = site.bridges();
    assert_eq!(
        next.reconcile(&plugin(), Some(&site.release()))
            .expect("finishes"),
        Settled::Applied
    );
    let steps = next.steps();
    let flush = format!("flush {}", site.application().display());
    let flushed = steps
        .iter()
        .position(|step| *step == flush)
        .expect("the application's directory is flushed");
    let recorded = steps
        .iter()
        .position(|step| step.starts_with("save "))
        .expect("the publication is recorded");
    assert!(flushed < recorded, "{steps:?}");

    // The run that removes, stopped between unlinking the hooks file and flushing its directory.
    let traced = Site::new();
    traced
        .bridges()
        .reconcile(&plugin(), Some(&traced.release()))
        .expect("applies");
    let bridges = traced.bridges();
    bridges.reconcile(&plugin(), None).expect("removes");
    let hooks = format!("unlink {}", traced.application().join(HOOKS_PATH).display());
    let unlinked = bridges
        .steps()
        .iter()
        .position(|step| *step == hooks)
        .expect("the hooks file is unlinked");
    let install = |site: &Site| {
        site.bridges()
            .reconcile(&plugin(), Some(&site.release()))
            .expect("applies");
    };
    let stopped = stopped_at(unlinked + 2, &install, &|_, bridges| {
        bridges.reconcile(&plugin(), None)
    })
    .expect("stops before the flush");
    let site = &stopped.site;
    let next = site.bridges();
    assert_eq!(
        next.reconcile(&plugin(), None).expect("finishes"),
        Settled::Removed
    );
    let steps = next.steps();
    let flush = format!(
        "flush {}",
        site.application()
            .join("skills/kalareach-channels/hooks")
            .display()
    );
    let flushed = steps
        .iter()
        .position(|step| *step == flush)
        .expect("the hooks directory is flushed");
    // One save marks the removal as begun; the next records what it took out.
    assert_eq!(
        steps[..flushed]
            .iter()
            .filter(|step| step.starts_with("save "))
            .count(),
        1,
        "{steps:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Protection, substitution and failures
// ---------------------------------------------------------------------------------------------

/// A replacement of the settings document has exactly the permission bits of the document it
/// replaces, whatever the creation mask, and so does the one the removal leaves.
#[cfg(unix)]
#[test]
fn a_replaced_document_keeps_exactly_its_permission_bits() {
    use std::os::unix::fs::PermissionsExt as _;
    for mode in [0o600, 0o640, 0o666] {
        let site = Site::new();
        let document = site.application().join("settings.json");
        std::fs::set_permissions(&document, std::fs::Permissions::from_mode(mode))
            .expect("the document's mode");
        let bridges = site.bridges();
        assert_eq!(
            bridges
                .reconcile(&plugin(), Some(&site.release()))
                .expect("applies"),
            Settled::Applied
        );
        let applied = std::fs::metadata(&document).expect("reads").permissions();
        assert_eq!(applied.mode() & 0o777, mode, "{mode:o}: applied");
        bridges.reconcile(&plugin(), None).expect("removes");
        let removed = std::fs::metadata(&document).expect("reads").permissions();
        assert_eq!(removed.mode() & 0o777, mode, "{mode:o}: removed");
    }
}

/// A document whose permission bits change between the read and the replacement is read again, and
/// the replacement keeps the new bits.
#[cfg(unix)]
#[test]
fn a_document_whose_permissions_change_meanwhile_is_read_again() {
    use std::os::unix::fs::PermissionsExt as _;
    let site = Site::new();
    let document = site.application().join("settings.json");
    std::fs::set_permissions(&document, std::fs::Permissions::from_mode(0o644))
        .expect("the document's mode");
    let bridges = site.bridges();
    let narrowed = Arc::new(AtomicBool::new(false));
    {
        let narrowed = Arc::clone(&narrowed);
        let document = document.clone();
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") && !narrowed.swap(true, Ordering::SeqCst) {
                std::fs::set_permissions(&document, std::fs::Permissions::from_mode(0o600))
                    .expect("somebody narrows it meanwhile");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert_eq!(settled, Settled::Applied);
    assert!(narrowed.load(Ordering::SeqCst));
    let mode = std::fs::metadata(&document)
        .expect("reads")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the narrower bits are kept");
    assert_eq!(
        std::fs::read_to_string(&document).expect("reads"),
        SETTINGS_WITH_KEY
    );
}

/// An access-control list put on the settings document between the read and the replacement stops
/// the replacement, and what the recipe had placed is taken out again.
#[cfg(target_os = "macos")]
#[test]
fn an_access_control_list_added_meanwhile_stops_the_replacement() {
    let site = Site::new();
    let document = site.application().join("settings.json");
    let _restriction = Restriction(document.clone());
    let before = site.tree();
    let bridges = site.bridges();
    {
        let document = document.clone();
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") {
                exacl::setfacl(
                    &[&document],
                    &[exacl::AclEntry::deny_group(
                        "everyone",
                        exacl::Perm::DELETE,
                        None,
                    )],
                    None,
                )
                .expect("somebody restricts it meanwhile");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(
        refused(&settled).contains("access-control list"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before, "nothing of the recipe is left");
    assert!(
        !exacl::getfacl(&document, None)
            .expect("reads the list")
            .is_empty(),
        "the document keeps its list"
    );
}

/// The protection of the document is read from the document the replacement would take the place
/// of: when the application's directory is moved after the copy was staged, and its document then
/// gains an access-control list, the replacement does not go ahead through the directory it holds.
#[cfg(target_os = "macos")]
#[test]
fn protection_is_read_from_the_document_the_replacement_would_take_the_place_of() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    let original = site.root.join("home/.claude-original");
    let _restriction = Restriction(original.join("settings.json"));
    {
        let application = site.application();
        let original = original.clone();
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") {
                std::fs::rename(&application, &original).expect("somebody moves it");
                std::fs::create_dir_all(&application).expect("and puts another there");
                exacl::setfacl(
                    &[&original.join("settings.json")],
                    &[exacl::AclEntry::deny_group(
                        "everyone",
                        exacl::Perm::DELETE,
                        None,
                    )],
                    None,
                )
                .expect("and restricts the document");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    assert_eq!(
        std::fs::read_to_string(original.join("settings.json")).expect("reads"),
        SETTINGS,
        "the document was not replaced"
    );
    assert!(
        !exacl::getfacl(original.join("settings.json"), None)
            .expect("reads the list")
            .is_empty(),
        "and keeps its list"
    );
    assert!(
        snapshot(&site.application()).is_empty(),
        "nothing was written in the directory put there"
    );
    let mut moved = snapshot(&original);
    moved.remove("settings.json");
    let mut expected = applied_tree(&before);
    expected.remove("settings.json");
    assert_eq!(
        moved, expected,
        "what was placed in the original stays, recorded, while another directory is in its place"
    );
}

/// An application directory replaced after the installation, by a link to a copy of it or by an
/// empty directory, is never changed by the removal, and what was placed stays recorded: the
/// removal is not reported as done, and once the directory the release was applied in is back, the
/// next removal takes out exactly what it placed.
#[cfg(unix)]
#[test]
fn a_directory_put_in_the_place_of_the_application_directory_is_never_changed() {
    for copy in [true, false] {
        let site = Site::new();
        let before = site.tree();
        let bridges = site.bridges();
        bridges
            .reconcile(&plugin(), Some(&site.release()))
            .expect("applies");
        let original = site.root.join("home/.claude-original");
        std::fs::rename(site.application(), &original).expect("somebody moves it");
        let elsewhere = site.root.join("elsewhere");
        if copy {
            copy_tree(&original, &elsewhere);
            std::os::unix::fs::symlink(&elsewhere, site.application())
                .expect("and links a copy there");
        } else {
            std::fs::create_dir_all(&elsewhere).expect("an empty directory");
            std::fs::rename(&elsewhere, site.application()).expect("and puts it there");
        }
        let put_there = snapshot(&site.application());
        let moved = snapshot(&original);

        let settled = bridges.reconcile(&plugin(), None).expect("reconciles");

        assert!(
            matches!(settled, Settled::Unsettled(_)),
            "copy {copy}: {settled:?}"
        );
        assert_eq!(
            snapshot(&site.application()),
            put_there,
            "copy {copy}: nothing in the directory put there was touched"
        );
        assert_eq!(
            snapshot(&original),
            moved,
            "copy {copy}: nor in the original"
        );
        let reports = bridges.reports().expect("reads");
        assert_eq!(reports[0].state, "removing", "copy {copy}: {reports:?}");
        assert!(
            reports[0].notes.iter().any(|note| {
                note.starts_with("could not be taken out")
                    && note.contains(HOOKS_PATH)
                    && note.contains("another directory")
            }),
            "copy {copy}: {reports:?}"
        );
        // A second reconciliation changes nothing and forgets nothing.
        assert!(matches!(
            bridges.reconcile(&plugin(), None).expect("reconciles"),
            Settled::Unsettled(_)
        ));

        // The original comes back, and the removal finishes in it.
        if copy {
            std::fs::remove_file(site.application()).expect("the link goes");
        } else {
            std::fs::remove_dir(site.application()).expect("the empty directory goes");
        }
        std::fs::rename(&original, site.application()).expect("the original comes back");
        assert_eq!(
            bridges.reconcile(&plugin(), None).expect("reconciles"),
            Settled::Removed,
            "copy {copy}"
        );
        assert_eq!(site.tree(), before, "copy {copy}: removed exactly");
        assert!(bridges.reports().expect("reads").is_empty(), "copy {copy}");
    }
}

/// A run stopped between making something and recording it leaves it named while an empty
/// directory is at the application directory's path: the record is about the directory the run
/// was in, and nothing in another directory says it is gone.
#[cfg(unix)]
#[test]
fn what_is_not_settled_stays_named_while_another_directory_is_in_place() {
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let stopped = (1..)
        .map_while(|step| stopped_at(step, &|_| {}, &apply))
        .find(Stopped::left_unrecorded)
        .expect("a run stopped between making something and recording it");
    let site = &stopped.site;
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    let left = temporaries(site);
    assert_eq!(left.len(), 1, "{left:?}");
    std::fs::rename(site.application(), site.root.join("home/.claude-original"))
        .expect("somebody moves it");
    std::fs::create_dir_all(site.application()).expect("and puts an empty directory there");

    let settled = site
        .bridges()
        .reconcile(&plugin(), None)
        .expect("reconciles");

    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    let reports = site.bridges().reports().expect("reads");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("not settled") && note.contains(&left[0])),
        "{reports:?}"
    );
}

/// A run stopped part way is not settled in a directory put in the application directory's place:
/// what it had in flight is named as not settled, and nothing there is removed.
#[cfg(unix)]
#[test]
fn a_run_stopped_part_way_is_not_settled_in_a_directory_put_in_its_place() {
    let mut checked = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(stopped) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let site = &stopped.site;
        if temporaries(site).is_empty() {
            continue;
        }
        // A staged file is at its temporary name. The directory is replaced by a link to a copy.
        let elsewhere = site.root.join("elsewhere");
        copy_tree(&site.application(), &elsewhere);
        let copied = snapshot(&elsewhere);
        std::fs::rename(site.application(), site.root.join("home/.claude-original"))
            .expect("somebody moves it");
        std::os::unix::fs::symlink(&elsewhere, site.application())
            .expect("and links another there");

        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert!(
            matches!(settled, Settled::Unsettled(_)),
            "step {step}: {settled:?}"
        );
        assert_eq!(
            snapshot(&elsewhere),
            copied,
            "step {step}: nothing in it was touched"
        );
        // What was in flight is named as not settled because the directory is another one, not
        // because of what the other directory happens to hold.
        let reports = site.bridges().reports().expect("reads");
        assert!(
            reports[0].notes.iter().any(|note| {
                note.starts_with("not settled") && note.contains("another directory")
            }),
            "step {step}: {reports:?}"
        );
        checked += 1;
    }
    assert!(checked >= 7, "each staged object was reached: {checked}");
}

/// An object somebody puts at a temporary name after this host renamed its staged copy from there,
/// and before it recorded the publication, is named, and does not hide what was published: the
/// removal still takes out what this host placed.
#[test]
fn an_object_at_a_former_temporary_name_does_not_hide_what_was_published() {
    let before = Site::new().tree();
    let mut checked = 0;
    for published in [MANIFEST_PATH, "settings.json"] {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let rename =
            |site: &Site| format!("rename {}", site.application().join(published).display());
        // Stopped just after the rename, before the flush and the record.
        let Some(stopped) = (1..)
            .map_while(|step| stopped_at(step, &|_| {}, &apply))
            .find(|stopped| stopped.steps.last() == Some(&rename(&stopped.site)))
        else {
            panic!("{published}: the rename was reached");
        };
        let site = &stopped.site;
        let staged = stopped
            .steps
            .iter()
            .rev()
            .find_map(|step| step.strip_prefix("stage "))
            .map(PathBuf::from)
            .expect("the staged copy");
        assert!(!staged.exists(), "{published}: renamed away");
        std::fs::write(&staged, b"somebody's own").expect("somebody puts a file there");

        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert!(
            matches!(settled, Settled::Unsettled(_)),
            "{published}: {settled:?}"
        );
        assert_eq!(
            std::fs::read(&staged).expect("left"),
            b"somebody's own",
            "{published}"
        );
        assert!(
            !site.application().join(MANIFEST_PATH).exists(),
            "{published}: what was published is taken out"
        );
        assert_eq!(
            std::fs::read_to_string(site.application().join("settings.json")).expect("reads"),
            SETTINGS,
            "{published}: and the key with it"
        );
        std::fs::remove_file(&staged).expect("its owner removes it");
        assert_eq!(
            site.bridges().reconcile(&plugin(), None).expect("finishes"),
            Settled::Removed,
            "{published}"
        );
        assert_eq!(site.tree(), before, "{published}");
        checked += 1;
    }
    assert_eq!(checked, 2);
}

/// A settings document the key would create is held to the size this host reads back, as one it
/// edits is: a recipe value that would make it larger is refused before anything is written.
#[test]
fn a_settings_document_the_key_would_create_past_the_limit_is_refused() {
    let site = Site::with_settings(None);
    let before = site.tree();
    let value = format!("[{}]", vec!["0"; 200_000].join(","));
    assert!(
        value.len() < 1 << 20,
        "the value itself is within the limit"
    );
    let mut target = site.release();
    for step in &mut target.recipe.install {
        if let kr_plugin_sdk::plugin::BridgeStep::AddConfigurationKey { value: set, .. } = step {
            set.clone_from(&value);
        }
    }

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");

    assert!(refused(&settled).contains("larger than"), "{settled:?}");
    assert_eq!(site.tree(), before, "nothing was written");
}

/// A staged write that fails takes back the file it made, and never a file somebody put at its
/// name meanwhile: that one is left and named.
#[test]
fn a_staged_write_that_fails_takes_back_only_the_file_it_made() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    bridges.staging_fails(|_| {});
    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(
        refused(&settled).contains("stopped by a test"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before, "the file it made is taken back");

    let site = Site::new();
    let bridges = site.bridges();
    let replaced = Arc::new(std::sync::Mutex::new(None));
    {
        let replaced = Arc::clone(&replaced);
        bridges.staging_fails(move |staged: &Path| {
            let another = staged.with_extension("another");
            std::fs::write(&another, b"somebody's own").expect("another file");
            std::fs::rename(&another, staged).expect("put in its place");
            *replaced.lock().expect("a lock") = Some(staged.to_path_buf());
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    let staged = replaced
        .lock()
        .expect("a lock")
        .clone()
        .expect("the write was made to fail");
    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    assert_eq!(
        std::fs::read(&staged).expect("left"),
        b"somebody's own",
        "the file somebody put there is left"
    );
    let reports = bridges.reports().expect("reads");
    let name = staged
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("not settled") && note.contains(&name)),
        "{reports:?}"
    );
}

/// A cleanup a stopped run made, which the next run finds done, is flushed before its record goes:
/// the staged copy recovery takes back, and the edit a removal withdraws.
#[test]
fn a_cleanup_a_stopped_run_made_is_flushed_before_its_record_goes() {
    // Recovery: an installation stopped before renaming the plugin manifest into place, then a
    // removal stopped just after it takes the staged copy back and before it flushes.
    let before_rename = |site: &Site| {
        format!(
            "rename {}",
            site.application().join(MANIFEST_PATH).display()
        )
    };
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let first = (1..)
        .find(|step| {
            stopped_at(*step + 1, &|_| {}, &apply)
                .is_some_and(|stopped| stopped.steps.last() == Some(&before_rename(&stopped.site)))
        })
        .expect("the rename is a step");
    let prepare = |site: &Site| {
        let bridges = site.bridges();
        bridges.stop_before(first);
        assert!(apply(site, &bridges).is_err(), "stopped before the rename");
    };
    let remove = |_: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), None);
    let traced = Site::new();
    prepare(&traced);
    let bridges = traced.bridges();
    bridges.reconcile(&plugin(), None).expect("removes");
    let unlinked = bridges
        .steps()
        .iter()
        .position(|step| step.starts_with("unlink ") && step.contains(".plugin.json."))
        .expect("the staged copy is taken back");
    let stopped = stopped_at(unlinked + 2, &prepare, &remove).expect("stops before the flush");
    let next = stopped.site.bridges();
    assert_eq!(
        next.reconcile(&plugin(), None).expect("finishes"),
        Settled::Removed
    );
    let steps = next.steps();
    let directory = format!(
        "flush {}",
        stopped
            .site
            .application()
            .join("skills/kalareach-channels/.claude-plugin")
            .display()
    );
    let flushed = steps
        .iter()
        .position(|step| *step == directory)
        .expect("the directory is flushed");
    let recorded = steps
        .iter()
        .position(|step| step.starts_with("save "))
        .expect("the record goes");
    assert!(flushed < recorded, "{steps:?}");

    // A removal whose edit is withdrawn because the document changed meanwhile, stopped just after
    // the withdrawn copy is taken back and before it flushes.
    let install = |site: &Site| {
        site.bridges()
            .reconcile(&plugin(), Some(&site.release()))
            .expect("applies");
    };
    let edited_once = |bridges: &NativeBridges, document: PathBuf| {
        let edited = Arc::new(AtomicBool::new(false));
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") && !edited.swap(true, Ordering::SeqCst) {
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(&document, text.replace("\"opus\"", "\"sonnet\""))
                    .expect("somebody edits it meanwhile");
            }
        });
    };
    let traced = Site::new();
    install(&traced);
    let bridges = traced.bridges();
    edited_once(&bridges, traced.application().join("settings.json"));
    bridges.reconcile(&plugin(), None).expect("removes");
    let withdrawn = bridges
        .steps()
        .iter()
        .position(|step| step.starts_with("unlink ") && step.contains(".settings.json."))
        .expect("the withdrawn copy is taken back");
    let remove_edited = |site: &Site, bridges: &NativeBridges| {
        edited_once(bridges, site.application().join("settings.json"));
        bridges.reconcile(&plugin(), None)
    };
    let stopped =
        stopped_at(withdrawn + 2, &install, &remove_edited).expect("stops before the flush");
    let next = stopped.site.bridges();
    assert_eq!(
        next.reconcile(&plugin(), None).expect("finishes"),
        Settled::Removed
    );
    let steps = next.steps();
    let directory = format!("flush {}", stopped.site.application().display());
    let flushed = steps
        .iter()
        .position(|step| *step == directory)
        .expect("the directory is flushed");
    let recorded = steps
        .iter()
        .position(|step| step.starts_with("save "))
        .expect("the record goes");
    assert!(flushed < recorded, "{steps:?}");
}

/// A copy of an installed file with the same bytes is not the file this host installed: a removal
/// leaves it and names it.
#[test]
fn a_copy_of_an_installed_file_is_not_taken_for_it() {
    let site = Site::new();
    let bridges = site.bridges();
    bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    // Somebody writes the same bytes to a new file and puts it in the installed file's place.
    let hooks = site.application().join(HOOKS_PATH);
    let copy = site.root.join("hooks-copy.json");
    std::fs::write(&copy, pinned("hooks.json")).expect("a copy");
    std::fs::rename(&copy, &hooks).expect("put in its place");

    bridges.reconcile(&plugin(), None).expect("reconciles");

    assert_eq!(std::fs::read(&hooks).expect("left"), pinned("hooks.json"));
    assert!(
        !site.application().join(SERVERS_PATH).exists(),
        "the rest goes"
    );
    let reports = bridges.reports().expect("reads");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.contains(HOOKS_PATH) && note.contains("not the file")),
        "{reports:?}"
    );
}

/// A settings document the key would take past the size this host reads back is refused before
/// anything is written.
#[test]
fn a_settings_document_the_key_would_take_past_the_limit_is_refused() {
    let padding = "x".repeat((1 << 20) - 64);
    let settings = format!("{{\"padding\": \"{padding}\", \"enabledPlugins\": {{}}}}\n");
    assert!(
        settings.len() < 1 << 20,
        "the document itself is within the limit"
    );
    let site = Site::with_settings(Some(&settings));
    let before = site.tree();

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("larger than"), "{settled:?}");
    assert_eq!(site.tree(), before, "nothing was written");
}

/// A file the undo of a refused recipe cannot take out keeps the bridge unsettled and named, not
/// refused as if nothing were left; once it can be taken out, the next reconciliation does.
#[cfg(unix)]
#[test]
fn a_file_the_undo_cannot_take_out_keeps_the_refusal_unsettled() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    let hooks = site.application().join("skills/kalareach-channels/hooks");
    let _writable = Writable(hooks.clone());
    {
        let document = site.application().join("settings.json");
        let hooks = hooks.clone();
        let edits = std::sync::atomic::AtomicUsize::new(0);
        bridges.before_publishing(move |destination: &Path| {
            if destination.ends_with("settings.json") {
                set_writable(&hooks, false);
                let edit = edits.fetch_add(1, Ordering::SeqCst);
                let text = std::fs::read_to_string(&document).expect("reads");
                std::fs::write(
                    &document,
                    text.replacen('{', &format!("{{\"edit{edit}\": 1, "), 1),
                )
                .expect("somebody edits it again");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    let Settled::Unsettled(reason) = &settled else {
        panic!("reported as clean: {settled:?}");
    };
    assert!(
        reason.contains("kept changing") && reason.contains("hooks.json"),
        "{reason}"
    );
    assert!(site.application().join(HOOKS_PATH).exists());
    let reports = bridges.reports().expect("reads");
    assert_eq!(reports[0].state, "removing", "{reports:?}");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("could not be taken out") && note.contains(HOOKS_PATH)),
        "{reports:?}"
    );

    set_writable(&hooks, true);
    assert_eq!(
        bridges.reconcile(&plugin(), None).expect("reconciles"),
        Settled::Removed
    );
    let mut after = site.tree();
    after.remove("settings.json");
    let mut expected = before;
    expected.remove("settings.json");
    assert_eq!(after, expected, "everything the recipe placed is gone");
}

/// A removal that cannot write its edit of the settings document leaves the key recorded and says
/// so, and leaves nothing beside it; once it can, the next reconciliation takes the key out.
#[cfg(unix)]
#[test]
fn a_removal_that_cannot_write_its_edit_keeps_the_key_recorded() {
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();
    bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let _writable = Writable(site.application());
    set_writable(&site.application(), false);

    let settled = bridges.reconcile(&plugin(), None).expect("reconciles");

    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    assert_eq!(
        std::fs::read_to_string(site.application().join("settings.json")).expect("reads"),
        SETTINGS_WITH_KEY
    );
    assert!(temporaries(&site).is_empty(), "nothing is left beside it");
    let reports = bridges.reports().expect("reads");
    assert!(
        reports[0].notes.iter().any(|note| {
            note.starts_with("could not be taken out")
                && note.contains("enabledPlugins.kalareach-channels@skills-dir")
        }),
        "{reports:?}"
    );

    set_writable(&site.application(), true);
    assert_eq!(
        bridges.reconcile(&plugin(), None).expect("reconciles"),
        Settled::Removed
    );
    assert_eq!(site.tree(), before);
}

/// A directory that cannot be read says nothing about what is in it: what is named as not settled
/// stays named while the application's directory cannot be opened, and is still named after.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_does_not_erase_what_is_not_settled() {
    use std::os::unix::fs::PermissionsExt as _;
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let stopped = (1..)
        .map_while(|step| stopped_at(step, &|_| {}, &apply))
        .find(Stopped::left_unrecorded)
        .expect("a run stopped between making something and recording it");
    let site = &stopped.site;
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
    let left = temporaries(site);
    assert_eq!(left.len(), 1, "{left:?}");
    let _restored = Writable(site.application());
    std::fs::set_permissions(site.application(), std::fs::Permissions::from_mode(0o000))
        .expect("the directory cannot be read");

    let failed = site.bridges().reconcile(&plugin(), None);

    assert!(failed.is_err(), "{failed:?}");
    std::fs::set_permissions(site.application(), std::fs::Permissions::from_mode(0o755))
        .expect("readable again");
    let reports = site.bridges().reports().expect("reads");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("not settled") && note.contains(&left[0])),
        "{reports:?}"
    );
}

/// Lets a directory's entries be changed, or stops that.
#[cfg(unix)]
fn set_writable(directory: &Path, writable: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if writable { 0o755 } else { 0o555 };
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
        .expect("the directory's mode");
}

/// A directory a test made read-only, made writable again when this is dropped.
#[cfg(unix)]
struct Writable(PathBuf);

#[cfg(unix)]
impl Drop for Writable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// Copies a directory tree, without following a link.
#[cfg(unix)]
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("readable") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("a type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).expect("a copy");
        }
    }
}
