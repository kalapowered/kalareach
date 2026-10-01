//! KR-REQ-11.42: a package's native bridge recipe applied in an application's own directory, and
//! exactly what it applied taken out again.
//!
//! The recipe is the Claude Code package's, release 0.3.0, built here from the three registration
//! files this repository pins in `fixtures/bridges/claude-code/`, which carry the digests that
//! release names. Every test works in a directory of its own on the internal disk: an application
//! directory with somebody's settings in it, a search path holding a stand-in for the application's
//! executable and for the forwarder, and a package directory holding the recipe's files.
//!
//! On Windows this host applies and removes no recipe. The executor refuses every one at its
//! preflight, before anything is written in an application's directory, because what it stands
//! on exists on macOS and Linux only: every name is reached from one handle on the application's
//! directory without following a link, a file is known by the device and inode a rename keeps, and
//! a copy about to replace a document keeps its permission bits, owners and protection. So every
//! test of what applying or removing does, and of where a run can stop, is compiled for Unix only,
//! and on Windows the one test of that refusal runs, with the helpers the others share unused.
#![cfg_attr(windows, allow(dead_code, unused_imports))]

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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

/// The registration a recipe installs starts the forwarder for its own package's application and
/// for no other: a package whose registration names another package's application is refused
/// before anything is written, and the package the registration names is applied.
#[cfg(unix)]
#[test]
fn a_registration_for_another_packages_application_is_refused() {
    let site = Site::new();
    let before = site.tree();
    let another = PluginId::new("kalareach/another-agent").expect("a plugin identifier");
    let target = BridgeTarget {
        plugin_id: another.clone(),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&another, Some(&target))
        .expect("reconciles");
    let reason = refused(&settled);
    assert!(
        reason.contains("claude-code") && reason.contains("kalareach/another-agent"),
        "{reason}"
    );
    assert_eq!(site.tree(), before, "nothing was written");

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert_eq!(settled, Settled::Applied);
}

/// What the refusal of a configuration key this host does not permit a bridge to add says.
#[cfg(unix)]
const UNPERMITTED_KEY: &str = "does not permit a native bridge";

/// The recipe of release 0.3.0 with one more configuration key added, and its removal.
#[cfg(unix)]
fn recipe_adding_key(key: &str, value: &str) -> NativeBridge {
    let mut recipe = serde_json::to_value(recipe()).expect("the recipe encodes");
    recipe["install"]
        .as_array_mut()
        .expect("the install steps")
        .push(
            serde_json::json!({"type": "add_configuration_key", "file": "settings.json",
                                  "key": key, "value": value}),
        );
    recipe["remove"]
        .as_array_mut()
        .expect("the removal steps")
        .insert(
            0,
            serde_json::json!({"type": "remove_configuration_key", "file": "settings.json",
                               "key": key}),
        );
    serde_json::from_value(recipe).expect("a recipe")
}

/// A native bridge may add the configuration keys this host names for its application, each with
/// the one value that enables what the bridge installed, and no other: a key that makes the
/// application run a program (a status line, an API key helper, a credential refresh, a hook, an
/// MCP server), a plugin key with another value, a key nested beyond the plugin's name, and a key
/// in another document are refused before anything is written. This closes the class by
/// construction, because no configuration value a bridge adds can hold a command. The control is
/// another plugin's own enabling key, which is applied.
#[cfg(unix)]
#[test]
fn a_configuration_key_the_host_does_not_permit_a_bridge_to_add_is_refused() {
    let hooks = serde_json::json!({
        "SessionStart": [{"hooks": [{"type": "command", "command": "kr-hook",
                                      "args": ["another-agent", "hook"]}]}]
    })
    .to_string();
    for (key, value) in [
        ("hooks", hooks.as_str()),
        ("statusLine.command", r#""other-command""#),
        (
            "statusLine",
            r#"{"type": "command", "command": "other-command"}"#,
        ),
        (
            "apiKeyHelper",
            r#""sh ~/.claude/skills/kalareach-channels/helper.sh""#,
        ),
        ("awsAuthRefresh", r#""other-command""#),
        ("awsCredentialExport", r#""other-command""#),
        ("otelHeadersHelper", r#""other-command""#),
        ("mcpServers.channels.command", r#""other-command""#),
        ("env.LD_PRELOAD", r#""/tmp/x""#),
        ("enabledPlugins", r#"{"a@skills-dir": true}"#),
        ("enabledPlugins.other@skills-dir", "false"),
        ("enabledPlugins.other@skills-dir", r#""yes""#),
        (
            "enabledPlugins.other@skills-dir",
            r#"{"command": "other-command"}"#,
        ),
        ("enabledPlugins.a.b", "true"),
        // A plugin the recipe did not install, a key without the suffix that names the source,
        // a value that is the text "true" or has anything beside it.
        ("enabledPlugins.another-plugin@skills-dir", "true"),
        ("enabledPlugins.kalareach-channels", "true"),
        ("enabledPlugins.kalareach-channels@other", "true"),
        ("enabledPlugins.kalareach-channels@skills-dir", r#""true""#),
        ("enabledPlugins.kalareach-channels@skills-dir", " true"),
        ("enabledPlugins.Kalareach-Channels@skills-dir", "true"),
        ("enabledPlugins.", "true"),
        ("enabledPlugins.bad name", "true"),
        ("permissions.allow", r#"["Bash(*)"]"#),
    ] {
        let site = Site::new();
        let before = site.tree();
        let target = BridgeTarget {
            recipe: recipe_adding_key(key, value),
            ..site.release()
        };
        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&target))
            .expect("reconciles");
        let reason = refused(&settled);
        assert!(
            reason.contains(UNPERMITTED_KEY) && reason.contains(key),
            "{key} = {value}: refused as a key this host does not permit: {reason}"
        );
        assert_eq!(site.tree(), before, "{key} = {value}: nothing was written");
    }
    // The same key in another document is not the one this host names.
    let site = Site::new();
    let before = site.tree();
    let mut recipe = serde_json::to_value(recipe()).expect("the recipe encodes");
    for list in ["install", "remove"] {
        for step in recipe[list].as_array_mut().expect("steps") {
            if step["file"] == "settings.json" {
                step["file"] = serde_json::json!("settings.local.json");
            }
        }
    }
    let target = BridgeTarget {
        recipe: serde_json::from_value(recipe).expect("a recipe"),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");
    assert!(
        refused(&settled).contains(UNPERMITTED_KEY)
            && refused(&settled).contains("settings.local.json"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before, "nothing was written");
    // The control: the recipe itself, which installs one registration and enables that one.
    let site = Site::new();
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert_eq!(settled, Settled::Applied, "{settled:?}");
}

/// The recipe of release 0.3.0 with its registration under `directory` and the key that enables
/// it named for the same: the one set of names a recipe may use for itself.
#[cfg(unix)]
fn recipe_named(directory: &str) -> NativeBridge {
    let mut recipe = serde_json::to_value(recipe()).expect("the recipe encodes");
    for list in ["install", "remove"] {
        for step in recipe[list].as_array_mut().expect("steps") {
            for member in ["destination", "key"] {
                if let Some(text) = step[member].as_str() {
                    step[member] = serde_json::json!(text.replace("kalareach-channels", directory));
                }
            }
        }
    }
    serde_json::from_value(recipe).expect("a recipe")
}

/// A native bridge installs the registration files its application reads from one directory of
/// its own and nothing else: a settings document (which a recipe could make hold a helper command
/// no key table sees), a file in another directory or in more than one, one that is nested deeper,
/// a name in another case, and a name the table does not list are refused before anything is
/// written, and the key that enables a registration names the directory the files are in. The
/// control is the same recipe under another name, which is applied.
#[cfg(unix)]
#[test]
fn a_file_a_bridge_installs_outside_the_registration_this_host_names_is_refused() {
    let helper: &[u8] = br#"{"apiKeyHelper": "other-command"}"#;
    let destinations = [
        "settings.json",
        "Settings.json",
        "settings.local.json",
        "skills/kalareach-channels/settings.json",
        "skills/kalareach-channels/helper.json",
        "skills/kalareach-channels/.MCP.json",
        "skills/kalareach-channels/hooks/hooks.JSON",
        "skills/kalareach-channels/hooks/extra/hooks.json",
        "Skills/kalareach-channels/hooks/hooks.json",
        "skills/Kalareach-Channels/hooks/hooks.json",
        "skills/kalareach.channels/hooks/hooks.json",
        "skills/hooks/hooks.json",
        "plugins/kalareach-channels/hooks/hooks.json",
    ];
    for destination in destinations {
        let site = Site::new();
        let before = site.tree();
        std::fs::write(site.package("a").join("bridge/hooks.json"), helper).expect("changes it");
        let digest = PayloadDigest::of(helper).to_string();
        let mut recipe =
            serde_json::to_value(recipe_with_hooks(&digest)).expect("the recipe encodes");
        for list in ["install", "remove"] {
            for step in recipe[list].as_array_mut().expect("steps") {
                if step["destination"] == HOOKS_PATH {
                    step["destination"] = serde_json::json!(destination);
                }
            }
        }
        let target = BridgeTarget {
            recipe: serde_json::from_value(recipe).expect("a recipe"),
            ..site.release()
        };
        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&target))
            .expect("reconciles");
        let reason = refused(&settled);
        assert!(
            reason.contains("does not permit a native bridge"),
            "{destination}: {reason}"
        );
        assert_eq!(site.tree(), before, "{destination}: nothing was written");
    }
    // Two directories, and a key for a directory the files are not in.
    let site = Site::new();
    let before = site.tree();
    let mut split = serde_json::to_value(recipe()).expect("the recipe encodes");
    for list in ["install", "remove"] {
        for step in split[list].as_array_mut().expect("steps") {
            if step["destination"] == SERVERS_PATH {
                step["destination"] = serde_json::json!("skills/other/.mcp.json");
            }
        }
    }
    let target = BridgeTarget {
        recipe: serde_json::from_value(split).expect("a recipe"),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");
    assert!(
        refused(&settled).contains("more than one directory"),
        "{settled:?}"
    );
    assert_eq!(site.tree(), before, "nothing was written");
    // A key that comes first in the recipe is held to the files that follow it.
    let site = Site::new();
    let mut reordered = serde_json::to_value(recipe()).expect("the recipe encodes");
    let steps = reordered["install"].as_array_mut().expect("steps");
    let key = steps.pop().expect("the key step");
    steps.insert(0, key);
    let target = BridgeTarget {
        recipe: serde_json::from_value(reordered).expect("a recipe"),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");
    assert_eq!(settled, Settled::Applied, "{settled:?}");
    // The control: the whole recipe under another name.
    let site = Site::new();
    let target = BridgeTarget {
        recipe: recipe_named("another-name"),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");
    assert_eq!(settled, Settled::Applied, "{settled:?}");
}

/// A file a recipe installs is JSON this host can read, whatever its name says, or the recipe is
/// refused: an application that reads it more leniently, or runs it as a script, would act on
/// bytes this host never checked. A script, a comment, a trailing comma, text that is not JSON, a
/// document nested deeper than this host reads and an empty file are each refused, and nothing is
/// written. The control is the same file as JSON.
#[cfg(unix)]
#[test]
fn a_file_a_recipe_installs_that_is_not_json_this_host_can_read_is_refused() {
    let deep = format!("{}0{}", "[".repeat(300), "]".repeat(300));
    let cases: [&[u8]; 6] = [
        b"{ // a comment\n \"hooks\": {} }",
        b"{\"hooks\": {},}",
        b"not json at all",
        b"#!/bin/sh\nother-command\n",
        deep.as_bytes(),
        b"",
    ];
    for bytes in cases {
        let site = Site::new();
        std::fs::write(site.package("a").join("bridge/hooks.json"), bytes).expect("changes it");
        let before = site.tree();
        let digest = PayloadDigest::of(bytes).to_string();
        let target = BridgeTarget {
            recipe: recipe_with_hooks(&digest),
            ..site.release()
        };

        let settled = site
            .bridges()
            .reconcile(&plugin(), Some(&target))
            .expect("reconciles");

        let reason = refused(&settled);
        assert!(
            reason.contains("cannot be read as JSON"),
            "{:?}: {reason}",
            String::from_utf8_lossy(bytes)
        );
        assert_eq!(site.tree(), before, "nothing was written");
    }
    let site = Site::new();
    let json: &[u8] = b"{\"hooks\": {}}";
    std::fs::write(site.package("a").join("bridge/hooks.json"), json).expect("changes it");
    let target = BridgeTarget {
        recipe: recipe_with_hooks(&PayloadDigest::of(json).to_string()),
        ..site.release()
    };
    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&target))
        .expect("reconciles");
    assert_eq!(settled, Settled::Applied, "{settled:?}");
}

/// A forwarder the host cannot name, and an application it does not know, refuse the recipe.
#[cfg(unix)]
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
#[cfg(unix)]
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

/// On Windows the host changes no application's directory. Each reconciliation refuses before
/// anything is written there and records why in the package's journal, and every one after the
/// first replaces that journal with a copy compared with it, leaving nothing else beside it.
#[cfg(windows)]
#[test]
fn on_windows_a_recipe_is_refused_and_recorded_at_every_reconciliation() {
    let why = "does not apply or remove a native bridge on Windows";
    let site = Site::new();
    let before = site.tree();
    let bridges = site.bridges();

    for _ in 0..3 {
        let settled = bridges
            .reconcile(&plugin(), Some(&site.release()))
            .expect("the refusal is recorded");
        assert!(refused(&settled).contains(why), "{settled:?}");
        assert_eq!(site.tree(), before, "nothing was written");
        // The journal read back says the same: the refusal, and why.
        let reports = bridges.reports().expect("reads");
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].state, "refused", "{reports:?}");
        assert!(
            reports[0].notes.iter().any(|note| note.contains(why)),
            "{reports:?}"
        );
        // The doctor reports it as refused, with nothing of it in place, and it is no warning.
        let check = kr_controller::catalogue::native_bridge::check(&reports);
        assert_eq!(check.status, kr_protocol::hostinfo::DoctorStatus::Ok);
        assert!(check.detail().contains("refused"), "{}", check.detail());
    }
    let journals: Vec<_> = std::fs::read_dir(site.root.join("state/native-bridges"))
        .expect("the journals")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(journals.len(), 1, "one journal and no copy: {journals:?}");
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
    // The record says so too, and so does a host started again, until the file is gone.
    let unclean = |bridges: &NativeBridges| {
        let reports = bridges.reports().expect("reads");
        assert_eq!(reports[0].state, "unsettled", "{reports:?}");
        assert!(
            reports[0]
                .notes
                .iter()
                .any(|note| note.starts_with("left in place") && note.contains(HOOKS_PATH)),
            "{reports:?}"
        );
    };
    unclean(&bridges);
    let restarted = site.bridges();
    let settled = restarted
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");
    assert!(
        matches!(&settled, Settled::Unsettled(reason) if reason.contains(HOOKS_PATH)),
        "{settled:?}"
    );
    unclean(&restarted);
    std::fs::remove_file(&hooks).expect("its owner removes it");
    assert_eq!(
        restarted
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles"),
        Settled::Applied
    );
    assert_eq!(
        restarted.reports().expect("reads")[0].state,
        "applied",
        "once it is gone"
    );
}

/// A refusal stopped at any of its steps, and settled by a host started again, is never reported
/// as clean while a file it placed, and somebody changed, is still there.
#[cfg(unix)]
#[test]
fn a_refusal_stopped_at_each_boundary_is_never_clean_while_a_changed_file_remains() {
    let mut reached = 0;
    for step in 1.. {
        let site = Site::new();
        let bridges = site.bridges();
        let hooks = site.application().join(HOOKS_PATH);
        {
            let document = site.application().join("settings.json");
            let hooks = hooks.clone();
            let edits = std::sync::atomic::AtomicUsize::new(0);
            bridges.before_publishing(move |destination: &Path| {
                if destination == document {
                    let edit = edits.fetch_add(1, Ordering::SeqCst);
                    if edit == 0 {
                        std::fs::write(&hooks, b"{\"hooks\": {}}").expect("somebody edits it");
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
        bridges.stop_before(step);
        if bridges.reconcile(&plugin(), Some(&site.release())).is_ok() {
            break;
        }

        let restarted = site.bridges();
        let settled = restarted
            .reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles");

        let changed_left = std::fs::read(&hooks).is_ok_and(|bytes| bytes == b"{\"hooks\": {}}");
        if changed_left {
            reached += 1;
            assert!(
                !matches!(settled, Settled::Refused(_) | Settled::Applied),
                "step {step}: {settled:?}"
            );
            let reports = restarted.reports().expect("reads");
            assert_ne!(reports[0].state, "refused", "step {step}: {reports:?}");
            assert!(
                reports[0]
                    .notes
                    .iter()
                    .any(|note| note.contains(HOOKS_PATH)),
                "step {step}: {reports:?}"
            );
        }
    }
    assert!(
        reached > 5,
        "the changed file was left at several boundaries: {reached}"
    );
}

/// A refusal names the file its undo had to leave even when, in the same run, something an earlier
/// removal left is found gone.
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

/// A document a replacement would give another group is not replaced: the replacement would
/// change who can read or change it.
#[cfg(unix)]
#[test]
fn a_document_a_replacement_would_give_another_group_is_refused() {
    use std::os::unix::fs::MetadataExt as _;
    let site = Site::new();
    let document = site.application().join("settings.json");
    let current = std::fs::metadata(&document).expect("reads").gid();
    let groups = std::process::Command::new("id")
        .arg("-G")
        .output()
        .expect("the account's groups");
    let other = String::from_utf8_lossy(&groups.stdout)
        .split_whitespace()
        .filter_map(|group| group.parse::<u32>().ok())
        .find(|group| *group != current);
    let Some(other) = other else {
        eprintln!("skipped: this account belongs to no second group to give the document");
        return;
    };
    std::os::unix::fs::chown(&document, None, Some(other)).expect("another group");
    let before = site.tree();

    let settled = site
        .bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("belongs to"), "{settled:?}");
    assert_eq!(site.tree(), before, "nothing of the recipe is left");
    assert_eq!(
        std::fs::metadata(&document).expect("reads").gid(),
        other,
        "the document keeps its group"
    );
}

/// A document given another group between the read and the replacement is read again, and not
/// replaced by a copy that would take that group away.
#[cfg(unix)]
#[test]
fn a_document_given_another_group_meanwhile_is_not_replaced() {
    use std::os::unix::fs::MetadataExt as _;
    let site = Site::new();
    let document = site.application().join("settings.json");
    let current = std::fs::metadata(&document).expect("reads").gid();
    let groups = std::process::Command::new("id")
        .arg("-G")
        .output()
        .expect("the account's groups");
    let other = String::from_utf8_lossy(&groups.stdout)
        .split_whitespace()
        .filter_map(|group| group.parse::<u32>().ok())
        .find(|group| *group != current);
    let Some(other) = other else {
        eprintln!("skipped: this account belongs to no second group to give the document");
        return;
    };
    let bridges = site.bridges();
    {
        let document = document.clone();
        bridges.before_publishing(move |destination: &Path| {
            if destination == document {
                std::os::unix::fs::chown(&document, None, Some(other))
                    .expect("somebody gives it another group meanwhile");
            }
        });
    }

    let settled = bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("belongs to"), "{settled:?}");
    assert_eq!(
        std::fs::metadata(&document).expect("reads").gid(),
        other,
        "the document keeps the group it was given"
    );
    assert_eq!(
        std::fs::read_to_string(&document).expect("reads"),
        SETTINGS,
        "and its bytes"
    );
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
#[cfg(unix)]
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

        let next = site.bridges();
        let settled = next.reconcile(&plugin(), None).expect("reconciles");

        assert!(
            matches!(settled, Settled::Unsettled(_)),
            "{published}: {settled:?}"
        );
        // The publication is recorded only after its directory is flushed, although nothing
        // was taken from the temporary name.
        let steps = next.steps();
        let directory = site
            .application()
            .join(published)
            .parent()
            .expect("a directory")
            .display()
            .to_string();
        let flushed = steps
            .iter()
            .position(|step| *step == format!("flush {directory}"))
            .expect("the directory is flushed");
        let recorded = steps
            .iter()
            .position(|step| step.starts_with("save "))
            .expect("the publication is recorded");
        assert!(flushed < recorded, "{published}: {steps:?}");
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

/// A staged write that fails takes back the file it made, and never a file somebody put at its
/// name meanwhile: that one is left and named.
#[cfg(unix)]
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
#[cfg(unix)]
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
    // Bounded by the run: the search ends at the first step past the last one a run makes.
    let first = (1..)
        .map_while(|step| stopped_at(step + 1, &|_| {}, &apply).map(|stopped| (step, stopped)))
        .find(|(_, stopped)| stopped.steps.last() == Some(&before_rename(&stopped.site)))
        .map(|(step, _)| step)
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
#[cfg(unix)]
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
#[cfg(unix)]
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

/// A record of something left or not settled goes only once its absence is shown in its own
/// directory and flushed.
#[cfg(unix)]
#[test]
fn a_record_goes_only_once_its_absence_is_flushed() {
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
    let path = site.application().join(&left[0]);
    if path.is_dir() {
        std::fs::remove_dir(&path).expect("its owner removes it");
    } else {
        std::fs::remove_file(&path).expect("its owner removes it");
    }

    let next = site.bridges();
    assert_eq!(
        next.reconcile(&plugin(), Some(&site.release()))
            .expect("reconciles"),
        Settled::Unchanged
    );

    let steps = next.steps();
    let directory = format!("flush {}", path.parent().expect("a directory").display());
    let flushed = steps
        .iter()
        .position(|step| *step == directory)
        .expect("its directory is flushed");
    let recorded = steps
        .iter()
        .position(|step| step.starts_with("save "))
        .expect("the record goes");
    assert!(flushed < recorded, "{steps:?}");
}

/// An application directory with nothing at its path, whether moved away or behind a link that
/// leads nowhere now, is not taken as deleted: what was placed stays recorded, and is taken out
/// once the directory is back. A change a stopped run left in flight is settled then from the
/// identities it recorded, so nothing is left behind.
#[cfg(unix)]
#[test]
fn a_missing_application_directory_keeps_what_was_placed_recorded() {
    for dangling in [false, true] {
        let site = Site::new();
        let before = site.tree();
        let bridges = site.bridges();
        bridges
            .reconcile(&plugin(), Some(&site.release()))
            .expect("applies");
        let original = site.root.join("home/.claude-original");
        std::fs::rename(site.application(), &original).expect("somebody moves it away");
        if dangling {
            std::os::unix::fs::symlink(site.root.join("nowhere"), site.application())
                .expect("and leaves a link that leads nowhere");
        }

        let settled = bridges.reconcile(&plugin(), None).expect("reconciles");

        assert!(
            matches!(settled, Settled::Unsettled(_)),
            "dangling {dangling}: {settled:?}"
        );
        let reports = bridges.reports().expect("reads");
        assert_eq!(
            reports[0].state, "removing",
            "dangling {dangling}: {reports:?}"
        );
        assert!(
            reports[0].notes.iter().any(|note| {
                note.starts_with("could not be taken out") && note.contains("is not there")
            }),
            "dangling {dangling}: {reports:?}"
        );
        if dangling {
            std::fs::remove_file(site.application()).expect("the link goes");
        }
        std::fs::rename(&original, site.application()).expect("the directory comes back");
        assert_eq!(
            bridges.reconcile(&plugin(), None).expect("reconciles"),
            Settled::Removed,
            "dangling {dangling}"
        );
        assert_eq!(site.tree(), before, "dangling {dangling}: removed exactly");
    }

    // A staged copy recorded and not yet renamed, while the directory is away.
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let stopped = (1..)
        .map_while(|step| stopped_at(step, &|_| {}, &apply))
        .find(|stopped| {
            let [.., staged, last] = stopped.steps.as_slice() else {
                return false;
            };
            staged.starts_with("stage ") && last.starts_with("save ")
        })
        .expect("a run stopped with a staged copy recorded");
    let site = &stopped.site;
    let before = Site::new().tree();
    let original = site.root.join("home/.claude-original");
    std::fs::rename(site.application(), &original).expect("somebody moves it away");

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
            .any(|note| note.starts_with("not settled") && note.contains("cannot be opened")),
        "{reports:?}"
    );
    std::fs::rename(&original, site.application()).expect("the directory comes back");
    assert_eq!(
        site.bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles"),
        Settled::Removed
    );
    assert_eq!(
        site.tree(),
        before,
        "the staged copy went by its recorded identity"
    );
}

/// A second link to the published file at its former temporary name does not hide the
/// publication: taking the link back still leaves the destination to be settled, and the removal
/// takes out what was published. Where the destination has since been replaced by a copy that holds
/// the key, the key is not the host's to take or to forget: it is named as not settled.
#[cfg(unix)]
#[test]
fn a_second_link_at_a_temporary_name_does_not_hide_what_was_published() {
    let before = Site::new().tree();
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let rename = |site: &Site| {
        format!(
            "rename {}",
            site.application().join("settings.json").display()
        )
    };
    for copied in [false, true] {
        let stopped = (1..)
            .map_while(|step| stopped_at(step, &|_| {}, &apply))
            .find(|stopped| stopped.steps.last() == Some(&rename(&stopped.site)))
            .expect("the settings document's rename was reached");
        let site = &stopped.site;
        let document = site.application().join("settings.json");
        let staged = stopped
            .steps
            .iter()
            .rev()
            .find_map(|step| step.strip_prefix("stage "))
            .map(PathBuf::from)
            .expect("the staged copy");
        std::fs::hard_link(&document, &staged)
            .expect("somebody links the document at its former temporary name");
        if copied {
            let copy = site.root.join("settings-copy.json");
            std::fs::copy(&document, &copy).expect("a copy");
            std::fs::rename(&copy, &document).expect("put in its place");
        }

        let settled = site
            .bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        if copied {
            assert!(matches!(settled, Settled::Unsettled(_)), "{settled:?}");
            assert_eq!(
                std::fs::read_to_string(&document).expect("reads"),
                SETTINGS_WITH_KEY,
                "the key in the copy is not taken"
            );
            let reports = site.bridges().reports().expect("reads");
            assert!(
                reports[0].notes.iter().any(|note| {
                    note.starts_with("not settled")
                        && note.contains("enabledPlugins.kalareach-channels@skills-dir")
                }),
                "{reports:?}"
            );
        } else {
            assert_eq!(settled, Settled::Removed);
            assert_eq!(site.tree(), before, "the key is taken out, and the link");
        }
    }
}

/// A file somebody changed in place after this host renamed it into place, and before the host
/// recorded doing so, is still the file this host placed: recovery records it, the removal leaves it
/// as changed and names it, and a refusal is not reported as clean while it is there. The
/// directories on the way are there already, so no directory of the host's is left to say so.
#[cfg(unix)]
#[test]
fn a_file_changed_between_its_rename_and_its_record_is_still_the_hosts() {
    use std::io::Write as _;
    let prepare = |site: &Site| {
        for directory in [
            "skills/kalareach-channels/.claude-plugin",
            "skills/kalareach-channels/hooks",
        ] {
            std::fs::create_dir_all(site.application().join(directory)).expect("a directory");
        }
    };
    let apply =
        |site: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), Some(&site.release()));
    let rename = |site: &Site| format!("rename {}", site.application().join(HOOKS_PATH).display());
    let stopped = (1..)
        .map_while(|step| stopped_at(step, &prepare, &apply))
        .find(|stopped| stopped.steps.last() == Some(&rename(&stopped.site)))
        .expect("the hooks file's rename was reached");
    let site = &stopped.site;
    let hooks = site.application().join(HOOKS_PATH);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&hooks)
        .and_then(|mut file| file.write_all(b"\n"))
        .expect("somebody appends to it in place");
    let changed = std::fs::read(&hooks).expect("reads");

    let restarted = site.bridges();
    let settled = restarted
        .reconcile(&plugin(), Some(&site.release()))
        .expect("reconciles");

    assert!(
        !matches!(settled, Settled::Refused(_) | Settled::Applied),
        "{settled:?}"
    );
    assert_eq!(std::fs::read(&hooks).expect("left"), changed);
    let reports = restarted.reports().expect("reads");
    assert_ne!(reports[0].state, "refused", "{reports:?}");
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.starts_with("left in place") && note.contains(HOOKS_PATH)),
        "{reports:?}"
    );
}

/// A key somebody else took out of the document is recorded as gone only once the document as it
/// is now, and its directory, are durable.
#[cfg(unix)]
#[test]
fn a_key_found_gone_is_recorded_only_after_its_document_is_synced() {
    let site = Site::new();
    site.bridges()
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let document = site.application().join("settings.json");
    std::fs::write(&document, SETTINGS).expect("somebody takes the key out in place");
    let bridges = site.bridges();

    assert_eq!(
        bridges.reconcile(&plugin(), None).expect("removes"),
        Settled::Removed
    );

    let steps = bridges.steps();
    let synced = steps
        .iter()
        .position(|step| *step == format!("sync {}", document.display()))
        .expect("the document is synced");
    let flushed = steps
        .iter()
        .position(|step| *step == format!("flush {}", site.application().display()))
        .expect("its directory is flushed");
    // One save marks the removal as begun; the next records the key gone.
    let saves: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step.starts_with("save "))
        .map(|(index, _)| index)
        .collect();
    assert!(
        saves.len() >= 2 && saves[0] < synced && synced < flushed && flushed < saves[1],
        "{steps:?}"
    );
}

/// A settings document somebody put in the place of the one this host created, with the same
/// bytes, is not deleted by the removal: it keeps its file, and loses only the key.
#[cfg(unix)]
#[test]
fn a_document_put_in_the_place_of_the_created_one_keeps_its_file() {
    let site = Site::with_settings(None);
    let bridges = site.bridges();
    bridges
        .reconcile(&plugin(), Some(&site.release()))
        .expect("applies");
    let document = site.application().join("settings.json");
    let copy = site.root.join("settings-copy.json");
    std::fs::copy(&document, &copy).expect("a copy");
    std::fs::rename(&copy, &document).expect("put in its place");

    assert_eq!(
        bridges.reconcile(&plugin(), None).expect("reconciles"),
        Settled::Removed
    );

    let text = std::fs::read_to_string(&document).expect("the document is still there");
    assert!(
        !text.contains("kalareach-channels@skills-dir"),
        "the key is taken out of it: {text}"
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

// ---------------------------------------------------------------------------------------------
// The Gemini CLI recipe
// ---------------------------------------------------------------------------------------------

/// The digests the Gemini CLI package's recipe names for its three files, which the files this
/// repository pins in `fixtures/bridges/gemini-cli/` carry.
const GEMINI_RECORD_DIGEST: &str =
    "ed5b5291f2e39bf679e945135210c5aee7863b8b8dbaa049dd53598507f172cb";
const GEMINI_MANIFEST_DIGEST: &str =
    "2ea510ab37639c8f4b9e380c3a168b06771088d31b2b933549213479d5e764e7";
const GEMINI_HOOKS_DIGEST: &str =
    "3ea3470d1d88d3f0d828668bcd98bacfa37b20fd638b6f5b38b7ddd58f55c0ba";

const GEMINI_RECORD_PATH: &str = "extensions/kalareach/.gemini-extension-install.json";
const GEMINI_MANIFEST_PATH: &str = "extensions/kalareach/gemini-extension.json";
const GEMINI_HOOKS_PATH: &str = "extensions/kalareach/hooks/hooks.json";

/// Somebody's own Gemini CLI settings, with a number a rewrite would spell differently.
const GEMINI_SETTINGS: &str = "{\n  \"theme\": \"dark\",\n  \"maxSessionTurns\": 1e2,\n  \"security\": {\"allowedExtensions\": [\"^/dev/null/kalareach$\"]}\n}\n";

/// The stand-in for Gemini CLI's executable, hashed for its version and never run.
const GEMINI_EXECUTABLE: &[u8] = b"\x7fELF a stand-in for Gemini CLI, hashed and never run";

fn gemini() -> PluginId {
    PluginId::new("kalareach/gemini-cli").expect("a plugin identifier")
}

/// The bytes of one pinned Gemini CLI file.
fn gemini_pinned(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/bridges/gemini-cli")
            .join(name),
    )
    .expect("a pinned Gemini CLI file")
}

/// The recipe the Gemini CLI package ships, as its manifest states it.
fn gemini_recipe() -> NativeBridge {
    serde_json::from_value(serde_json::json!({
        "application": "Gemini CLI",
        "application_range": "=0.60.0",
        "install": [
            {"type": "install_file", "source": "bridge/gemini-extension-install.json",
             "destination": GEMINI_RECORD_PATH, "digest": GEMINI_RECORD_DIGEST},
            {"type": "install_file", "source": "bridge/gemini-extension.json",
             "destination": GEMINI_MANIFEST_PATH, "digest": GEMINI_MANIFEST_DIGEST},
            {"type": "install_file", "source": "bridge/hooks.json",
             "destination": GEMINI_HOOKS_PATH, "digest": GEMINI_HOOKS_DIGEST}
        ],
        "remove": [
            {"type": "remove_file", "destination": GEMINI_HOOKS_PATH,
             "digest": GEMINI_HOOKS_DIGEST},
            {"type": "remove_file", "destination": GEMINI_MANIFEST_PATH,
             "digest": GEMINI_MANIFEST_DIGEST},
            {"type": "remove_file", "destination": GEMINI_RECORD_PATH,
             "digest": GEMINI_RECORD_DIGEST}
        ],
        "grant_statement": "Installs three files under your own Gemini CLI directory: the manifest of an extension named kalareach, its hooks, and the record of where it is installed. Gemini CLI then starts the KalaReach forwarder itself, through bash, so the forwarder runs under Gemini CLI's own permissions and outside the KalaReach plugin sandbox, outside Wasmtime."
    }))
    .expect("the Gemini CLI recipe")
}

fn gemini_match_rules() -> Vec<MatchRule> {
    serde_json::from_value(serde_json::json!([
        {"id": "gemini-cli-npm",
         "executable": {"file_stem": "gemini", "path_suffix": [], "version_range": null},
         "distribution": {"registry": "npm", "package": "@google/gemini-cli"},
         "confidence": "exact"},
        {"id": "gemini-cli-executable",
         "executable": {"file_stem": "gemini", "path_suffix": [], "version_range": null},
         "distribution": null,
         "confidence": "inferred"}
    ]))
    .expect("the release's match rules")
}

/// One test's own directories for the Gemini CLI: its directory with somebody's settings and
/// somebody's own extension in it, a search path with a stand-in for its executable and for the
/// forwarder, and a package directory holding the recipe's files.
struct GeminiSite {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl GeminiSite {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("a temporary directory");
        let root = temp.path().to_path_buf();
        let site = Self { _temp: temp, root };
        std::fs::create_dir_all(site.application().join("extensions/theirs"))
            .expect("an extension");
        std::fs::write(site.application().join("settings.json"), GEMINI_SETTINGS)
            .expect("settings");
        std::fs::write(
            site.application()
                .join("extensions/theirs/gemini-extension.json"),
            "{\"name\": \"theirs\", \"version\": \"1.0.0\"}\n",
        )
        .expect("an extension manifest");
        std::fs::create_dir_all(site.root.join("bin")).expect("a search path");
        std::fs::write(site.root.join("bin/gemini"), GEMINI_EXECUTABLE).expect("an executable");
        std::fs::write(site.forwarder(), b"a stand-in for the forwarder").expect("a forwarder");
        for name in [
            "gemini-extension-install.json",
            "gemini-extension.json",
            "hooks.json",
        ] {
            let path = site.package().join("bridge").join(name);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a package");
            std::fs::write(path, gemini_pinned(name)).expect("a package file");
        }
        site
    }

    fn application(&self) -> PathBuf {
        self.root.join("home/.gemini")
    }

    fn forwarder(&self) -> PathBuf {
        self.root.join("bin/kr-hook")
    }

    fn package(&self) -> PathBuf {
        self.root.join("packages/gemini")
    }

    fn host(&self) -> BridgeHost {
        BridgeHost {
            journals: self.root.join("state/native-bridges"),
            applications: vec![ApplicationDirectory {
                application: "Gemini CLI".to_owned(),
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

    /// The release the package ships, with a signed record naming the stand-in executable at the
    /// one version the recipe accepts.
    fn release(&self) -> BridgeTarget {
        BridgeTarget {
            plugin_id: gemini(),
            package_digest: PayloadDigest::of(b"gemini release"),
            package_dir: self.package(),
            recipe: gemini_recipe(),
            match_rules: gemini_match_rules(),
            qualified: vec![QualifiedExecutable {
                digest: hex_digest(GEMINI_EXECUTABLE),
                version: "0.60.0".to_owned(),
            }],
        }
    }

    fn tree(&self) -> BTreeMap<String, Node> {
        snapshot(&self.application())
    }

    /// The tree a Gemini CLI directory has once the recipe is applied: the extension's
    /// directories and its three files, and nothing of anybody's own touched.
    fn applied(&self, before: &BTreeMap<String, Node>) -> BTreeMap<String, Node> {
        let mut expected = before.clone();
        for directory in ["extensions/kalareach", "extensions/kalareach/hooks"] {
            expected.insert(directory.to_owned(), Node::Directory);
        }
        for (path, name) in [
            (GEMINI_RECORD_PATH, "gemini-extension-install.json"),
            (GEMINI_MANIFEST_PATH, "gemini-extension.json"),
            (GEMINI_HOOKS_PATH, "hooks.json"),
        ] {
            expected.insert(path.to_owned(), Node::File(gemini_pinned(name)));
        }
        expected
    }
}

/// KR-REQ-11.42: a host names Claude Code's directory, `.claude` under the account's home, and no
/// other application's. Gemini CLI's is not named, so its recipe places nothing on a host: removal
/// would have to keep the install record for as long as anything else stays in the extension's
/// directory, which a recipe cannot say.
#[test]
fn kr_req_11_42_the_host_names_claude_codes_directory_and_no_other() {
    use kr_controller::catalogue::native_bridge::application_directories;
    let home = Path::new("/home/somebody");
    let named: Vec<(String, PathBuf)> = application_directories(home)
        .into_iter()
        .map(|directory| (directory.application, directory.directory))
        .collect();
    assert_eq!(
        named,
        [("Claude Code".to_owned(), home.join(".claude"))],
        "the application directories a host names"
    );
}

/// KR-REQ-11.42: the Gemini CLI recipe writes the extension's three files, in the directories it
/// makes, and nothing else: somebody's settings and somebody's own extension keep their bytes.
/// The forwarder its hooks start is named for the application the registration says, and the
/// registration is a hook.
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_gemini_cli_recipe_writes_its_three_files_and_nothing_else() {
    let site = GeminiSite::new();
    let before = site.tree();
    let bridges = site.bridges();

    let settled = bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("reconciles");

    assert_eq!(settled, Settled::Applied);
    assert_eq!(
        site.tree(),
        site.applied(&before),
        "exactly the recipe's changes"
    );
    for path in ["settings.json", "extensions/theirs/gemini-extension.json"] {
        assert_eq!(site.tree()[path], before[path], "{path} keeps its bytes");
    }
    let facts = bridges
        .facts(&gemini(), site.release().package_digest)
        .expect("reads")
        .expect("applied, with the registration read from the hooks file");
    assert_eq!(
        facts.application, "gemini-cli",
        "the name the hooks invoke the forwarder for"
    );
    assert_eq!(
        facts.surfaces,
        [BridgeSurface::Hook].into_iter().collect(),
        "the hooks file registers hooks and no channel"
    );
    assert_eq!(facts.forwarder, site.forwarder());
}

/// KR-REQ-11.42: removal takes the three files and the directories the installation made, and the
/// Gemini CLI directory is again byte for byte what it was. The control is a directory that holds
/// nothing of anybody's own, which is left empty.
#[cfg(unix)]
#[test]
fn kr_req_11_42_removing_the_gemini_cli_recipe_restores_the_directory() {
    let site = GeminiSite::new();
    let before = site.tree();
    let bridges = site.bridges();
    bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("applies");
    assert_ne!(site.tree(), before);

    let settled = bridges.reconcile(&gemini(), None).expect("removes");

    assert_eq!(settled, Settled::Removed);
    assert_eq!(site.tree(), before, "the directory is what it was");
    assert!(bridges.reports().expect("reads").is_empty());
    assert!(
        bridges
            .facts(&gemini(), site.release().package_digest)
            .expect("reads")
            .is_none()
    );
}

/// KR-REQ-11.42: where something else has to stay in the extension's directory, a file of
/// somebody's own or one that changed since it was installed, removal keeps the record of where the
/// extension is installed with it, because Gemini CLI refuses to start while an extension's
/// directory has no record where its settings list the extensions allowed. What was ours and still
/// holds its bytes goes. The control is the case above: a directory with nothing else in it loses
/// the record with the rest.
///
/// A recipe's removal steps each delete a file that still holds its bytes, so no recipe can say
/// "this one last, and only when the directory is otherwise empty": the case fails until the
/// recipe format has such a step.
#[cfg(unix)]
#[test]
#[ignore = "the recipe format has no removal step that waits until nothing else is left"]
fn kr_req_11_42_the_gemini_cli_record_stays_while_anything_else_stays_beside_it() {
    for (name, beside) in [
        ("a file of their own", "notes.txt"),
        ("a hooks file somebody changed", "hooks/hooks.json"),
        ("a manifest somebody changed", "gemini-extension.json"),
    ] {
        let site = GeminiSite::new();
        let bridges = site.bridges();
        bridges
            .reconcile(&gemini(), Some(&site.release()))
            .expect("applies");
        let directory = site.application().join("extensions/kalareach");
        std::fs::write(directory.join(beside), b"somebody's own bytes").expect("somebody's file");

        let settled = bridges.reconcile(&gemini(), None).expect("removes");

        let left = site.tree();
        assert!(
            left.contains_key(GEMINI_RECORD_PATH),
            "{name}: the record stays with {beside}: {settled:?}"
        );
        assert_eq!(
            left[&format!("extensions/kalareach/{beside}")],
            Node::File(b"somebody's own bytes".to_vec()),
            "{name}: what is somebody's stays as it is"
        );
        for ours in [GEMINI_HOOKS_PATH, GEMINI_MANIFEST_PATH] {
            if ours != format!("extensions/kalareach/{beside}") {
                assert!(!left.contains_key(ours), "{name}: {ours} was ours and goes");
            }
        }
        assert!(
            !matches!(settled, Settled::Removed),
            "{name}: a removal that left something is not reported as complete: {settled:?}"
        );
    }
}

/// KR-REQ-11.42: an application the host does not know places nothing: a Gemini CLI recipe on a
/// host that names only Claude Code's directory is refused, naming the application, and nothing is
/// written anywhere.
#[cfg(unix)]
#[test]
fn kr_req_11_42_an_application_the_host_does_not_know_places_nothing() {
    let site = GeminiSite::new();
    let before = site.tree();
    let claude_only = NativeBridges::new(BridgeHost {
        applications: vec![ApplicationDirectory {
            application: "Claude Code".to_owned(),
            directory: site.root.join("home/.claude"),
        }],
        ..site.host()
    });

    let settled = claude_only
        .reconcile(&gemini(), Some(&site.release()))
        .expect("reconciles");

    assert!(refused(&settled).contains("Gemini CLI"), "{settled:?}");
    assert_eq!(site.tree(), before, "nothing was written");
    assert!(
        !site.root.join("home/.claude").exists(),
        "no other application's directory was made"
    );
}

/// KR-REQ-11.42: an installation of the Gemini CLI recipe stopped before any of its steps is never
/// reported as applied, and the next reconciliation finishes it when the release is still wanted
/// and takes it out when it is not. Something made and not yet recorded is named, and the bridge
/// is not reported as applied until its owner removes it.
#[cfg(unix)]
#[test]
fn kr_req_11_42_a_gemini_cli_installation_stopped_at_each_boundary_is_finished_or_undone() {
    let reference = GeminiSite::new();
    let before = reference.tree();
    let applied = reference.applied(&before);
    let mut boundaries = 0;
    let mut unrecorded = 0;
    for step in 1.. {
        let site = GeminiSite::new();
        let bridges = site.bridges();
        bridges.stop_before(step);
        if bridges.reconcile(&gemini(), Some(&site.release())).is_ok() {
            break;
        }
        boundaries += 1;
        let left_unrecorded = bridges
            .steps()
            .last()
            .is_some_and(|last| last.starts_with("stage ") || last.starts_with("make "));
        assert!(
            site.bridges()
                .facts(&gemini(), site.release().package_digest)
                .expect("reads")
                .is_none(),
            "step {step}: never reported as applied while unfinished"
        );
        let finished = site
            .bridges()
            .reconcile(&gemini(), Some(&site.release()))
            .expect("finishes");
        if left_unrecorded {
            unrecorded += 1;
            let Settled::Unsettled(reason) = &finished else {
                panic!("step {step}: {finished:?}");
            };
            let left: Vec<String> = site
                .tree()
                .into_keys()
                .filter(|name| name.contains(".kalareach"))
                .collect();
            assert_eq!(left.len(), 1, "step {step}: {left:?}");
            let name = Path::new(&left[0])
                .file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned();
            assert!(reason.contains(&name), "step {step}: {reason}");
            let path = site.application().join(&left[0]);
            if path.is_dir() {
                std::fs::remove_dir(&path).expect("the owner removes it");
            } else {
                std::fs::remove_file(&path).expect("the owner removes it");
            }
            assert_eq!(
                site.bridges()
                    .reconcile(&gemini(), Some(&site.release()))
                    .expect("finishes"),
                Settled::Unchanged,
                "step {step}"
            );
        } else {
            assert_eq!(finished, Settled::Applied, "step {step}");
        }
        assert_eq!(site.tree(), applied, "step {step}: finished exactly");

        // The same stop, and the release no longer wanted: undone to the byte.
        let site = GeminiSite::new();
        let bridges = site.bridges();
        bridges.stop_before(step);
        assert!(bridges.reconcile(&gemini(), Some(&site.release())).is_err());
        let undone = site
            .bridges()
            .reconcile(&gemini(), None)
            .expect("takes it out");
        if left_unrecorded {
            let Settled::Unsettled(_) = &undone else {
                panic!("step {step}: {undone:?}");
            };
            for name in site
                .tree()
                .into_keys()
                .filter(|name| name.contains(".kalareach"))
                .collect::<Vec<_>>()
            {
                let path = site.application().join(&name);
                if path.is_dir() {
                    std::fs::remove_dir(&path).expect("the owner removes it");
                } else {
                    std::fs::remove_file(&path).expect("the owner removes it");
                }
            }
            site.bridges().reconcile(&gemini(), None).expect("finishes");
        }
        assert_eq!(site.tree(), before, "step {step}: undone exactly");
    }
    assert!(boundaries > 8, "every step was a boundary: {boundaries}");
    assert!(
        unrecorded >= 3,
        "files and directories were made unrecorded: {unrecorded}"
    );
}

/// What the refusal of a command the host does not read says.
#[cfg(unix)]
const UNREAD_COMMAND: &str = "starts the forwarder with arguments it does not accept from a bridge";

/// KR-REQ-11.42: a command that is not a string, and the forwarder's name with an argument list
/// that is not exactly the application and the surface as two words, are commands the host does
/// not read, wherever they stand: a list with a third member of any kind, one that is not a word,
/// a command member that is not text, a one-line command with an argument list beside it, and a
/// member beside the command that a forwarder registration does not use. Each is refused before anything is written, alone and
/// beside a good command.
#[cfg(unix)]
#[test]
fn kr_req_11_42_a_command_in_a_shape_the_host_does_not_read_is_refused_wherever_it_stands() {
    let good = serde_json::json!({"type": "command", "name": "kalareach",
                                  "command": "kr-hook", "args": ["gemini-cli", "hook"]});
    let shapes = [
        serde_json::json!({"type": "command", "name": "kalareach", "command": 5}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": null}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": ["kr-hook"]}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", "hook", 5]}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", "hook", "extra"]}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli"]}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", 5]}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook"}),
        serde_json::json!({"type": "command", "name": "kalareach",
                           "command": "kr-hook gemini-cli hook", "args": ["extra"]}),
        serde_json::json!({"type": "command", "name": "kalareach",
                           "command": "kr-hook gemini-cli hook", "args": []}),
        // A member a forwarder registration does not use can make the program run in another
        // environment or place: it is refused whatever its value.
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", "hook"], "env": {"LD_PRELOAD": "/tmp/x"}}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", "hook"], "cwd": "/tmp"}),
        serde_json::json!({"type": "command", "name": "kalareach", "command": "kr-hook",
                           "args": ["gemini-cli", "hook"], "shell": "bash"}),
        serde_json::json!({"type": "command", "name": "kalareach",
                           "command": "kr-hook gemini-cli hook", "env": {}}),
    ];
    for shape in shapes {
        for hooks in [
            vec![shape.clone()],
            vec![good.clone(), shape.clone()],
            vec![shape.clone(), good.clone()],
        ] {
            let site = GeminiSite::new();
            let before = site.tree();
            let bytes =
                serde_json::json!({"hooks": {"SessionStart": [{"hooks": hooks}]}}).to_string();
            let target = gemini_target_with_hooks(&site, bytes.as_bytes());
            let settled = site
                .bridges()
                .reconcile(&gemini(), Some(&target))
                .expect("reconciles");
            let reason = refused(&settled);
            assert!(
                reason.contains(UNREAD_COMMAND),
                "{bytes}: refused as a command the host does not read: {reason}"
            );
            assert_eq!(site.tree(), before, "{bytes}: nothing was written");
        }
    }
    // The control: the same list form with exactly the application and the surface is applied.
    let site = GeminiSite::new();
    let bytes = serde_json::json!({"hooks": {"SessionStart": [{"hooks": [good]}]}}).to_string();
    let target = gemini_target_with_hooks(&site, bytes.as_bytes());
    assert_eq!(
        site.bridges()
            .reconcile(&gemini(), Some(&target))
            .expect("reconciles"),
        Settled::Applied
    );
}

/// A package whose hooks file is `bytes`, with a recipe that names it.
#[cfg(unix)]
fn gemini_target_with_hooks(site: &GeminiSite, bytes: &[u8]) -> BridgeTarget {
    std::fs::write(site.package().join("bridge/hooks.json"), bytes).expect("a package file");
    let mut recipe = serde_json::to_value(gemini_recipe()).expect("the recipe encodes");
    let digest = PayloadDigest::of(bytes).to_string();
    for list in ["install", "remove"] {
        for step in recipe[list].as_array_mut().expect("steps") {
            if step["destination"] == GEMINI_HOOKS_PATH {
                step["digest"] = serde_json::json!(digest);
            }
        }
    }
    BridgeTarget {
        recipe: serde_json::from_value(recipe).expect("a recipe"),
        ..site.release()
    }
}

/// A hooks file whose entries run `commands`, one hook each.
#[cfg(unix)]
fn gemini_hooks(commands: &[&str]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = commands
        .iter()
        .map(|command| {
            serde_json::json!({"hooks": [{"type": "command", "name": "kalareach",
                                           "command": command, "timeout": 5000}]})
        })
        .collect();
    serde_json::json!({"hooks": {"SessionStart": entries}})
        .to_string()
        .into_bytes()
}

/// KR-REQ-11.42: every command a bridge's registration runs is the forwarder, in a form the host
/// reads: the forwarder's name alone with its arguments in a list, or one line of the forwarder's
/// name, the application it reports for and the surface, separated by single spaces, each word of
/// plain characters. A command that is anything else is refused before anything is written, and
/// it is refused wherever it stands: a quoted or escaped name, an operator, another application
/// or surface, white space other than the one space, and a bad command beside a good one. The
/// control is the line the Gemini CLI package ships.
#[cfg(unix)]
#[test]
fn kr_req_11_42_every_command_a_registration_runs_is_the_forwarder_in_a_form_the_host_reads() {
    let good = "kr-hook gemini-cli hook";
    let refused_alone = [
        "kr-hook gemini-cli hook; touch /tmp/other",
        "kr-hook gemini-cli hook && other",
        "kr-hook gemini-cli  hook",
        "kr-hook gemini-cli\thook",
        "kr-hook gemini-cli",
        "kr-hook gemini-cli hook extra",
        "kr-hook 'gemini-cli' hook",
        "kr-hook gemini$(other) hook",
        "kr-hook `other` hook",
        "kr-hook Gemini-CLI hook",
        "kr-hook 'gemini-cli' channel",
        "kr-hook Gemini-CLI channel",
        "kr-hook gemini-cli tool",
        "\"kr-hook\" another-agent channel; other-command",
        "'kr-hook' gemini-cli hook",
        "kr\\-hook gemini-cli hook",
        "other-command",
        "other-command kr-hook gemini-cli hook",
        " kr-hook gemini-cli hook",
        "kr-hook gemini-cli hook ",
        "",
    ];
    for command in refused_alone {
        // On its own, and beside a command that is good.
        for commands in [vec![command], vec![good, command], vec![command, good]] {
            let site = GeminiSite::new();
            let before = site.tree();
            let target = gemini_target_with_hooks(&site, &gemini_hooks(&commands));
            let settled = site
                .bridges()
                .reconcile(&gemini(), Some(&target))
                .expect("reconciles");
            let reason = refused(&settled);
            assert!(
                reason.contains(UNREAD_COMMAND),
                "{commands:?}: refused as a command the host does not read: {reason}"
            );
            assert_eq!(site.tree(), before, "{commands:?}: nothing was written");
        }
    }
    // A line in the form the host reads, for another application, is read and refused for what it
    // says: the registration is for an application other than the package's.
    let site = GeminiSite::new();
    let before = site.tree();
    let target =
        gemini_target_with_hooks(&site, &gemini_hooks(&[good, "kr-hook another-agent hook"]));
    let settled = site
        .bridges()
        .reconcile(&gemini(), Some(&target))
        .expect("reconciles");
    let reason = refused(&settled);
    assert!(
        reason.contains("gemini-cli") && reason.contains("another-agent"),
        "{reason}"
    );
    assert_eq!(site.tree(), before, "nothing was written");
    // The control: the line the package ships, once and repeated, is applied.
    for commands in [vec![good], vec![good, good]] {
        let site = GeminiSite::new();
        let target = gemini_target_with_hooks(&site, &gemini_hooks(&commands));
        let settled = site
            .bridges()
            .reconcile(&gemini(), Some(&target))
            .expect("reconciles");
        assert_eq!(settled, Settled::Applied, "{commands:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// What the doctor reports of the bridges
// ---------------------------------------------------------------------------------------------

/// The first sixteen hexadecimal digits of a digest, as the doctor writes a file's digest.
fn short(digest: &str) -> &str {
    &digest[..16]
}

/// The doctor's check of what `bridges` holds now.
fn doctor_check(bridges: &NativeBridges) -> kr_protocol::hostinfo::DoctorCheck {
    kr_controller::catalogue::native_bridge::check(&bridges.reports().expect("reads"))
}

/// KR-REQ-11.42: the doctor reports an applied bridge: the package, the application and each file
/// by its digest, and that it is applied, with no warning. With no bridge it says nothing applies.
/// Names are what a check's sentence only states by class and length, so what it carries of the
/// bridge's own words is the digests.
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_doctor_reports_an_applied_bridge_and_its_files_by_digest() {
    use kr_protocol::hostinfo::DoctorStatus;
    let site = GeminiSite::new();
    let bridges = site.bridges();
    let none = doctor_check(&bridges);
    assert_eq!(none.id(), "native-bridges");
    assert_eq!(none.status, DoctorStatus::NotApplicable, "{none:?}");

    bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("applies");

    let reports = bridges.reports().expect("reads");
    let [report] = reports.as_slice() else {
        panic!("one bridge: {reports:?}");
    };
    assert_eq!(report.application.as_deref(), Some("Gemini CLI"));
    let mut files: Vec<(&str, &str)> = report
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.digest.as_str()))
        .collect();
    files.sort_unstable();
    let mut expected = [
        (GEMINI_RECORD_PATH, GEMINI_RECORD_DIGEST),
        (GEMINI_MANIFEST_PATH, GEMINI_MANIFEST_DIGEST),
        (GEMINI_HOOKS_PATH, GEMINI_HOOKS_DIGEST),
    ];
    expected.sort_unstable();
    assert_eq!(files, expected, "each file the host published, by digest");

    let check = doctor_check(&bridges);
    assert_eq!(check.status, DoctorStatus::Ok, "{check:?}");
    let detail = check.detail();
    assert!(detail.contains("applied"), "{detail}");
    for (_, digest) in expected {
        assert!(detail.contains(short(digest)), "{digest} in {detail}");
    }
    assert!(
        !detail.contains("gemini-cli") && !detail.contains(".gemini"),
        "a check's sentence states a name or a path by class and length only: {detail}"
    );
}

/// KR-REQ-11.42: a journal the listing names and that is gone by the time it is read, as a
/// removal finishing beside the doctor's read leaves, is not a bridge to report and not a failure
/// to read: the other bridges are reported and the check is the check of those. A dangling name in
/// the journals' directory is that case, made without a race. The control is a journal that is
/// there, which is reported.
#[cfg(unix)]
#[test]
fn kr_req_11_42_a_journal_that_goes_before_it_is_read_is_no_failure_to_read() {
    use kr_protocol::hostinfo::DoctorStatus;
    let site = GeminiSite::new();
    let bridges = site.bridges();
    bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("applies");
    let journals = site.root.join("state/native-bridges");
    std::os::unix::fs::symlink(
        site.root.join("nothing-here"),
        journals.join("0123456789abcdef.json"),
    )
    .expect("a name that leads nowhere");

    let reports = bridges
        .reports()
        .expect("the journal that is gone is skipped");

    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].state, "applied");
    assert_eq!(doctor_check(&bridges).status, DoctorStatus::Ok);
}

/// KR-REQ-11.42: the doctor warns for a bridge whose recipe is half applied, wherever an
/// installation stopped, and for one half removed; before anything is recorded there is nothing to
/// warn of, a bridge that stopped before a removal's first change is still applied, one finished is
/// applied, and one taken out leaves nothing to report.
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_doctor_warns_for_a_bridge_whose_recipe_is_half_applied() {
    use kr_protocol::hostinfo::DoctorStatus;
    let expected = |bridges: &NativeBridges| match bridges.reports().expect("reads").as_slice() {
        [] => DoctorStatus::NotApplicable,
        [report] if report.state == "applied" || report.state == "removed" => DoctorStatus::Ok,
        [_] => DoctorStatus::Warning,
        other => panic!("one bridge: {other:?}"),
    };
    let (mut warned, mut applied) = (0, 0);
    for step in 1.. {
        let site = GeminiSite::new();
        let bridges = site.bridges();
        bridges.stop_before(step);
        if bridges.reconcile(&gemini(), Some(&site.release())).is_ok() {
            break;
        }
        let half = doctor_check(&site.bridges());
        assert_eq!(
            half.status,
            expected(&site.bridges()),
            "step {step}: {half:?}"
        );
        if half.status == DoctorStatus::Warning {
            warned += 1;
            assert!(
                half.detail().contains("applying") || half.detail().contains("unsettled"),
                "step {step}: {}",
                half.detail()
            );
        }
        site.bridges()
            .reconcile(&gemini(), Some(&site.release()))
            .expect("finishes");
        // Finished, it is applied; where something was made and not yet recorded, the next run
        // names it and the bridge is not reported as applied until its owner removes it.
        let finished = doctor_check(&site.bridges());
        assert_eq!(finished.status, expected(&site.bridges()), "step {step}");
        if finished.status == DoctorStatus::Ok {
            applied += 1;
        } else {
            assert!(
                finished.detail().contains("unsettled"),
                "{}",
                finished.detail()
            );
        }
    }
    assert!(
        warned > 8,
        "most steps leave a recipe half applied: {warned}"
    );
    assert!(
        applied > 3,
        "a run that stopped is finished by the next: {applied}"
    );

    // A removal that stopped part way.
    let mut removing = 0;
    for step in 1.. {
        let site = GeminiSite::new();
        site.bridges()
            .reconcile(&gemini(), Some(&site.release()))
            .expect("applies");
        let bridges = site.bridges();
        bridges.stop_before(step);
        if bridges.reconcile(&gemini(), None).is_ok() {
            break;
        }
        let half = doctor_check(&site.bridges());
        assert_eq!(
            half.status,
            expected(&site.bridges()),
            "removal {step}: {half:?}"
        );
        if half.status == DoctorStatus::Warning {
            removing += 1;
            assert!(
                half.detail().contains("removing") || half.detail().contains("unsettled"),
                "removal {step}: {}",
                half.detail()
            );
        }
        // A removal that finishes leaves no record of a bridge, so there is nothing to report.
        site.bridges().reconcile(&gemini(), None).expect("finishes");
        let removed = doctor_check(&site.bridges());
        assert_eq!(
            removed.status,
            DoctorStatus::NotApplicable,
            "removal {step}: {removed:?}"
        );
    }
    assert!(removing > 2, "a removal has its own boundaries: {removing}");
}

/// KR-REQ-11.42: the doctor warns for an applied bridge whose installed files no longer match what
/// was applied, and says nothing of a bridge nobody changed.
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_doctor_warns_for_an_applied_bridge_that_no_longer_matches() {
    use kr_protocol::hostinfo::DoctorStatus;
    let site = GeminiSite::new();
    let bridges = site.bridges();
    bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("applies");
    assert_eq!(doctor_check(&bridges).status, DoctorStatus::Ok);

    std::fs::write(site.application().join(GEMINI_HOOKS_PATH), b"{}").expect("changed");

    let drifted = doctor_check(&bridges);
    assert_eq!(drifted.status, DoctorStatus::Warning, "{drifted:?}");
}

/// KR-REQ-11.42: the doctor warns for a bridge that was removed with something left in place,
/// because a file somebody changed since it was installed is not taken out: the row says it was
/// removed, as a warning. The control is a removal that left nothing, which leaves no row (the
/// half-applied case's removals).
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_doctor_warns_for_a_removal_that_left_something_in_place() {
    use kr_protocol::hostinfo::DoctorStatus;
    let site = GeminiSite::new();
    let bridges = site.bridges();
    bridges
        .reconcile(&gemini(), Some(&site.release()))
        .expect("applies");
    std::fs::write(
        site.application().join(GEMINI_HOOKS_PATH),
        b"{\"somebody\": 1}",
    )
    .expect("changed");

    let settled = bridges.reconcile(&gemini(), None).expect("removes");

    assert_eq!(settled, Settled::Removed, "{settled:?}");
    let reports = bridges.reports().expect("reads");
    let [report] = reports.as_slice() else {
        panic!("one bridge: {reports:?}");
    };
    assert_eq!(report.state, "removed", "{report:?}");
    assert!(!report.notes.is_empty(), "something was left: {report:?}");
    let check = doctor_check(&bridges);
    assert_eq!(check.status, DoctorStatus::Warning, "{check:?}");
    assert!(check.detail().contains("removed"), "{}", check.detail());
}

/// KR-REQ-11.42: a recipe the host refuses is reported as refused, and is not a warning: nothing
/// of it is in place. On Windows every recipe is refused, and the journal says why.
#[cfg(unix)]
#[test]
fn kr_req_11_42_the_doctor_reports_a_refused_recipe_as_refused() {
    use kr_protocol::hostinfo::DoctorStatus;
    let site = GeminiSite::new();
    let claude_only = NativeBridges::new(BridgeHost {
        applications: vec![ApplicationDirectory {
            application: "Claude Code".to_owned(),
            directory: site.root.join("home/.claude"),
        }],
        ..site.host()
    });
    claude_only
        .reconcile(&gemini(), Some(&site.release()))
        .expect("reconciles");

    let check = doctor_check(&claude_only);
    assert_eq!(check.status, DoctorStatus::Ok, "{check:?}");
    assert!(check.detail().contains("refused"), "{}", check.detail());
}
