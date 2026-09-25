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

// ---------------------------------------------------------------------------------------------
// Stopped at each boundary
// ---------------------------------------------------------------------------------------------

/// Runs `first` on a fresh site stopped before step `step`, and returns the site when the run
/// stopped, or `None` when it finished before reaching that step.
fn stopped_at(
    step: usize,
    prepare: &dyn Fn(&Site),
    first: &dyn Fn(&Site, &NativeBridges) -> kr_controller::Result<Settled>,
) -> Option<Site> {
    let site = Site::new();
    prepare(&site);
    let bridges = site.bridges();
    bridges.stop_before(step);
    match first(&site, &bridges) {
        Err(_) => Some(site),
        Ok(_) => None,
    }
}

/// KR-REQ-11.42: an installation stopped before any of its steps is never reported as applied, and
/// the next reconciliation finishes it when the release is still wanted and takes it out when it is
/// not, leaving no temporary file behind.
#[test]
fn kr_req_11_42_an_installation_stopped_at_each_boundary_is_finished_or_undone() {
    let reference = Site::new();
    let before = reference.tree();
    let applied = applied_tree(&before);
    let mut boundaries = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(site) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        boundaries += 1;
        assert!(
            site.bridges()
                .facts(&plugin(), site.release().package_digest)
                .expect("reads")
                .is_none(),
            "step {step}: never reported as applied while unfinished"
        );
        assert_eq!(
            site.bridges()
                .reconcile(&plugin(), Some(&site.release()))
                .expect("finishes"),
            Settled::Applied,
            "step {step}"
        );
        assert_eq!(site.tree(), applied, "step {step}: finished exactly");

        let site = stopped_at(step, &|_| {}, &apply).expect("stops again");
        site.bridges()
            .reconcile(&plugin(), None)
            .expect("takes it out");
        assert_eq!(site.tree(), before, "step {step}: undone exactly");
        assert!(
            site.bridges().reports().expect("reads").is_empty(),
            "step {step}"
        );
    }
    assert!(boundaries > 20, "every step was a boundary: {boundaries}");
}

/// KR-REQ-11.42: a removal stopped before any of its steps is finished by the next
/// reconciliation.
#[test]
fn kr_req_11_42_a_removal_stopped_at_each_boundary_is_finished() {
    let reference = Site::new();
    let before = reference.tree();
    let mut boundaries = 0;
    for step in 1.. {
        let install = |site: &Site| {
            site.bridges()
                .reconcile(&plugin(), Some(&site.release()))
                .expect("applies");
        };
        let remove = |_: &Site, bridges: &NativeBridges| bridges.reconcile(&plugin(), None);
        let Some(site) = stopped_at(step, &install, &remove) else {
            break;
        };
        boundaries += 1;
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
        site.bridges().reconcile(&plugin(), None).expect("finishes");
        assert_eq!(site.tree(), before, "step {step}: removed exactly");
    }
    assert!(boundaries > 10, "every step was a boundary: {boundaries}");
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
        let Some(site) = stopped_at(step, &install, &upgrade) else {
            break;
        };
        boundaries += 1;
        let next = site.next_release();
        assert_eq!(
            site.bridges()
                .reconcile(&plugin(), Some(&next))
                .expect("finishes"),
            Settled::Applied,
            "step {step}"
        );
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
        let names: Vec<String> = site.tree().into_keys().collect();
        assert!(
            names.iter().all(|name| !name.contains(".kalareach")),
            "step {step}: no temporary file is left: {names:?}"
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
        let Some(site) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let theirs = site.application().join(MANIFEST_PATH);
        if theirs.exists() || !theirs.parent().is_some_and(Path::is_dir) {
            continue;
        }
        // Stopped with the file noted or staged and not in place. The owner writes the bytes the
        // recipe would have written, where it would have.
        std::fs::write(&theirs, pinned("plugin-manifest.json")).expect("the owner's copy");

        site.bridges()
            .reconcile(&plugin(), None)
            .expect("reconciles");

        assert_eq!(
            std::fs::read(&theirs).expect("kept"),
            pinned("plugin-manifest.json"),
            "step {step}: the owner's file is left"
        );
        let names: Vec<String> = site.tree().into_keys().collect();
        assert!(
            names.iter().all(|name| !name.contains(".kalareach")),
            "step {step}: no temporary file is left: {names:?}"
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "the noted and the staged boundaries were both reached: {checked}"
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
        let Some(site) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
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
/// shown to be this host's: it is neither taken nor claimed, and the bridge is not reported as
/// applied. A key recorded as published before the rewrite is this host's.
#[test]
fn a_key_whose_document_was_rewritten_meanwhile_stays_unsettled() {
    let mut unsettled = 0;
    for step in 1.. {
        let apply = |site: &Site, bridges: &NativeBridges| {
            bridges.reconcile(&plugin(), Some(&site.release()))
        };
        let Some(site) = stopped_at(step, &|_| {}, &apply) else {
            break;
        };
        let document = site.application().join("settings.json");
        let text = std::fs::read_to_string(&document).expect("reads");
        let names: Vec<String> = site.tree().into_keys().collect();
        if text != SETTINGS_WITH_KEY || names.iter().any(|name| name.contains(".kalareach")) {
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
