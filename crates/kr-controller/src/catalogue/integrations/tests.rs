//! The entries a session gets, from admitted packages read by a worker's rules.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::admission::AdmittedPackage;
use kr_protocol::ids::PluginId;
use kr_worker::broker::catalogue::testing::admitted;
use kr_worker::broker::connectors::fixture;

use super::*;

/// A directory of the test's own, removed when it is dropped.
struct Store(PathBuf);

impl Store {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("kr-integrations-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        Self(root)
    }

    /// One package of `shape`, as an admission hands it over, with what `installed` makes of its
    /// installation.
    fn admitted(
        &self,
        shape: &fixture::Shape,
        installed: impl FnOnce(&mut kr_worker::broker::connectors::ConnectorSource),
    ) -> AdmittedPackage {
        let mut source = fixture::package(&self.0, &self.0.join("kr-hook"), shape)
            .expect("the package is written");
        installed(&mut source);
        admitted(&source)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plugin(name: &str) -> PluginId {
    PluginId::new(format!("kalareach/{name}")).expect("a plugin identifier")
}

fn enabled(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|name| format!("kalareach/{name}"))
        .collect()
}

/// KR-REQ-12.07: one entry for each connector whose integration applies, with the command and the
/// flags its verified manifest declares, on where the configuration names its package and off
/// where it does not.
#[test]
fn each_integration_that_applies_gives_an_entry_on_or_off_by_the_configuration() {
    let store = Store::new("entries");
    let packages = vec![
        store.admitted(&fixture::Shape::claude_code(), |_| {}),
        store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {}),
        store.admitted(&fixture::Shape::qoder_cli(), |_| {}),
    ];
    let reading = Integrations::new().read(&packages);
    let entries = entries(&reading, &enabled(&["claude-code", "qoder-cli"]));
    let summary: Vec<(PluginId, &str, usize, bool)> = entries
        .iter()
        .map(|entry| {
            (
                entry.plugin_id.clone(),
                entry.command.as_str(),
                entry.flags.len(),
                entry.enabled,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (plugin("claude-code"), "claude", 2, true),
            (plugin("gemini-cli"), "gemini", 0, false),
            (plugin("qoder-cli"), "qodercli", 2, true),
        ]
    );
    assert_eq!(
        entries[0].flags,
        fixture::FLAGS.map(str::to_owned),
        "the flags are the verified manifest's"
    );
    assert_eq!(entries[2].flags, fixture::qoder_flags());
}

/// KR-REQ-12.07: an integration whose grant the installation does not hold gives no entry, whatever
/// the configuration names; nor does a package that declares none, nor two packages that integrate
/// one command.
#[test]
fn an_integration_that_does_not_apply_gives_no_entry() {
    let store = Store::new("none");
    let ungranted = store.admitted(&fixture::Shape::gemini_cli(&[]), |source| {
        source
            .granted
            .remove(&PluginCapability::CommandIntegrationLaunch);
    });
    let undeclared = store.admitted(
        &fixture::Shape {
            plugin_name: "silent",
            integration: None,
            ..fixture::Shape::claude_code()
        },
        |_| {},
    );
    let qoder = store.admitted(&fixture::Shape::qoder_cli(), |_| {});
    let another = store.admitted(
        &fixture::Shape {
            plugin_name: "another-qoder",
            ..fixture::Shape::qoder_cli()
        },
        |_| {},
    );
    let reading = Integrations::new().read(&[ungranted, undeclared, qoder, another]);
    assert!(
        reading
            .packages
            .iter()
            .filter(|(_, read)| read.is_ok())
            .count()
            == 2,
        "the two that integrate no command are read: {:?}",
        reading
            .packages
            .iter()
            .map(|(package, read)| (package.plugin_id.clone(), read.as_ref().err().cloned()))
            .collect::<Vec<_>>()
    );
    assert!(
        entries(
            &reading,
            &enabled(&["gemini-cli", "silent", "qoder-cli", "another-qoder"])
        )
        .is_empty()
    );
}

/// A package is checked once by its hash: a reading after its copy lost a file still reads it, as
/// the verified files a hash names never change.
#[test]
fn a_package_is_checked_once_by_its_hash() {
    let store = Store::new("once");
    let package = store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {});
    let integrations = Integrations::new();
    assert_eq!(
        entries(&integrations.read(std::slice::from_ref(&package)), &[]).len(),
        1
    );
    std::fs::remove_file(Path::new(&package.package_dir).join("presentation.json"))
        .expect("a file of the copy goes");
    assert_eq!(
        entries(&integrations.read(std::slice::from_ref(&package)), &[]).len(),
        1,
        "the check this reader kept"
    );
    assert!(
        entries(&Integrations::new().read(&[package]), &[]).is_empty(),
        "a reader that never checked it refuses the copy"
    );
}
