//! The agents the host offers to start, drawn from the connectors the worker holds.
//!
//! Each case writes connector packages the way the catalogue's store extracts one and hands the
//! worker what an installation hands it. The offers are what `shell.launch.surface` answers: one
//! for each distinct command, in the order of the command, from the packages the worker admitted.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-13.11 | every test here |

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::root::LaunchCommand;
use kr_worker::broker::connectors::{ConnectorSource, ConnectorSources, fixture};

/// A directory of the test's own, removed when it is dropped.
struct Store {
    root: PathBuf,
}

impl Store {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("kr-launch-offers-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        Self { root }
    }

    fn shaped(&self, shape: &fixture::Shape) -> ConnectorSource {
        fixture::package(&self.root, Path::new(fixture::FORWARDER), shape)
            .expect("the package is written")
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A package that integrates no command and recognises `executable` in any directory.
fn recognising(
    plugin_name: &'static str,
    display_name: &'static str,
    executable: &'static str,
) -> fixture::Shape {
    fixture::Shape {
        plugin_name,
        display_name,
        executable,
        integration: None,
        native_bridge: false,
        ..fixture::Shape::claude_code()
    }
}

/// What each offer says: the package, its label and the command it sends.
fn offered(sources: &ConnectorSources) -> Vec<(String, String, Vec<String>)> {
    sources
        .launch_offers()
        .into_iter()
        .map(|offer| {
            let LaunchCommand::Arguments(command) = offer.command else {
                panic!("an offer sends the command alone, as an argument vector");
            };
            (offer.plugin_id.as_str().to_owned(), offer.label, command)
        })
        .collect()
}

fn entry(plugin_id: &str, label: &str, command: &str) -> (String, String, Vec<String>) {
    (
        plugin_id.to_owned(),
        label.to_owned(),
        vec![command.to_owned()],
    )
}

/// KR-REQ-13.11: the offers are one for each command among the packages the worker holds, in the
/// order of the command. A package gives the command its manifest declares as its integration
/// whether or not the installation holds the capability that lets the integration run, so Qoder CLI
/// offers `qodercli` and not the name of the first file its rules recognise.
#[test]
fn kr_req_13_11_the_offers_are_the_commands_of_the_held_packages_in_the_order_of_the_command() {
    let store = Store::new("order");
    let mut qoder = store.shaped(&fixture::Shape {
        // The installation put its entry under its own directory; only the command is typed.
        directory: &[".qoder", "entry"],
        ..fixture::Shape::qoder_cli()
    });
    qoder
        .granted
        .remove(&PluginCapability::CommandIntegrationLaunch);
    let sources = ConnectorSources::new();
    let refused = sources.replace(vec![
        store.shaped(&fixture::Shape::gemini_cli(&[])),
        qoder,
        store.shaped(&fixture::Shape::codex_backend()),
        store.shaped(&fixture::Shape::claude_code()),
    ]);
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(
        offered(&sources),
        vec![
            entry("kalareach/claude-code", "Claude Code", "claude"),
            entry("kalareach/codex", "Codex CLI", "codex"),
            entry("kalareach/gemini-cli", "Gemini CLI", "gemini"),
            entry("kalareach/qoder-cli", "Qoder CLI", "qodercli"),
        ]
    );
}

/// KR-REQ-13.11: a command two packages integrate is one the worker leaves both out of, so neither
/// is offered, and a package it did not hold is not offered either.
#[test]
fn kr_req_13_11_a_command_two_packages_integrate_is_offered_by_neither() {
    let first = Store::new("first");
    let second = Store::new("second");
    let sources = ConnectorSources::new();
    let refused = sources.replace(vec![
        first.shaped(&fixture::Shape::claude_code()),
        second.shaped(&fixture::Shape::claude_code()),
    ]);
    assert_eq!(refused.len(), 2);
    assert!(offered(&sources).is_empty());
}

/// KR-REQ-13.11: of packages that give one command, the one whose integration applies wins, then
/// the one whose plugin identifier sorts first, whichever order the installation lists them in.
#[test]
fn kr_req_13_11_a_shared_command_is_offered_once_by_a_package_chosen_the_same_way_every_time() {
    let store = Store::new("shared");
    // Two packages of one application that integrate nothing: the lower identifier gives the offer.
    for order in [[0, 1], [1, 0]] {
        let sources = ConnectorSources::new();
        let both = [
            store.shaped(&recognising("opencode", "OpenCode", "opencode")),
            store.shaped(&recognising(
                "opencode-attach",
                "OpenCode (serve and attach)",
                "opencode",
            )),
        ];
        let listed: Vec<_> = order.iter().map(|index| both[*index].clone()).collect();
        assert!(sources.replace(listed).is_empty());
        assert_eq!(
            offered(&sources),
            vec![entry("kalareach/opencode", "OpenCode", "opencode")]
        );
    }

    // A package whose integration applies wins the command it shares, though its identifier sorts
    // after the other's.
    let sources = ConnectorSources::new();
    assert!(
        sources
            .replace(vec![
                store.shaped(&recognising("aardvark", "Aardvark", "claude")),
                store.shaped(&fixture::Shape::claude_code()),
            ])
            .is_empty()
    );
    assert_eq!(
        offered(&sources),
        vec![entry("kalareach/claude-code", "Claude Code", "claude")]
    );
}

/// KR-REQ-13.11: a package whose only rule names the directory its application installs into and
/// that declares no integration has no name a person types, so it offers nothing.
#[test]
fn kr_req_13_11_a_package_that_names_no_command_to_type_offers_nothing() {
    let store = Store::new("directory");
    let sources = ConnectorSources::new();
    assert!(
        sources
            .replace(vec![store.shaped(&fixture::Shape {
                directory: &[".tool", "bin"],
                ..recognising("tool", "Tool", "tool")
            })])
            .is_empty()
    );
    assert!(offered(&sources).is_empty());
}
