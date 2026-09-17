//! Finding the test components, and building the things every test needs around them.
//!
//! The components are built by `scripts/build-plugin-fixtures.sh` into
//! `fixtures/plugins/components/build/`. They are not committed: Rust embeds build paths in a
//! component's custom sections, so two machines produce different bytes for the same source.
//!
//! A test that needs one and cannot find the build directory at all says so and returns, because
//! "the components have not been built" is not a failure of the case under test. A test that finds
//! the directory and not the component it asked for fails, because that is a build that produced
//! the wrong thing. Setting `KR_REQUIRE_PLUGIN_FIXTURES=1`, which continuous integration does,
//! turns the first case into a failure too.

#![allow(
    dead_code,
    reason = "two test binaries share this module, and each uses the part of it that its cases need"
)]

use std::path::PathBuf;
use std::sync::Arc;

use kr_plugin_runtime::runtime::binding::{BindingId, BindingRequest};
use kr_plugin_runtime::runtime::host::{
    BindingActivity, BindingFacts, ScopedSourceEvent, SourceProvenance,
};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::{PluginId, RepositoryGeneration, SourceEventHandle};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Uuid;

/// The environment variable that makes an unbuilt component set a failure.
pub const REQUIRE: &str = "KR_REQUIRE_PLUGIN_FIXTURES";

/// Returns the directory the built components are in.
pub fn build_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/components/build")
        .canonicalize()
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/plugins/components/build")
        })
}

/// Loads one built component, or says why the test cannot run.
///
/// # Panics
///
/// Panics when the build directory exists and the named component is not in it, and when
/// [`REQUIRE`] is set and the directory is absent.
pub fn component(name: &str) -> Option<Arc<[u8]>> {
    let directory = build_directory();
    let path = directory.join(format!("{name}.wasm"));
    if !directory.is_dir() {
        let required = std::env::var(REQUIRE).is_ok_and(|value| value == "1");
        assert!(
            !required,
            "{REQUIRE}=1 and the test components are not built; run scripts/build-plugin-fixtures.sh"
        );
        eprintln!(
            "skipping: the test components are not built. Run scripts/build-plugin-fixtures.sh"
        );
        return None;
    }
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the component build directory exists and {} is not in it: {error}",
            path.display()
        )
    });
    Some(Arc::from(bytes))
}

/// The well-behaved component that exercises every export.
pub fn well_behaved() -> Option<Arc<[u8]>> {
    component("well-behaved")
}

/// Returns a binding request for one plugin name.
pub fn request(plugin: &str, seed: u8) -> BindingRequest {
    BindingRequest {
        binding_id: BindingId::new(Uuid::from_bytes([seed; 16])),
        identity: PluginIdentity::new(
            PluginId::new(format!("kalareach/{plugin}")).expect("a bounded identifier"),
            PackageVersion::parse("1.0.0").expect("a semantic version"),
            PayloadDigest::of(plugin.as_bytes()),
            RepositoryGeneration::new(1),
        ),
        facts: facts(plugin),
        executable: "/usr/local/bin/example-agent".to_owned(),
    }
}

/// Returns the facts a component reads about its binding.
pub fn facts(plugin: &str) -> BindingFacts {
    BindingFacts {
        plugin_id: format!("kalareach/{plugin}"),
        binding_revision: 3,
        activity: BindingActivity::Running,
        thread_id: Some("thread-1".to_owned()),
        turn_id: Some("turn-1".to_owned()),
        updated_at_ms: 1_700_000_000_000,
        held_rights: vec![ActionRight::SessionView, ActionRight::AgentPrompt],
    }
}

/// Returns one terminal-scrape observation.
pub fn scrape(handle: &str, text: &str) -> ScopedSourceEvent {
    ScopedSourceEvent::new(
        SourceEventHandle::new(handle).expect("a bounded handle"),
        SourceProvenance::TerminalScrape,
        1_700_000_000_001,
        None,
        text.as_bytes().to_vec(),
    )
}

/// Returns one native request, with its upstream request identifier.
pub fn native_request(handle: &str, request_id: &str, text: &str) -> ScopedSourceEvent {
    ScopedSourceEvent::new(
        SourceEventHandle::new(handle).expect("a bounded handle"),
        SourceProvenance::NativeProtocol,
        1_700_000_000_002,
        Some(request_id.to_owned()),
        text.as_bytes().to_vec(),
    )
}
