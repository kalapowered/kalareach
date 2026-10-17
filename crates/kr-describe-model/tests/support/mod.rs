//! What the tests that need the real weights share: where the weights are, the check that they are
//! the selected profile's, and saying so in the test's output (which `--show-output` prints under
//! the test's name) when this host does not have them.

// Each test file takes the parts it needs.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_describe::priority::Cancellation;
use kr_describe::profile::ModelProfile;
use kr_describe::profile::catalogue::Catalogue;
use kr_describe_model::assets::verify_file;
use kr_describe_model::llama::LlamaRuntime;

/// Where the benchmark keeps the weights on this platform, or where this run is told they are.
pub fn cache_directory() -> Option<PathBuf> {
    if let Some(given) = std::env::var_os("KR_DESCRIBE_MODEL_CACHE") {
        return Some(PathBuf::from(given));
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    Some(if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach-describe")
    } else {
        home.join(".cache/kalareach-describe")
    })
}

/// Says, in the test's own output, that it did not run and why.
///
/// A test that returns early passes, so the harness's summary reads "ok" and says nothing more. The
/// line starts `skipped:`, which the conformance report reads as a case that did not run, and it
/// is written to the test's captured output in one piece: the harness shows it under the test's
/// name (`--show-output`), where the report finds it, and no other writer's output can break it.
pub fn did_not_run(test: &str, why: &str) {
    println!("skipped: {test} did not run: {why}");
}

/// The selected profile and where this host keeps its weights.
pub struct Weights {
    /// The profile every real-weights test runs against.
    pub profile: ModelProfile,
    /// The file the profile names, in the cache.
    pub path: PathBuf,
}

/// Finds the selected profile's weights in the cache, or says that `test` did not run.
pub fn weights(test: &str) -> Option<Weights> {
    let profile = Catalogue::builtin()
        .expect("this build's profiles")
        .default_profile()
        .clone();
    let asset = profile
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights")
        .clone();
    let Some(path) = cache_directory().map(|cache| cache.join(&asset.file_name)) else {
        did_not_run(test, "this host has no home directory");
        return None;
    };
    if std::fs::metadata(&path).map(|about| about.len()).ok() != Some(asset.bytes) {
        did_not_run(test, &format!("{} is not on this host", path.display()));
        return None;
    }
    Some(Weights { profile, path })
}

/// Loads the selected profile's real weights, after checking the file by its digest and not only
/// its size, or says that `test` did not run.
pub fn loaded(test: &str) -> Option<(ModelProfile, LlamaRuntime)> {
    let Weights { profile, path } = weights(test)?;
    let asset = profile
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights");
    verify_file(asset, &path).expect("the cached weights are the profile's");
    let runtime = LlamaRuntime::load(
        &profile,
        &path,
        &Cancellation::new(),
        Instant::now() + Duration::from_secs(300),
    )
    .expect("the real weights load");
    Some((profile, runtime))
}

/// The same, for a test that needs only the runtime.
pub fn runtime(test: &str) -> Option<LlamaRuntime> {
    loaded(test).map(|(_, runtime)| runtime)
}
