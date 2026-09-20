//! What every description test needs: identifiers, clock readings and the shipped profiles.
//!
//! Only the pieces that no test could avoid are here. A helper that belongs to one area - a queue
//! context, a validated result, a service over the deterministic runtime - stays in the file that
//! drives that area, where a reader can see what it does without leaving the test.
#![allow(dead_code)]

use kr_describe::context::ContextBinding;
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment};
use kr_describe::profile::ModelProfile;
use kr_describe::profile::catalogue::Catalogue;
use kr_describe::time::Reading;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::scalars::Uuid;

/// The target the tests select profiles for.
pub const MAC: &str = "aarch64-apple-darwin";

/// A session identifier a test can name twice.
pub fn session(seed: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([seed; 16]))
}

/// An environment identifier a test can name twice.
pub fn environment_id(seed: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([seed | 0x80; 16]))
}

/// A native execution environment.
pub fn native(seed: u8) -> ExecutionEnvironment {
    ExecutionEnvironment::new(environment_id(seed), EnvironmentKind::Native)
}

/// The binding a session is described under.
pub fn binding() -> ContextBinding {
    ContextBinding::new("desktop-1/terminal/epoch-1")
}

/// One reading of both clocks, at a monotonic millisecond a test chooses.
pub fn at(monotonic_ms: u64) -> Reading {
    Reading::new(monotonic_ms, 1_700_000_000_000 + monotonic_ms)
}

/// The profiles this build ships.
pub fn built_in() -> Catalogue {
    Catalogue::builtin().expect("this build ships profiles it can run")
}

/// The default profile.
pub fn default_profile() -> ModelProfile {
    built_in().default_profile().clone()
}
