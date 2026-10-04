//! The description model: the one crate in this workspace that links a model runtime.
//!
//! `kr-describe` is the description service without a model: the deterministic titles, the
//! scheduler and resource policy, the signed profiles, the names, pins and provenance store, the
//! wire to the description process and that process's serving code. A process that links it alone
//! links no inference library, so the control daemon serves descriptions from metadata and holds
//! the store with no model anywhere in its dependency graph. What runs a real model is here, on top
//! of it:
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`llama`] | The llama.cpp runtime, CPU only, as the model the description process runs |
//! | [`assets`] | The check that a downloaded model file is the one its signed profile records |
//! | [`fixtures`] | The sessions the benchmark and the tests describe, the largest context in four scripts |
//!
//! The `kr-describe-inference` binary is the description process the daemon starts: the serving
//! code in `kr_describe::serve` over [`llama::Llama`]. The `kr-describe-bench` binary checks real
//! weights with [`assets`] and measures them through [`llama`]; `scripts/bench-descriptions.sh`
//! fetches the weights and runs it.

pub mod assets;
pub mod fixtures;
pub mod llama;
