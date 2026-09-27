//! The description model: the one crate in this workspace that links a model runtime.
//!
//! `kr-describe` is the description service without a model: the deterministic titles, the
//! scheduler and resource policy, the signed profiles, the inference seam and the names, pins and
//! provenance store. A process that links it alone links no inference library, so the control
//! daemon serves descriptions from metadata and holds the store with no model anywhere in its
//! dependency graph. What runs a real model is here, on top of it:
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`llama`] | The llama.cpp runtime, CPU only, behind the service's inference seam |
//! | [`assets`] | The check that a downloaded model file is the one its signed profile records |
//!
//! The `kr-describe-bench` binary checks real weights with [`assets`] and measures them through
//! [`llama`]; `scripts/bench-descriptions.sh` fetches the weights and runs it.

pub mod assets;
pub mod llama;
