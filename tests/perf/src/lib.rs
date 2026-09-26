//! The performance harness.
//!
//! Section 27 states its performance targets for a reference host and asks for every figure to be
//! kept with the host it was taken on. [`record`] is the record every measurement keeps its figure
//! in: the host's conditions at the edges of what was timed, and one Markdown section per figure
//! under `KR_TEST_ARTIFACTS_DIR`, headed by the identifier it measures. `scripts/bench-all.sh` runs
//! every measurement and reads those sections back.

pub mod record;
