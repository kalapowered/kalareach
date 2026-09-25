//! The conformance report.
//!
//! Section 29 asks every repository to map its contract changes to the specification's acceptance
//! identifiers, to name the harness commands that reproduce each result and to publish those
//! results in a machine-readable form with the exact versions they were taken at. This crate is
//! that report for this repository. It keeps no index of identifiers: the tests name the rows they
//! prove, in their comments, their names and their case tables, and the report reads those at run
//! time, runs the suites that hold them and writes one result keyed by identifier.
//!
//! `docs/conformance/README.md` states the result's schema and every rule the report reads a
//! source with.

pub mod clike;
pub mod evidence;
pub mod id;
pub mod identity;
pub mod libtest;
pub mod map;
pub mod plan;
pub mod report;
pub mod run;
pub mod rust_items;
pub mod rust_lex;
pub mod typescript;
pub mod vitest;
pub mod workspace;
