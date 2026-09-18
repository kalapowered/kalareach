//! Section 9's action model, as this worker decides it.
//!
//! The receipt journal is next door in [`crate::journal`], because the durable identity of a
//! mutation is a store rather than a policy. What is here is every decision the journal's writes
//! rest on, in one module so the answers cannot drift between the callers that need them:
//!
//! | Module | What it decides |
//! | --- | --- |
//! | [`window`] | The freshness window a first admission is bound to, and the deadline it produces |
//! | [`dedup`] | Whether a fresh identifier may supersede an uncertain outcome, and the outstanding-mutation limit |
//! | [`cancel`] | Who may cancel a pending action |
//! | [`observation`] | Additive evidence about an action, which never becomes an execution state on its own |
//! | [`time`] | The one host time contract every expiry is decided by |
//! | [`adapter`] | The platform time service, read through the interface the platform actually supports |
//!
//! Nothing in here reads a clock of its own. Deadlines are decided on the transport's
//! suspend-aware continuous clock inside one process and on the machine's boot-scoped continuous
//! clock between two, and the wall clock is a thing this host records and distrusts rather than a
//! thing it measures with.

pub mod adapter;
pub mod cancel;
pub mod dedup;
pub mod observation;
pub mod time;
pub mod window;
