//! The root editor's fence, driven from the worker.
//!
//! [`kr_shell_integration::contract::fence::FenceMachine`] is the single source of fence and detach
//! truth. This module is what turns its answers into things that happen: bytes held back from the
//! pseudo-terminal or released to it in their original order, frames for the reader's mailbox, an
//! `editor_busy` event for the client whose keystrokes waited, an attachment removed, a launch
//! answered. There is no second state machine here and no heuristic fence: every decision below
//! comes from one `apply` call, and every consequence is one of the machine's own actions.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`driver`] | The machine, the clock, the hold and the translation of every action |
//! | [`bridge`] | The endpoint's accept loop, the handshake and the frames in both directions |
//!
//! # What the driver adds to the machine
//!
//! Three things the contract deliberately leaves to the host, and nothing else.
//!
//! * **The clock and the timer.** The machine takes a reading; the driver supplies it from the
//!   suspend-aware continuous clock and arms one timer at [`driver::FenceDriver::deadline`].
//! * **The phase gate.** [`kr_shell_integration::host::phase::PhaseGate`] decides whether a fence
//!   may be started at all, whether a launch is admitted, and whether an accepted line may be
//!   attributed. Below a qualified session the reader's boundaries are answered and recorded and no
//!   exchange begins, so a startup profile that asks a question is never held up by one.
//! * **The bytes.** The machine names batches; the driver holds the actual bytes and hands them to
//!   the writer in the order the machine releases them.

pub mod bridge;
pub mod driver;

pub use crate::fence::driver::{
    Effects, FenceDriver, Outbound, ReaderDiscards, Step, TakeoverReceipt,
};
