//! Pairing, from the side of the devices that talk to a host.
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`room`] | The rendezvous room socket a host and a candidate open, with its role, its bounds and its typed failures |
//!
//! A short-code invitation's host and the candidates that answer it meet in a rendezvous room.
//! Both reach it through [`room::RoomConnector`], so one implementation carries the TLS, the
//! upgrade and the ping and queue bounds for both roles.

pub mod room;
