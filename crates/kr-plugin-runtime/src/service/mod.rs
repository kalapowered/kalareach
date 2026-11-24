//! Being the plugin host.
//!
//! The engine lives in `kr-plugin-host`, one process per environment. What its callers need -- the
//! protocol, the descriptor a worker finds the host through, the client a worker uses and the
//! launcher that starts the host -- is `kr_plugin_service`, which links no engine, so a worker or
//! the control daemon may link it without being able to run a component. This module is the other
//! side: the host serving its callers, over the instances this crate runs.
//!
//! # Modules
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`host`] | Serving workers: the accept loop, peer credentials and the request handling |
//! | `four` | What a `kr-plugin-host/4` connection reads and writes beside what `/3` does |
//! | `wire` | The conversions between what a call carries and what a component reads |

mod four;
pub mod host;
mod wire;
