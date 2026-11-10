//! The calls that touch the machine. Each module owns one family of them and allows the unsafe
//! code those calls need.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | `ffi` | Wide strings, owned handles, errors and identifiers |
//! | `acl` | Permissions on files and directories |
//! | `registry` | Values in the machine's registry |
//! | `account` | The two boundary accounts, their rights and their sign-in |
//! | `service` | The service manager: the broker's service and the Application Identity service |
//! | `token` | The logon token Git runs under |
//! | `launch` | Starting a program under a token |
//! | `verify` | The check that the payload was signed by the publisher |
//! | `applocker` | PowerShell's application-control cmdlets and the event log |
//! | `pipe` | The broker's local pipe |
//! | `proof` | The proof that the boundary is in force, and that it was released |
//! | `broker` | The broker service |
//! | `install` | The installation, its repair and its removal |
//! | `setup` | The setup program's command line |

pub mod account;
pub mod acl;
pub mod applocker;
pub mod broker;
pub mod ffi;
pub mod install;
pub mod launch;
pub mod pipe;
pub mod proof;
pub mod registry;
pub mod service;
pub mod setup;
pub mod token;
pub mod verify;
