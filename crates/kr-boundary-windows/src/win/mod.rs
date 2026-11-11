//! The calls that touch the machine. Each module owns one family of them and allows the unsafe
//! code those calls need.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | `ffi` | Wide strings, owned handles, errors and identifiers |
//! | `boot` | The identifier of the current start of Windows, in a volatile registry key |
//! | `acl` | Permissions on files and directories |
//! | `registry` | Values in the machine's registry |
//! | `account` | The two boundary accounts, their rights and their sign-in |
//! | `service` | The service manager: the broker's service and the Application Identity service |
//! | `token` | The logon token Git runs under |
//! | `job` | The job every child of an invocation is made in |
//! | `launch` | Starting a program: the broker's one process creation |
//! | `sd` | The security descriptors the broker makes |
//! | `verify` | The check that the payload was signed by the publisher |
//! | `applocker` | PowerShell's application-control cmdlets and the event log |
//! | `privilege` | The backup and restore privileges, held by one thread for one privileged action |
//! | `root` | An invocation's private root: its creation and its removal |
//! | `journal` | The journal's file: each row written through before the step it protects, and read back after a crash |
//! | `walk` | The anchored walk: objects reached by identifier from a held directory |
//! | `pipe` | The broker's local pipe |
//! | `proof` | The proof that the boundary is in force, and that it was released |
//! | `broker` | The broker service |
//! | `install` | The installation, its repair and its removal |
//! | `setup` | The setup program's command line |

pub mod account;
pub mod acl;
pub mod applocker;
pub mod boot;
pub mod broker;
pub mod ffi;
pub mod fresh;
pub mod install;
pub mod job;
pub mod journal;
pub mod launch;
pub mod pipe;
pub mod privilege;
pub mod proof;
pub mod registry;
pub mod root;
pub mod sd;
pub mod service;
pub mod setup;
pub mod token;
pub mod verify;
pub mod walk;
