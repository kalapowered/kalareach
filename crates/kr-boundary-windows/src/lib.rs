//! The Windows execution boundary: its administrator installation, its removal, the resident broker
//! that starts Git as the two boundary accounts, and the checks that tell whether the boundary is in
//! force.
//!
//! Windows judges which programs an account may start by the program's identity, which a file's
//! own permission entries cannot defeat. The installation turns that on for the whole computer with
//! an application-control policy that lets every account run every program and denies the two
//! boundary accounts everything but Git, a short list of Git's own programs and the credential
//! helper. Git runs as those accounts, started by a service that Windows runs as SYSTEM, because
//! only such a service can make a logon token for an account whose password nobody holds.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`notice`] | The plain notice a person reads before the installation, shown in one place |
//! | [`policy`] | The application-control policy: its three rules, its writing, and the reading of an effective policy back into one form |
//! | [`manifest`] | The record of what the installation laid down, and the record of what was there before |
//! | [`events`] | What the platform's application-control log says about a program it refused |
//! | [`frame`] | The broker's pipe protocol: framed messages with limits, and the requests and answers |
//! | [`journal`] | The framing of the journal's records: a length, the bytes and a checksum, with a torn tail dropped |
//! | [`state`] | What the doctor says in each state of the installation |
//!
//! The calls that touch the machine live in `win`, which builds on Windows only. Everything above
//! it builds and is tested everywhere, so the notice, the policy's two forms, the stores and the
//! protocol are held to real bytes on every platform.
//!
//! ## What the boundary does not promise
//!
//! The accounts can write wherever an access entry lets them: the folders KalaReach gives them, the
//! places every account may write, and any folder someone has granted them. What they cannot do is
//! start a program they were not given. An administrator can change the rules; the boundary guards
//! against a hostile repository and a misbehaving Git, not against an administrator.

pub mod events;
pub mod frame;
pub mod journal;
pub mod manifest;
pub mod notice;
pub mod policy;
pub mod state;

#[cfg(windows)]
pub mod win;
