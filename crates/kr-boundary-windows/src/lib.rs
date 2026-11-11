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
//! | [`filekey`] | The identity of an object on a volume, which the walk, the private root and the journal name instead of a path |
//! | [`frame`] | The broker's pipe protocol: framed messages with limits, and the requests and answers |
//! | [`mod@env`] | The environment of every child, built from a fixed table and nothing of the caller's |
//! | [`quote`] | A child's command line, quoted so that the platform's own splitting gives back its parts |
//! | [`journal`] | The journal's records: their framing (a length, the bytes and a checksum, with a torn tail dropped), their rows and the order the rows may come in |
//! | [`repository`] | What the broker reads of a repository before it starts Git, from bytes alone: its `HEAD`, its attributes, its configuration listing and the output of the five readers it runs |
//! | [`refusal`] | The refusal those readers give: a kind, the rule's name and a short text |
//! | [`names`] | The grammar of the branch names and object identifiers the broker admits |
//! | [`messages`] | The product's own messages whose exact words are fixed: the installer's wait for application control, and the broker's answer while its proof has not passed |
//! | [`operation`] | The eight commands a request may name: their argument tables, the settings every command runs with, the one rule for line endings, and the checks of the repository's state |
//! | [`state`] | What the doctor says in each state of the installation |
//! | [`window`] | When the proof's search for a refusal is over: a run cut by the window's own end ends it, a run that failed does not |
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
//!
//! ### Crash reports
//!
//! The broker sets its error mode once, when it starts, and every program it starts inherits that
//! mode. The claim is this and no more: on the Windows builds the cases ran on, the system's own
//! crash reporting is not invoked for the broker or for a program that inherits the mode, so a
//! crash of either leaves no dump of its memory. A program that asks for the default error mode
//! again, or that writes a dump of itself, is outside the claim, and so is a computer on which an
//! administrator has configured error reporting for the broker's own program.

pub mod env;
pub mod events;
pub mod filekey;
pub mod frame;
pub mod journal;
pub mod manifest;
pub mod messages;
pub mod names;
pub mod notice;
pub mod operation;
pub mod policy;
pub mod quote;
pub mod refusal;
pub mod repository;
pub mod state;
pub mod window;

#[cfg(windows)]
pub mod win;
