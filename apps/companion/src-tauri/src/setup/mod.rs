//! What first-start setup needs from the machine, and nothing else.
//!
//! Section 3 gives the setup assistant two jobs the rest of this application does not have. It
//! checks the stable signed application and helper identity before it guides anybody through a
//! permission, because an operating system grants a permission to a signed identity and a build
//! whose identity moves loses every grant it was given. And it guides each permission category
//! separately, to a place in the platform's own settings that the assistant cannot press on the
//! person's behalf.
//!
//! Both are read-only. Nothing here grants a permission, changes a setting or writes anything: the
//! whole module reports what is, and opens a settings pane by its name when the person asks for
//! it. That is the ceiling the interface states, and it is a real one — [`identity`] can say which
//! identity a grant would be recorded against, and no amount of asking the platform can say
//! whether a screen image will come out, because on this platform the operation is the check.

pub mod identity;
pub mod settings;
