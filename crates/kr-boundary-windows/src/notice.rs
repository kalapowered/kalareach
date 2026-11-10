//! The plain notice a person reads before the boundary is installed.
//!
//! One text, shown in two places: by `kr host boundary install` in the person's own terminal
//! before it asks for an administrator prompt, and by the setup program in its own window before
//! it asks for a typed yes. Both read this constant, so the person sees the same words each time.

/// The notice, as plain text with one bullet to a line.
pub const NOTICE: &str = "To make Git operations safe on Windows, KalaReach needs a change that only an administrator can make. It does this:\n\
- It turns on Windows application control (AppLocker) for the whole computer. One rule lets every account run every program, as before: your own programs keep running from any folder. A second rule lets two new accounts, which only KalaReach uses, run only Git, a short list of Git's own programs and KalaReach's credential helper. After a Git update the change may need to be repeated, with an administrator prompt.\n\
- It creates those two accounts and tells Windows to refuse them sign-in at the screen and by Remote Desktop.\n\
- It starts the Application Identity service and sets it to start with Windows. It adds a background service, run by Windows as SYSTEM, that does one thing: start Git as those accounts for you.\n\
- It saves the application-control and service settings that were there before. Removal puts back what the installer changed and leaves alone anything an administrator changed later. If the computer already enforces application control, the installer stops and changes nothing.\n\
\n\
What stays true: those accounts can write in the folders KalaReach gives them, in places every account can write to (the Public folder, ProgramData, Windows' temporary folder, files in Windows\\Tasks, the top of the system drive) and in any folder that anyone has given them access to. They cannot start executable programs they were not given, wherever those are; a listed program that reads script text, such as Git's shell, can still read the script text it is given. An administrator of this computer can change these rules; KalaReach guards against a hostile repository and a misbehaving Git, not against an administrator. Remove it all with `kr host boundary remove`, before you uninstall KalaReach.";
