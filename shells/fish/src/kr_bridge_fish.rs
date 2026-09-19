//! The fish half of the KalaReach root-editor bridge.
//!
//! Copyright (c) Kala Powered.
//!
//! This file is added to fish by the KalaReach reader patch set and is
//! distributed under the GNU General Public Licence, version 2, that governs the rest of
//! the package; see shells/fish/LICENSE.
//!
//! fish's reader is Rust, so the shell-independent bridge core stays the C it is in every other
//! package and this module is the reader's side of it: it answers the `kr_shell_*` questions the
//! core asks from fish's own state, and it calls the core at the reader's own boundaries.
//!
//! Everything the contract asks a package to prove about its reader is read here in one operation,
//! at the instant the reader is asked: the sequence that invoked the current operation, the bytes
//! the terminal still holds, the events queued ahead of it, the edit buffer and which reader is
//! running. Taking the three queue states together, rather than one after another, is what a fence
//! rests on.
//!
//! Nothing here blocks the reader. The core's socket is non-blocking, its descriptor joins the
//! reader's own select set, and the mailbox is read at key-sequence boundaries and while the reader
//! waits for a key.

use std::cell::UnsafeCell;
use std::ffi::{CStr, CString, c_char, c_int, c_ulong};
use std::os::fd::RawFd;

use super::reader::{Reader, ReaderData, kr_terminal_eof, read_generation_count};
use crate::env::{EnvMode, EnvSetMode, EnvStack, Environment as _};
use crate::input::{
    CharEvent, DEFAULT_BIND_MODE, InputEventQueuer as _, KeyNameStyle, ReadlineCmd, bindings,
    input_function_get_code, input_get_bind_mode,
};
use crate::key::Key;
use crate::key::Modifiers;
use crate::parser::Parser;
use crate::prelude::*;
use crate::threads::assert_is_main_thread;
use fish_widestring::{WString, bytes2wcstring, wcs2bytes, wstr};

/// Which reader is running, as the contract names them.
const KR_CONTEXT_PRIMARY: c_int = 0;
const KR_CONTEXT_READ_BUILTIN: c_int = 2;

/// The editor's keymap.
const KR_KEYMAP_EMACS: c_int = 0;
const KR_KEYMAP_VI_INSERT: c_int = 1;
const KR_KEYMAP_VI_COMMAND: c_int = 2;
const KR_KEYMAP_CUSTOM: c_int = 3;

/// Where the reader took a character from.
const KR_SOURCE_TERMINAL: c_int = 0;
const KR_SOURCE_PUSHED_BACK: c_int = 3;
const KR_SOURCE_PASTE: c_int = 4;

/// Why the reader left.
pub const KR_LEAVE_COMMAND_ACCEPTED: c_int = 0;
pub const KR_LEAVE_READER_TAKEOVER: c_int = 2;
pub const KR_LEAVE_CANCELLATION: c_int = 3;
pub const KR_LEAVE_ROOT_EXIT: c_int = 4;

/// What the integration lost.
pub const KR_LOSS_POST_STARTUP_FAILURE: c_int = 0;
pub const KR_LOSS_SEMANTIC_HOOK_LOSS: c_int = 1;
pub const KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT: c_int = 3;

/// What the pre-EOF decision returns.
const KR_CONSUME: c_int = 1;

/// The longest invoking key sequence the snapshot carries.
const KR_KEYS_MAX: usize = 64;

/// The reader's own state, read in one operation at one instant.
///
/// The layout is `kr_reader_state` in `kr_bridge.h`, which the core fills in and reads back.
#[repr(C)]
pub struct KrReaderState {
    prompt_generation: c_ulong,
    reader_revision: c_ulong,
    reader_context: c_int,

    buffer_revision: c_ulong,
    buffer_empty: c_int,
    keymap: c_int,

    pending_quoted_insertion: c_int,
    pending_macro_input: c_int,
    pending_search: c_int,
    pending_numeric_argument: c_int,
    pending_multikey_sequence: c_int,
    pending_vi_motion: c_int,
    pending_paste: c_int,

    keys: [u8; KR_KEYS_MAX],
    keys_len: usize,
    pending_bytes: c_ulong,
    queued_keys: c_ulong,

    tty_typeahead_drained: c_int,
    macro_input_drained: c_int,
    partial_key_drained: c_int,

    cwd_revision: c_ulong,
}

impl Default for KrReaderState {
    fn default() -> Self {
        // Safety: every field is a plain integer or an array of them, so all zeroes is a value.
        unsafe { std::mem::zeroed() }
    }
}

/// What a non-destructive cancellation ended. The layout is `kr_cancellation` in `kr_bridge.h`.
#[repr(C)]
pub struct KrCancellation {
    partial_escape: c_int,
    quoted_insertion: c_int,
    vi_motion: c_int,
    multikey_sequence: c_int,
    macro_input: c_int,
    buffer_preserved: c_int,
    discarded_bytes: c_ulong,
}

unsafe extern "C" {
    fn kr_bridge_registered() -> c_int;
    fn kr_bridge_managed() -> c_int;
    fn kr_bridge_activate();
    fn kr_bridge_hooks_activated(prompt_generation: c_ulong);
    fn kr_bridge_editor_enter();
    fn kr_bridge_editor_leave(reason: c_int);
    fn kr_bridge_reader_idle();
    fn kr_bridge_command_accepted();
    fn kr_bridge_pre_eof(key: c_int, source: c_int) -> c_int;
    fn kr_bridge_service();
    fn kr_bridge_fd() -> c_int;
    fn kr_bridge_wants_write() -> c_int;
    fn kr_bridge_cancel_settled();
    fn kr_bridge_lost(loss: c_int, detail: *const c_char);
    fn kr_bridge_launch_pending() -> c_int;
}

/// The reader the core's questions are answered from, while one of its calls is in flight.
///
/// Every call into the core goes through [`with_reader`], which parks the reader here and takes it
/// out again afterwards. The core is synchronous and runs on the reader's own thread, so these
/// pointers are live for exactly as long as the call that parked them, and the borrow the caller
/// holds is suspended for the whole of it.
struct ParkedReader {
    data: *mut ReaderData,
    parser: *mut Parser,
}

struct ParkedReaderCell(UnsafeCell<Option<ParkedReader>>);
// Safety: the reader runs on the main thread and nothing else reads this.
unsafe impl Sync for ParkedReaderCell {}
static PARKED: ParkedReaderCell = ParkedReaderCell(UnsafeCell::new(None));

/// The reader-side state the contract counts, which fish keeps no counter of.
struct BridgeState {
    /// Counts primary readers, so a fence from an earlier prompt is stale.
    prompt_generation: u64,
    /// Counts every reader, so a reader started inside a prompt is a different reader.
    reader_revision: u64,
    /// Counts the directory changes a launch's expectation is checked against.
    ///
    /// The buffer's own revision is the reader's own edit generation, which counts edits rather
    /// than differences: a binding that changes the line and puts it back has changed it twice.
    cwd_revision: u64,
    /// How many readers are running, because one can start inside another.
    reader_depth: usize,

    /// The sequence that invoked the operation running now, which is this reader's `$KEYS`.
    ///
    /// These are the reader's own decoded keys rather than the bytes the terminal sent: one key
    /// can arrive as a whole escape sequence under a keyboard protocol, and a gesture is one key
    /// whatever encoding carried it.
    invoking_keys: Vec<u8>,
    /// How many keys that sequence holds, which is what tells one key from a binding of several.
    invoking_key_count: usize,
    /// The character the single key that invoked it stands for, when it was one key.
    invoking_byte: Option<u8>,
    /// How many events the reader has peeked for a sequence it has not resolved yet.
    peeked_keys: usize,
    /// How many bytes those events arrived as, which is what a cancellation throws away.
    peeked_bytes: usize,
    /// True while the reader waits for another key, which is what makes a sequence partial.
    in_key_wait: bool,
    /// True while a resolved sequence has not run: the person typed it, so it goes first.
    key_selected: bool,
    /// True while an input function waits for the target character it takes as an argument.
    pending_target: bool,
    /// True while `get-key` waits for the literal key it reports rather than acts on.
    pending_literal_key: bool,
    /// True while the decoder holds the first bytes of a character it has not finished.
    partial_character: bool,
    /// True while the reader holds characters it has taken and not yet put in the buffer.
    accumulated_characters: bool,
    /// True when the character being judged came from the reader's own queue.
    source_pushed_back: bool,
    /// Whether this wait has already reported the reader idle.
    idle_reported: bool,

    /// A takeover's cancellation: requested inside the wait, settled at the next boundary.
    cancel_requested: bool,
    /// The old lease's undelivered input, dropped once the reader is out of what it was inside.
    cancel_drain: bool,
    /// The text a launch installed, so a revocation takes exactly that back out.
    installed: Option<WString>,
    /// Set by the core when it accepts a line; acted on once the core's call has returned.
    accept_requested: bool,
    /// True once the acceptance has been submitted and the reader has not left with it yet.
    accept_submitted: bool,

    /// The gesture key the named binding is installed on, and what was bound in each mode it
    /// went on before it.
    gesture_key: Option<Key>,
    gesture_previous: Vec<(WString, Vec<WString>)>,
    gesture_bound: bool,
    /// True once the gesture has been looked at, so a terminal that starts with none is still
    /// followed when the person gives it one.
    gesture_followed: bool,
}

struct BridgeStateCell(UnsafeCell<BridgeState>);
// Safety: the reader runs on the main thread and nothing else reads this.
unsafe impl Sync for BridgeStateCell {}
static STATE: BridgeStateCell = BridgeStateCell(UnsafeCell::new(BridgeState {
    prompt_generation: 0,
    reader_revision: 0,
    cwd_revision: 0,
    reader_depth: 0,
    invoking_keys: Vec::new(),
    invoking_key_count: 0,
    invoking_byte: None,
    peeked_keys: 0,
    peeked_bytes: 0,
    in_key_wait: false,
    key_selected: false,
    pending_target: false,
    pending_literal_key: false,
    partial_character: false,
    accumulated_characters: false,
    source_pushed_back: false,
    idle_reported: false,
    cancel_requested: false,
    cancel_drain: false,
    installed: None,
    accept_requested: false,
    accept_submitted: false,
    gesture_key: None,
    gesture_previous: Vec::new(),
    gesture_bound: false,
    gesture_followed: false,
}));

/// The bridge's own state. Main thread only, like the reader it belongs to.
///
/// Every caller takes it for one short stretch and gives it back: it is never held across a call
/// into the core, which can ask a question that needs it again.
fn state() -> &'static mut BridgeState {
    assert_is_main_thread();
    // Safety: only ever taken on the main thread, and never held across a call into the core.
    unsafe { &mut *STATE.0.get() }
}

/// Runs `body` with `reader` parked where the core's questions can reach it.
///
/// Nesting is real: a `read` builtin runs inside a primary reader, and the inner reader parks over
/// the outer one and gives it back on the way out.
fn with_reader<R>(reader: &mut Reader<'_>, body: impl FnOnce() -> R) -> R {
    assert_is_main_thread();
    let parked = ParkedReader {
        data: reader.data as *mut ReaderData,
        parser: reader.parser as *mut Parser,
    };
    // Safety: main thread only; the previous value goes back before this function returns.
    let previous = unsafe { (*PARKED.0.get()).replace(parked) };
    let result = body();
    // Safety: same cell, same thread, and nothing between here and there took it away.
    unsafe { *PARKED.0.get() = previous };
    result
}

/// The parked reader, for a question the core asks while one of its calls is in flight.
fn parked_data() -> Option<&'static mut ReaderData> {
    assert_is_main_thread();
    // Safety: main thread only, and the pointer is live for the whole of the call that parked it.
    unsafe { (*PARKED.0.get()).as_ref().map(|parked| &mut *parked.data) }
}

/// The parked reader's parser.
fn parked_parser() -> Option<&'static mut Parser> {
    assert_is_main_thread();
    // Safety: as above, and it is a different object from the reader data beside it.
    unsafe { (*PARKED.0.get()).as_ref().map(|parked| &mut *parked.parser) }
}

/// The character a key stands for, where it stands for one.
///
/// The reader names a control character by the letter it is typed with and a modifier, so the
/// gesture the terminal's line discipline holds as one byte is that letter and `ctrl` here. This
/// is the way back, and it is what the end-of-file decision and the fence snapshot both carry:
/// under a keyboard protocol one key arrives as a whole escape sequence, and neither the last byte
/// of that sequence nor its length says anything about which key it was.
fn control_byte(key: Key) -> Option<u8> {
    let plain = !key.modifiers.alt && !key.modifiers.shift && !key.modifiers.sup;
    if key.modifiers.ctrl && plain {
        if key.codepoint.is_ascii_lowercase() {
            return Some(key.codepoint as u8 - b'a' + 1);
        }
        // The control characters above the letters, which the reader names in upper case.
        if ('A'..='_').contains(&key.codepoint) {
            return Some(key.codepoint as u8 - b'A' + 1);
        }
        return None;
    }
    if key.modifiers == Modifiers::default() && key.codepoint.is_ascii() {
        return Some(key.codepoint as u8);
    }
    None
}

/// How many bytes the terminal is still holding for this reader.
fn terminal_typeahead(fd: RawFd) -> u64 {
    if fd < 0 {
        return 0;
    }
    let mut available: c_int = 0;
    // Safety: a read-only ioctl on a descriptor the reader owns, writing into a local.
    let result = unsafe { libc::ioctl(fd, libc::FIONREAD, &raw mut available) };
    if result < 0 || available < 0 {
        0
    } else {
        u64::try_from(available).unwrap_or(0)
    }
}

/// One of the shell's own variables, as a string, or empty when it is not set.
fn named_value(parser: &Parser, name: &wstr) -> WString {
    parser
        .vars()
        .get(name)
        .map(|value| value.as_string())
        .unwrap_or_default()
}

/// The keymap the editor is in, as the contract names them.
fn keymap_of(parser: &Parser) -> c_int {
    let vars = parser.vars();
    let bindings = vars
        .get(L!("fish_key_bindings"))
        .map(|value| value.as_string())
        .unwrap_or_default();
    if bindings.is_empty() || bindings == L!("fish_default_key_bindings") {
        return KR_KEYMAP_EMACS;
    }
    if bindings != L!("fish_vi_key_bindings") && bindings != L!("fish_hybrid_key_bindings") {
        return KR_KEYMAP_CUSTOM;
    }
    // fish names the vi modes in `fish_bind_mode`; the ones that insert text are the insert mode.
    let mode = input_get_bind_mode(vars);
    if mode == L!("insert") || mode == L!("replace") || mode == L!("replace_one") {
        KR_KEYMAP_VI_INSERT
    } else {
        KR_KEYMAP_VI_COMMAND
    }
}

// ---- what the reader supplies ------------------------------------------------------------------

/// Fills `out` from the reader's own state, atomically.
///
/// # Safety
///
/// `out` is the core's own `kr_reader_state`, which it owns for the whole of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_reader_state(out: *mut KrReaderState) {
    // Safety: the core passes a pointer to one of its own live structures.
    let out = unsafe { &mut *out };
    *out = KrReaderState::default();

    let state = state();
    out.prompt_generation = state.prompt_generation as c_ulong;
    out.reader_revision = state.reader_revision as c_ulong;

    let Some(data) = parked_data() else {
        // Outside a reader there is nothing to prove: every queue reads as clear and the buffer as
        // empty, and the worker's own phase gate is what keeps that from becoming a fence.
        out.reader_context = KR_CONTEXT_PRIMARY;
        out.buffer_empty = 1;
        out.tty_typeahead_drained = 1;
        out.macro_input_drained = 1;
        out.partial_key_drained = 1;
        out.buffer_revision = read_generation_count() as c_ulong;
        out.cwd_revision = state.cwd_revision as c_ulong;
        return;
    };

    let mut vi_count = false;
    let mut vi_operator = false;
    if let Some(parser) = parked_parser() {
        out.keymap = keymap_of(parser);
        // This reader's own vi bindings accumulate a count and wait for an operator's motion in
        // the shell's own variables, and they are where those two states are.
        vi_count = !named_value(parser, L!("__fish_vi_count")).is_empty();
        vi_operator = !named_value(parser, L!("__fish_vi_operator")).is_empty()
            || input_get_bind_mode(parser.vars()) == L!("operator");
    }

    out.reader_context = if data.kr_is_primary() {
        KR_CONTEXT_PRIMARY
    } else {
        // fish edits a continuation inside one buffer, so the other reader it runs is the one the
        // `read` builtin pushes.
        KR_CONTEXT_READ_BUILTIN
    };
    // The reader's own edit generation: one for every edit the line went through, which is what
    // makes a change and a change back two changes rather than none.
    out.buffer_revision = read_generation_count() as c_ulong;
    out.buffer_empty = c_int::from(data.kr_command_line().is_empty());

    // fish has no quoted insertion of its own; `get-key` is the operation that waits for a literal
    // key and reports it rather than acting on it, which is the state the exclusion protects.
    out.pending_quoted_insertion = c_int::from(state.pending_literal_key);
    // Events queued ahead of the terminal are the reader's own input, not the person's.
    out.pending_macro_input = c_int::from(!data.input_data.queue.is_empty());
    out.pending_search = c_int::from(data.kr_search_active());
    out.pending_numeric_argument = c_int::from(vi_count);
    out.pending_multikey_sequence = c_int::from(state.in_key_wait && state.peeked_keys > 0);
    // A jump waiting for its target, and an operator waiting for the motion it applies to.
    out.pending_vi_motion = c_int::from(state.pending_target || vi_operator);
    out.pending_paste = c_int::from(data.input_data.paste_buffer.is_some());

    let keys = state.invoking_keys.len().min(KR_KEYS_MAX);
    out.keys[..keys].copy_from_slice(&state.invoking_keys[..keys]);
    out.keys_len = keys;
    out.pending_bytes =
        (terminal_typeahead(data.kr_input_fd()) + u64::from(state.key_selected)) as c_ulong;
    out.queued_keys = data.input_data.queue.len() as c_ulong;

    out.tty_typeahead_drained = c_int::from(out.pending_bytes == 0);
    out.macro_input_drained = c_int::from(out.queued_keys == 0);
    // Anything that owns input the reader has taken and not acted on holds this queue: a sequence
    // it has peeked and not resolved, the first bytes of a character it has not finished,
    // characters it has read and not yet put in the buffer, an input function waiting for its
    // target, `get-key` waiting for a literal key, an operator waiting for the motion it applies
    // to, and a count waiting for the command it counts.
    out.partial_key_drained = c_int::from(
        !(state.in_key_wait && state.peeked_keys > 0)
            && !state.partial_character
            && !state.accumulated_characters
            && !state.pending_target
            && !state.pending_literal_key
            && !vi_operator
            && !vi_count,
    );

    out.cwd_revision = state.cwd_revision as c_ulong;
}

/// Installs `text` in the empty edit buffer. Returns non-zero when it went in.
///
/// # Safety
///
/// `text` is `len` bytes the core owns for the whole of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_install_command(text: *const c_char, len: usize) -> c_int {
    let Some(data) = parked_data() else {
        return 0;
    };
    if len == 0 || !data.kr_command_line().is_empty() {
        return 0;
    }
    // Safety: the core hands over exactly `len` bytes of its own encoded command.
    let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), len) };
    let line = bytes2wcstring(bytes);
    data.kr_set_command_line(&line);

    let installed = data.kr_command_line().to_owned();
    let state = state();
    let went_in = !installed.is_empty();
    state.installed = went_in.then_some(installed);
    c_int::from(went_in)
}

/// Removes text a launch installed that has not been accepted. Returns non-zero when it came out.
///
/// The acceptance this bridge submitted goes with it: a line that was on its way to the editor's
/// own execute is taken off that way as well as out of the buffer, so a revoked launch leaves
/// nothing behind wherever the reader had got to.
#[unsafe(no_mangle)]
pub extern "C" fn kr_shell_remove_installed() -> c_int {
    let Some(installed) = state().installed.take() else {
        return 0;
    };
    {
        let state = state();
        state.accept_requested = false;
        state.accept_submitted = false;
    }
    let Some(data) = parked_data() else {
        return 0;
    };
    // The acceptance this bridge put in the queue has not run yet if it is still there.
    data.input_data.queue.retain(|event| {
        !matches!(event, CharEvent::Readline(readline) if readline.cmd == ReadlineCmd::Execute)
    });
    // Only the text this launch installed comes out, and only while it is still all there.
    if data.kr_command_line() == installed {
        data.kr_clear_command_line();
    }
    1
}

/// Accepts the installed line.
///
/// The acceptance itself is the editor's own `execute`, submitted at the boundary this call
/// returns to, so the line goes through the same path a person's return key takes.
#[unsafe(no_mangle)]
pub extern "C" fn kr_shell_accept_line() {
    state().accept_requested = true;
}

/// Ends the pending key wait and keeps the edit buffer, reporting what it ended.
///
/// # Safety
///
/// `out` is the core's own `kr_cancellation`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_cancel_key_wait(out: *mut KrCancellation) {
    // Safety: the core passes a pointer to one of its own live structures.
    let out = unsafe { &mut *out };
    let queued = parked_data().map_or(0, |data| {
        data.input_data
            .queue
            .iter()
            .filter(|event| event.is_char())
            .count()
    });
    let queued_bytes: usize = parked_data().map_or(0, |data| {
        data.input_data.queue.iter().map(event_bytes).sum()
    });
    let state = state();
    let partial = state.in_key_wait && state.peeked_keys > 0;

    out.partial_escape = c_int::from(partial && state.invoking_keys.first() == Some(&0x1b));
    out.multikey_sequence = c_int::from(partial);
    out.quoted_insertion = c_int::from(state.pending_literal_key);
    out.vi_motion = c_int::from(state.pending_target);
    out.macro_input = c_int::from(queued > 0);
    // The reader's own interruption path keeps the edit buffer: it gives the part-read sequence
    // back, handles the interruption and tries the sequence again, and nothing in it touches the
    // line.
    out.buffer_preserved = 1;

    if out.partial_escape != 0
        || out.multikey_sequence != 0
        || out.quoted_insertion != 0
        || out.vi_motion != 0
        || out.macro_input != 0
    {
        // What the drain will throw away: the bytes the person's own queued input arrived as,
        // and the bytes of the sequence this reader had peeked and not resolved.
        out.discarded_bytes = (queued_bytes + state.peeked_bytes) as c_ulong;
        // The reader is inside something, so it is brought out of it: the wait ends here and the
        // old lease's undelivered input is dropped at the boundary that follows.
        state.cancel_requested = true;
    } else {
        // Nothing was in progress, so there is nothing to unwind and nothing to throw away. The
        // reader stays in the wait it is in, and a sequence the person starts afterwards is not
        // taken for one this cancellation ended.
        out.discarded_bytes = 0;
    }
}

/// Returns `argument` quoted for this shell, in memory the caller frees, or null.
///
/// Every argument is quoted, including the first: an argument vector is installed as literal
/// arguments, and a bare word at command position would be a function name, an abbreviation or a
/// variable expansion rather than the name the caller asked to run. Inside this shell's single
/// quotes only a backslash and a single quote mean anything, so escaping those two is the whole
/// of it.
///
/// # Safety
///
/// `argument` is a null-terminated string the core owns for the whole of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_quote_argument(argument: *const c_char) -> *mut c_char {
    // Safety: the core passes one of its own null-terminated strings.
    let argument = unsafe { CStr::from_ptr(argument) };
    let mut quoted = Vec::with_capacity(argument.to_bytes().len() + 3);
    quoted.push(b'\'');
    for byte in argument.to_bytes() {
        if *byte == b'\\' || *byte == b'\'' {
            quoted.push(b'\\');
        }
        quoted.push(*byte);
    }
    quoted.push(b'\'');
    quoted.push(0);

    // Safety: the core frees this with `free`, so it comes from `malloc`.
    let destination = unsafe { libc::malloc(quoted.len()) }.cast::<u8>();
    if destination.is_null() {
        return std::ptr::null_mut();
    }
    // Safety: `destination` holds exactly `quoted.len()` bytes, which is what is copied into it.
    unsafe { std::ptr::copy_nonoverlapping(quoted.as_ptr(), destination, quoted.len()) };
    destination.cast::<c_char>()
}

/// Prints one line above the prompt and redraws it.
///
/// # Safety
///
/// `line` is a null-terminated string the core owns for the whole of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_print_hint(line: *const c_char) {
    // Safety: the core passes one of its own null-terminated strings.
    let line = unsafe { CStr::from_ptr(line) };
    let text = bytes2wcstring(line.to_bytes());
    if let Some(data) = parked_data() {
        data.kr_print_above_prompt(&text);
    }
}

/// The terminal's `VEOF`, or -1 when the terminal has no end-of-file character.
///
/// The reader holds the terminal in the shell's own modes while it reads, and those keep their own
/// control characters, so the character the person configured is the one the shell hands to the
/// programs it runs. A disabled `VEOF` leaves the terminal with no gesture, so no character is one.
#[unsafe(no_mangle)]
pub extern "C" fn kr_shell_veof() -> c_int {
    kr_terminal_eof()
}

/// Removes one variable from the shell's own exported environment.
///
/// # Safety
///
/// `name` is a null-terminated string the core owns for the whole of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kr_shell_unexport(name: *const c_char) {
    // Safety: the core passes one of its own null-terminated strings.
    let name = unsafe { CStr::from_ptr(name) };
    let name = bytes2wcstring(name.to_bytes());
    // The shell's own variable goes with the environment entry, so a child inherits neither.
    for scope in [EnvMode::GLOBAL, EnvMode::UNIVERSAL] {
        EnvStack::globals().remove(&name, EnvSetMode::new(scope, /*is_repainting=*/ false));
    }
}

// ---- what the reader calls ---------------------------------------------------------------------

/// True once the handshake has been accepted.
pub fn registered() -> bool {
    // Safety: the core keeps this flag and asks nothing of ours to report it.
    unsafe { kr_bridge_registered() != 0 }
}

/// True once this shell has ever been a managed root shell. It never returns to false.
pub fn managed() -> bool {
    // Safety: as above.
    unsafe { kr_bridge_managed() != 0 }
}

/// Attempts the handshake, unless the bootstrap variables say there is nothing to attempt.
///
/// Called once, before the user's startup files and before the first primary reader. A shell that
/// inherited nothing skips it, which is what keeps the guarded startup entry inert in every child.
pub fn activate() {
    assert_is_main_thread();
    // Safety: no reader exists yet, so nothing of ours is parked and nothing is asked of one.
    unsafe { kr_bridge_activate() };
}

/// Reports that the user's startup files have run and the user-facing hooks are live.
///
/// This is also where the named binding goes on: the gesture is bound after the user's own `bind`
/// calls, so their configuration is what it is put on top of rather than what it replaces.
pub fn hooks_activated(reader: &mut Reader<'_>) {
    if !registered() {
        return;
    }
    bind_gesture(reader);
    let generation = state().prompt_generation + 1;
    with_reader(reader, || {
        // Safety: the reader is parked for the whole of the call.
        unsafe { kr_bridge_hooks_activated(generation as c_ulong) };
    });
}

/// Reports that the ground the integration stood on has gone.
pub fn lost(reader: &mut Reader<'_>, loss: c_int, detail: &wstr) {
    let detail = CString::new(wcs2bytes(detail)).unwrap_or_default();
    with_reader(reader, || {
        // Safety: the reader is parked, and the detail lives until the call returns.
        unsafe { kr_bridge_lost(loss, detail.as_ptr()) };
    });
}

/// The bridge's descriptor, for the reader's own select set, or -1.
pub fn bridge_fd() -> RawFd {
    if !registered() {
        return -1;
    }
    // Safety: the core owns the descriptor and only reports it.
    unsafe { kr_bridge_fd() }
}

/// The reader has started. Reports the boundary and resets what belongs to one reader.
pub fn editor_enter(reader: &mut Reader<'_>) {
    if !registered() {
        return;
    }
    if state().reader_depth > 0 {
        // A reader starting inside another is a takeover: the one that was running is over, and
        // it is still underneath, so it comes back when this one leaves.
        emit_leave(reader, KR_LEAVE_READER_TAKEOVER);
    }
    state().reader_depth += 1;
    let primary = reader.kr_is_primary();
    {
        let state = state();
        state.reader_revision += 1;
        if primary {
            state.prompt_generation += 1;
        }
        state.invoking_keys.clear();
        state.peeked_keys = 0;
        state.peeked_bytes = 0;
        state.in_key_wait = false;
        state.key_selected = false;
        state.pending_target = false;
        state.pending_literal_key = false;
        state.source_pushed_back = false;
        state.idle_reported = false;
        state.cancel_requested = false;
        state.cancel_drain = false;
        state.installed = None;
        state.accept_requested = false;
        state.accept_submitted = false;
    }

    // A reassigned gesture takes effect at the prompt it names, which is this one.
    follow_gesture(reader);

    emit_enter(reader);
}

/// Reports one reader's entry.
fn emit_enter(reader: &mut Reader<'_>) {
    with_reader(reader, || {
        // Safety: the reader is parked for the whole of both calls.
        unsafe {
            // A reader that is starting is not inside anything a cancellation has to unwind.
            kr_bridge_cancel_settled();
            kr_bridge_editor_enter();
        }
    });
}

/// Reports one reader's departure, with the accepted line first when there was one.
fn emit_leave(reader: &mut Reader<'_>, reason: c_int) {
    with_reader(reader, || {
        // Safety: the reader is parked for the whole of these calls.
        unsafe {
            kr_bridge_cancel_settled();
            if reason == KR_LEAVE_COMMAND_ACCEPTED {
                // The accepted line is reported from the reader, inside the fence, before the
                // leave: a record sent afterwards could only say that nothing was established.
                kr_bridge_command_accepted();
            }
            kr_bridge_editor_leave(reason);
        }
    });
}

/// The reader is leaving. An accepted line is reported first, from inside the fence.
///
/// A reader that was running underneath this one comes back, and it is a different reader from the
/// one that just left: it gets its own revision and its own entry, so a fence taken against the
/// reader that has gone is stale rather than mistaken for the one running now.
pub fn editor_leave(reader: &mut Reader<'_>, reason: c_int) {
    if !registered() || state().reader_depth == 0 {
        return;
    }
    {
        let state = state();
        state.reader_depth -= 1;
        state.installed = None;
        state.accept_requested = false;
        state.accept_submitted = false;
        state.cancel_requested = false;
        state.cancel_drain = false;
    }
    emit_leave(reader, reason);

    if state().reader_depth > 0 {
        {
            let state = state();
            state.reader_revision += 1;
            state.invoking_keys.clear();
            state.invoking_key_count = 0;
            state.invoking_byte = None;
            state.peeked_keys = 0;
            state.peeked_bytes = 0;
            state.in_key_wait = false;
            state.key_selected = false;
            state.pending_target = false;
            state.pending_literal_key = false;
            state.source_pushed_back = false;
            state.idle_reported = false;
        }
        emit_enter(reader);
    }
}

/// Reads the mailbox and answers what is in it.
///
/// Safe only at a key-sequence boundary or while the reader waits for a key, which is where every
/// caller of this is. Returns true when the reader must come out of what it is doing: a launch was
/// accepted, or a cancellation ended the wait.
pub fn service(reader: &mut Reader<'_>) -> bool {
    if !registered() {
        return false;
    }
    with_reader(reader, || {
        // Safety: the reader is parked for the whole of the call.
        unsafe { kr_bridge_service() };
    });
    settle(reader)
}

/// Carries out what reading the mailbox asked the reader to do.
fn settle(reader: &mut Reader<'_>) -> bool {
    let mut interrupted = false;
    if std::mem::take(&mut state().accept_requested) {
        // The line goes through the editor's own acceptance, submitted at this boundary. The
        // record of what was installed stays until the reader actually leaves with it: until
        // then a revocation still has text to take back out.
        state().accept_submitted = true;
        reader.push_front(CharEvent::from_readline(ReadlineCmd::Execute, vec![]));
        interrupted = true;
    }
    if std::mem::take(&mut state().cancel_requested) {
        // The reader's own interruption path: a non-character event in the queue makes it give
        // back the part-read sequence, handle this first and try the sequence again. The edit
        // buffer is not touched by any of it.
        reader.push_front(CharEvent::from_check_exit());
        // The part-read sequence comes back to the queue behind that event, and it is the old
        // lease's undelivered input, so it goes at the boundary this pass ends at. Nothing more
        // is read or answered until the reader has come out of what the cancellation ended,
        // which is that boundary rather than this one.
        state().cancel_drain = true;
        state().idle_reported = false;
        interrupted = true;
    }
    interrupted
}

/// One key-sequence boundary: the reader has resolved one complete sequence and is between
/// operations, which is where its mailbox is read.
pub fn boundary(reader: &mut Reader<'_>) {
    if !managed() {
        return;
    }
    state().key_selected = true;
    let _ = service(reader);
    let state = state();
    state.key_selected = false;
    // The next wait is a fresh chance to be idle.
    state.idle_reported = false;
}

/// The reader is about to wait for a key with nothing left to read.
///
/// This is one of the three points a worker retries a withheld fence at.
pub fn before_wait(reader: &mut Reader<'_>) {
    if !registered() {
        return;
    }
    if reader.kr_querying() || terminal_typeahead(reader.kr_input_fd()) > 0 {
        // A reader with bytes still waiting on its terminal has something left to read, whether
        // that is the person's typing or the answer to a question it asked the terminal itself.
        return;
    }
    {
        let state = state();
        if state.idle_reported || state.peeked_keys > 0 {
            return;
        }
        state.idle_reported = true;
        state.in_key_wait = true;
    }
    if reader.input_data.queue.iter().any(CharEvent::is_char) {
        let state = state();
        state.idle_reported = false;
        state.in_key_wait = false;
        return;
    }
    with_reader(reader, || {
        // Safety: the reader is parked for the whole of the call.
        unsafe { kr_bridge_reader_idle() };
    });
    state().in_key_wait = false;
}

/// Reads the mailbox while the reader waits for a key.
pub fn wait(reader: &mut Reader<'_>) -> bool {
    if !registered() {
        return false;
    }
    state().in_key_wait = true;
    let interrupted = service(reader);
    state().in_key_wait = false;
    interrupted
}

/// The end of one pass of the read loop.
///
/// Whatever a cancellation ended has ended by here, so anything that was waiting behind it is read
/// at this boundary rather than at the person's next keystroke.
pub fn pass_end(reader: &mut Reader<'_>) {
    if !registered() {
        return;
    }
    if std::mem::take(&mut state().cancel_drain) {
        // The reader is out of whatever the cancellation ended, so the old lease's undelivered
        // input goes here rather than reaching the person's next prompt. The edit buffer, which
        // is not input, stays exactly as it was.
        reader.input_data.queue.retain(|event| !event.is_char());
        {
            let state = state();
            state.peeked_keys = 0;
            state.peeked_bytes = 0;
            state.pending_target = false;
            state.pending_literal_key = false;
            state.idle_reported = false;
        }
        with_reader(reader, || {
            // Safety: the reader is parked for the whole of the call.
            unsafe { kr_bridge_cancel_settled() };
        });
    }
    let _ = service(reader);
}

/// True while a launch this bridge installed is waiting to be accepted.
pub fn launch_pending() -> bool {
    // Safety: the core keeps this flag and asks nothing of ours to report it.
    unsafe { kr_bridge_launch_pending() != 0 }
}

/// Records the sequence that invoked the operation about to run, which is this reader's `$KEYS`.
///
/// What is recorded is the reader's own keys, one entry per key, rather than the bytes that
/// carried them: under a keyboard protocol one key arrives as a whole escape sequence, and a
/// gesture is one key however it was encoded.
pub fn record_invoking_keys(events: &[CharEvent]) {
    let state = state();
    state.invoking_keys.clear();
    state.invoking_key_count = 0;
    state.invoking_byte = None;
    for event in events {
        let Some(key) = event.get_key() else {
            continue;
        };
        state.invoking_key_count += 1;
        state.invoking_byte = control_byte(key.key.key);
        match state.invoking_byte {
            Some(byte) => state.invoking_keys.push(byte),
            None => {
                let mut encoded = [0u8; 4];
                state
                    .invoking_keys
                    .extend(key.key.key.codepoint.encode_utf8(&mut encoded).as_bytes().iter());
            }
        }
    }
    if state.invoking_key_count != 1 {
        state.invoking_byte = None;
    }
    state.invoking_keys.truncate(KR_KEYS_MAX);
}

/// Records the events the reader has peeked for a sequence it has not resolved.
///
/// Both how many there are and the bytes they arrived as: one key can be a whole escape sequence,
/// and what a cancellation throws away is counted in bytes.
pub fn note_peeked(events: &[CharEvent]) {
    let state = state();
    state.peeked_keys = events.len();
    state.peeked_bytes = events.iter().map(event_bytes).sum();
}

/// How many bytes of the terminal's own input this event carried.
///
/// An event the reader made for itself carries none: a readline command pushed by a binding is
/// not input the person typed, and throwing it away discards no bytes of theirs.
fn event_bytes(event: &CharEvent) -> usize {
    event
        .get_key()
        .map_or(0, |key| wcs2bytes(&key.seq).len())
}

/// Records which of the reader's own input sources the character being judged came from.
pub fn note_source_pushed_back(pushed_back: bool) {
    state().source_pushed_back = pushed_back;
}

/// An input function waiting for the target character it takes as an argument.
pub fn note_pending_target(active: bool) {
    state().pending_target = active;
}

/// `get-key` waiting for the literal key it reports.
pub fn note_pending_literal_key(active: bool) {
    state().pending_literal_key = active;
}

/// The decoder holding the first bytes of a character it has not finished.
pub fn note_partial_character(active: bool) {
    state().partial_character = active;
}

/// The reader holding characters it has taken from the terminal and not yet put in the buffer.
pub fn note_accumulated_characters(active: bool) {
    state().accumulated_characters = active;
}

/// A directory change, which is one whether or not it ends where it started.
pub fn note_cwd_changed() {
    state().cwd_revision += 1;
}

/// True while the bridge holds an answer it could not finish writing.
pub fn wants_write() -> bool {
    // Safety: the core keeps this and asks nothing of ours to report it.
    registered() && unsafe { kr_bridge_wants_write() != 0 }
}

// ---- the named reader binding ------------------------------------------------------------------

/// Every bind mode this reader can be in, so a gesture is a gesture in all of them.
///
/// The shell's own vi bindings move between modes as the person types, and a key bound in one of
/// them is the editor's own everywhere else. The modes below are the ones the shipped bindings
/// use, plus whichever the reader is in now.
fn gesture_modes(parser: &Parser) -> Vec<WString> {
    let mut modes: Vec<WString> = [
        DEFAULT_BIND_MODE,
        L!("insert"),
        L!("visual"),
        L!("replace"),
        L!("replace_one"),
        L!("operator"),
        L!("paste"),
    ]
    .iter()
    .map(|mode| (*mode).to_owned())
    .collect();
    let current = input_get_bind_mode(parser.vars());
    if !modes.contains(&current) {
        modes.push(current);
    }
    modes
}

/// Puts the named binding on the gesture key in every mode, keeping whatever was bound there.
///
/// The previous commands are kept rather than discarded: outside the detach condition the binding
/// runs them, so the person's own key keeps doing what they bound it to.
fn bind_gesture(reader: &mut Reader<'_>) {
    let veof = kr_shell_veof();
    let key = u8::try_from(veof).ok().map(Key::from_single_byte);
    if state().gesture_followed && state().gesture_bound && state().gesture_key == key {
        return;
    }
    state().gesture_followed = true;
    if state().gesture_bound {
        unbind_gesture();
    }
    let Some(key) = key else {
        // A terminal with no end-of-file character has no gesture to bind. The next prompt looks
        // again, so a terminal that is given one later is followed.
        state().gesture_key = None;
        return;
    };

    let modes = gesture_modes(reader.parser);
    let mut previous: Vec<(WString, Vec<WString>)> = Vec::with_capacity(modes.len());
    let mut bindings = bindings();
    for mode in modes {
        // What this key does in this mode now: the person's own binding where they made one, and
        // the editor's own where they did not. Whichever it is, that is what runs outside the
        // detach condition, so the key keeps doing what it did.
        let mut before: Vec<WString> = bindings
            .get(&[key], Some(&mode), /*user=*/ true)
            .first()
            .map(|binding| binding.commands.clone())
            .unwrap_or_default();
        if before.is_empty() {
            before = bindings
                .get(&[key], Some(&mode), /*user=*/ false)
                .first()
                .map(|binding| binding.commands.clone())
                .unwrap_or_default();
        }
        bindings.add(
            vec![key],
            KeyNameStyle::Normal,
            vec![L!("kr-eof-decide").to_owned()],
            mode.clone(),
            None,
            /*user=*/ true,
            None,
        );
        previous.push((mode, before));
    }
    drop(bindings);

    let state = state();
    state.gesture_key = Some(key);
    state.gesture_previous = previous;
    state.gesture_bound = true;
}

/// Takes the named binding off the gesture key and gives every mode back what it had.
fn unbind_gesture() {
    let state = state();
    let Some(key) = state.gesture_key else {
        state.gesture_bound = false;
        return;
    };
    let previous = std::mem::take(&mut state.gesture_previous);
    state.gesture_bound = false;
    state.gesture_key = None;

    let mut bindings = bindings();
    for (mode, commands) in previous {
        if commands.is_empty() {
            bindings.erase(&[key], &mode, /*user=*/ true);
        } else {
            bindings.add(
                vec![key],
                KeyNameStyle::Normal,
                commands,
                mode,
                None,
                /*user=*/ true,
                None,
            );
        }
    }
}

/// Follows a `VEOF` reassignment to the key it names, at the prompt it takes effect at.
///
/// The character the reader is holding was typed under the gesture that was in force when it was
/// typed, so the binding moves between prompts rather than inside one.
pub fn follow_gesture(reader: &mut Reader<'_>) {
    if !registered() || !state().gesture_followed {
        return;
    }
    bind_gesture(reader);
}

/// The named binding: the end-of-file decision, taken with the actual reader context.
///
/// Outside the detach condition the previous function or script block runs, which is what keeps a
/// key the person bound doing what they bound it to.
pub fn eof_decide(reader: &mut Reader<'_>) {
    let pasting = reader.input_data.paste_buffer.is_some();
    let (source, key) = {
        let state = state();
        let source = if state.source_pushed_back {
            KR_SOURCE_PUSHED_BACK
        } else if pasting {
            KR_SOURCE_PASTE
        } else {
            KR_SOURCE_TERMINAL
        };
        // The decoded key, and only when one key invoked this: a binding of several keys is that
        // binding's, and the character at the end of it belongs to the sequence rather than being
        // a gesture somebody made.
        let key = if state.invoking_key_count == 1 {
            state.invoking_byte.unwrap_or(0)
        } else {
            0
        };
        (source, key)
    };

    let consumed = with_reader(reader, || {
        // Safety: the reader is parked for the whole of the call.
        unsafe { kr_bridge_pre_eof(c_int::from(key), source) == KR_CONSUME }
    });
    let _ = settle(reader);
    if consumed {
        // `consume` continues the same reader, so there is nothing left to do with the character.
        return;
    }
    replay_previous_binding(reader);
}

/// Runs what was bound to the gesture key, in this mode, before the named binding went on it.
fn replay_previous_binding(reader: &mut Reader<'_>) {
    let mode = input_get_bind_mode(reader.parser.vars());
    let commands = state()
        .gesture_previous
        .iter()
        .find(|(bound, _)| *bound == mode)
        .map(|(_, commands)| commands.clone())
        .unwrap_or_default();
    if commands.is_empty() {
        // Nothing was on this key in this mode, and an unbound key is one the editor does
        // nothing with. Substituting its end-of-file command here would end a shell over a key
        // that never had that meaning.
        return;
    }
    // The same order `bind` itself uses: the commands run front to back, so they go on in reverse.
    for command in commands.iter().rev() {
        let event = match input_function_get_code(command) {
            Some(code) => CharEvent::from_readline(code, vec![]),
            None => CharEvent::Command(command.clone()),
        };
        reader.push_front(event);
    }
}
