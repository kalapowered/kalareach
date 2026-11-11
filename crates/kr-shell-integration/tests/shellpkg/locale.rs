//! The locale a package's shell runs in.
//!
//! An editor draws a changed line differently in a byte locale and in a multibyte one: Readline
//! rewrites the characters it has to move over in the first, and moves the cursor over them with a
//! control sequence in the second. People run the product under UTF-8, and a hosted runner can
//! carry a locale of its own, so the harness starts every shell in the byte locale and a case that
//! depends on how the editor draws goes through [`in_each_locale`], which runs it under each
//! locale in turn and names the locale of every run in the log.
//!
//! A platform with no UTF-8 locale gets no run under it, and says so. A run that has to show the
//! UTF-8 runs sets `KR_REQUIRE_UTF8_LOCALE=1`, which turns that into a failure, as the other
//! `KR_REQUIRE_*` switches do for the tools and services they name. Any other value is refused.
//! A platform that cannot be asked at all is a failure whatever the switch says: a probe that
//! could not run has not found that there is no UTF-8 locale.

use std::env::VarError;
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::{self, ThreadId};

use kr_shell_integration::contract::qualification::ShellKind;

/// Set to `1` by a run that has to show the cases under a UTF-8 locale.
const REQUIRE: &str = "KR_REQUIRE_UTF8_LOCALE";

/// The locale of every shell the harness starts when no case has chosen another.
const BYTE_LOCALE: &str = "C";

/// The locale name of the run [`in_each_locale`] is making on each thread that is making one.
///
/// A static list keyed by thread and not a `thread_local!`: the conformance report reads this
/// module for the functions a case calls, and a macro it does not know in a module makes it
/// distrust every call it cannot prove, which would drop the keyed tests that reach the cases
/// through here. A thread id has no order and a hash map cannot be built in a static, so a list of
/// the few threads that run a case at once is what this holds.
static IN_FORCE: Mutex<Vec<(ThreadId, String)>> = Mutex::new(Vec::new());

/// The runs in force. A case that panics holds no lock, and a poisoned list is as good as any
/// other.
fn runs() -> MutexGuard<'static, Vec<(ThreadId, String)>> {
    IN_FORCE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The locale a shell started now runs in: the one of the run [`in_each_locale`] is making on this
/// thread, and the byte locale outside one.
#[must_use]
pub fn locale_in_force() -> String {
    let this = thread::current().id();
    runs()
        .iter()
        .find(|(thread, _)| *thread == this)
        .map_or_else(|| BYTE_LOCALE.to_owned(), |(_, name)| name.clone())
}

/// Holds a locale in force while it lives, and puts the byte locale back when it ends, however
/// the run ends.
struct InForce;

impl InForce {
    /// # Panics
    ///
    /// Panics when a run is already in force on this thread: the inner run would end with the byte
    /// locale back in force for what is left of the outer one, under a log line that names
    /// another.
    fn set(name: &str) -> Self {
        let this = thread::current().id();
        let mut held = runs();
        assert!(
            !held.iter().any(|(thread, _)| *thread == this),
            "`in_each_locale` is running inside a run of its own"
        );
        held.push((this, name.to_owned()));
        Self
    }
}

impl Drop for InForce {
    fn drop(&mut self) {
        let this = thread::current().id();
        runs().retain(|(thread, _)| *thread != this);
    }
}

/// The locales a case that depends on how the editor draws runs under, in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Locale {
    /// The C locale, in which the editor works on bytes.
    Bytes,
    /// A UTF-8 locale, in which the editor works on characters.
    Utf8,
}

impl Locale {
    const BOTH: [Self; 2] = [Self::Bytes, Self::Utf8];

    /// What a log calls this locale.
    fn label(self) -> &'static str {
        match self {
            Self::Bytes => "byte",
            Self::Utf8 => "UTF-8",
        }
    }

    /// The name this platform gives the locale: nothing where it lists none, and the reason where
    /// it could not be asked.
    fn name_here(self) -> Result<Option<String>, String> {
        match self {
            Self::Bytes => Ok(Some(BYTE_LOCALE.to_owned())),
            Self::Utf8 => utf8_name_here(),
        }
    }
}

/// Whether the switch that makes a missing UTF-8 locale a failure is set.
///
/// # Panics
///
/// Panics on any value but `1`, since a value nothing reads would leave the run as lax as one
/// that had not set it.
fn required() -> bool {
    match std::env::var(REQUIRE) {
        Err(VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        other => panic!("{REQUIRE} is set to {other:?}; it is set to 1 or left unset"),
    }
}

/// The UTF-8 locale this platform runs a shell under, by the name the platform lists it under.
///
/// The platform's own `locale -a` is the list of names its C library accepts, so no list of names
/// is kept here to fall behind a platform. macOS lists the directories of `/usr/share/locale`,
/// `en_US.UTF-8` among them; glibc, on the Ubuntu build box and the hosted Linux runners, lists
/// the locales that are installed and the built-in `C.utf8`. A listed name counts when
/// `locale charmap` says `UTF-8` under it, because a name the library accepts but cannot load
/// falls back to the C locale and a run under it would be a byte run that says it is not. Where
/// several names qualify the first that the platform's usual one names comes first, then the rest
/// as listed, so a log names the same locale from one run to the next.
///
/// The one answer that lets a case go without its UTF-8 run is that `locale` ran and listed no
/// UTF-8 name that `locale charmap` confirms. A `locale` that is missing, or that ends with an
/// error, is an `Err` carrying why.
fn utf8_name_here() -> Result<Option<String>, String> {
    let usual: &[&str] = if cfg!(target_os = "macos") {
        &["en_US.UTF-8"]
    } else {
        &["C.UTF-8", "en_US.UTF-8"]
    };
    let listing = locale_program(&["-a"], None)?;
    let mut names: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|name| normalised(name).ends_with(".utf8"))
        .collect();
    // The sort is stable, so the names the platform's usual list does not hold keep their order.
    names.sort_by_key(|name| {
        usual
            .iter()
            .position(|usual| normalised(usual) == normalised(name))
            .unwrap_or(usual.len())
    });
    for name in names {
        if locale_program(&["charmap"], Some(name))?.trim() == "UTF-8" {
            return Ok(Some(name.to_owned()));
        }
    }
    Ok(None)
}

/// A locale name without the spellings that do not tell two names apart.
fn normalised(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "")
}

/// What `locale <args>` prints under `LC_ALL=<under>`, or why it could not be run.
fn locale_program(args: &[&str], under: Option<&str>) -> Result<String, String> {
    let mut command = Command::new("locale");
    command.args(args);
    if let Some(name) = under {
        command.env("LC_ALL", name);
    }
    let output = command
        .output()
        .map_err(|error| format!("`locale {}` could not start: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`locale {}` ended with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Writes a line to the run's log, past the capture that keeps the output of a passing case.
///
/// # Panics
///
/// Panics when the line cannot be written: the line is how a log says which locale a run used or
/// that it made none, and a log that lost it would read as if the run had been made.
fn say(line: &str) {
    writeln!(std::io::stderr(), "{line}")
        .expect("the log takes the line that names the locale of a run");
}

/// Runs `body` once under each locale this platform has, and says in the log which locale each run
/// used and which one the platform lacks. Every shell the body starts runs in that run's locale.
///
/// A platform without a UTF-8 locale gets no run under it, and the log says so by the platform's
/// name, unless `KR_REQUIRE_UTF8_LOCALE=1` is set, which makes it a failure; a case that stays
/// quiet about a run it did not make would pass as if it had made it. A failure in the body is
/// reported again with the case, the shell and the locale it happened under in front of it.
///
/// # Panics
///
/// Panics when the switch holds a value other than `1`, when the platform cannot be asked for its
/// locales, when a UTF-8 locale is required and the platform lists none, when a line cannot be
/// written to the log, and when the body panics.
pub fn in_each_locale(kind: ShellKind, case: &str, mut body: impl FnMut()) {
    let required = required();
    for locale in Locale::BOTH {
        let label = locale.label();
        let platform = std::env::consts::OS;
        let name = match locale.name_here() {
            Ok(Some(name)) => name,
            Ok(None) => {
                assert!(
                    !required,
                    "{REQUIRE} is set and {platform} lists no {label} locale to run {case} \
                     ({kind:?}) under"
                );
                say(&format!(
                    "{case} ({kind:?}): {platform} has no {label} locale, so the run under it is \
                     not made"
                ));
                continue;
            }
            Err(why) => panic!(
                "{case} ({kind:?}) cannot tell whether {platform} has a {label} locale: {why}"
            ),
        };
        say(&format!(
            "{case} ({kind:?}): run under the {label} locale {name}"
        ));
        let _in_force = InForce::set(&name);
        if let Err(payload) = catch_unwind(AssertUnwindSafe(&mut body)) {
            let reason = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_else(|| "a panic that carries no message".to_owned());
            panic!("{case} ({kind:?}) failed under the {label} locale {name}: {reason}");
        }
    }
}
