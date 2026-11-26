//! The form of the text that names a project folder.
//!
//! A client names its project by a path on a local drive: a drive letter, a colon and a backslash,
//! then folder names separated by backslashes. The verbatim spelling of the same path (the same
//! text after `\\?\`) is the same path. Every other form is refused before the broker opens
//! anything: a share, a host with a port, a pipe, a device, a `GLOBALROOT` or volume name, a
//! relative text and a text that names a drive without its root. Opening such a text as the
//! system would make the computer's account call a host the client chose, hand the system's token
//! to a pipe server, or resolve a name in the service's own folder.
//!
//! The broker never opens the whole text. It opens the drive's root and then each name beneath the
//! folder above it, so a name in this form is one name and never a path: it holds no separator,
//! no stream mark, no wildcard and no dot name.

/// The longest name a folder has on an NTFS volume, in UTF-16 units.
pub const MAX_NAME_UNITS: usize = 255;

/// A path on a local drive, taken apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPath {
    /// The drive's letter, in capitals.
    pub drive: char,
    /// The names below the drive's root, from the root down; none for the root itself.
    pub names: Vec<Vec<u16>>,
}

/// Takes a text apart when it is a path on a local drive, and answers nothing for any other text.
///
/// One backslash may end the text. A name is one to 255 UTF-16 units, is not a dot name and does
/// not end in a dot or a space (the platform drops those), and holds no control character and
/// none of `/ : * ? " < > |`.
#[must_use]
pub fn parse(text: &str) -> Option<LocalPath> {
    let rest = text.strip_prefix(r"\\?\").unwrap_or(text);
    let mut chars = rest.chars();
    let drive = chars.next().filter(char::is_ascii_alphabetic)?;
    if chars.next()? != ':' || chars.next()? != '\\' {
        return None;
    }
    let tail = chars.as_str();
    let (body, ended) = match tail.strip_suffix('\\') {
        Some(body) => (body, true),
        None => (tail, false),
    };
    if body.is_empty() && ended {
        return None;
    }
    let mut names = Vec::new();
    if !body.is_empty() {
        for name in body.split('\\') {
            names.push(units_of(name)?);
        }
    }
    Some(LocalPath {
        drive: drive.to_ascii_uppercase(),
        names,
    })
}

fn units_of(name: &str) -> Option<Vec<u16>> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let refused = units.is_empty()
        || units.len() > MAX_NAME_UNITS
        || name.ends_with('.')
        || name.ends_with(' ')
        || name
            .chars()
            .any(|mark| mark < ' ' || "/:*?\"<>|".contains(mark));
    (!refused).then_some(units)
}

/// How the platform names a local disk volume that has a drive letter: this text and then digits.
const VOLUME_DEVICE: &str = r"\Device\HarddiskVolume";

/// Whether the target text of a drive letter's link names a local disk volume: exactly the volume
/// device's name and digits. A share (`\Device\Mup` or the redirector's name), a folder that a
/// `subst` made a drive of, and any other device are not.
#[must_use]
pub fn is_local_volume_target(target: &[u16]) -> bool {
    let wanted: Vec<u16> = VOLUME_DEVICE.encode_utf16().collect();
    target
        .strip_prefix(wanted.as_slice())
        .is_some_and(|digits| {
            !digits.is_empty()
                && digits
                    .iter()
                    .all(|unit| (u16::from(b'0')..=u16::from(b'9')).contains(unit))
        })
}
