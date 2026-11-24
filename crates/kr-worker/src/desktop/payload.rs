//! What a usable image payload is.
//!
//! A capture tool that exits successfully has said nothing about the file it was asked to write: it
//! can leave no file, an empty one, a different format, or the head of an image whose body never
//! arrived. A header alone, or a payload that stops short, establishes nothing, so a check accepts
//! an image only when the whole structure of its format is there. The rules read bytes and nothing
//! else, so every route that measures an image shares them and a case settles them without a
//! desktop.
//!
//! The file a tool wrote is read by [`read_image`], which is the one reader of an image: it opens
//! the path without following a link and without waiting for a writer, takes a regular file and
//! nothing else, reads no more than [`IMAGE_LIMIT`] bytes, and says why when it cannot.

use std::io::Read as _;
use std::path::Path;

use kr_protocol::hostinfo::export::{ContentClass, Sentence};

use super::probe::Deadline;

/// Why a payload is not an image a check can count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// There are no bytes: no file was written, or an empty one.
    Empty,
    /// The bytes do not begin as the format does.
    NotThisFormat,
    /// The structure is there and holds no pixels.
    NoPixels,
    /// The structure begins and stops before it ends.
    CutShort,
    /// What is at the path is not a regular file: a link, a pipe, a folder or a device. Nothing was
    /// read from it, and a link was not followed.
    NotAFile,
    /// The file holds more bytes than a check reads into memory, which is this many.
    TooLarge(u64),
    /// The file is there and could not be read, for this reason in the system's own words.
    Unreadable(String),
}

impl Fault {
    /// What a check says of a tool that exited successfully and left a payload that is not an
    /// image: the one frame every route that measures an image uses, and the fault's own words at
    /// its end.
    pub(super) fn left_no_usable_image(&self) -> Sentence {
        let frame = Sentence::new()
            .stated("the screen-copy tool exited successfully and left no usable image: ");
        match self {
            Self::Empty => frame.stated("no file, or an empty one"),
            Self::NotThisFormat => frame.stated("a file that is not a PNG image"),
            Self::NoPixels => frame.stated("a PNG image with no pixels"),
            Self::CutShort => frame.stated("a PNG image that is cut short"),
            Self::NotAFile => frame.stated("something that is not a regular file"),
            Self::TooLarge(limit) => frame
                .stated("a file of more than ")
                .number(*limit)
                .stated(" bytes"),
            Self::Unreadable(error) => frame
                .stated("a file that could not be read: ")
                .withheld(ContentClass::Message, error),
        }
    }
}

/// The most bytes of an image that a check reads into memory: 256 MiB.
///
/// The image is read whole, which is what the capability is about. The largest an uncompressed
/// capture of one 8K output or three 4K outputs comes to is about 100 to 130 MB, so this is about
/// twice that, and it bounds what a file that a tool left can cost the worker in memory.
pub(super) const IMAGE_LIMIT: u64 = 256 * 1024 * 1024;

/// Reads the image a tool was asked to write.
///
/// `None` is the time running out, which is not the same as a file that could not be read. A path
/// with no file at it reads as no bytes, which [`png`] calls empty. Anything else that is not a
/// whole read of a regular file is the [`Fault`] that says why.
pub(super) fn read_image(path: &Path, deadline: &Deadline) -> Option<Result<Vec<u8>, Fault>> {
    read_image_up_to(path, deadline, IMAGE_LIMIT)
}

/// [`read_image`], with the byte limit given.
fn read_image_up_to(
    path: &Path,
    deadline: &Deadline,
    limit: u64,
) -> Option<Result<Vec<u8>, Fault>> {
    if deadline.expired() {
        return None;
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_symlink()) {
        // Where a link cannot be refused by the open itself, it is refused by a look before it.
        return Some(Err(Fault::NotAFile));
    }
    let file = match open_image(path) {
        Ok(file) => file,
        Err(error) => {
            let found = std::fs::symlink_metadata(path).map(|found| found.file_type());
            return Some(match found {
                // The open refused a link, or there is a pipe or a folder the open could not take.
                Ok(kind) if !kind.is_file() => Err(Fault::NotAFile),
                _ if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                _ => Err(Fault::Unreadable(error.to_string())),
            });
        }
    };
    match file.metadata() {
        Ok(found) if found.is_file() => {}
        Ok(_) => return Some(Err(Fault::NotAFile)),
        Err(error) => return Some(Err(Fault::Unreadable(error.to_string()))),
    }
    // One byte more than the limit is read, so that a file of exactly the limit is whole.
    let mut file = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    let mut block = [0_u8; 64 * 1024];
    loop {
        if deadline.expired() {
            return None;
        }
        match file.read(&mut block) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&block[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Some(Err(Fault::Unreadable(error.to_string()))),
        }
    }
    if u64::try_from(bytes.len()).is_ok_and(|read| read > limit) {
        return Some(Err(Fault::TooLarge(limit)));
    }
    Some(Ok(bytes))
}

/// Opens the image without following a link and without waiting for whatever is on the other end
/// of a pipe, and without making a terminal device the controlling terminal.
fn open_image(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// What a usable PNG measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Png {
    /// Width in pixels, from the image header.
    pub(super) width: u32,
    /// Height in pixels, from the image header.
    pub(super) height: u32,
}

/// The eight bytes every PNG begins with.
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The length of a chunk's length field and of its type field, and of its check value after it.
const CHUNK_HEAD: usize = 8;
const CHUNK_TAIL: usize = 4;

/// The length of an image header chunk's data.
const HEADER_DATA: usize = 13;

/// Reads a PNG payload and says what it measures, or why it is not one a check can count.
///
/// It is accepted only with its signature, an image header that names a width and a height above
/// zero, at least one image data chunk that holds bytes, and an end chunk, every chunk inside the
/// bytes given. The data is not decoded and the check values are not read: the question is whether
/// the file is whole, and the bytes of a whole file are what a person's screen made of them.
pub(super) fn png(bytes: &[u8]) -> Result<Png, Fault> {
    if bytes.is_empty() {
        return Err(Fault::Empty);
    }
    if !bytes.starts_with(&SIGNATURE) {
        // A prefix of the signature is a payload that stopped, which is not another format.
        return Err(if SIGNATURE.starts_with(bytes) {
            Fault::CutShort
        } else {
            Fault::NotThisFormat
        });
    }
    let mut position = SIGNATURE.len();
    let mut size = None;
    let mut holds_pixels = false;
    let mut ended = false;
    let mut first = true;
    while position < bytes.len() {
        let Some(head) = bytes.get(position..position + CHUNK_HEAD) else {
            return Err(Fault::CutShort);
        };
        let length = usize::try_from(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
            .map_err(|_| Fault::CutShort)?;
        let kind = &head[4..8];
        let data = position + CHUNK_HEAD;
        let end = data
            .checked_add(length)
            .and_then(|end| end.checked_add(CHUNK_TAIL))
            .ok_or(Fault::CutShort)?;
        if end > bytes.len() {
            return Err(Fault::CutShort);
        }
        if first {
            // The header is the first chunk, and it is the only place the size is written.
            if kind != b"IHDR" || length != HEADER_DATA {
                return Err(Fault::NotThisFormat);
            }
            let field = |at: usize| {
                u32::from_be_bytes([
                    bytes[data + at],
                    bytes[data + at + 1],
                    bytes[data + at + 2],
                    bytes[data + at + 3],
                ])
            };
            size = Some(Png {
                width: field(0),
                height: field(4),
            });
            first = false;
        } else if kind == b"IDAT" && length > 0 {
            holds_pixels = true;
        } else if kind == b"IEND" {
            ended = true;
            break;
        }
        position = end;
    }
    if !ended {
        return Err(Fault::CutShort);
    }
    match size {
        Some(measured) if measured.width > 0 && measured.height > 0 && holds_pixels => Ok(measured),
        _ => Err(Fault::NoPixels),
    }
}

/// The cases of this module, and the whole PNG the cases of the routes that measure one write as a
/// capture tool's output.
#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// One chunk: its length, its type, its data and a check value the reader does not look at.
    pub(in crate::desktop) fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(data.len())
            .expect("a short chunk")
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    /// The data of an image header for a size.
    fn header(width: u32, height: u32) -> Vec<u8> {
        let mut data = width.to_be_bytes().to_vec();
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 2, 0, 0, 0]);
        data
    }

    /// A whole PNG of a size, as the chunks a capture tool writes.
    pub(in crate::desktop) fn whole(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend(chunk(b"IHDR", &header(width, height)));
        bytes.extend(chunk(b"IDAT", &[0x78, 0x9c, 0x01, 0x02, 0x03]));
        bytes.extend(chunk(b"IEND", &[]));
        bytes
    }

    #[test]
    fn a_whole_png_measures_its_size() {
        assert_eq!(
            png(&whole(1280, 720)),
            Ok(Png {
                width: 1280,
                height: 720
            })
        );
    }

    /// KR-REQ-03.29, LP-3: a payload that is not a whole image establishes nothing, each in its own
    /// way.
    #[test]
    fn a_payload_that_is_not_a_whole_image_is_refused_for_what_it_lacks() {
        assert_eq!(png(&[]), Err(Fault::Empty));
        assert_eq!(
            png(b"%!PS-Adobe-3.0 not an image"),
            Err(Fault::NotThisFormat)
        );
        // A signature and nothing after it, a header alone, and a body that stops inside a chunk.
        let mut head = SIGNATURE.to_vec();
        assert_eq!(png(&head), Err(Fault::CutShort));
        head.extend(chunk(b"IHDR", &header(1280, 720)));
        assert_eq!(png(&head), Err(Fault::CutShort));
        let whole = whole(1280, 720);
        for cut in [4, 20, whole.len() - 13, whole.len() - 12, whole.len() - 1] {
            assert_eq!(png(&whole[..cut]), Err(Fault::CutShort), "cut at {cut}");
        }
        // The end chunk is there and no pixels came before it.
        let mut without = SIGNATURE.to_vec();
        without.extend(chunk(b"IHDR", &header(1280, 720)));
        without.extend(chunk(b"IEND", &[]));
        assert_eq!(png(&without), Err(Fault::NoPixels));
        // An image data chunk with no bytes holds no pixels either.
        let mut empty_data = SIGNATURE.to_vec();
        empty_data.extend(chunk(b"IHDR", &header(1280, 720)));
        empty_data.extend(chunk(b"IDAT", &[]));
        empty_data.extend(chunk(b"IEND", &[]));
        assert_eq!(png(&empty_data), Err(Fault::NoPixels));
        // A size of zero.
        assert_eq!(png(&self::whole(0, 720)), Err(Fault::NoPixels));
        assert_eq!(png(&self::whole(1280, 0)), Err(Fault::NoPixels));
        // A header that is not the first chunk, and one of the wrong length.
        let mut late = SIGNATURE.to_vec();
        late.extend(chunk(b"IDAT", &[1, 2, 3]));
        late.extend(chunk(b"IHDR", &header(1280, 720)));
        late.extend(chunk(b"IEND", &[]));
        assert_eq!(png(&late), Err(Fault::NotThisFormat));
        let mut short = SIGNATURE.to_vec();
        short.extend(chunk(b"IHDR", &[0; 5]));
        short.extend(chunk(b"IDAT", &[1]));
        short.extend(chunk(b"IEND", &[]));
        assert_eq!(png(&short), Err(Fault::NotThisFormat));
    }

    /// A chunk that says it is longer than the file is cut short, however large it says it is.
    #[test]
    fn a_length_that_runs_past_the_file_is_cut_short_and_never_overflows() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&[0; 20]);
        assert_eq!(png(&bytes), Err(Fault::CutShort));
    }
    /// A folder of a case's own, removed with it.
    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("kr-image-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(&path).expect("a folder of this case's own");
            Self(path)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("a file");
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn plenty() -> Deadline {
        Deadline::after(std::time::Duration::from_secs(30))
    }

    /// KR-REQ-03.29, LP-9: a regular file is read whole, and a path with no file at it reads as no
    /// bytes, which is what an empty payload is.
    #[test]
    fn a_regular_file_is_read_whole_and_an_absent_one_reads_as_nothing() {
        let dir = Dir::new();
        let image = whole(1280, 720);
        let path = dir.file("image.png", &image);
        assert_eq!(read_image(&path, &plenty()), Some(Ok(image)));
        assert_eq!(
            read_image(&dir.0.join("absent.png"), &plenty()),
            Some(Ok(Vec::new()))
        );
    }

    /// KR-REQ-03.29, LP-9: a link is not followed, and a folder is not a file: neither is read.
    #[cfg(unix)]
    #[test]
    fn a_link_and_a_folder_are_not_regular_files() {
        let dir = Dir::new();
        let target = dir.file("target.png", &whole(1280, 720));
        let link = dir.0.join("link.png");
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        assert_eq!(
            read_image(&link, &plenty()),
            Some(Err(Fault::NotAFile)),
            "a link to a whole image"
        );
        let dangling = dir.0.join("dangling.png");
        std::os::unix::fs::symlink(dir.0.join("nowhere"), &dangling).expect("a link");
        assert_eq!(read_image(&dangling, &plenty()), Some(Err(Fault::NotAFile)));
        let folder = dir.0.join("folder.png");
        std::fs::create_dir(&folder).expect("a folder");
        assert_eq!(read_image(&folder, &plenty()), Some(Err(Fault::NotAFile)));
    }

    /// KR-REQ-03.29, LP-9: a pipe with no writer is not waited for.
    #[cfg(unix)]
    #[test]
    fn a_pipe_is_refused_and_not_waited_for() {
        let dir = Dir::new();
        let pipe = dir.0.join("pipe.png");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(read_image(&pipe, &plenty()));
        });
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the read waited for a writer to the pipe"),
            Some(Err(Fault::NotAFile))
        );
    }

    /// KR-REQ-03.29, LP-9: a file of more bytes than the limit is too large, whatever it holds, and
    /// one of exactly the limit is whole.
    #[test]
    fn a_file_over_the_limit_is_too_large_and_one_at_the_limit_is_whole() {
        let dir = Dir::new();
        let at = dir.file("at.png", &[7; 1_000]);
        let over = dir.file("over.png", &[7; 1_001]);
        assert_eq!(
            read_image_up_to(&at, &plenty(), 1_000),
            Some(Ok(vec![7; 1_000]))
        );
        assert_eq!(
            read_image_up_to(&over, &plenty(), 1_000),
            Some(Err(Fault::TooLarge(1_000)))
        );
    }

    /// KR-REQ-03.29, LP-9: a file that is there and cannot be read is said, with the system's own
    /// words, and is not called an absent or an empty one. A privileged process can read it, which
    /// is a different case.
    #[cfg(unix)]
    #[test]
    fn a_file_closed_to_this_process_is_unreadable_and_not_absent() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = Dir::new();
        let path = dir.file("closed.png", &whole(1280, 720));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("closes it");
        if std::fs::File::open(&path).is_ok() {
            return;
        }
        match read_image(&path, &plenty()) {
            Some(Err(Fault::Unreadable(said))) => {
                assert!(said.contains("Permission denied"), "{said}");
            }
            other => panic!("not said as unreadable: {other:?}"),
        }
    }

    /// KR-REQ-03.29, LP-9: a read that the time has run out for gives no answer at all, which is
    /// not a fault of the file.
    #[test]
    fn a_read_after_the_time_is_gone_is_no_answer() {
        let dir = Dir::new();
        let path = dir.file("image.png", &whole(1280, 720));
        let gone = Deadline::after(std::time::Duration::ZERO);
        assert_eq!(read_image(&path, &gone), None);
        assert_eq!(read_image(&dir.0.join("absent.png"), &gone), None);
    }

    /// KR-REQ-03.29, LP-9: what a check says of a tool that left no usable image, for the three
    /// faults of the file's own, in the words the lead approved.
    #[test]
    fn the_words_for_a_file_that_is_not_there_to_be_measured() {
        let said = |fault: Fault| fault.left_no_usable_image().as_str().to_owned();
        let frame = "the screen-copy tool exited successfully and left no usable image: ";
        assert_eq!(
            said(Fault::NotAFile),
            format!("{frame}something that is not a regular file")
        );
        assert_eq!(
            said(Fault::TooLarge(IMAGE_LIMIT)),
            format!("{frame}a file of more than 268435456 bytes")
        );
        assert!(
            said(Fault::Unreadable("Permission denied".to_owned()))
                .starts_with(&format!("{frame}a file that could not be read: ")),
        );
        assert_eq!(IMAGE_LIMIT, 268_435_456);
    }
}
