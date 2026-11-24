//! What a usable image payload is.
//!
//! A capture tool that exits successfully has said nothing about the file it was asked to write: it
//! can leave no file, an empty one, a different format, or the head of an image whose body never
//! arrived. A header alone, or a payload that stops short, establishes nothing, so a check accepts
//! an image only when the whole structure of its format is there. These functions read bytes and
//! nothing else, so every route that measures an image shares them and a case settles them without
//! a desktop.

/// Why a payload is not an image a check can count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// There are no bytes: no file was written, or an empty one.
    Empty,
    /// The bytes do not begin as the format does.
    NotThisFormat,
    /// The structure is there and holds no pixels.
    NoPixels,
    /// The structure begins and stops before it ends.
    CutShort,
}

impl Fault {
    /// What a check says of a tool that exited successfully and left a payload that is not an
    /// image: the one frame every route that measures an image uses, and the fault's own words at
    /// its end.
    pub(super) fn left_no_usable_image(self) -> kr_protocol::hostinfo::export::Sentence {
        kr_protocol::hostinfo::export::Sentence::new()
            .stated("the screen-copy tool exited successfully and left no usable image: ")
            .stated(self.words())
    }

    /// What the fault is, as the end of a sentence that says what the tool left.
    pub(super) const fn words(self) -> &'static str {
        match self {
            Self::Empty => "no file, or an empty one",
            Self::NotThisFormat => "a file that is not a PNG image",
            Self::NoPixels => "a PNG image with no pixels",
            Self::CutShort => "a PNG image that is cut short",
        }
    }
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
}
