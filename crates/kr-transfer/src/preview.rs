//! The bounded preview decoder.
//!
//! Section 14 fixes four numbers and a format list, and this module is those bounds and nothing
//! else: a 40-megapixel input limit, a 256 MiB decode-memory limit, a 16 MiB decoded-thumbnail
//! budget, and PNG, JPEG, WebP and the **first** frame of a GIF. HTML and SVG stay files; rendering
//! either one needs a reviewed renderer, and this is not one.
//!
//! WebP is on that list and is withheld here, which is a decision rather than an omission. The
//! pinned lossless decoder takes its Huffman group count from a sixteen-bit metadata field and
//! allocates a table set per group, so a file of a few kilobytes can ask for hundreds of megabytes
//! that no bound on pixels can catch. The decoder is not compiled in, the bytes are recognised
//! from their signature, and the attachment publishes with no preview and a reason. The preview
//! returns when the pin bounds that allocation.
//!
//! Three properties matter more than the decode itself.
//!
//! * The format comes from the bytes, not from the client. A declared media type is a claim and a
//!   filename extension is metadata; `image`'s own sniffing decides what decoder runs, and PNG,
//!   JPEG and GIF are the only decoders this crate compiles in.
//! * A refusal is a refusal, never a substitute. When a decode fails, is too large, or is a format
//!   this decoder does not handle, the attachment publishes with no preview and the original file
//!   is untouched. Nothing invents a placeholder image.
//! * Unsupported media is never presented as a supported model image. The caller reads that from
//!   whether a preview exists at all, so an adapter never has to guess from a media type.
//!
//! The dimensions are read from the header before anything is decoded, so an image above the pixel
//! limit costs a header read rather than an allocation.

use std::io::{BufReader, Read, Seek, SeekFrom};

use image::{ImageFormat, ImageReader, Limits};
use kr_protocol::scalars::{Bytes, U64};
use kr_protocol::transfer::{
    AttachmentPreview, MAX_PREVIEW_DECODE_BYTES, MAX_PREVIEW_FRAME_BYTES, MAX_PREVIEW_INPUT_BYTES,
    MAX_PREVIEW_PIXELS, PREVIEW_THUMBNAIL_EDGES, PreviewFormat,
};

/// Media types that are files whatever their bytes look like.
const NEVER_DECODED: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
];

/// How many bytes of working memory a decode is charged per pixel of the image.
///
/// This is the number that makes the 256 MiB budget something this crate enforces rather than
/// something it hopes for: `image` documents its own allocation limit as advisory, and its
/// decoders hold more than the output buffer while they work. Sixteen is the worst case among the
/// four formats compiled in here:
///
/// * a PNG decoded to sixteen-bit RGBA is eight bytes per pixel of output;
/// * a decoder that composites, as an animated WebP would, holds the output, the frame it decoded
///   and the canvas it draws onto, which is three four-byte buffers at once;
/// * a GIF holds its frame buffer and the image it crops into.
///
/// Sixteen covers each of those with room left, so an image whose estimate fits the budget cannot
/// make the pinned decoders exceed it. The number belongs to the pins in the manifest: it is
/// re-derived when `image` or one of its codecs moves.
const DECODE_BYTES_PER_PIXEL: u64 = 16;

/// Why no preview was produced.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PreviewRefusal {
    /// The declared media type is one this decoder never opens.
    #[error("{media_type} is a file, not an image this decoder renders")]
    NeverDecoded {
        /// The declared media type.
        media_type: String,
    },
    /// The bytes are not one of the formats this decoder handles.
    #[error("the bytes are not PNG, JPEG or GIF")]
    UnsupportedFormat,
    /// The bytes are a format whose decoder this host withholds.
    #[error("no preview for this format: {reason}")]
    FormatWithheld {
        /// Why the format is not decoded here.
        reason: &'static str,
    },
    /// The encoded image is larger than a preview decoder reads.
    #[error("{len} encoded bytes is above the {MAX_PREVIEW_INPUT_BYTES}-byte input limit")]
    InputTooLarge {
        /// The encoded length.
        len: u64,
    },
    /// The image declares more pixels than the input limit allows.
    #[error("{width} by {height} is {pixels} pixels, above the {MAX_PREVIEW_PIXELS}-pixel limit")]
    TooManyPixels {
        /// The declared width.
        width: u64,
        /// The declared height.
        height: u64,
        /// Their product.
        pixels: u64,
    },
    /// Decoding the image would want more memory than the budget allows.
    #[error(
        "{width} by {height} would want about {estimate} bytes, above the \
             {MAX_PREVIEW_DECODE_BYTES}-byte decode budget"
    )]
    DecodeTooLarge {
        /// The declared width.
        width: u64,
        /// The declared height.
        height: u64,
        /// The estimate that exceeded the budget.
        estimate: u64,
    },
    /// The file could not be read.
    #[error("the file could not be read: {detail}")]
    Unreadable {
        /// What the platform reported.
        detail: String,
    },
    /// The decoder refused the image, which includes refusing it for the memory limit.
    #[error("the image could not be decoded within the bounded decoder's limits: {detail}")]
    DecodeFailed {
        /// What the decoder reported.
        detail: String,
    },
    /// The thumbnail could not be encoded small enough to travel in a result.
    #[error("no thumbnail of this image encodes within the {MAX_PREVIEW_FRAME_BYTES}-byte budget")]
    ThumbnailTooLarge,
}

/// Produces a bounded thumbnail of one image, or says why it did not.
///
/// The source is read from an open handle and left rewound to its start, so the caller can go on
/// using the same handle.
///
/// Four bounds, in the order they apply: the encoded input, the pixel count, the estimated decode
/// memory, and the encoded thumbnail. The first three are checked before anything large is asked
/// for; the fourth shrinks the thumbnail until it fits or gives up.
///
/// # Errors
///
/// Returns the refusal. Every one of them leaves the original file exactly as it was.
pub fn generate<S: Read + Seek>(
    source: &mut S,
    declared_media_type: &str,
) -> std::result::Result<AttachmentPreview, PreviewRefusal> {
    let lowered = declared_media_type.trim().to_ascii_lowercase();
    let base = lowered.split(';').next().unwrap_or(&lowered).trim();
    if NEVER_DECODED.contains(&base) {
        return Err(PreviewRefusal::NeverDecoded {
            media_type: declared_media_type.to_owned(),
        });
    }
    let outcome = decode(source);
    // The handle goes back to where it started whether the decode worked or not: the caller still
    // has to verify and publish the file.
    let _ = source.seek(SeekFrom::Start(0));
    outcome
}

fn decode<S: Read + Seek>(
    source: &mut S,
) -> std::result::Result<AttachmentPreview, PreviewRefusal> {
    let encoded = encoded_len(source)?;
    if encoded > MAX_PREVIEW_INPUT_BYTES {
        return Err(PreviewRefusal::InputTooLarge { len: encoded });
    }
    // Two passes over the same handle, both bounded by the encoded limit. The header decides the
    // format and the dimensions, and only then does anything ask for a buffer.
    let (format, width, height) = header(source)?;
    check_bounds(width, height)?;
    if format == ImageFormat::Gif {
        // The frame is what gets allocated, and it is not always the screen the header reports.
        let (frame_width, frame_height) = gif_frame_extent(source)?;
        check_bounds(frame_width, frame_height)?;
    }
    rewind(source)?;
    let mut reader =
        ImageReader::with_format(BufReader::new(source.take(MAX_PREVIEW_INPUT_BYTES)), format);
    reader.limits(limits());
    // A GIF decoder used as one image decoder yields the first frame and reads no further; the
    // animation interface is a separate call this crate never makes.
    let image = reader
        .decode()
        .map_err(|error| PreviewRefusal::DecodeFailed {
            detail: error.to_string(),
        })?;
    // Checked again on what was actually decoded. The header pass and the decode pass are two
    // reads of the same handle, and a GIF's logical screen is not always its first frame's size,
    // so the bounds are applied to the image that exists rather than to the one the header
    // described.
    check_bounds(image.width(), image.height())?;
    let (thumbnail, encoded_thumbnail) = encode_thumbnail(&image)?;
    Ok(AttachmentPreview {
        source_format: match format {
            ImageFormat::Png => PreviewFormat::Png,
            ImageFormat::Jpeg => PreviewFormat::Jpeg,
            _ => PreviewFormat::GifFirstFrame,
        },
        source_width: U64::new(u64::from(image.width())),
        source_height: U64::new(u64::from(image.height())),
        width: U64::new(u64::from(thumbnail.0)),
        height: U64::new(u64::from(thumbnail.1)),
        thumbnail: Bytes::new(encoded_thumbnail),
    })
}

/// Refuses an image above either of the two bounds the specification fixes.
fn check_bounds(width: u32, height: u32) -> std::result::Result<(), PreviewRefusal> {
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > MAX_PREVIEW_PIXELS {
        return Err(PreviewRefusal::TooManyPixels {
            width: u64::from(width),
            height: u64::from(height),
            pixels,
        });
    }
    let estimate = pixels.saturating_mul(DECODE_BYTES_PER_PIXEL);
    if estimate > MAX_PREVIEW_DECODE_BYTES {
        return Err(PreviewRefusal::DecodeTooLarge {
            width: u64::from(width),
            height: u64::from(height),
            estimate,
        });
    }
    Ok(())
}

/// Encodes a thumbnail small enough to travel in a result.
///
/// The largest edge that fits wins. An image whose thumbnail will not fit at the smallest edge
/// publishes without a preview, which is the same answer as any other refusal.
fn encode_thumbnail(
    image: &image::DynamicImage,
) -> std::result::Result<((u32, u32), Vec<u8>), PreviewRefusal> {
    for edge in PREVIEW_THUMBNAIL_EDGES {
        let thumbnail = image.thumbnail(*edge, *edge);
        let mut encoded = std::io::Cursor::new(Vec::new());
        thumbnail
            .write_to(&mut encoded, ImageFormat::Png)
            .map_err(|error| PreviewRefusal::DecodeFailed {
                detail: error.to_string(),
            })?;
        let encoded = encoded.into_inner();
        let len = encoded.len() as u64;
        // The frame budget is the tighter of the two limits a thumbnail has to meet, and the
        // constant assertion in the tests below is what keeps it that way.
        if len <= MAX_PREVIEW_FRAME_BYTES {
            return Ok(((thumbnail.width(), thumbnail.height()), encoded));
        }
    }
    Err(PreviewRefusal::ThumbnailTooLarge)
}

/// Returns the encoded length of the source, leaving the handle where it found it.
fn encoded_len<S: Seek>(source: &mut S) -> std::result::Result<u64, PreviewRefusal> {
    let len = source
        .seek(SeekFrom::End(0))
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })?;
    rewind(source)?;
    Ok(len)
}

/// Why a WebP is not decoded here.
const WEBP_WITHHELD: &str = "this host does not decode WebP: the pinned decoder allocates from its own metadata, which no \
     bound on pixels can limit";

/// Returns true when these bytes are a WebP.
///
/// Twelve bytes decide it: the RIFF container's tag, its length, and the form type. Nothing is
/// decoded and nothing is allocated beyond the twelve bytes.
fn webp_signature<S: Read + Seek>(source: &mut S) -> std::result::Result<bool, PreviewRefusal> {
    rewind(source)?;
    let mut head = [0_u8; 12];
    let read = source
        .take(12)
        .read(&mut head)
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })?;
    Ok(read == 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP")
}

/// How far into a GIF this crate looks for the first frame's own extent.
///
/// The extent is in the first image descriptor, after the header, any global colour table and any
/// extension blocks. A file that puts its first frame beyond this is one this crate does not
/// preview, which is an answer rather than an allocation.
const GIF_SCAN_BYTES: u64 = 64 * 1024;

/// Returns the extent the first frame of a GIF declares for itself.
///
/// The decoder reports a GIF's *logical screen* as the image's dimensions and crops the first
/// frame into it, so a one-pixel screen with an enormous frame passes every check made on the
/// reported dimensions and then allocates the frame regardless. The frame's own extent is in its
/// image descriptor, which is what this reads.
fn gif_frame_extent<S: Read + Seek>(
    source: &mut S,
) -> std::result::Result<(u32, u32), PreviewRefusal> {
    rewind(source)?;
    let mut head = Vec::new();
    source
        .take(GIF_SCAN_BYTES)
        .read_to_end(&mut head)
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })?;
    let at = |index: usize| head.get(index).copied();
    let word = |index: usize| match (at(index), at(index + 1)) {
        (Some(low), Some(high)) => Some(u32::from(low) | (u32::from(high) << 8)),
        _ => None,
    };
    // The header and the logical screen descriptor are thirteen bytes, and the global colour
    // table, when the packed field says there is one, follows them.
    let packed = at(10).ok_or(PreviewRefusal::UnsupportedFormat)?;
    let mut cursor = 13_usize;
    if packed & 0x80 != 0 {
        // Two to the power of the size field plus one entries, three bytes each.
        let entries = 1_usize << ((packed & 0x07) + 1);
        cursor = cursor.saturating_add(entries.saturating_mul(3));
    }
    loop {
        match at(cursor) {
            // An image descriptor: two words of position, then two of extent.
            Some(0x2c) => {
                let width = word(cursor + 5).ok_or(PreviewRefusal::UnsupportedFormat)?;
                let height = word(cursor + 7).ok_or(PreviewRefusal::UnsupportedFormat)?;
                return Ok((width, height));
            }
            // An extension: a label, then length-prefixed sub-blocks ending in a zero length.
            Some(0x21) => {
                cursor = cursor.saturating_add(2);
                loop {
                    let len = at(cursor).ok_or(PreviewRefusal::UnsupportedFormat)?;
                    cursor = cursor.saturating_add(1 + usize::from(len));
                    if len == 0 {
                        break;
                    }
                }
            }
            // The trailer, or anything this crate does not read.
            _ => return Err(PreviewRefusal::UnsupportedFormat),
        }
    }
}

/// Reads the format and the dimensions from the header alone.
fn header<S: Read + Seek>(
    source: &mut S,
) -> std::result::Result<(ImageFormat, u32, u32), PreviewRefusal> {
    rewind(source)?;
    let mut reader = ImageReader::new(BufReader::new(source.take(MAX_PREVIEW_INPUT_BYTES)))
        .with_guessed_format()
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })?;
    let format = match reader.format() {
        Some(format @ (ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif)) => format,
        // The decoder is not compiled in, so `image` cannot name this format. The signature is
        // read here instead, so the refusal says which format it was rather than lumping a WebP in
        // with everything this host does not recognise.
        _ if webp_signature(source)? => {
            return Err(PreviewRefusal::FormatWithheld {
                reason: WEBP_WITHHELD,
            });
        }
        _ => return Err(PreviewRefusal::UnsupportedFormat),
    };
    reader.limits(limits());
    let (width, height) =
        reader
            .into_dimensions()
            .map_err(|error| PreviewRefusal::DecodeFailed {
                detail: error.to_string(),
            })?;
    Ok((format, width, height))
}

fn rewind<S: Seek>(source: &mut S) -> std::result::Result<(), PreviewRefusal> {
    source
        .seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })
}

/// The decoder's own limits.
///
/// `max_alloc` is what the library will refuse where it checks, and the dimension bounds are the
/// pixel limit applied to each axis. Neither is trusted on its own: the library documents
/// `max_alloc` as advisory, which is why the encoded input and the estimated decode memory are
/// bounded before the decoder is built.
fn limits() -> Limits {
    let mut limits = Limits::no_limits();
    limits.max_alloc = Some(MAX_PREVIEW_DECODE_BYTES);
    let edge = u32::try_from(MAX_PREVIEW_PIXELS).unwrap_or(u32::MAX);
    limits.max_image_width = Some(edge);
    limits.max_image_height = Some(edge);
    limits
}

#[cfg(test)]
mod tests {
    use kr_protocol::transfer::MAX_PREVIEW_THUMBNAIL_BYTES;

    use super::*;
    use image::{DynamicImage, RgbaImage};
    use std::io::Cursor;

    fn encoded(width: u32, height: u32, format: ImageFormat) -> Vec<u8> {
        let mut image = RgbaImage::new(width, height);
        for (index, pixel) in image.pixels_mut().enumerate() {
            let shade = u8::try_from(index % 251).unwrap_or(0);
            *pixel = image::Rgba([shade, 255 - shade, shade / 2, 255]);
        }
        let image = DynamicImage::ImageRgba8(image);
        let mut out = Cursor::new(Vec::new());
        // GIF and JPEG are not RGBA formats; the encoder converts, which is what a real file does.
        image.write_to(&mut out, format).expect("encodes");
        out.into_inner()
    }

    #[test]
    fn each_decoded_format_produces_a_bounded_thumbnail() {
        for (format, expected) in [
            (ImageFormat::Png, PreviewFormat::Png),
            (ImageFormat::Jpeg, PreviewFormat::Jpeg),
            (ImageFormat::Gif, PreviewFormat::GifFirstFrame),
        ] {
            let bytes = encoded(800, 600, format);
            let mut source = Cursor::new(bytes);
            let preview = generate(&mut source, "image/png").expect("decodes");
            assert_eq!(preview.source_format, expected, "{format:?}");
            assert_eq!(preview.source_width, U64::new(800));
            assert_eq!(preview.source_height, U64::new(600));
            let largest = PREVIEW_THUMBNAIL_EDGES[0];
            assert!(preview.width.get() <= u64::from(largest));
            assert!(preview.height.get() <= u64::from(largest));
            assert!(preview.thumbnail.len() as u64 <= MAX_PREVIEW_FRAME_BYTES);
            // The thumbnail is PNG whatever the source was.
            assert_eq!(
                image::guess_format(preview.thumbnail.as_slice()).expect("a known format"),
                ImageFormat::Png
            );
            // The handle is left where the caller can go on reading from it.
            assert_eq!(source.position(), 0);
        }
    }

    #[test]
    fn the_format_comes_from_the_bytes_and_not_from_the_declaration() {
        // A real PNG declared as something else still decodes as a PNG, and the preview says so.
        let mut source = Cursor::new(encoded(32, 32, ImageFormat::Png));
        let preview = generate(&mut source, "application/octet-stream").expect("decodes");
        assert_eq!(preview.source_format, PreviewFormat::Png);
        // A real GIF declared as a PNG decodes as a GIF's first frame.
        let mut source = Cursor::new(encoded(32, 32, ImageFormat::Gif));
        let preview = generate(&mut source, "image/png").expect("decodes");
        assert_eq!(preview.source_format, PreviewFormat::GifFirstFrame);
    }

    #[test]
    fn html_and_svg_stay_files() {
        for media_type in [
            "text/html",
            "image/svg+xml",
            "text/html; charset=utf-8",
            "IMAGE/SVG+XML",
        ] {
            let mut source = Cursor::new(encoded(8, 8, ImageFormat::Png));
            assert!(
                matches!(
                    generate(&mut source, media_type),
                    Err(PreviewRefusal::NeverDecoded { .. })
                ),
                "{media_type} should never be decoded"
            );
        }
    }

    #[test]
    fn an_svg_document_is_not_an_image_this_decoder_renders() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"></svg>"#;
        let mut source = Cursor::new(svg.to_vec());
        assert_eq!(
            generate(&mut source, "application/octet-stream"),
            Err(PreviewRefusal::UnsupportedFormat)
        );
    }

    #[test]
    fn an_unsupported_format_produces_no_preview() {
        // A TIFF header. The format is real and this build does not compile its decoder.
        let mut source = Cursor::new(b"II\x2a\x00\x08\x00\x00\x00".to_vec());
        assert_eq!(
            generate(&mut source, "image/tiff"),
            Err(PreviewRefusal::UnsupportedFormat)
        );
        let mut plain = Cursor::new(b"just some text, not an image at all".to_vec());
        assert_eq!(
            generate(&mut plain, "text/plain"),
            Err(PreviewRefusal::UnsupportedFormat)
        );
    }

    #[test]
    fn an_image_above_the_pixel_limit_is_refused_from_its_header() {
        // A complete one-pixel GIF whose logical screen descriptor is then rewritten to declare
        // 65535 by 65535, which is 4,294,836,225 pixels. The file stays tiny and the header is the
        // only thing that has to be read to refuse it.
        let mut bytes = encoded(1, 1, ImageFormat::Gif);
        bytes[6..10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let mut source = Cursor::new(bytes);
        match generate(&mut source, "image/gif") {
            Err(PreviewRefusal::TooManyPixels {
                width,
                height,
                pixels,
            }) => {
                assert_eq!(width, 65_535);
                assert_eq!(height, 65_535);
                assert_eq!(pixels, 65_535 * 65_535);
                assert!(pixels > MAX_PREVIEW_PIXELS);
            }
            other => panic!("expected a pixel-limit refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_image_produces_no_preview_and_no_panic() {
        let mut bytes = encoded(64, 64, ImageFormat::Png);
        bytes.truncate(40);
        let mut source = Cursor::new(bytes);
        assert!(matches!(
            generate(&mut source, "image/png"),
            Err(PreviewRefusal::DecodeFailed { .. })
        ));
    }

    #[test]
    fn the_decoder_limits_are_the_four_numbers_the_specification_fixes() {
        let limits = limits();
        assert_eq!(limits.max_alloc, Some(256 * 1024 * 1024));
        assert_eq!(MAX_PREVIEW_PIXELS, 40_000_000);
        assert_eq!(MAX_PREVIEW_THUMBNAIL_BYTES, 16 * 1024 * 1024);
        assert_eq!(PREVIEW_THUMBNAIL_EDGES[0], 512);
        // The frame budget is the one this crate adds, because a result travels in one frame.
        const {
            assert!(MAX_PREVIEW_FRAME_BYTES < MAX_PREVIEW_THUMBNAIL_BYTES);
            // A draft with four previews has to fit a control frame.
            assert!(
                MAX_PREVIEW_FRAME_BYTES * 4 < kr_protocol::limits::MAX_CONTROL_FRAME_LEN as u64
            );
        }
    }
}
