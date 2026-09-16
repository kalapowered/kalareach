//! The bounded preview decoder.
//!
//! Section 14 fixes four numbers and a format list, and this module is those bounds and nothing
//! else: a 40-megapixel input limit, a 256 MiB decode-memory limit, a 16 MiB decoded-thumbnail
//! budget, and PNG, JPEG, WebP and the **first** frame of a GIF. HTML and SVG stay files; rendering
//! either one needs a reviewed renderer, and this is not one.
//!
//! Three properties matter more than the decode itself.
//!
//! * The format comes from the bytes, not from the client. A declared media type is a claim and a
//!   filename extension is metadata; `image`'s own sniffing decides what decoder runs, and the four
//!   formats above are the only ones this crate compiles in.
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
    AttachmentPreview, MAX_PREVIEW_DECODE_BYTES, MAX_PREVIEW_PIXELS, MAX_PREVIEW_THUMBNAIL_BYTES,
    PREVIEW_THUMBNAIL_EDGE, PreviewFormat,
};

/// Media types that are files whatever their bytes look like.
const NEVER_DECODED: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
];

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
    /// The bytes are not one of the four formats this decoder handles.
    #[error("the bytes are not PNG, JPEG, WebP or GIF")]
    UnsupportedFormat,
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
    /// The thumbnail encoded larger than the budget.
    #[error("the thumbnail is {len} bytes, above the {MAX_PREVIEW_THUMBNAIL_BYTES}-byte budget")]
    ThumbnailTooLarge {
        /// The encoded length.
        len: u64,
    },
}

/// Produces a bounded thumbnail of one image, or says why it did not.
///
/// The source is read from an open handle and left rewound to its start, so the caller can go on
/// using the same handle.
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
    // Two passes over the same handle: the header decides the format and the dimensions, and only
    // then does anything ask for a buffer. An image that declares more pixels than the limit
    // allows costs a header read.
    let (format, width, height) = header(source)?;
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > MAX_PREVIEW_PIXELS {
        return Err(PreviewRefusal::TooManyPixels {
            width: u64::from(width),
            height: u64::from(height),
            pixels,
        });
    }
    rewind(source)?;
    let mut reader = ImageReader::with_format(BufReader::new(&mut *source), format);
    reader.limits(limits());
    // A GIF decoder used as one image decoder yields the first frame and reads no further; the
    // animation interface is a separate call this crate never makes.
    let image = reader
        .decode()
        .map_err(|error| PreviewRefusal::DecodeFailed {
            detail: error.to_string(),
        })?;
    let thumbnail = image.thumbnail(PREVIEW_THUMBNAIL_EDGE, PREVIEW_THUMBNAIL_EDGE);
    let mut encoded = std::io::Cursor::new(Vec::new());
    thumbnail
        .write_to(&mut encoded, ImageFormat::Png)
        .map_err(|error| PreviewRefusal::DecodeFailed {
            detail: error.to_string(),
        })?;
    let encoded = encoded.into_inner();
    if encoded.len() as u64 > MAX_PREVIEW_THUMBNAIL_BYTES {
        return Err(PreviewRefusal::ThumbnailTooLarge {
            len: encoded.len() as u64,
        });
    }
    Ok(AttachmentPreview {
        source_format: match format {
            ImageFormat::Png => PreviewFormat::Png,
            ImageFormat::Jpeg => PreviewFormat::Jpeg,
            ImageFormat::WebP => PreviewFormat::Webp,
            _ => PreviewFormat::GifFirstFrame,
        },
        source_width: U64::new(u64::from(width)),
        source_height: U64::new(u64::from(height)),
        width: U64::new(u64::from(thumbnail.width())),
        height: U64::new(u64::from(thumbnail.height())),
        thumbnail: Bytes::new(encoded),
    })
}

/// Reads the format and the dimensions from the header alone.
fn header<S: Read + Seek>(
    source: &mut S,
) -> std::result::Result<(ImageFormat, u32, u32), PreviewRefusal> {
    rewind(source)?;
    let mut reader = ImageReader::new(BufReader::new(&mut *source))
        .with_guessed_format()
        .map_err(|error| PreviewRefusal::Unreadable {
            detail: error.to_string(),
        })?;
    let format = match reader.format() {
        Some(
            format @ (ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP | ImageFormat::Gif),
        ) => format,
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
/// `max_alloc` is the decode-memory bound. The dimension bounds are the pixel limit applied to each
/// axis, so a single enormous edge is refused by the decoder before the product check runs; the
/// product check then refuses the shapes that pass both axes but are still too large.
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
    fn each_of_the_four_formats_decodes_to_a_bounded_thumbnail() {
        for (format, expected) in [
            (ImageFormat::Png, PreviewFormat::Png),
            (ImageFormat::Jpeg, PreviewFormat::Jpeg),
            (ImageFormat::Gif, PreviewFormat::GifFirstFrame),
            (ImageFormat::WebP, PreviewFormat::Webp),
        ] {
            let bytes = encoded(800, 600, format);
            let mut source = Cursor::new(bytes);
            let preview = generate(&mut source, "image/png").expect("decodes");
            assert_eq!(preview.source_format, expected, "{format:?}");
            assert_eq!(preview.source_width, U64::new(800));
            assert_eq!(preview.source_height, U64::new(600));
            assert!(preview.width.get() <= u64::from(PREVIEW_THUMBNAIL_EDGE));
            assert!(preview.height.get() <= u64::from(PREVIEW_THUMBNAIL_EDGE));
            assert!(preview.thumbnail.len() as u64 <= MAX_PREVIEW_THUMBNAIL_BYTES);
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
        assert_eq!(PREVIEW_THUMBNAIL_EDGE, 512);
    }
}
