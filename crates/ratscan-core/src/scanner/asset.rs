//! Static image-resource validation.
//!
//! Archive resources are inspected in memory only. The parser uses signatures
//! and bounded container lengths; it does not invoke image decoders.

/// Image container recognized by its magic bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    Png,
    Gif,
    Jpeg,
    WebP,
    Bmp,
}

/// A non-image payload found after a complete image container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrailingPayloadKind {
    Zip,
    Pe,
    Elf,
}

/// Static facts about an archive asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetAnalysis {
    pub declared_format: Option<ImageFormat>,
    pub detected_format: Option<ImageFormat>,
    pub extension_matches_magic: bool,
    pub trailing_payload: Option<TrailingPayloadKind>,
}

/// Inspects an image asset's extension, signature, and bytes following its
/// complete container. A format mismatch is intentionally distinct from a
/// hidden payload so callers can score them differently.
pub fn inspect_asset(path: &str, bytes: &[u8]) -> AssetAnalysis {
    let declared_format = image_format_from_path(path);
    let detected_format = image_format_from_magic(bytes);
    let extension_matches_magic = match (declared_format, detected_format) {
        (Some(declared), Some(detected)) => declared == detected,
        // A non-image resource is outside this recognizer's scope. A claimed
        // image without image magic is still an explicit mismatch.
        (None, _) => true,
        (Some(_), None) => false,
    };
    let trailing_payload = image_end_offset(bytes, detected_format)
        .and_then(|offset| bytes.get(offset..))
        .and_then(trailing_payload_kind);

    AssetAnalysis {
        declared_format,
        detected_format,
        extension_matches_magic,
        trailing_payload,
    }
}

/// Maps a conventional image extension to a container format.
pub fn image_format_from_path(path: &str) -> Option<ImageFormat> {
    let lower = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if lower.ends_with(".png") {
        Some(ImageFormat::Png)
    } else if lower.ends_with(".gif") {
        Some(ImageFormat::Gif)
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some(ImageFormat::Jpeg)
    } else if lower.ends_with(".webp") {
        Some(ImageFormat::WebP)
    } else if lower.ends_with(".bmp") {
        Some(ImageFormat::Bmp)
    } else {
        None
    }
}

/// Identifies an image container from its leading bytes.
pub fn image_format_from_magic(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageFormat::Png)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some(ImageFormat::Gif)
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(ImageFormat::Jpeg)
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some(ImageFormat::WebP)
    } else if bytes.starts_with(b"BM") {
        Some(ImageFormat::Bmp)
    } else {
        None
    }
}

fn image_end_offset(bytes: &[u8], format: Option<ImageFormat>) -> Option<usize> {
    match format? {
        ImageFormat::Png => png_end_offset(bytes),
        ImageFormat::Gif => gif_end_offset(bytes),
        ImageFormat::Jpeg => jpeg_end_offset(bytes),
        ImageFormat::WebP => webp_end_offset(bytes),
        ImageFormat::Bmp => bmp_end_offset(bytes),
    }
}

fn png_end_offset(bytes: &[u8]) -> Option<usize> {
    let mut offset = 8usize;
    while offset.checked_add(12)? <= bytes.len() {
        let length = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
        let chunk_end = offset.checked_add(12)?.checked_add(length)?;
        if chunk_end > bytes.len() {
            return None;
        }
        if bytes.get(offset + 4..offset + 8)? == b"IEND" {
            return Some(chunk_end);
        }
        offset = chunk_end;
    }
    None
}

fn gif_end_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .iter()
        .position(|byte| *byte == 0x3b)
        .map(|index| index + 1)
}

fn jpeg_end_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .position(|window| window == [0xff, 0xd9])
        .map(|index| index + 2)
}

fn webp_end_offset(bytes: &[u8]) -> Option<usize> {
    let riff_size = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    let end = 8usize.checked_add(riff_size)?;
    (end <= bytes.len()).then_some(end)
}

fn bmp_end_offset(bytes: &[u8]) -> Option<usize> {
    let size = u32::from_le_bytes(bytes.get(2..6)?.try_into().ok()?) as usize;
    (size >= 14 && size <= bytes.len()).then_some(size)
}

fn trailing_payload_kind(bytes: &[u8]) -> Option<TrailingPayloadKind> {
    let payload = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let bytes = &bytes[payload..];
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(TrailingPayloadKind::Zip)
    } else if bytes.starts_with(b"MZ") {
        Some(TrailingPayloadKind::Pe)
    } else if bytes.starts_with(b"\x7fELF") {
        Some(TrailingPayloadKind::Elf)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{inspect_asset, ImageFormat, TrailingPayloadKind};

    fn minimal_png() -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"IEND");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    #[test]
    fn accepts_a_png_with_matching_extension_and_no_trailing_payload() {
        let analysis = inspect_asset("assets/example/textures/icon.png", &minimal_png());

        assert_eq!(analysis.declared_format, Some(ImageFormat::Png));
        assert_eq!(analysis.detected_format, Some(ImageFormat::Png));
        assert!(analysis.extension_matches_magic);
        assert_eq!(analysis.trailing_payload, None);
    }

    #[test]
    fn identifies_an_image_extension_mismatch_without_calling_it_a_payload() {
        let analysis = inspect_asset("assets/example/icon.png", b"GIF89a\0\0\0;");

        assert_eq!(analysis.detected_format, Some(ImageFormat::Gif));
        assert!(!analysis.extension_matches_magic);
        assert_eq!(analysis.trailing_payload, None);
    }

    #[test]
    fn detects_zip_pe_and_elf_appended_to_complete_images() {
        let mut png_with_zip = minimal_png();
        png_with_zip.extend_from_slice(b"PK\x03\x04archive");
        assert_eq!(
            inspect_asset("assets/icon.png", &png_with_zip).trailing_payload,
            Some(TrailingPayloadKind::Zip)
        );

        let gif_with_pe = b"GIF89a\0\0\0;MZpayload";
        assert_eq!(
            inspect_asset("assets/icon.gif", gif_with_pe).trailing_payload,
            Some(TrailingPayloadKind::Pe)
        );

        let jpeg_with_elf = b"\xff\xd8\xffimage\xff\xd9\x7fELFpayload";
        assert_eq!(
            inspect_asset("assets/icon.jpg", jpeg_with_elf).trailing_payload,
            Some(TrailingPayloadKind::Elf)
        );
    }

    #[test]
    fn ignores_non_image_resources() {
        let analysis = inspect_asset("assets/example/data.bin", b"MZpayload");

        assert_eq!(analysis.declared_format, None);
        assert_eq!(analysis.detected_format, None);
        assert!(analysis.extension_matches_magic);
        assert_eq!(analysis.trailing_payload, None);
    }
}
