use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader, Luma};
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(b"\xff\xd8\xff")
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Zeroizing<String>>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| Error::Invalid("could not identify QR image format"))?;
    if !matches!(reader.format(), Some(ImageFormat::Png | ImageFormat::Jpeg)) {
        return Err(Error::Invalid("QR input must be a PNG or JPEG image"));
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|_| Error::Invalid("QR image is damaged or exceeds image resource limits"))?;
    if u64::from(decoded.width()) * u64::from(decoded.height()) > 16_777_216 {
        return Err(Error::Invalid("QR image exceeds the 16 megapixel limit"));
    }
    let mut prepared = rqrr::PreparedImage::prepare(decoded.to_luma8());
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err(Error::Invalid(
            "no QR code found; use an uncropped, clear PNG or JPEG image",
        ));
    }
    grids
        .into_iter()
        .enumerate()
        .map(|(index, grid)| {
            let (_, content) = grid.decode().map_err(|_| {
                Error::Invalid("could not decode QR code; try a clearer image").entry(index + 1)
            })?;
            Ok(Zeroizing::new(content))
        })
        .collect()
}

pub fn encode(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).map_err(|_| {
        Error::Invalid("data is too large for a QR code; use a file export or individual QR codes")
    })?;
    let pixels = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(384, 384)
        .build();
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(pixels)
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|_| Error::Invalid("could not encode QR image"))?;
    Ok(Zeroizing::new(output.into_inner()))
}
