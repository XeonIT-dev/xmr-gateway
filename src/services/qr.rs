//! High-contrast PNG QR code generation encoded in Base64 for Monero payment URIs.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{ExtendedColorType, ImageEncoder, Luma, codecs::png::PngEncoder};
use qrcode::{EcLevel, QrCode};

use crate::error::{GatewayError, GatewayResult};

/// Minimum pixel width/height for generated QR code PNG images.
const QR_MIN_DIMENSION_PX: u32 = 320;

/// Encodes `payload` (typically a `monero:` URI) into a crisp, high-contrast PNG QR code
/// returned as a standard Base64 string.
///
/// # Design Choices
/// - Uses Error Correction Level `M` (15%) for optimal resilience vs module density on mobile
///   Telegram screens.
/// - Uses pure black (`0`) on pure white (`255`) 8-bit grayscale (`L8`) with a standard
///   4-module quiet zone so hardware/mobile wallet scanners decode reliably in dark/light themes.
///
/// # Errors
/// Returns [`GatewayError::QrGeneration`] if QR encoding or PNG compression fails.
pub fn generate_qr_png_base64(payload: &str) -> GatewayResult<String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| GatewayError::QrGeneration(format!("failed to encode QR matrix: {e}")))?;

    let image = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(QR_MIN_DIMENSION_PX, QR_MIN_DIMENSION_PX)
        .dark_color(Luma([0]))
        .light_color(Luma([255]))
        .build();

    let mut png_bytes = Vec::with_capacity(4096);
    let encoder = PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            ExtendedColorType::L8,
        )
        .map_err(|e| GatewayError::QrGeneration(format!("failed to encode QR PNG: {e}")))?;

    Ok(STANDARD.encode(&png_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_high_contrast_png_base64() {
        let uri = "monero:888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H?tx_amount=1.250000000000&tx_description=order-123";
        let b64 = generate_qr_png_base64(uri).unwrap();
        let decoded = STANDARD.decode(&b64).unwrap();

        // Standard 8-byte PNG signature
        assert!(decoded.len() > 64);
        assert_eq!(
            &decoded[..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }
}
