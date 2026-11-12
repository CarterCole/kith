//! QR codes of join links for the pages (spec §7.13). The CLI prints its own as text.

use qrcode::render::svg;
use qrcode::QrCode;

/// A QR code of `text` as an SVG image, black on white.
pub fn svg(text: &str) -> Option<String> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_an_svg() {
        let s = svg("https://hub.example/join/abc").unwrap();
        assert!(s.starts_with("<?xml") && s.contains("<svg") && s.contains("#000000"));
    }
}
