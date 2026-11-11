//! QR codes for join links (spec §7.13): SVG for the pages, text for a terminal.

use qrcode::render::{svg, unicode::Dense1x2};
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

/// A QR code of `text` as lines of half-block characters, two modules to a line. Dark
/// modules are the drawn ones, so print it in black on white (see [`terminal_colors`])
/// or a dark-themed terminal shows a negative that some cameras won't read.
pub fn text(text: &str) -> Option<String> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<Dense1x2>()
            .quiet_zone(true)
            .dark_color(Dense1x2::Dark)
            .light_color(Dense1x2::Light)
            .build(),
    )
}

/// Each line wrapped in ANSI black-on-white, for printing [`text`] to a terminal of any
/// theme.
pub fn terminal_colors(qr: &str) -> String {
    qr.lines()
        .map(|l| format!("\x1b[30;107m{l}\x1b[0m\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_both_ways() {
        let url = "https://hub.example/join/abc";
        let s = svg(url).unwrap();
        assert!(s.starts_with("<?xml") && s.contains("<svg") && s.contains("#000000"));
        let t = text(url).unwrap();
        let lines: Vec<_> = t.lines().collect();
        assert!(lines.len() > 10);
        assert!(lines
            .iter()
            .all(|l| l.chars().count() == lines[0].chars().count()));
        assert!(terminal_colors(&t).starts_with("\x1b[30;107m"));
    }
}
