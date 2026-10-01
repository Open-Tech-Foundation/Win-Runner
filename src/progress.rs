//! Terminal progress output: a winget-style download bar that is redrawn in
//! place on a terminal and reduced to plain final lines elsewhere.
//!
//! Progress messages are text. One that ends in `\r` is a transient status
//! line, replaced by the next message; any other is a permanent line.
//! [`StatusWriter`] renders such messages for one output stream.

const BAR_WIDTH: usize = 30;
const FILLED: &str = "\x1b[96m"; // bright cyan
const EMPTY: &str = "\x1b[90m"; // dark gray
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// A size in decimal units, as winget shows them: `950 B`, `14.5 MB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// One bar line, colored with ANSI escapes:
/// `  ██████████▒▒▒▒▒▒▒▒  14.5 MB / 32.1 MB  3.2 MB/s`. Without a known
/// total it shows the bytes received; the rate shows while in progress.
pub fn download_bar(received: u64, total: Option<u64>, bytes_per_second: Option<f64>) -> String {
    let mut line = String::from("  ");
    match total {
        Some(total) if total > 0 => {
            let filled = (received.min(total) as u128 * BAR_WIDTH as u128 / total as u128) as usize;
            line.push_str(FILLED);
            line.push_str(&"█".repeat(filled));
            line.push_str(EMPTY);
            line.push_str(&"▒".repeat(BAR_WIDTH - filled));
            line.push_str(RESET);
            line.push_str(&format!(
                "  {} / {}",
                format_bytes(received),
                format_bytes(total)
            ));
        }
        _ => line.push_str(&format_bytes(received)),
    }
    let finished = total.is_some_and(|total| received >= total);
    if let Some(rate) = bytes_per_second.filter(|rate| *rate > 0.0 && !finished) {
        line.push_str(&format!("  {DIM}{}/s{RESET}", format_bytes(rate as u64)));
    }
    line
}

/// `text` without ANSI escape sequences.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            // Parameters and intermediates, up to the final byte.
            for next in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(character);
    }
    out
}

/// Renders progress messages for one output stream. On a terminal, a
/// transient line is redrawn in place and colors are kept (unless
/// `NO_COLOR` is set); elsewhere transient lines are dropped and colors
/// removed, so logs and pipes get only the permanent lines.
pub struct StatusWriter {
    terminal: bool,
    color: bool,
    /// A transient line is on screen.
    transient: bool,
}

impl StatusWriter {
    pub fn new(terminal: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        Self::with_color(terminal, terminal && !no_color)
    }

    fn with_color(terminal: bool, color: bool) -> Self {
        Self {
            terminal,
            color,
            transient: false,
        }
    }

    /// What to write for `message`.
    pub fn render(&mut self, message: &str) -> String {
        let transient = message.ends_with('\r');
        let text = message.trim_end_matches('\r');
        let text = if self.color {
            text.to_string()
        } else {
            strip_ansi(text)
        };
        if !self.terminal {
            return if transient { String::new() } else { text };
        }
        let mut out = String::new();
        if self.transient || transient {
            out.push_str("\r\x1b[2K");
        }
        out.push_str(&text);
        self.transient = transient;
        out
    }

    /// What to write when the messages end, so a transient line left on
    /// screen (after a failure) does not run into the next output.
    pub fn finish(&mut self) -> String {
        if std::mem::take(&mut self.transient) {
            "\r\x1b[2K".to_string()
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_decimal_units_like_winget() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(14_500_000), "14.5 MB");
        assert_eq!(format_bytes(32_100_000_000), "32.1 GB");
    }

    #[test]
    fn the_bar_fills_with_the_received_share_and_shows_the_rate_until_done() {
        let half = strip_ansi(&download_bar(16_000_000, Some(32_000_000), Some(4_000_000.0)));
        assert_eq!(
            half,
            format!("  {}{}  16.0 MB / 32.0 MB  4.0 MB/s", "█".repeat(15), "▒".repeat(15))
        );
        let done = strip_ansi(&download_bar(32_000_000, Some(32_000_000), Some(4_000_000.0)));
        assert_eq!(done, format!("  {}  32.0 MB / 32.0 MB", "█".repeat(30)));
        assert_eq!(strip_ansi(&download_bar(2_500, None, None)), "  2.5 KB");
        assert!(download_bar(1, Some(2), None).contains(FILLED));
    }

    #[test]
    fn a_terminal_redraws_transient_lines_in_place() {
        let mut writer = StatusWriter::with_color(true, true);
        assert_eq!(writer.render("Downloading\n"), "Downloading\n");
        assert_eq!(writer.render("\x1b[96m█\x1b[0m 10%\r"), "\r\x1b[2K\x1b[96m█\x1b[0m 10%");
        assert_eq!(writer.render("██ 20%\r"), "\r\x1b[2K██ 20%");
        assert_eq!(writer.render("done\n"), "\r\x1b[2Kdone\n");
        assert_eq!(writer.render("next\n"), "next\n");
        writer.render("partial\r");
        assert_eq!(writer.finish(), "\r\x1b[2K");
        assert_eq!(writer.finish(), "");
    }

    #[test]
    fn other_streams_get_only_permanent_lines_without_color() {
        let mut writer = StatusWriter::with_color(false, false);
        assert_eq!(writer.render("\x1b[96m██\x1b[0m 20%\r"), "");
        assert_eq!(writer.render("  \x1b[96m██\x1b[0m  32.0 MB\n"), "  ██  32.0 MB\n");
        assert_eq!(writer.finish(), "");
        let mut plain_terminal = StatusWriter::with_color(true, false);
        assert_eq!(plain_terminal.render("\x1b[96m██\x1b[0m\r"), "\r\x1b[2K██");
    }
}
