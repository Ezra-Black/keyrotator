//! The credits box: shown once, the first time rekey runs in a terminal,
//! and at the end of `--help`. Never printed to stdout, in scripts, or over MCP.

use std::io::IsTerminal;
use std::path::PathBuf;

pub const REPO_URL: &str = "https://github.com/Ezra-Black/keyrotator";
pub const AUTHOR_URL: &str = "https://www.ezrablack.dev";

fn lines() -> [String; 4] {
    [
        format!(
            "rekey v{} — created by Ezra Black",
            env!("CARGO_PKG_VERSION")
        ),
        String::new(),
        format!("Please consider contributing:  {REPO_URL}"),
        format!("Support the creator:           {AUTHOR_URL}"),
    ]
}

/// The box as plain text (for `--help`).
pub fn plain() -> String {
    render(|s| s.to_string())
}

fn render(bold: impl Fn(&str) -> String) -> String {
    let lines = lines();
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0) + 4;
    let mut out = format!("╭{}╮\n", "─".repeat(width));
    for l in &lines {
        let pad = width - 2 - l.chars().count();
        out.push_str(&format!("│  {}{}│\n", bold(l), " ".repeat(pad)));
    }
    out.push_str(&format!("╰{}╯", "─".repeat(width)));
    out
}

fn marker() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("rekey").join(".welcome-shown"))
}

/// Show the box on the first interactive run, then remember that we did.
pub fn show_once() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let Some(marker) = marker() else { return };
    if marker.exists() {
        return;
    }
    let boxed = render(|s| console::style(s).bold().to_string());
    eprintln!("\n{boxed}\n");
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&marker, "");
}

#[cfg(test)]
mod tests {
    #[test]
    fn box_lines_are_aligned() {
        let b = super::plain();
        let widths: Vec<usize> = b.lines().map(|l| l.chars().count()).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{b}");
        assert!(b.contains("Ezra Black") && b.contains(super::REPO_URL));
    }
}
