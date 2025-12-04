use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::types::PeerInfo;

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;

pub fn bordered_block(title: Option<&str>) -> Block<'_> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    match title {
        Some(t) => block.title(t),
        None => block,
    }
}

pub fn label(key: &str, val: &str) -> Line<'static> {
    Line::from(vec![
        key.to_string().fg(Color::Yellow),
        val.to_string().into(),
    ])
}

pub fn section(title: &str) -> Line<'static> {
    Line::from(format!("── {title} ──").fg(Color::Cyan))
}

pub fn peer_lines(peer: &PeerInfo) -> Vec<Line<'static>> {
    let mut lines = vec![label("  Key: ", &truncate_key(&peer.public_key))];

    if let Some(ep) = &peer.endpoint {
        lines.push(label("  Endpoint: ", ep));
    }
    if !peer.allowed_ips.is_empty() {
        lines.push(label("  Allowed IPs: ", &peer.allowed_ips.join(", ")));
    }
    if let Some(hs) = &peer.latest_handshake {
        lines.push(label("  Last Handshake: ", hs));
    }
    if peer.transfer_rx > 0 || peer.transfer_tx > 0 {
        lines.push(Line::from(vec![
            "  Transfer: ".to_string().fg(Color::Yellow),
            "↓ ".fg(Color::Green),
            format_bytes(peer.transfer_rx).into(),
            "  ".into(),
            "↑ ".fg(Color::Magenta),
            format_bytes(peer.transfer_tx).into(),
        ]));
    }
    lines
}

pub fn render_help(f: &mut Frame) {
    let area = centered_rect(50, 60, f.area());
    f.render_widget(Clear, area);

    let keys = [
        ("j / ↓", "Move down"),
        ("k / ↑", "Move up"),
        ("g / G", "First / Last"),
        ("Enter", "Toggle tunnel"),
        ("d", "Toggle details"),
        ("r", "Refresh"),
        ("?", "Help"),
        ("q", "Quit"),
    ];

    let mut lines: Vec<Line> = vec![
        Line::from("Keyboard Shortcuts".fg(Color::Cyan).bold()),
        Line::raw(""),
    ];
    lines.extend(
        keys.iter()
            .map(|(k, d)| Line::from(vec![format!("  {k:<10}").fg(Color::Yellow), (*d).into()])),
    );
    lines.push(Line::raw(""));
    lines.push(Line::from(
        "Press any key to close".fg(Color::DarkGray).italic(),
    ));

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Help ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black)),
        area,
    );
}

pub fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
    let v = Layout::vertical([
        Constraint::Percentage((100 - h) / 2),
        Constraint::Percentage(h),
        Constraint::Percentage((100 - h) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - w) / 2),
        Constraint::Percentage(w),
        Constraint::Percentage((100 - w) / 2),
    ])
    .split(v[1])[1]
}

pub fn truncate_key(key: &str) -> String {
    if key.len() > 20 {
        format!("{}…{}", &key[..8], &key[key.len() - 8..])
    } else {
        key.into()
    }
}

pub fn format_bytes(b: u64) -> String {
    match b {
        _ if b >= GIB => format!("{:.2} GiB", b as f64 / GIB as f64),
        _ if b >= MIB => format!("{:.2} MiB", b as f64 / MIB as f64),
        _ if b >= KIB => format!("{:.2} KiB", b as f64 / KIB as f64),
        _ => format!("{b} B"),
    }
}
