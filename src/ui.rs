use humansize::{BINARY, format_size};
use qrcode::{QrCode, render::unicode};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::types::PeerInfo;

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

pub fn render_confirm(f: &mut Frame, name: &str) {
    let area = centered_rect(40, 20, f.area());
    f.render_widget(Clear, area);

    let lines = vec![
        Line::from("Delete tunnel?".fg(Color::Red).bold()),
        Line::raw(""),
        Line::from(format!("'{name}'").fg(Color::Yellow)),
        Line::raw(""),
        Line::from(vec![
            "y".fg(Color::Green).bold(),
            " to confirm, ".into(),
            "any key".fg(Color::Yellow),
            " to cancel".into(),
        ]),
    ];

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Confirm ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            )
            .style(Style::default().bg(Color::Black))
            .alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

pub fn render_full_tunnel_warning(f: &mut Frame, name: &str) {
    let area = centered_rect(60, 30, f.area());
    f.render_widget(Clear, area);

    let lines = vec![
        Line::from("Full-tunnel warning".fg(Color::Yellow).bold()),
        Line::raw(""),
        Line::from(format!("'{name}'").fg(Color::Cyan)),
        Line::raw(""),
        Line::from("AllowedIPs includes a default route.".fg(Color::White)),
        Line::from("If you're connected via SSH, enabling this".fg(Color::White)),
        Line::from("may lock you out of the server.".fg(Color::White)),
        Line::raw(""),
        Line::from(vec![
            "y".fg(Color::Green).bold(),
            " to enable anyway, ".into(),
            "any key".fg(Color::Yellow),
            " to cancel".into(),
        ]),
    ];

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Warning ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .style(Style::default().bg(Color::Black))
            .alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

pub fn render_add_menu(f: &mut Frame) {
    let area = centered_rect(48, 32, f.area());
    f.render_widget(Clear, area);

    let lines = vec![
        Line::from("Add Tunnel".fg(Color::Cyan).bold()),
        Line::raw(""),
        Line::from(vec![
            "i".fg(Color::Yellow).bold(),
            " / ".into(),
            "1".fg(Color::Yellow).bold(),
            "  Import from file".into(),
        ]),
        Line::from(vec![
            "a".fg(Color::Yellow).bold(),
            " / ".into(),
            "2".fg(Color::Yellow).bold(),
            "  Import directory".into(),
        ]),
        Line::from(vec![
            "c".fg(Color::Yellow).bold(),
            " / ".into(),
            "3".fg(Color::Yellow).bold(),
            "  Create client".into(),
        ]),
        Line::from(vec![
            "s".fg(Color::Yellow).bold(),
            " / ".into(),
            "4".fg(Color::Yellow).bold(),
            "  Create server".into(),
        ]),
        Line::raw(""),
        Line::from("Esc".fg(Color::DarkGray).italic()),
        Line::from("to cancel".fg(Color::DarkGray).italic()),
    ];

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Add ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black))
            .alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

pub fn render_input(f: &mut Frame, title: &str, prompt: &str, value: &str, hint: Option<&str>) {
    let area = centered_rect(70, 30, f.area());
    f.render_widget(Clear, area);

    let mut lines = vec![
        Line::from(prompt.fg(Color::Yellow)),
        Line::raw(""),
        Line::from(format!("{value}█")),
        Line::raw(""),
    ];

    if let Some(h) = hint {
        lines.push(Line::from(h.fg(Color::DarkGray).italic()));
        lines.push(Line::raw(""));
    }

    lines.push(Line::from(vec![
        "Enter".fg(Color::Green).bold(),
        " confirm  ".into(),
        "Esc".fg(Color::Yellow),
        " cancel".into(),
    ]));

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(format!(" {title} "))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black)),
        area,
    );
}

pub fn render_peer_config(f: &mut Frame, config: &str, suggested_path: &str) {
    let area = centered_rect(80, 70, f.area());
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = vec![
        Line::from("New Peer Config".fg(Color::Cyan).bold()),
        Line::raw(""),
    ];
    lines.extend(config.lines().map(Line::raw));
    lines.push(Line::raw(""));
    lines.push(Line::from(format!("Suggested file: {suggested_path}")));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        "s".fg(Color::Green).bold(),
        " save  ".into(),
        "q".fg(Color::Yellow).bold(),
        " qr  ".into(),
        "Esc".fg(Color::DarkGray),
        " close".into(),
    ]));

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Peer ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub fn render_peer_qr(f: &mut Frame, qr: &QrCode) {
    // Render QR code to string with proper aspect ratio using Dense1x2
    let qr_string = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();

    let qr_lines: Vec<Line> = qr_string.lines().map(Line::raw).collect();
    let qr_width = u16::try_from(qr_lines.first().map_or(0, ratatui::prelude::Line::width))
        .unwrap_or(u16::MAX);
    let qr_height = u16::try_from(qr_lines.len()).unwrap_or(u16::MAX);

    // Size the box to fit the QR code plus border and footer
    let box_width = (qr_width + 4).min(f.area().width);
    let box_height = (qr_height + 4).min(f.area().height); // +4 for border and footer line

    // Center the box
    let x = f.area().x + (f.area().width.saturating_sub(box_width)) / 2;
    let y = f.area().y + (f.area().height.saturating_sub(box_height)) / 2;
    let area = Rect::new(x, y, box_width, box_height);

    f.render_widget(Clear, area);

    let mut lines = qr_lines;
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        "b".fg(Color::Yellow).bold(),
        " back  ".into(),
        "Esc".fg(Color::DarkGray),
        " close".into(),
    ]));

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Peer Config QR ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black))
            .alignment(Alignment::Center),
        area,
    );
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
        ("a", "Add tunnel"),
        ("e", "Export all tunnels to zip"),
        ("x", "Delete tunnel"),
        ("p", "Add peer (server only)"),
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
    format_size(b, BINARY)
}
