//! WireGuard TUI Manager
//! A terminal user interface for managing WireGuard tunnels locally.

use std::{fs, io::stdout, path::PathBuf, process::Command, time::Duration};

use color_eyre::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Clone)]
struct Tunnel {
    name: String,
    config_path: PathBuf,
    is_active: bool,
    interface: Option<InterfaceInfo>,
}

#[derive(Debug, Clone, Default)]
struct InterfaceInfo {
    public_key: String,
    listen_port: Option<u16>,
    peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, Default)]
struct PeerInfo {
    public_key: String,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    latest_handshake: Option<String>,
    transfer_rx: u64,
    transfer_tx: u64,
}

// ============================================================================
// Application State
// ============================================================================

struct App {
    tunnels: Vec<Tunnel>,
    list_state: ListState,
    show_details: bool,
    show_help: bool,
    message: Option<(String, MessageKind)>,
    should_quit: bool,
}

#[derive(Clone)]
enum MessageKind {
    Info,
    Success,
    Error,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            tunnels: Vec::new(),
            list_state: ListState::default(),
            show_details: false,
            show_help: false,
            message: None,
            should_quit: false,
        };
        app.refresh_tunnels();
        if !app.tunnels.is_empty() {
            app.list_state.select(Some(0));
        }
        app
    }

    fn refresh_tunnels(&mut self) {
        self.tunnels = discover_tunnels();
        for tunnel in &mut self.tunnels {
            tunnel.is_active = is_interface_active(&tunnel.name);
            if tunnel.is_active {
                tunnel.interface = get_interface_info(&tunnel.name);
            }
        }
        // Maintain selection bounds
        if let Some(selected) = self.list_state.selected() {
            if selected >= self.tunnels.len() && !self.tunnels.is_empty() {
                self.list_state.select(Some(self.tunnels.len() - 1));
            }
        } else if !self.tunnels.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn selected_tunnel(&self) -> Option<&Tunnel> {
        self.list_state.selected().and_then(|i| self.tunnels.get(i))
    }

    fn select_next(&mut self) {
        if self.tunnels.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1).min(self.tunnels.len() - 1),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn select_previous(&mut self) {
        if self.tunnels.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn toggle_selected(&mut self) {
        let Some(selected) = self.list_state.selected() else {
            return;
        };
        let Some(tunnel) = self.tunnels.get(selected) else {
            return;
        };

        let name = tunnel.name.clone();
        let is_active = tunnel.is_active;

        let result = if is_active {
            bring_interface_down(&name)
        } else {
            bring_interface_up(&name)
        };

        match result {
            Ok(()) => {
                let action = if is_active { "stopped" } else { "started" };
                self.message = Some((format!("Tunnel '{name}' {action}"), MessageKind::Success));
                self.refresh_tunnels();
            }
            Err(e) => {
                self.message = Some((format!("Error: {e}"), MessageKind::Error));
            }
        }
    }

    fn set_message(&mut self, msg: impl Into<String>, kind: MessageKind) {
        self.message = Some((msg.into(), kind));
    }
}

// ============================================================================
// WireGuard System Interaction
// ============================================================================

fn discover_tunnels() -> Vec<Tunnel> {
    let config_dir = PathBuf::from("/etc/wireguard");
    let mut tunnels = Vec::new();

    if let Ok(entries) = fs::read_dir(&config_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "conf")
                && let Some(stem) = path.file_stem()
            {
                let name = stem.to_string_lossy().to_string();
                tunnels.push(Tunnel {
                    name,
                    config_path: path,
                    is_active: false,
                    interface: None,
                });
            }
        }
    }

    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    tunnels
}

fn is_interface_active(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn get_interface_info(name: &str) -> Option<InterfaceInfo> {
    let output = Command::new("wg").args(["show", name]).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wg_show_output(&stdout)
}

fn parse_wg_show_output(output: &str) -> Option<InterfaceInfo> {
    let mut info = InterfaceInfo::default();
    let mut current_peer: Option<PeerInfo> = None;

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("public key:") {
            if current_peer.is_some() {
                // This is the interface's public key shown after a peer block
                // Actually, wg show format has interface first, then peers
            }
            let value = line.strip_prefix("public key:")?.trim();
            if current_peer.is_none() {
                info.public_key = value.to_string();
            } else if let Some(ref mut peer) = current_peer {
                peer.public_key = value.to_string();
            }
        } else if line.starts_with("listening port:") {
            let value = line.strip_prefix("listening port:")?.trim();
            info.listen_port = value.parse().ok();
        } else if line.starts_with("peer:") {
            // Save previous peer
            if let Some(peer) = current_peer.take() {
                info.peers.push(peer);
            }
            let value = line.strip_prefix("peer:")?.trim();
            current_peer = Some(PeerInfo {
                public_key: value.to_string(),
                ..Default::default()
            });
        } else if line.starts_with("endpoint:") {
            if let Some(ref mut peer) = current_peer {
                peer.endpoint = Some(line.strip_prefix("endpoint:")?.trim().to_string());
            }
        } else if line.starts_with("allowed ips:") {
            if let Some(ref mut peer) = current_peer {
                let ips = line.strip_prefix("allowed ips:")?.trim();
                peer.allowed_ips = ips.split(", ").map(String::from).collect();
            }
        } else if line.starts_with("latest handshake:") {
            if let Some(ref mut peer) = current_peer {
                peer.latest_handshake =
                    Some(line.strip_prefix("latest handshake:")?.trim().to_string());
            }
        } else if line.starts_with("transfer:")
            && let Some(ref mut peer) = current_peer
        {
            let transfer = line.strip_prefix("transfer:")?.trim();
            // Parse "X received, Y sent"
            let parts: Vec<&str> = transfer.split(", ").collect();
            if let Some(rx) = parts.first() {
                peer.transfer_rx = parse_transfer_bytes(rx);
            }
            if let Some(tx) = parts.get(1) {
                peer.transfer_tx = parse_transfer_bytes(tx);
            }
        }
    }

    // Don't forget the last peer
    if let Some(peer) = current_peer {
        info.peers.push(peer);
    }

    Some(info)
}

fn parse_transfer_bytes(s: &str) -> u64 {
    let s = s.replace(" received", "").replace(" sent", "");
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 2 {
        return 0;
    }

    let value: f64 = parts[0].parse().unwrap_or(0.0);
    let unit = parts[1].to_uppercase();

    match unit.as_str() {
        "B" => value as u64,
        "KIB" => (value * 1024.0) as u64,
        "MIB" => (value * 1024.0 * 1024.0) as u64,
        "GIB" => (value * 1024.0 * 1024.0 * 1024.0) as u64,
        "TIB" => (value * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => 0,
    }
}

fn bring_interface_up(name: &str) -> Result<(), String> {
    let output = Command::new("wg-quick")
        .args(["up", name])
        .output()
        .map_err(|e| format!("Failed to execute wg-quick: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn bring_interface_down(name: &str) -> Result<(), String> {
    let output = Command::new("wg-quick")
        .args(["down", name])
        .output()
        .map_err(|e| format!("Failed to execute wg-quick: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ============================================================================
// Terminal Setup
// ============================================================================

fn setup_terminal() -> Result<DefaultTerminal> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let terminal = ratatui::init();
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    ratatui::restore();
    Ok(())
}

// ============================================================================
// Event Handling
// ============================================================================

fn handle_events(app: &mut App) -> Result<()> {
    if event::poll(Duration::from_millis(100))?
        && let Event::Key(key) = event::read()?
    {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        // Clear message on any key press
        app.message = None;

        // Handle help overlay first
        if app.show_help {
            app.show_help = false;
            return Ok(());
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.should_quit = true;
            }
            KeyCode::Char('j') | KeyCode::Down => app.select_next(),
            KeyCode::Char('k') | KeyCode::Up => app.select_previous(),
            KeyCode::Char('g') => app.list_state.select(Some(0)),
            KeyCode::Char('G') => {
                if !app.tunnels.is_empty() {
                    app.list_state.select(Some(app.tunnels.len() - 1));
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => app.toggle_selected(),
            KeyCode::Char('d') => app.show_details = !app.show_details,
            KeyCode::Char('r') => {
                app.refresh_tunnels();
                app.set_message("Tunnels refreshed", MessageKind::Info);
            }
            KeyCode::Char('?') => app.show_help = true,
            _ => {}
        }
    }
    Ok(())
}

// ============================================================================
// UI Rendering
// ============================================================================

fn ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Main layout: list on left, details on right (if enabled)
    let main_chunks = if app.show_details {
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area)
    } else {
        Layout::horizontal([Constraint::Percentage(100)]).split(area)
    };

    // Vertical layout for list area: title, list, status bar
    let list_chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .split(main_chunks[0]);

    render_header(frame, list_chunks[0]);
    render_tunnel_list(frame, app, list_chunks[1]);
    render_status_bar(frame, app, list_chunks[2]);

    if app.show_details && main_chunks.len() > 1 {
        render_details(frame, app, main_chunks[1]);
    }

    if app.show_help {
        render_help_overlay(frame, area);
    }
}

fn render_header(frame: &mut Frame, area: Rect) {
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" WireGuard ", Style::default().fg(Color::Cyan).bold()),
        Span::styled("TUI Manager", Style::default().fg(Color::White)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(title, area);
}

fn render_tunnel_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .tunnels
        .iter()
        .map(|tunnel| {
            let status_icon = if tunnel.is_active { "●" } else { "○" };
            let status_color = if tunnel.is_active {
                Color::Green
            } else {
                Color::DarkGray
            };

            let line = Line::from(vec![
                Span::styled(
                    format!(" {status_icon} "),
                    Style::default().fg(status_color),
                ),
                Span::styled(&tunnel.name, Style::default().fg(Color::White)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Tunnels ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let content = if let Some((ref msg, ref kind)) = app.message {
        let color = match kind {
            MessageKind::Info => Color::Blue,
            MessageKind::Success => Color::Green,
            MessageKind::Error => Color::Red,
        };
        Line::from(Span::styled(format!(" {msg}"), Style::default().fg(color)))
    } else {
        Line::from(vec![
            Span::styled(" j/k", Style::default().fg(Color::Yellow)),
            Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" toggle  "),
            Span::styled("d", Style::default().fg(Color::Yellow)),
            Span::raw(" details  "),
            Span::styled("?", Style::default().fg(Color::Yellow)),
            Span::raw(" help  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit"),
        ])
    };

    let status = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(status, area);
}

fn render_details(frame: &mut Frame, app: &App, area: Rect) {
    let Some(tunnel) = app.selected_tunnel() else {
        let empty = Paragraph::new(" No tunnel selected")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .title(" Details ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(empty, area);
        return;
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Name: ", Style::default().fg(Color::Yellow)),
            Span::raw(&tunnel.name),
        ]),
        Line::from(vec![
            Span::styled("Config: ", Style::default().fg(Color::Yellow)),
            Span::raw(tunnel.config_path.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Yellow)),
            if tunnel.is_active {
                Span::styled("Active", Style::default().fg(Color::Green))
            } else {
                Span::styled("Inactive", Style::default().fg(Color::Red))
            },
        ]),
        Line::raw(""),
    ];

    if let Some(ref iface) = tunnel.interface {
        lines.push(Line::from(Span::styled(
            "── Interface ──",
            Style::default().fg(Color::Cyan),
        )));

        if !iface.public_key.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Public Key: ", Style::default().fg(Color::Yellow)),
                Span::raw(truncate_key(&iface.public_key)),
            ]));
        }

        if let Some(port) = iface.listen_port {
            lines.push(Line::from(vec![
                Span::styled("Listen Port: ", Style::default().fg(Color::Yellow)),
                Span::raw(port.to_string()),
            ]));
        }

        if !iface.peers.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                format!("── Peers ({}) ──", iface.peers.len()),
                Style::default().fg(Color::Cyan),
            )));

            for (i, peer) in iface.peers.iter().enumerate() {
                if i > 0 {
                    lines.push(Line::raw(""));
                }

                lines.push(Line::from(vec![
                    Span::styled("  Key: ", Style::default().fg(Color::Yellow)),
                    Span::raw(truncate_key(&peer.public_key)),
                ]));

                if let Some(ref endpoint) = peer.endpoint {
                    lines.push(Line::from(vec![
                        Span::styled("  Endpoint: ", Style::default().fg(Color::Yellow)),
                        Span::raw(endpoint),
                    ]));
                }

                if !peer.allowed_ips.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("  Allowed IPs: ", Style::default().fg(Color::Yellow)),
                        Span::raw(peer.allowed_ips.join(", ")),
                    ]));
                }

                if let Some(ref handshake) = peer.latest_handshake {
                    lines.push(Line::from(vec![
                        Span::styled("  Last Handshake: ", Style::default().fg(Color::Yellow)),
                        Span::raw(handshake),
                    ]));
                }

                if peer.transfer_rx > 0 || peer.transfer_tx > 0 {
                    lines.push(Line::from(vec![
                        Span::styled("  Transfer: ", Style::default().fg(Color::Yellow)),
                        Span::styled("↓ ", Style::default().fg(Color::Green)),
                        Span::raw(format_bytes(peer.transfer_rx)),
                        Span::raw("  "),
                        Span::styled("↑ ", Style::default().fg(Color::Magenta)),
                        Span::raw(format_bytes(peer.transfer_tx)),
                    ]));
                }
            }
        }
    }

    let details = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(" Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(details, area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 60, area);

    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default().fg(Color::Cyan).bold(),
        )),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  j / ↓    ", Style::default().fg(Color::Yellow)),
            Span::raw("Move down"),
        ]),
        Line::from(vec![
            Span::styled("  k / ↑    ", Style::default().fg(Color::Yellow)),
            Span::raw("Move up"),
        ]),
        Line::from(vec![
            Span::styled("  g        ", Style::default().fg(Color::Yellow)),
            Span::raw("Go to first"),
        ]),
        Line::from(vec![
            Span::styled("  G        ", Style::default().fg(Color::Yellow)),
            Span::raw("Go to last"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  Enter    ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle tunnel on/off"),
        ]),
        Line::from(vec![
            Span::styled("  Space    ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle tunnel on/off"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  d        ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle details panel"),
        ]),
        Line::from(vec![
            Span::styled("  r        ", Style::default().fg(Color::Yellow)),
            Span::raw("Refresh tunnel list"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ?        ", Style::default().fg(Color::Yellow)),
            Span::raw("Show this help"),
        ]),
        Line::from(vec![
            Span::styled("  q / Esc  ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray).italic(),
        )),
    ];

    let help = Paragraph::new(Text::from(help_text))
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().bg(Color::Black));

    frame.render_widget(help, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn truncate_key(key: &str) -> String {
    if key.len() > 20 {
        format!("{}…{}", &key[..8], &key[key.len() - 8..])
    } else {
        key.to_string()
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut terminal = setup_terminal()?;
    let mut app = App::new();

    // Main loop
    while !app.should_quit {
        terminal.draw(|frame| ui(frame, &mut app))?;
        handle_events(&mut app)?;
    }

    restore_terminal()?;
    Ok(())
}
