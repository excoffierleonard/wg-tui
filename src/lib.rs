//! WireGuard TUI Manager - Core library

use std::{fs, path::PathBuf, process::Command, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

// ============================================================================
// Constants
// ============================================================================

const CONFIG_DIR: &str = "/etc/wireguard";
const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct Tunnel {
    pub name: String,
    pub config_path: PathBuf,
    pub is_active: bool,
    pub interface: Option<InterfaceInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceInfo {
    pub public_key: String,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<String>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

#[derive(Clone)]
pub enum Message {
    Info(String),
    Success(String),
    Error(String),
}

impl Message {
    fn color(&self) -> Color {
        match self {
            Self::Info(_) => Color::Blue,
            Self::Success(_) => Color::Green,
            Self::Error(_) => Color::Red,
        }
    }

    fn text(&self) -> &str {
        match self {
            Self::Info(s) | Self::Success(s) | Self::Error(s) => s,
        }
    }
}

// ============================================================================
// Application
// ============================================================================

pub struct App {
    tunnels: Vec<Tunnel>,
    list_state: ListState,
    show_details: bool,
    show_help: bool,
    message: Option<Message>,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
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

    pub fn refresh_tunnels(&mut self) {
        self.tunnels = discover_tunnels();
        for tunnel in &mut self.tunnels {
            tunnel.is_active = is_interface_active(&tunnel.name);
            if tunnel.is_active {
                tunnel.interface = get_interface_info(&tunnel.name);
            }
        }
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        match (self.list_state.selected(), self.tunnels.is_empty()) {
            (_, true) => self.list_state.select(None),
            (None, false) => self.list_state.select(Some(0)),
            (Some(i), false) if i >= self.tunnels.len() => {
                self.list_state.select(Some(self.tunnels.len() - 1));
            }
            _ => {}
        }
    }

    fn selected_tunnel(&self) -> Option<&Tunnel> {
        self.list_state.selected().and_then(|i| self.tunnels.get(i))
    }

    fn select_next(&mut self) {
        if let Some(i) = self.list_state.selected() {
            self.list_state
                .select(Some((i + 1).min(self.tunnels.len().saturating_sub(1))));
        }
    }

    fn select_previous(&mut self) {
        if let Some(i) = self.list_state.selected() {
            self.list_state.select(Some(i.saturating_sub(1)));
        }
    }

    fn select_first(&mut self) {
        if !self.tunnels.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn select_last(&mut self) {
        if !self.tunnels.is_empty() {
            self.list_state.select(Some(self.tunnels.len() - 1));
        }
    }

    fn toggle_selected(&mut self) {
        let Some(tunnel) = self.list_state.selected().and_then(|i| self.tunnels.get(i)) else {
            return;
        };

        let (name, is_active) = (tunnel.name.clone(), tunnel.is_active);
        let result = if is_active {
            interface_down(&name)
        } else {
            interface_up(&name)
        };

        match result {
            Ok(()) => {
                let action = if is_active { "stopped" } else { "started" };
                self.message = Some(Message::Success(format!("Tunnel '{name}' {action}")));
                self.refresh_tunnels();
            }
            Err(e) => self.message = Some(Message::Error(format!("Error: {e}"))),
        }
    }

    pub fn handle_events(&mut self) -> std::io::Result<()> {
        if !event::poll(Duration::from_millis(100))? {
            return Ok(());
        }

        let Event::Key(key) = event::read()? else {
            return Ok(());
        };
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        self.message = None;

        if self.show_help {
            self.show_help = false;
            return Ok(());
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('q') | KeyCode::Esc, _) => self.should_quit = true,
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => self.should_quit = true,
            (KeyCode::Char('j') | KeyCode::Down, _) => self.select_next(),
            (KeyCode::Char('k') | KeyCode::Up, _) => self.select_previous(),
            (KeyCode::Char('g'), _) => self.select_first(),
            (KeyCode::Char('G'), _) => self.select_last(),
            (KeyCode::Enter | KeyCode::Char(' '), _) => self.toggle_selected(),
            (KeyCode::Char('d'), _) => self.show_details = !self.show_details,
            (KeyCode::Char('r'), _) => {
                self.refresh_tunnels();
                self.message = Some(Message::Info("Tunnels refreshed".into()));
            }
            (KeyCode::Char('?'), _) => self.show_help = true,
            _ => {}
        }
        Ok(())
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let chunks = if self.show_details {
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        } else {
            Layout::horizontal([Constraint::Percentage(100)])
        }
        .split(frame.area());

        let list_chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(chunks[0]);

        self.render_header(frame, list_chunks[0]);
        self.render_tunnel_list(frame, list_chunks[1]);
        self.render_status_bar(frame, list_chunks[2]);

        if self.show_details && chunks.len() > 1 {
            self.render_details(frame, chunks[1]);
        }

        if self.show_help {
            render_help_overlay(frame, frame.area());
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
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

    fn render_tunnel_list(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .tunnels
            .iter()
            .map(|t| {
                let (icon, color) = if t.is_active {
                    ("●", Color::Green)
                } else {
                    ("○", Color::DarkGray)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!(" {icon} "), Style::default().fg(color)),
                    Span::styled(&t.name, Style::default().fg(Color::White)),
                ]))
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

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let content = match &self.message {
            Some(msg) => Line::from(Span::styled(
                format!(" {}", msg.text()),
                Style::default().fg(msg.color()),
            )),
            None => Line::from(vec![
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
            ]),
        };
        frame.render_widget(
            Paragraph::new(content).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            area,
        );
    }

    fn render_details(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let Some(tunnel) = self.selected_tunnel() else {
            frame.render_widget(
                Paragraph::new(" No tunnel selected")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(block),
                area,
            );
            return;
        };

        let mut lines = vec![
            labeled_line("Name: ", &tunnel.name),
            labeled_line("Config: ", &tunnel.config_path.display().to_string()),
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

        if let Some(iface) = &tunnel.interface {
            lines.push(section_header("Interface"));
            if !iface.public_key.is_empty() {
                lines.push(labeled_line(
                    "Public Key: ",
                    &truncate_key(&iface.public_key),
                ));
            }
            if let Some(port) = iface.listen_port {
                lines.push(labeled_line("Listen Port: ", &port.to_string()));
            }

            if !iface.peers.is_empty() {
                lines.push(Line::raw(""));
                lines.push(section_header(&format!("Peers ({})", iface.peers.len())));
                for (i, peer) in iface.peers.iter().enumerate() {
                    if i > 0 {
                        lines.push(Line::raw(""));
                    }
                    lines.extend(peer_lines(peer));
                }
            }
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines))
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

// ============================================================================
// WireGuard Interaction
// ============================================================================

fn discover_tunnels() -> Vec<Tunnel> {
    let Ok(entries) = fs::read_dir(CONFIG_DIR) else {
        return Vec::new();
    };

    let mut tunnels: Vec<Tunnel> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let is_conf = path.extension().is_some_and(|ext| ext == "conf");
            let name = path.file_stem()?.to_string_lossy().into();
            is_conf.then_some(Tunnel {
                name,
                config_path: path,
                ..Default::default()
            })
        })
        .collect();

    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    tunnels
}

fn is_interface_active(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn get_interface_info(name: &str) -> Option<InterfaceInfo> {
    let output = Command::new("wg").args(["show", name]).output().ok()?;
    output
        .status
        .success()
        .then(|| parse_wg_output(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_wg_output(output: &str) -> InterfaceInfo {
    let mut info = InterfaceInfo::default();
    let mut current_peer: Option<PeerInfo> = None;

    for line in output.lines().map(str::trim) {
        match line.split_once(':') {
            Some(("public key", v)) if current_peer.is_none() => info.public_key = v.trim().into(),
            Some(("listening port", v)) => info.listen_port = v.trim().parse().ok(),
            Some(("peer", v)) => {
                if let Some(peer) = current_peer.take() {
                    info.peers.push(peer);
                }
                current_peer = Some(PeerInfo {
                    public_key: v.trim().into(),
                    ..Default::default()
                });
            }
            Some(("endpoint", v)) if current_peer.is_some() => {
                current_peer.as_mut().unwrap().endpoint = Some(v.trim().into());
            }
            Some(("allowed ips", v)) if current_peer.is_some() => {
                current_peer.as_mut().unwrap().allowed_ips =
                    v.trim().split(", ").map(Into::into).collect();
            }
            Some(("latest handshake", v)) if current_peer.is_some() => {
                current_peer.as_mut().unwrap().latest_handshake = Some(v.trim().into());
            }
            Some(("transfer", v)) if current_peer.is_some() => {
                let peer = current_peer.as_mut().unwrap();
                let parts: Vec<&str> = v.trim().split(", ").collect();
                if let Some(rx) = parts.first() {
                    peer.transfer_rx = parse_bytes(rx);
                }
                if let Some(tx) = parts.get(1) {
                    peer.transfer_tx = parse_bytes(tx);
                }
            }
            _ => {}
        }
    }

    if let Some(peer) = current_peer {
        info.peers.push(peer);
    }
    info
}

fn parse_bytes(s: &str) -> u64 {
    let s = s.replace(" received", "").replace(" sent", "");
    let mut parts = s.split_whitespace();
    let value: f64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);

    match parts.next().map(|u| u.to_uppercase()).as_deref() {
        Some("B") => value as u64,
        Some("KIB") => (value * KIB as f64) as u64,
        Some("MIB") => (value * MIB as f64) as u64,
        Some("GIB") => (value * GIB as f64) as u64,
        Some("TIB") => (value * GIB as f64 * 1024.0) as u64,
        _ => 0,
    }
}

fn interface_up(name: &str) -> Result<(), String> {
    run_wg_quick("up", name)
}

fn interface_down(name: &str) -> Result<(), String> {
    run_wg_quick("down", name)
}

fn run_wg_quick(action: &str, name: &str) -> Result<(), String> {
    let output = Command::new("wg-quick")
        .args([action, name])
        .output()
        .map_err(|e| e.to_string())?;
    output
        .status
        .success()
        .then_some(())
        .ok_or_else(|| String::from_utf8_lossy(&output.stderr).trim().into())
}

// ============================================================================
// UI Helpers
// ============================================================================

fn labeled_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(value.to_string()),
    ])
}

fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {title} ──"),
        Style::default().fg(Color::Cyan),
    ))
}

fn peer_lines(peer: &PeerInfo) -> Vec<Line<'static>> {
    let mut lines = vec![labeled_line("  Key: ", &truncate_key(&peer.public_key))];

    if let Some(ep) = &peer.endpoint {
        lines.push(labeled_line("  Endpoint: ", ep));
    }
    if !peer.allowed_ips.is_empty() {
        lines.push(labeled_line(
            "  Allowed IPs: ",
            &peer.allowed_ips.join(", "),
        ));
    }
    if let Some(hs) = &peer.latest_handshake {
        lines.push(labeled_line("  Last Handshake: ", hs));
    }
    if peer.transfer_rx > 0 || peer.transfer_tx > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                "  Transfer: ".to_string(),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("↓ ", Style::default().fg(Color::Green)),
            Span::raw(format_bytes(peer.transfer_rx)),
            Span::raw("  "),
            Span::styled("↑ ", Style::default().fg(Color::Magenta)),
            Span::raw(format_bytes(peer.transfer_tx)),
        ]));
    }
    lines
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(50, 60, area);
    frame.render_widget(Clear, popup);

    let help_text: Vec<Line> = [
        ("", "Keyboard Shortcuts", true),
        ("", "", false),
        ("  j / ↓    ", "Move down", false),
        ("  k / ↑    ", "Move up", false),
        ("  g        ", "Go to first", false),
        ("  G        ", "Go to last", false),
        ("", "", false),
        ("  Enter    ", "Toggle tunnel", false),
        ("  Space    ", "Toggle tunnel", false),
        ("", "", false),
        ("  d        ", "Toggle details", false),
        ("  r        ", "Refresh list", false),
        ("", "", false),
        ("  ?        ", "Show this help", false),
        ("  q / Esc  ", "Quit", false),
    ]
    .into_iter()
    .map(|(key, desc, is_title)| {
        if is_title {
            Line::from(Span::styled(desc, Style::default().fg(Color::Cyan).bold()))
        } else if key.is_empty() {
            Line::raw("")
        } else {
            Line::from(vec![
                Span::styled(key, Style::default().fg(Color::Yellow)),
                Span::raw(desc),
            ])
        }
    })
    .chain(std::iter::once(Line::from(Span::styled(
        "Press any key to close",
        Style::default().fg(Color::DarkGray).italic(),
    ))))
    .collect();

    frame.render_widget(
        Paragraph::new(Text::from(help_text))
            .block(
                Block::default()
                    .title(" Help ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().bg(Color::Black)),
        popup,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let v = Layout::vertical([
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
    .split(v[1])[1]
}

fn truncate_key(key: &str) -> String {
    if key.len() > 20 {
        format!("{}…{}", &key[..8], &key[key.len() - 8..])
    } else {
        key.to_string()
    }
}

fn format_bytes(bytes: u64) -> String {
    match bytes {
        b if b >= GIB => format!("{:.2} GiB", b as f64 / GIB as f64),
        b if b >= MIB => format!("{:.2} MiB", b as f64 / MIB as f64),
        b if b >= KIB => format!("{:.2} KiB", b as f64 / KIB as f64),
        b => format!("{b} B"),
    }
}
