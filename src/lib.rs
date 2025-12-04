use std::{fs, path::PathBuf, process::Command, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

const CONFIG_DIR: &str = "/etc/wireguard";
const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;

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
    fn style(&self) -> Style {
        Style::default().fg(match self {
            Self::Info(_) => Color::Blue,
            Self::Success(_) => Color::Green,
            Self::Error(_) => Color::Red,
        })
    }

    fn text(&self) -> &str {
        match self {
            Self::Info(s) | Self::Success(s) | Self::Error(s) => s,
        }
    }
}

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
        for t in &mut self.tunnels {
            t.is_active = is_interface_active(&t.name);
            if t.is_active {
                t.interface = get_interface_info(&t.name);
            }
        }
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let selected = match (self.list_state.selected(), self.tunnels.len()) {
            (_, 0) => None,
            (None | Some(0), _) => Some(0),
            (Some(i), len) => Some(i.min(len - 1)),
        };
        self.list_state.select(selected);
    }

    fn selected(&self) -> Option<&Tunnel> {
        self.list_state.selected().and_then(|i| self.tunnels.get(i))
    }

    fn move_selection(&mut self, delta: isize) {
        if let Some(i) = self.list_state.selected() {
            let new = (i as isize + delta).clamp(0, self.tunnels.len().saturating_sub(1) as isize);
            self.list_state.select(Some(new as usize));
        }
    }

    fn toggle_selected(&mut self) {
        let Some(tunnel) = self.selected() else {
            return;
        };
        let (name, active) = (tunnel.name.clone(), tunnel.is_active);

        match wg_quick(if active { "down" } else { "up" }, &name) {
            Ok(()) => {
                self.message = Some(Message::Success(format!(
                    "Tunnel '{name}' {}",
                    if active { "stopped" } else { "started" }
                )));
                self.refresh_tunnels();
            }
            Err(e) => self.message = Some(Message::Error(e)),
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
            (KeyCode::Char('j') | KeyCode::Down, _) => self.move_selection(1),
            (KeyCode::Char('k') | KeyCode::Up, _) => self.move_selection(-1),
            (KeyCode::Char('g'), _) => self.list_state.select(Some(0)),
            (KeyCode::Char('G'), _) => self
                .list_state
                .select(Some(self.tunnels.len().saturating_sub(1))),
            (KeyCode::Enter | KeyCode::Char(' '), _) => self.toggle_selected(),
            (KeyCode::Char('d'), _) => self.show_details = !self.show_details,
            (KeyCode::Char('r'), _) => {
                self.refresh_tunnels();
                self.message = Some(Message::Info("Refreshed".into()));
            }
            (KeyCode::Char('?'), _) => self.show_help = true,
            _ => {}
        }
        Ok(())
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::horizontal(if self.show_details {
            vec![Constraint::Percentage(40), Constraint::Percentage(60)]
        } else {
            vec![Constraint::Percentage(100)]
        })
        .split(frame.area());

        let main = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(chunks[0]);

        self.render_header(frame, main[0]);
        self.render_list(frame, main[1]);
        self.render_status(frame, main[2]);

        if self.show_details && chunks.len() > 1 {
            self.render_details(frame, chunks[1]);
        }
        if self.show_help {
            render_help(frame);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let title = Line::from(vec![
            " WireGuard ".fg(Color::Cyan).bold(),
            "TUI Manager".fg(Color::White),
        ]);
        f.render_widget(Paragraph::new(title).block(bordered_block(None)), area);
    }

    fn render_list(&mut self, f: &mut Frame, area: Rect) {
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
                    format!(" {icon} ").fg(color),
                    t.name.clone().fg(Color::White),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(bordered_block(Some(" Tunnels ")))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_status(&self, f: &mut Frame, area: Rect) {
        let content = match &self.message {
            Some(msg) => Line::styled(format!(" {}", msg.text()), msg.style()),
            None => Line::from(vec![
                " j/k".fg(Color::Yellow),
                " nav  ".into(),
                "Enter".fg(Color::Yellow),
                " toggle  ".into(),
                "d".fg(Color::Yellow),
                " details  ".into(),
                "?".fg(Color::Yellow),
                " help  ".into(),
                "q".fg(Color::Yellow),
                " quit".into(),
            ]),
        };
        f.render_widget(Paragraph::new(content).block(bordered_block(None)), area);
    }

    fn render_details(&self, f: &mut Frame, area: Rect) {
        let Some(tunnel) = self.selected() else {
            f.render_widget(
                Paragraph::new(" No tunnel selected")
                    .fg(Color::DarkGray)
                    .block(bordered_block(Some(" Details "))),
                area,
            );
            return;
        };

        let mut lines = vec![
            label("Name: ", &tunnel.name),
            label("Config: ", &tunnel.config_path.display().to_string()),
            Line::from(vec![
                "Status: ".fg(Color::Yellow),
                if tunnel.is_active {
                    "Active".fg(Color::Green)
                } else {
                    "Inactive".fg(Color::Red)
                },
            ]),
            Line::raw(""),
        ];

        if let Some(iface) = &tunnel.interface {
            lines.push(section("Interface"));
            if !iface.public_key.is_empty() {
                lines.push(label("Public Key: ", &truncate_key(&iface.public_key)));
            }
            if let Some(port) = iface.listen_port {
                lines.push(label("Listen Port: ", &port.to_string()));
            }

            for (i, peer) in iface.peers.iter().enumerate() {
                lines.push(Line::raw(""));
                if i == 0 {
                    lines.push(section(&format!("Peers ({})", iface.peers.len())));
                }
                lines.extend(peer_lines(peer));
            }
        }

        f.render_widget(
            Paragraph::new(Text::from(lines))
                .block(bordered_block(Some(" Details ")))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

fn discover_tunnels() -> Vec<Tunnel> {
    let Ok(entries) = fs::read_dir(CONFIG_DIR) else {
        return vec![];
    };

    let mut tunnels: Vec<_> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            (path.extension()? == "conf").then_some(())?;
            Some(Tunnel {
                name: path.file_stem()?.to_string_lossy().into(),
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
    let out = Command::new("wg").args(["show", name]).output().ok()?;
    out.status
        .success()
        .then(|| parse_wg_output(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_wg_output(output: &str) -> InterfaceInfo {
    let mut info = InterfaceInfo::default();
    let mut peer: Option<PeerInfo> = None;

    for line in output.lines().map(str::trim) {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let val = val.trim();

        match (key, peer.as_mut()) {
            ("public key", None) => info.public_key = val.into(),
            ("listening port", _) => info.listen_port = val.parse().ok(),
            ("peer", _) => {
                if let Some(p) = peer.take() {
                    info.peers.push(p);
                }
                peer = Some(PeerInfo {
                    public_key: val.into(),
                    ..Default::default()
                });
            }
            ("endpoint", Some(p)) => p.endpoint = Some(val.into()),
            ("allowed ips", Some(p)) => p.allowed_ips = val.split(", ").map(Into::into).collect(),
            ("latest handshake", Some(p)) => p.latest_handshake = Some(val.into()),
            ("transfer", Some(p)) => {
                let parts: Vec<_> = val.split(", ").collect();
                if let Some(rx) = parts.first() {
                    p.transfer_rx = parse_bytes(rx);
                }
                if let Some(tx) = parts.get(1) {
                    p.transfer_tx = parse_bytes(tx);
                }
            }
            _ => {}
        }
    }
    if let Some(p) = peer {
        info.peers.push(p);
    }
    info
}

fn parse_bytes(s: &str) -> u64 {
    let s = s.replace(" received", "").replace(" sent", "");
    let mut parts = s.split_whitespace();
    let val: f64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);

    match parts.next().map(|u| u.to_uppercase()).as_deref() {
        Some("B") => val as u64,
        Some("KIB") => (val * KIB as f64) as u64,
        Some("MIB") => (val * MIB as f64) as u64,
        Some("GIB") => (val * GIB as f64) as u64,
        Some("TIB") => (val * GIB as f64 * 1024.0) as u64,
        _ => 0,
    }
}

fn wg_quick(action: &str, name: &str) -> Result<(), String> {
    let out = Command::new("wg-quick")
        .args([action, name])
        .output()
        .map_err(|e| e.to_string())?;
    out.status
        .success()
        .then_some(())
        .ok_or_else(|| String::from_utf8_lossy(&out.stderr).trim().into())
}

fn bordered_block(title: Option<&str>) -> Block<'_> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    match title {
        Some(t) => block.title(t),
        None => block,
    }
}

fn label(key: &str, val: &str) -> Line<'static> {
    Line::from(vec![
        key.to_string().fg(Color::Yellow),
        val.to_string().into(),
    ])
}

fn section(title: &str) -> Line<'static> {
    Line::from(format!("── {title} ──").fg(Color::Cyan))
}

fn peer_lines(peer: &PeerInfo) -> Vec<Line<'static>> {
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

fn render_help(f: &mut Frame) {
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

fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
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

fn truncate_key(key: &str) -> String {
    if key.len() > 20 {
        format!("{}…{}", &key[..8], &key[key.len() - 8..])
    } else {
        key.into()
    }
}

fn format_bytes(b: u64) -> String {
    match b {
        _ if b >= GIB => format!("{:.2} GiB", b as f64 / GIB as f64),
        _ if b >= MIB => format!("{:.2} MiB", b as f64 / MIB as f64),
        _ if b >= KIB => format!("{:.2} KiB", b as f64 / KIB as f64),
        _ => format!("{b} B"),
    }
}
