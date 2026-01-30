use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Text},
    widgets::{List, ListItem, ListState, Paragraph, Wrap},
};

use crate::error::Error;

use crate::{
    types::{Message, NewServerDraft, NewTunnelDraft, Tunnel},
    ui::{
        bordered_block, label, peer_lines, render_add_menu, render_confirm,
        render_full_tunnel_warning, render_help, render_input, section, truncate_key,
    },
    wireguard::{
        create_server_tunnel, create_tunnel, default_egress_interface, delete_tunnel,
        discover_tunnels, export_tunnels_to_zip, generate_private_key, get_interface_info,
        import_tunnel, is_full_tunnel_config, is_interface_active, suggest_server_address,
        wg_quick,
    },
};

pub struct App {
    tunnels: Vec<Tunnel>,
    list_state: ListState,
    show_details: bool,
    show_help: bool,
    confirm_delete: bool,
    confirm_full_tunnel: Option<String>,
    show_add_menu: bool,
    input_path: Option<String>,
    export_path: Option<String>,
    new_tunnel: Option<NewTunnelWizard>,
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
            confirm_delete: false,
            confirm_full_tunnel: None,
            show_add_menu: false,
            input_path: None,
            export_path: None,
            new_tunnel: None,
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

        if !active && is_full_tunnel_config(&name) {
            self.confirm_full_tunnel = Some(name);
            return;
        }

        self.toggle_selected_with_name(&name);
    }

    fn toggle_selected_with_name(&mut self, name: &str) {
        let active = self
            .tunnels
            .iter()
            .find(|t| t.name == name)
            .map(|t| t.is_active)
            .unwrap_or(false);

        match wg_quick(if active { "down" } else { "up" }, name) {
            Ok(()) => {
                self.message = Some(Message::Success(format!(
                    "Tunnel '{name}' {}",
                    if active { "stopped" } else { "started" }
                )));
                self.refresh_tunnels();
            }
            Err(e) => self.message = Some(Message::Error(e.to_string())),
        }
    }

    fn delete_selected(&mut self) {
        let Some(tunnel) = self.selected() else {
            return;
        };
        let (name, active) = (tunnel.name.clone(), tunnel.is_active);

        match delete_tunnel(&name, active) {
            Ok(()) => {
                self.message = Some(Message::Success(format!("Tunnel '{name}' deleted")));
                self.refresh_tunnels();
            }
            Err(e) => self.message = Some(Message::Error(e.to_string())),
        }
    }

    pub fn handle_events(&mut self) -> Result<(), Error> {
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

        if self.confirm_delete {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.confirm_delete = false;
                    self.delete_selected();
                }
                _ => {
                    self.confirm_delete = false;
                    self.message = Some(Message::Info("Delete cancelled".into()));
                }
            }
            return Ok(());
        }

        if let Some(ref name) = self.confirm_full_tunnel {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let name = name.clone();
                    self.confirm_full_tunnel = None;
                    self.toggle_selected_with_name(&name);
                }
                _ => {
                    self.confirm_full_tunnel = None;
                    self.message = Some(Message::Info("Enable cancelled".into()));
                }
            }
            return Ok(());
        }

        if let Some(ref mut path) = self.input_path {
            match key.code {
                KeyCode::Enter => {
                    let path_str = path.clone();
                    self.input_path = None;
                    match import_tunnel(&path_str) {
                        Ok(name) => {
                            self.message =
                                Some(Message::Success(format!("Tunnel '{name}' imported")));
                            self.refresh_tunnels();
                        }
                        Err(e) => self.message = Some(Message::Error(e.to_string())),
                    }
                }
                KeyCode::Esc => {
                    self.input_path = None;
                    self.message = Some(Message::Info("Import cancelled".into()));
                }
                KeyCode::Backspace => {
                    path.pop();
                }
                KeyCode::Char(c) => {
                    path.push(c);
                }
                _ => {}
            }
            return Ok(());
        }

        if let Some(ref mut path) = self.export_path {
            match key.code {
                KeyCode::Enter => {
                    let path_str = path.clone();
                    self.export_path = None;
                    match export_tunnels_to_zip(&path_str) {
                        Ok(dest) => {
                            self.message = Some(Message::Success(format!(
                                "Exported {} tunnels to {}",
                                self.tunnels.len(),
                                dest.display()
                            )));
                        }
                        Err(e) => self.message = Some(Message::Error(e.to_string())),
                    }
                }
                KeyCode::Esc => {
                    self.export_path = None;
                    self.message = Some(Message::Info("Export cancelled".into()));
                }
                KeyCode::Backspace => {
                    path.pop();
                }
                KeyCode::Char(c) => {
                    path.push(c);
                }
                _ => {}
            }
            return Ok(());
        }

        if let Some(ref mut wizard) = self.new_tunnel {
            match key.code {
                KeyCode::Enter => {
                    let finished = {
                        if let Some(err) = wizard.validate_current() {
                            self.message = Some(Message::Error(err));
                            return Ok(());
                        }
                        wizard.advance()
                    };
                    if finished {
                        let wizard = self.new_tunnel.take().unwrap();
                        match wizard {
                            NewTunnelWizard::Client(wizard) => {
                                let draft = wizard.draft;
                                match create_tunnel(&draft) {
                                    Ok(()) => {
                                        let name = draft.name;
                                        self.message = Some(Message::Success(format!(
                                            "Tunnel '{name}' created"
                                        )));
                                        self.refresh_tunnels();
                                    }
                                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                                }
                            }
                            NewTunnelWizard::Server(wizard) => {
                                let draft = wizard.draft;
                                match create_server_tunnel(&draft) {
                                    Ok(()) => {
                                        let name = draft.name;
                                        self.message = Some(Message::Success(format!(
                                            "Tunnel '{name}' created"
                                        )));
                                        self.refresh_tunnels();
                                    }
                                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                                }
                            }
                        }
                    }
                }
                KeyCode::Esc => {
                    self.new_tunnel = None;
                    self.message = Some(Message::Info("Create cancelled".into()));
                }
                KeyCode::Backspace => {
                    wizard.current_value_mut().pop();
                }
                KeyCode::Char(c) => {
                    wizard.current_value_mut().push(c);
                }
                _ => {}
            }
            return Ok(());
        }

        if self.show_add_menu {
            match key.code {
                KeyCode::Char('i') | KeyCode::Char('1') => {
                    self.show_add_menu = false;
                    self.input_path = Some(String::new());
                }
                KeyCode::Char('c') | KeyCode::Char('2') => {
                    self.show_add_menu = false;
                    let name = self.default_tunnel_name();
                    self.new_tunnel = Some(NewTunnelWizard::client(name));
                }
                KeyCode::Char('s') | KeyCode::Char('3') => {
                    self.show_add_menu = false;
                    let name = self.default_tunnel_name();
                    let address = suggest_server_address();
                    let egress = default_egress_interface().unwrap_or_default();
                    let private_key = match generate_private_key() {
                        Ok(key) => key,
                        Err(e) => {
                            self.message = Some(Message::Error(e.to_string()));
                            return Ok(());
                        }
                    };
                    self.new_tunnel = Some(NewTunnelWizard::server(
                        name,
                        address,
                        "51820".into(),
                        private_key,
                        egress,
                    ));
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_add_menu = false;
                }
                _ => {}
            }
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
            (KeyCode::Char('x'), _) => {
                if self.selected().is_some() {
                    self.confirm_delete = true;
                }
            }
            (KeyCode::Char('a'), _) => self.show_add_menu = true,
            (KeyCode::Char('e'), _) => {
                if self.tunnels.is_empty() {
                    self.message = Some(Message::Error("No tunnels to export".into()));
                } else {
                    self.export_path = Some("wg-tunnels.zip".into());
                }
            }
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
        if self.confirm_delete
            && let Some(tunnel) = self.selected()
        {
            render_confirm(frame, &tunnel.name);
        }
        if let Some(ref name) = self.confirm_full_tunnel {
            render_full_tunnel_warning(frame, name);
        }
        if self.show_add_menu {
            render_add_menu(frame);
        }
        if let Some(ref path) = self.input_path {
            let cwd = std::env::current_dir()
                .map(|p| format!("cwd: {}  (use ~/ for home)", p.display()))
                .ok();
            render_input(
                frame,
                "Import Tunnel",
                "File path (.conf):",
                path,
                cwd.as_deref(),
            );
        }
        if let Some(ref path) = self.export_path {
            let hint = std::env::current_dir()
                .map(|p| {
                    format!(
                        "{} tunnel(s) — cwd: {}  (use ~/ for home)",
                        self.tunnels.len(),
                        p.display()
                    )
                })
                .ok();
            render_input(
                frame,
                "Export All Tunnels",
                "Destination (.zip):",
                path,
                hint.as_deref(),
            );
        }
        if let Some(ref wizard) = self.new_tunnel {
            let (title, prompt, hint) = wizard.ui();
            render_input(
                frame,
                &title,
                prompt,
                wizard.current_value(),
                hint.as_deref(),
            );
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

#[derive(Debug, Clone)]
enum NewTunnelWizard {
    Client(NewClientWizard),
    Server(NewServerWizard),
}

impl NewTunnelWizard {
    fn client(name: String) -> Self {
        Self::Client(NewClientWizard::new(name))
    }

    fn server(
        name: String,
        address: String,
        listen_port: String,
        private_key: String,
        egress_interface: String,
    ) -> Self {
        Self::Server(NewServerWizard::new(
            name,
            address,
            listen_port,
            private_key,
            egress_interface,
        ))
    }

    fn current_value(&self) -> &str {
        match self {
            Self::Client(wizard) => wizard.current_value(),
            Self::Server(wizard) => wizard.current_value(),
        }
    }

    fn current_value_mut(&mut self) -> &mut String {
        match self {
            Self::Client(wizard) => wizard.current_value_mut(),
            Self::Server(wizard) => wizard.current_value_mut(),
        }
    }

    fn ui(&self) -> (String, &'static str, Option<String>) {
        match self {
            Self::Client(wizard) => wizard.ui(),
            Self::Server(wizard) => wizard.ui(),
        }
    }

    fn validate_current(&self) -> Option<String> {
        match self {
            Self::Client(wizard) => wizard.validate_current(),
            Self::Server(wizard) => wizard.validate_current(),
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Self::Client(wizard) => wizard.advance(),
            Self::Server(wizard) => wizard.advance(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientWizardStep {
    Name,
    PrivateKey,
    Address,
    Dns,
    PeerPublicKey,
    AllowedIps,
    Endpoint,
}

impl ClientWizardStep {
    fn next(self) -> Option<Self> {
        match self {
            Self::Name => Some(Self::PrivateKey),
            Self::PrivateKey => Some(Self::Address),
            Self::Address => Some(Self::Dns),
            Self::Dns => Some(Self::PeerPublicKey),
            Self::PeerPublicKey => Some(Self::AllowedIps),
            Self::AllowedIps => Some(Self::Endpoint),
            Self::Endpoint => None,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Name => 1,
            Self::PrivateKey => 2,
            Self::Address => 3,
            Self::Dns => 4,
            Self::PeerPublicKey => 5,
            Self::AllowedIps => 6,
            Self::Endpoint => 7,
        }
    }
}

#[derive(Debug, Clone)]
struct NewClientWizard {
    step: ClientWizardStep,
    draft: NewTunnelDraft,
}

impl NewClientWizard {
    fn new(name: String) -> Self {
        Self {
            step: ClientWizardStep::Name,
            draft: NewTunnelDraft {
                name,
                private_key: String::new(),
                address: "10.0.0.2/32".into(),
                dns: String::new(),
                peer_public_key: String::new(),
                allowed_ips: "0.0.0.0/0, ::/0".into(),
                endpoint: String::new(),
            },
        }
    }

    fn current_value(&self) -> &str {
        match self.step {
            ClientWizardStep::Name => &self.draft.name,
            ClientWizardStep::PrivateKey => &self.draft.private_key,
            ClientWizardStep::Address => &self.draft.address,
            ClientWizardStep::Dns => &self.draft.dns,
            ClientWizardStep::PeerPublicKey => &self.draft.peer_public_key,
            ClientWizardStep::AllowedIps => &self.draft.allowed_ips,
            ClientWizardStep::Endpoint => &self.draft.endpoint,
        }
    }

    fn current_value_mut(&mut self) -> &mut String {
        match self.step {
            ClientWizardStep::Name => &mut self.draft.name,
            ClientWizardStep::PrivateKey => &mut self.draft.private_key,
            ClientWizardStep::Address => &mut self.draft.address,
            ClientWizardStep::Dns => &mut self.draft.dns,
            ClientWizardStep::PeerPublicKey => &mut self.draft.peer_public_key,
            ClientWizardStep::AllowedIps => &mut self.draft.allowed_ips,
            ClientWizardStep::Endpoint => &mut self.draft.endpoint,
        }
    }

    fn ui(&self) -> (String, &'static str, Option<String>) {
        let title = format!("New Tunnel (Client {}/7)", self.step.index());
        let (prompt, hint) = match self.step {
            ClientWizardStep::Name => ("Interface name:", Some("required".into())),
            ClientWizardStep::PrivateKey => ("Private key:", Some("required".into())),
            ClientWizardStep::Address => {
                ("Interface address:", Some("example: 10.0.0.2/32".into()))
            }
            ClientWizardStep::Dns => ("DNS (optional):", Some("comma-separated".into())),
            ClientWizardStep::PeerPublicKey => ("Peer public key:", Some("required".into())),
            ClientWizardStep::AllowedIps => {
                ("Peer allowed IPs:", Some("default: 0.0.0.0/0, ::/0".into()))
            }
            ClientWizardStep::Endpoint => ("Peer endpoint:", Some("host:port".into())),
        };
        (title, prompt, hint)
    }

    fn validate_current(&self) -> Option<String> {
        let value = self.current_value().trim();
        match self.step {
            ClientWizardStep::Name => {
                if value.is_empty() {
                    return Some("Interface name is required".into());
                }
                if value.chars().any(|c| c.is_whitespace() || c == '/') {
                    return Some("Interface name cannot contain spaces or '/'".into());
                }
            }
            ClientWizardStep::PrivateKey
            | ClientWizardStep::Address
            | ClientWizardStep::PeerPublicKey
            | ClientWizardStep::AllowedIps
            | ClientWizardStep::Endpoint => {
                if value.is_empty() {
                    return Some("Field is required".into());
                }
            }
            ClientWizardStep::Dns => {}
        }
        None
    }

    fn advance(&mut self) -> bool {
        if let Some(next) = self.step.next() {
            self.step = next;
            false
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerWizardStep {
    Name,
    Address,
    ListenPort,
    EgressInterface,
}

impl ServerWizardStep {
    fn next(self) -> Option<Self> {
        match self {
            Self::Name => Some(Self::Address),
            Self::Address => Some(Self::ListenPort),
            Self::ListenPort => Some(Self::EgressInterface),
            Self::EgressInterface => None,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Name => 1,
            Self::Address => 2,
            Self::ListenPort => 3,
            Self::EgressInterface => 4,
        }
    }
}

#[derive(Debug, Clone)]
struct NewServerWizard {
    step: ServerWizardStep,
    draft: NewServerDraft,
}

impl NewServerWizard {
    fn new(
        name: String,
        address: String,
        listen_port: String,
        private_key: String,
        egress_interface: String,
    ) -> Self {
        Self {
            step: ServerWizardStep::Name,
            draft: NewServerDraft {
                name,
                private_key,
                address,
                listen_port,
                egress_interface,
            },
        }
    }

    fn current_value(&self) -> &str {
        match self.step {
            ServerWizardStep::Name => &self.draft.name,
            ServerWizardStep::Address => &self.draft.address,
            ServerWizardStep::ListenPort => &self.draft.listen_port,
            ServerWizardStep::EgressInterface => &self.draft.egress_interface,
        }
    }

    fn current_value_mut(&mut self) -> &mut String {
        match self.step {
            ServerWizardStep::Name => &mut self.draft.name,
            ServerWizardStep::Address => &mut self.draft.address,
            ServerWizardStep::ListenPort => &mut self.draft.listen_port,
            ServerWizardStep::EgressInterface => &mut self.draft.egress_interface,
        }
    }

    fn ui(&self) -> (String, &'static str, Option<String>) {
        let title = format!("New Tunnel (Server {}/4)", self.step.index());
        let (prompt, hint) = match self.step {
            ServerWizardStep::Name => ("Interface name:", Some("required".into())),
            ServerWizardStep::Address => ("Server address:", Some("example: 10.0.0.1/32".into())),
            ServerWizardStep::ListenPort => ("Listen port:", Some("default: 51820".into())),
            ServerWizardStep::EgressInterface => {
                let hint = if self.draft.egress_interface.is_empty() {
                    "required".into()
                } else {
                    format!("detected: {}", self.draft.egress_interface)
                };
                ("Egress interface:", Some(hint))
            }
        };
        (title, prompt, hint)
    }

    fn validate_current(&self) -> Option<String> {
        let value = self.current_value().trim();
        match self.step {
            ServerWizardStep::Name => {
                if value.is_empty() {
                    return Some("Interface name is required".into());
                }
                if value.chars().any(|c| c.is_whitespace() || c == '/') {
                    return Some("Interface name cannot contain spaces or '/'".into());
                }
            }
            ServerWizardStep::Address
            | ServerWizardStep::ListenPort
            | ServerWizardStep::EgressInterface => {
                if value.is_empty() {
                    return Some("Field is required".into());
                }
            }
        }
        None
    }

    fn advance(&mut self) -> bool {
        if let Some(next) = self.step.next() {
            self.step = next;
            false
        } else {
            true
        }
    }
}

impl App {
    fn default_tunnel_name(&self) -> String {
        for i in 0..1000u32 {
            let name = format!("wg{i}");
            if !self.tunnels.iter().any(|t| t.name == name) {
                return name;
            }
        }
        "wg0".into()
    }
}
