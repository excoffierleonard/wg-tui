use std::{fs, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use qrcode::QrCode;
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
        render_full_tunnel_warning, render_help, render_input, render_peer_config, render_peer_qr,
        section, truncate_key,
    },
    wireguard::{
        add_server_peer, create_server_tunnel, create_tunnel, default_egress_interface,
        delete_tunnel, detect_public_ip, discover_tunnels, expand_path, export_tunnels_to_zip,
        generate_private_key, get_interface_info, import_tunnel, is_full_tunnel_config,
        is_interface_active, suggest_server_address, wg_quick,
    },
};

pub struct App {
    tunnels: Vec<Tunnel>,
    list_state: ListState,
    flags: AppFlags,
    confirm_full_tunnel: Option<String>,
    input_path: Option<String>,
    export_path: Option<String>,
    new_tunnel: Option<NewTunnelWizard>,
    pending_peer: Option<PendingPeerConfig>,
    peer_endpoint_input: Option<String>,
    peer_dns_input: Option<String>,
    peer_config: Option<PeerConfigState>,
    peer_save_path: Option<String>,
    message: Option<Message>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AppFlags {
    bits: u8,
}

impl AppFlags {
    const SHOW_DETAILS: u8 = 1 << 0;
    const SHOW_HELP: u8 = 1 << 1;
    const CONFIRM_DELETE: u8 = 1 << 2;
    const SHOW_ADD_MENU: u8 = 1 << 3;
    const SHOULD_QUIT: u8 = 1 << 4;

    fn show_details(self) -> bool {
        self.is_set(Self::SHOW_DETAILS)
    }

    fn show_help(self) -> bool {
        self.is_set(Self::SHOW_HELP)
    }

    fn confirm_delete(self) -> bool {
        self.is_set(Self::CONFIRM_DELETE)
    }

    fn show_add_menu(self) -> bool {
        self.is_set(Self::SHOW_ADD_MENU)
    }

    fn should_quit(self) -> bool {
        self.is_set(Self::SHOULD_QUIT)
    }

    fn set_show_help(&mut self, value: bool) {
        self.set(Self::SHOW_HELP, value);
    }

    fn set_confirm_delete(&mut self, value: bool) {
        self.set(Self::CONFIRM_DELETE, value);
    }

    fn set_show_add_menu(&mut self, value: bool) {
        self.set(Self::SHOW_ADD_MENU, value);
    }

    fn set_should_quit(&mut self, value: bool) {
        self.set(Self::SHOULD_QUIT, value);
    }

    fn toggle_show_details(&mut self) {
        self.toggle(Self::SHOW_DETAILS);
    }

    fn set(&mut self, flag: u8, value: bool) {
        if value {
            self.bits |= flag;
        } else {
            self.bits &= !flag;
        }
    }

    fn toggle(&mut self, flag: u8) {
        self.bits ^= flag;
    }

    fn is_set(self, flag: u8) -> bool {
        self.bits & flag != 0
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    #[must_use]
    pub fn new() -> Self {
        let mut app = Self {
            tunnels: Vec::new(),
            list_state: ListState::default(),
            flags: AppFlags::default(),
            confirm_full_tunnel: None,
            input_path: None,
            export_path: None,
            new_tunnel: None,
            pending_peer: None,
            peer_endpoint_input: None,
            peer_dns_input: None,
            peer_config: None,
            peer_save_path: None,
            message: None,
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

    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.flags.should_quit()
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
        let Some(i) = self.list_state.selected() else {
            return;
        };
        let max_index = self.tunnels.len().saturating_sub(1);
        let max_index = isize::try_from(max_index).unwrap_or(0);
        let current = isize::try_from(i).unwrap_or(0);
        let new = (current + delta).clamp(0, max_index);
        let new = usize::try_from(new).unwrap_or(0);
        self.list_state.select(Some(new));
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
            .is_some_and(|t| t.is_active);

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

    /// Polls for input events and dispatches them to the app.
    ///
    /// # Errors
    ///
    /// Returns an error if event polling or reading fails.
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

        self.handle_key(key);
        Ok(())
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        self.message = None;

        if self.consume_help() {
            return;
        }
        if self.consume_confirm_delete(key) {
            return;
        }
        if self.consume_confirm_full_tunnel(key) {
            return;
        }
        if self.consume_peer_save_path(key) {
            return;
        }
        if self.consume_import_path(key) {
            return;
        }
        if self.consume_export_path(key) {
            return;
        }
        if self.consume_peer_endpoint_input(key) {
            return;
        }
        if self.consume_peer_dns_input(key) {
            return;
        }
        if self.consume_new_tunnel_wizard(key) {
            return;
        }
        if self.consume_peer_config(key) {
            return;
        }
        if self.consume_add_menu(key) {
            return;
        }

        self.handle_global_key(key);
    }

    fn consume_help(&mut self) -> bool {
        if self.flags.show_help() {
            self.flags.set_show_help(false);
            return true;
        }
        false
    }

    fn consume_confirm_delete(&mut self, key: crossterm::event::KeyEvent) -> bool {
        if !self.flags.confirm_delete() {
            return false;
        }
        if let KeyCode::Char('y' | 'Y') = key.code {
            self.flags.set_confirm_delete(false);
            self.delete_selected();
        } else {
            self.flags.set_confirm_delete(false);
            self.message = Some(Message::Info("Delete cancelled".into()));
        }
        true
    }

    fn consume_confirm_full_tunnel(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref name) = self.confirm_full_tunnel else {
            return false;
        };
        if let KeyCode::Char('y' | 'Y') = key.code {
            let name = name.clone();
            self.confirm_full_tunnel = None;
            self.toggle_selected_with_name(&name);
        } else {
            self.confirm_full_tunnel = None;
            self.message = Some(Message::Info("Enable cancelled".into()));
        }
        true
    }

    fn consume_peer_save_path(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.peer_save_path else {
            return false;
        };
        match key.code {
            KeyCode::Enter => {
                let path_str = path.clone();
                self.peer_save_path = None;
                let Some(peer) = &self.peer_config else {
                    return true;
                };
                let dest = expand_path(&path_str);
                if dest.exists() {
                    self.message = Some(Message::Error("File already exists".into()));
                    return true;
                }
                match fs::write(&dest, &peer.config_text) {
                    Ok(()) => {
                        self.message = Some(Message::Success(format!(
                            "Peer config saved to {}",
                            dest.display()
                        )));
                    }
                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                }
            }
            KeyCode::Esc => {
                self.peer_save_path = None;
                self.message = Some(Message::Info("Save cancelled".into()));
            }
            KeyCode::Backspace => {
                path.pop();
            }
            KeyCode::Char(c) => {
                path.push(c);
            }
            _ => {}
        }
        true
    }

    fn consume_import_path(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.input_path else {
            return false;
        };
        match key.code {
            KeyCode::Enter => {
                let path_str = path.clone();
                self.input_path = None;
                match import_tunnel(&path_str) {
                    Ok(name) => {
                        self.message = Some(Message::Success(format!("Tunnel '{name}' imported")));
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
        true
    }

    fn consume_export_path(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.export_path else {
            return false;
        };
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
        true
    }

    fn consume_peer_endpoint_input(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut endpoint) = self.peer_endpoint_input else {
            return false;
        };
        match key.code {
            KeyCode::Enter => {
                let endpoint_str = endpoint.trim().to_string();
                if endpoint_str.is_empty() {
                    self.message = Some(Message::Error("Endpoint is required".into()));
                    return true;
                }
                if let Some(pending) = self.pending_peer.as_mut() {
                    pending.endpoint = endpoint_str;
                }
                self.peer_endpoint_input = None;
                self.peer_dns_input = Some(String::new());
            }
            KeyCode::Esc => {
                self.peer_endpoint_input = None;
                self.pending_peer = None;
                self.message = Some(Message::Info("Peer config cancelled".into()));
            }
            KeyCode::Backspace => {
                endpoint.pop();
            }
            KeyCode::Char(c) => {
                endpoint.push(c);
            }
            _ => {}
        }
        true
    }

    fn consume_peer_dns_input(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut dns) = self.peer_dns_input else {
            return false;
        };
        match key.code {
            KeyCode::Enter => {
                let dns_str = dns.trim().to_string();
                let Some(pending) = self.pending_peer.take() else {
                    self.peer_dns_input = None;
                    return true;
                };
                let dns_block = if dns_str.is_empty() {
                    String::new()
                } else {
                    format!("DNS = {dns_str}\n")
                };
                let config_text = pending
                    .template
                    .replace("__ENDPOINT__", &pending.endpoint)
                    .replace("__DNS_BLOCK__", &dns_block);
                self.peer_config = Some(PeerConfigState::new(config_text, pending.suggested_path));
                self.peer_dns_input = None;
            }
            KeyCode::Esc => {
                self.peer_dns_input = None;
                self.pending_peer = None;
                self.message = Some(Message::Info("Peer config cancelled".into()));
            }
            KeyCode::Backspace => {
                dns.pop();
            }
            KeyCode::Char(c) => {
                dns.push(c);
            }
            _ => {}
        }
        true
    }

    fn consume_new_tunnel_wizard(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut wizard) = self.new_tunnel else {
            return false;
        };
        match key.code {
            KeyCode::Enter => {
                let finished = {
                    if let Some(err) = wizard.validate_current() {
                        self.message = Some(Message::Error(err));
                        return true;
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
                                    self.message =
                                        Some(Message::Success(format!("Tunnel '{name}' created")));
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
                                    self.message =
                                        Some(Message::Success(format!("Tunnel '{name}' created")));
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
        true
    }

    fn consume_peer_config(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut peer) = self.peer_config else {
            return false;
        };
        match key.code {
            KeyCode::Char('s') => {
                self.peer_save_path = Some(peer.suggested_path.clone());
                peer.show_qr = false;
            }
            KeyCode::Char('q') => {
                if let Ok(code) = QrCode::new(peer.config_text.as_bytes()) {
                    peer.qr_code = Some(code);
                    peer.show_qr = true;
                } else {
                    peer.show_qr = false;
                    self.message = Some(Message::Error("QR data is too large".into()));
                }
            }
            KeyCode::Char('b') => {
                peer.show_qr = false;
            }
            KeyCode::Esc => {
                self.peer_config = None;
            }
            _ => {}
        }
        true
    }

    fn consume_add_menu(&mut self, key: crossterm::event::KeyEvent) -> bool {
        if !self.flags.show_add_menu() {
            return false;
        }
        match key.code {
            KeyCode::Char('i' | '1') => {
                self.flags.set_show_add_menu(false);
                self.input_path = Some(String::new());
            }
            KeyCode::Char('c' | '2') => {
                self.flags.set_show_add_menu(false);
                let name = self.default_tunnel_name();
                self.new_tunnel = Some(NewTunnelWizard::client(name));
            }
            KeyCode::Char('s' | '3') => {
                self.flags.set_show_add_menu(false);
                let name = self.default_tunnel_name();
                let address = suggest_server_address();
                let egress = default_egress_interface().unwrap_or_default();
                let private_key = match generate_private_key() {
                    Ok(key) => key,
                    Err(e) => {
                        self.message = Some(Message::Error(e.to_string()));
                        return true;
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
                self.flags.set_show_add_menu(false);
            }
            _ => {}
        }
        true
    }

    fn handle_global_key(&mut self, key: crossterm::event::KeyEvent) {
        match (key.code, key.modifiers) {
            (KeyCode::Char('q') | KeyCode::Esc, _) => self.flags.set_should_quit(true),
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                self.flags.set_should_quit(true);
            }
            (KeyCode::Char('j') | KeyCode::Down, _) => self.move_selection(1),
            (KeyCode::Char('k') | KeyCode::Up, _) => self.move_selection(-1),
            (KeyCode::Char('g'), _) => self.list_state.select(Some(0)),
            (KeyCode::Char('G'), _) => self
                .list_state
                .select(Some(self.tunnels.len().saturating_sub(1))),
            (KeyCode::Enter | KeyCode::Char(' '), _) => self.toggle_selected(),
            (KeyCode::Char('d'), _) => self.flags.toggle_show_details(),
            (KeyCode::Char('x'), _) => {
                if self.selected().is_some() {
                    self.flags.set_confirm_delete(true);
                }
            }
            (KeyCode::Char('a'), _) => self.flags.set_show_add_menu(true),
            (KeyCode::Char('p'), _) => {
                let Some(tunnel) = self.selected() else {
                    return;
                };
                match add_server_peer(&tunnel.name) {
                    Ok(peer) => {
                        let endpoint = detect_public_ip()
                            .map(|ip| format!("{ip}:{}", peer.listen_port))
                            .unwrap_or_default();
                        self.pending_peer = Some(PendingPeerConfig::new(
                            peer.client_config_template,
                            peer.suggested_filename,
                            endpoint.clone(),
                        ));
                        self.peer_endpoint_input = Some(endpoint);
                        self.message = Some(Message::Success("Peer added".into()));
                        self.refresh_tunnels();
                    }
                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                }
            }
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
            (KeyCode::Char('?'), _) => self.flags.set_show_help(true),
            _ => {}
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::horizontal(if self.flags.show_details() {
            vec![Constraint::Percentage(40), Constraint::Percentage(60)]
        } else {
            vec![Constraint::Percentage(100)]
        })
        .split(frame.area());

        self.render_main(frame, chunks[0]);
        if self.flags.show_details() && chunks.len() > 1 {
            self.render_details(frame, chunks[1]);
        }
        self.render_overlays(frame);
    }

    fn render_main(&mut self, frame: &mut Frame, area: Rect) {
        let main = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

        Self::render_header(frame, main[0]);
        self.render_list(frame, main[1]);
        self.render_status(frame, main[2]);
    }

    fn render_overlays(&mut self, frame: &mut Frame) {
        if self.flags.show_help() {
            render_help(frame);
        }
        if self.flags.confirm_delete()
            && let Some(tunnel) = self.selected()
        {
            render_confirm(frame, &tunnel.name);
        }
        if let Some(ref name) = self.confirm_full_tunnel {
            render_full_tunnel_warning(frame, name);
        }
        if self.flags.show_add_menu() {
            render_add_menu(frame);
        }
        self.render_path_inputs(frame);
        self.render_wizard_input(frame);
        self.render_peer_input(frame);
        self.render_peer_output(frame);
    }

    fn render_path_inputs(&mut self, frame: &mut Frame) {
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
    }

    fn render_wizard_input(&mut self, frame: &mut Frame) {
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

    fn render_peer_input(&mut self, frame: &mut Frame) {
        if let Some(ref endpoint) = self.peer_endpoint_input {
            render_input(
                frame,
                "Peer Endpoint",
                "Endpoint (host:port):",
                endpoint,
                Some("Confirm or edit the server address"),
            );
        }
        if let Some(ref dns) = self.peer_dns_input {
            render_input(
                frame,
                "Peer DNS",
                "DNS (optional):",
                dns,
                Some("Leave empty to skip"),
            );
        }
    }

    fn render_peer_output(&mut self, frame: &mut Frame) {
        if let Some(ref peer) = self.peer_config {
            if peer.show_qr {
                if let Some(code) = peer.qr_code.as_ref() {
                    render_peer_qr(frame, code);
                } else {
                    render_peer_config(frame, &peer.config_text, &peer.suggested_path);
                }
            } else {
                render_peer_config(frame, &peer.config_text, &peer.suggested_path);
            }
        }
        if let Some(ref path) = self.peer_save_path {
            render_input(
                frame,
                "Save Peer Config",
                "Destination (.conf):",
                path,
                Some("Press Enter to save"),
            );
        }
    }

    fn render_header(f: &mut Frame, area: Rect) {
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

#[derive(Clone)]
struct PeerConfigState {
    config_text: String,
    suggested_path: String,
    show_qr: bool,
    qr_code: Option<QrCode>,
}

impl PeerConfigState {
    fn new(config_text: String, suggested_path: String) -> Self {
        Self {
            config_text,
            suggested_path,
            show_qr: false,
            qr_code: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingPeerConfig {
    template: String,
    suggested_path: String,
    endpoint: String,
}

impl PendingPeerConfig {
    fn new(template: String, suggested_path: String, endpoint: String) -> Self {
        Self {
            template,
            suggested_path,
            endpoint,
        }
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
