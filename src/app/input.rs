use std::{fs, path::Path, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use qrcode::QrCode;

use crate::{
    error::Error,
    types::Message,
    wireguard::{
        ImportConflictPolicy, add_server_peer, default_egress_interface, delete_tunnel,
        detect_public_ip, expand_path, export_tunnels_to_zip, generate_private_key, import_tunnel,
        import_tunnels, import_zip_conflict_count, is_full_tunnel_config, suggest_server_address,
        wg_quick,
    },
};

use super::{
    App,
    wizard::{NewTunnelWizard, PeerConfigState, PendingImport, PendingPeerConfig},
};

// ---------------------------------------------------------------------------
// Text input helper
// ---------------------------------------------------------------------------

enum InputAction {
    Submit,
    Cancel,
    Edited,
    Unhandled,
}

fn handle_text_input(key: &crossterm::event::KeyEvent, buffer: &mut String) -> InputAction {
    match key.code {
        KeyCode::Enter => InputAction::Submit,
        KeyCode::Esc => InputAction::Cancel,
        KeyCode::Backspace => {
            buffer.pop();
            InputAction::Edited
        }
        KeyCode::Char(c) => {
            buffer.push(c);
            InputAction::Edited
        }
        _ => InputAction::Unhandled,
    }
}

// ---------------------------------------------------------------------------
// Event handling
// ---------------------------------------------------------------------------

impl App {
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
        if self.consume_import_conflict_choice(key) {
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
        if self.consume_import_zip(key) {
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
        match handle_text_input(&key, path) {
            InputAction::Submit => {
                let dest = expand_path(path);
                self.peer_save_path = None;
                let Some(peer) = &self.peer_config else {
                    return true;
                };
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
            InputAction::Cancel => {
                self.peer_save_path = None;
                self.message = Some(Message::Info("Save cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_import_path(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.input_path else {
            return false;
        };
        match handle_text_input(&key, path) {
            InputAction::Submit => {
                let resolved = expand_path(path);
                self.input_path = None;
                match import_tunnel(&resolved) {
                    Ok(name) => {
                        self.message = Some(Message::Success(format!("Tunnel '{name}' imported")));
                        self.refresh_tunnels();
                    }
                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                }
            }
            InputAction::Cancel => {
                self.input_path = None;
                self.message = Some(Message::Info("Import cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_import_zip(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.input_zip else {
            return false;
        };
        match handle_text_input(&key, path) {
            InputAction::Submit => {
                let resolved = expand_path(path);
                self.input_zip = None;
                match import_zip_conflict_count(&resolved) {
                    Ok(conflicts) if conflicts > 0 => {
                        self.pending_import = Some(PendingImport {
                            path: resolved,
                            conflicts,
                        });
                    }
                    Ok(_) => self.finish_import(&resolved, ImportConflictPolicy::SkipConflicts),
                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                }
            }
            InputAction::Cancel => {
                self.input_zip = None;
                self.message = Some(Message::Info("Import cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_import_conflict_choice(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(pending) = self.pending_import.take() else {
            return false;
        };

        match key.code {
            KeyCode::Char('y' | 'Y') => {
                self.finish_import(&pending.path, ImportConflictPolicy::AutoRename);
            }
            KeyCode::Char('n' | 'N') => {
                self.finish_import(&pending.path, ImportConflictPolicy::SkipConflicts);
            }
            _ => {
                self.message = Some(Message::Info("Import cancelled".into()));
            }
        }

        true
    }

    fn consume_export_path(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut path) = self.export_path else {
            return false;
        };
        match handle_text_input(&key, path) {
            InputAction::Submit => {
                let dest = expand_path(path);
                self.export_path = None;
                match export_tunnels_to_zip(&dest) {
                    Ok(()) => {
                        self.message = Some(Message::Success(format!(
                            "Exported {} tunnels to {}",
                            self.tunnels.len(),
                            dest.display()
                        )));
                    }
                    Err(e) => self.message = Some(Message::Error(e.to_string())),
                }
            }
            InputAction::Cancel => {
                self.export_path = None;
                self.message = Some(Message::Info("Export cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_peer_endpoint_input(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut endpoint) = self.peer_endpoint_input else {
            return false;
        };
        match handle_text_input(&key, endpoint) {
            InputAction::Submit => {
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
            InputAction::Cancel => {
                self.peer_endpoint_input = None;
                self.pending_peer = None;
                self.message = Some(Message::Info("Peer config cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_peer_dns_input(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut dns) = self.peer_dns_input else {
            return false;
        };
        match handle_text_input(&key, dns) {
            InputAction::Submit => {
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
            InputAction::Cancel => {
                self.peer_dns_input = None;
                self.pending_peer = None;
                self.message = Some(Message::Info("Peer config cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
        }
        true
    }

    fn consume_new_tunnel_wizard(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(ref mut wizard) = self.new_tunnel else {
            return false;
        };
        match handle_text_input(&key, wizard.current_value_mut()) {
            InputAction::Submit => {
                if let Some(err) = wizard.validate_current() {
                    self.message = Some(Message::Error(err));
                    return true;
                }
                let finished = wizard.advance();
                if finished {
                    let wizard = self.new_tunnel.take().unwrap();
                    match wizard.create() {
                        Ok(name) => {
                            self.message =
                                Some(Message::Success(format!("Tunnel '{name}' created")));
                            self.refresh_tunnels();
                        }
                        Err(e) => self.message = Some(Message::Error(e.to_string())),
                    }
                }
            }
            InputAction::Cancel => {
                self.new_tunnel = None;
                self.message = Some(Message::Info("Create cancelled".into()));
            }
            InputAction::Edited | InputAction::Unhandled => {}
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
            KeyCode::Char('z' | '2') => {
                self.flags.set_show_add_menu(false);
                self.input_zip = Some(String::new());
            }
            KeyCode::Char('c' | '3') => {
                self.flags.set_show_add_menu(false);
                let name = self.default_tunnel_name();
                self.new_tunnel = Some(NewTunnelWizard::client(name));
            }
            KeyCode::Char('s' | '4') => {
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

    pub(super) fn toggle_selected(&mut self) {
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

    pub(super) fn toggle_selected_with_name(&mut self, name: &str) {
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

    pub(super) fn delete_selected(&mut self) {
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

    fn finish_import(&mut self, path: &Path, policy: ImportConflictPolicy) {
        match import_tunnels(path, policy) {
            Ok(count) => {
                self.message = Some(Message::Success(format!("{count} Tunnel(s) imported")));
                self.refresh_tunnels();
            }
            Err(e) => self.message = Some(Message::Error(e.to_string())),
        }
    }
}
