use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Text},
    widgets::{List, ListItem, Paragraph, Wrap},
};

use crate::ui::{
    bordered_block, label, peer_lines, render_add_menu, render_confirm, render_full_tunnel_warning,
    render_help, render_import_conflict, render_input, render_peer_config, render_peer_qr, section,
    truncate_key,
};

use super::App;

impl App {
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
        if let Some(ref pending) = self.pending_import {
            render_import_conflict(frame, pending.conflicts);
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
        if let Some(ref path) = self.input_zip {
            let cwd = std::env::current_dir()
                .map(|p| format!("cwd: {}  (use ~/ for home)", p.display()))
                .ok();
            render_input(
                frame,
                "Import Zip",
                "Zip path (.zip):",
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
