mod input;
mod render;
mod wizard;

use ratatui::widgets::ListState;

use crate::{
    types::{Message, Tunnel},
    wireguard::{discover_tunnels, get_interface_info, is_interface_active},
};

use wizard::{NewTunnelWizard, PeerConfigState, PendingImport, PendingPeerConfig};

pub struct App {
    pub(crate) tunnels: Vec<Tunnel>,
    pub(crate) list_state: ListState,
    pub(crate) flags: AppFlags,
    pub(crate) confirm_full_tunnel: Option<String>,
    pub(crate) input_path: Option<String>,
    pub(crate) input_zip: Option<String>,
    pub(crate) export_path: Option<String>,
    pub(crate) pending_import: Option<PendingImport>,
    pub(crate) new_tunnel: Option<NewTunnelWizard>,
    pub(crate) pending_peer: Option<PendingPeerConfig>,
    pub(crate) peer_endpoint_input: Option<String>,
    pub(crate) peer_dns_input: Option<String>,
    pub(crate) peer_config: Option<PeerConfigState>,
    pub(crate) peer_save_path: Option<String>,
    pub(crate) message: Option<Message>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AppFlags {
    bits: u8,
}

impl AppFlags {
    const SHOW_DETAILS: u8 = 1 << 0;
    const SHOW_HELP: u8 = 1 << 1;
    const CONFIRM_DELETE: u8 = 1 << 2;
    const SHOW_ADD_MENU: u8 = 1 << 3;
    const SHOULD_QUIT: u8 = 1 << 4;

    pub fn show_details(self) -> bool {
        self.is_set(Self::SHOW_DETAILS)
    }

    pub fn show_help(self) -> bool {
        self.is_set(Self::SHOW_HELP)
    }

    pub fn confirm_delete(self) -> bool {
        self.is_set(Self::CONFIRM_DELETE)
    }

    pub fn show_add_menu(self) -> bool {
        self.is_set(Self::SHOW_ADD_MENU)
    }

    pub fn should_quit(self) -> bool {
        self.is_set(Self::SHOULD_QUIT)
    }

    pub fn set_show_help(&mut self, value: bool) {
        self.set(Self::SHOW_HELP, value);
    }

    pub fn set_confirm_delete(&mut self, value: bool) {
        self.set(Self::CONFIRM_DELETE, value);
    }

    pub fn set_show_add_menu(&mut self, value: bool) {
        self.set(Self::SHOW_ADD_MENU, value);
    }

    pub fn set_should_quit(&mut self, value: bool) {
        self.set(Self::SHOULD_QUIT, value);
    }

    pub fn toggle_show_details(&mut self) {
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
            input_zip: None,
            export_path: None,
            pending_import: None,
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

    pub(crate) fn clamp_selection(&mut self) {
        let selected = match (self.list_state.selected(), self.tunnels.len()) {
            (_, 0) => None,
            (None | Some(0), _) => Some(0),
            (Some(i), len) => Some(i.min(len - 1)),
        };
        self.list_state.select(selected);
    }

    pub(crate) fn selected(&self) -> Option<&Tunnel> {
        self.list_state.selected().and_then(|i| self.tunnels.get(i))
    }

    pub(crate) fn move_selection(&mut self, delta: isize) {
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

    pub(crate) fn default_tunnel_name(&self) -> String {
        for i in 0..1000u32 {
            let name = format!("wg{i}");
            if !self.tunnels.iter().any(|t| t.name == name) {
                return name;
            }
        }
        "wg0".into()
    }
}
