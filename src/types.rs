use std::path::PathBuf;

use ratatui::style::{Color, Style};

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

#[derive(Debug, Clone)]
pub struct NewTunnelDraft {
    pub name: String,
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub peer_public_key: String,
    pub allowed_ips: String,
    pub endpoint: String,
}

#[derive(Debug, Clone)]
pub struct NewServerDraft {
    pub name: String,
    pub private_key: String,
    pub address: String,
    pub listen_port: String,
    pub egress_interface: String,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub client_config_template: String,
    pub suggested_filename: String,
    pub listen_port: u16,
}

#[derive(Clone)]
pub enum Message {
    Info(String),
    Success(String),
    Error(String),
}

impl Message {
    #[must_use]
    pub fn style(&self) -> Style {
        Style::default().fg(match self {
            Self::Info(_) => Color::Blue,
            Self::Success(_) => Color::Green,
            Self::Error(_) => Color::Red,
        })
    }

    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Info(s) | Self::Success(s) | Self::Error(s) => s,
        }
    }
}
