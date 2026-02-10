use qrcode::QrCode;

use crate::{
    error::Error,
    types::{NewServerDraft, NewTunnelDraft},
    wireguard::{create_server_tunnel, create_tunnel},
};

// ---------------------------------------------------------------------------
// Wizard trait
// ---------------------------------------------------------------------------

pub(crate) trait WizardSteps {
    fn current_value(&self) -> &str;
    fn current_value_mut(&mut self) -> &mut String;
    fn ui(&self) -> (String, &'static str, Option<String>);
    fn validate_current(&self) -> Option<String>;
    /// Returns `true` when the wizard is finished (all steps complete).
    fn advance(&mut self) -> bool;
}

// ---------------------------------------------------------------------------
// Tunnel wizard enum (dispatches to Client / Server)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) enum NewTunnelWizard {
    Client(NewClientWizard),
    Server(NewServerWizard),
}

impl NewTunnelWizard {
    pub fn client(name: String) -> Self {
        Self::Client(NewClientWizard::new(name))
    }

    pub fn server(
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

    fn as_steps(&self) -> &dyn WizardSteps {
        match self {
            Self::Client(w) => w,
            Self::Server(w) => w,
        }
    }

    fn as_steps_mut(&mut self) -> &mut dyn WizardSteps {
        match self {
            Self::Client(w) => w,
            Self::Server(w) => w,
        }
    }

    pub fn current_value(&self) -> &str {
        self.as_steps().current_value()
    }

    pub fn current_value_mut(&mut self) -> &mut String {
        self.as_steps_mut().current_value_mut()
    }

    pub fn ui(&self) -> (String, &'static str, Option<String>) {
        self.as_steps().ui()
    }

    pub fn validate_current(&self) -> Option<String> {
        self.as_steps().validate_current()
    }

    pub fn advance(&mut self) -> bool {
        self.as_steps_mut().advance()
    }

    /// Creates the tunnel and returns its name on success.
    pub fn create(self) -> Result<String, Error> {
        match self {
            Self::Client(w) => {
                create_tunnel(&w.draft)?;
                Ok(w.draft.name)
            }
            Self::Server(w) => {
                create_server_tunnel(&w.draft)?;
                Ok(w.draft.name)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client wizard
// ---------------------------------------------------------------------------

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
pub(crate) struct NewClientWizard {
    step: ClientWizardStep,
    pub draft: NewTunnelDraft,
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
}

impl WizardSteps for NewClientWizard {
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
            ClientWizardStep::Name => validate_interface_name_input(value),
            ClientWizardStep::PrivateKey
            | ClientWizardStep::Address
            | ClientWizardStep::PeerPublicKey
            | ClientWizardStep::AllowedIps
            | ClientWizardStep::Endpoint => {
                if value.is_empty() {
                    return Some("Field is required".into());
                }
                None
            }
            ClientWizardStep::Dns => None,
        }
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

// ---------------------------------------------------------------------------
// Server wizard
// ---------------------------------------------------------------------------

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
pub(crate) struct NewServerWizard {
    step: ServerWizardStep,
    pub draft: NewServerDraft,
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
}

impl WizardSteps for NewServerWizard {
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
            ServerWizardStep::Name => validate_interface_name_input(value),
            ServerWizardStep::Address
            | ServerWizardStep::ListenPort
            | ServerWizardStep::EgressInterface => {
                if value.is_empty() {
                    return Some("Field is required".into());
                }
                None
            }
        }
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

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct PeerConfigState {
    pub config_text: String,
    pub suggested_path: String,
    pub show_qr: bool,
    pub qr_code: Option<QrCode>,
}

impl PeerConfigState {
    pub fn new(config_text: String, suggested_path: String) -> Self {
        Self {
            config_text,
            suggested_path,
            show_qr: false,
            qr_code: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingPeerConfig {
    pub template: String,
    pub suggested_path: String,
    pub endpoint: String,
}

impl PendingPeerConfig {
    pub fn new(template: String, suggested_path: String, endpoint: String) -> Self {
        Self {
            template,
            suggested_path,
            endpoint,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingImport {
    pub path: std::path::PathBuf,
    pub conflicts: u32,
}

// ---------------------------------------------------------------------------
// Shared validation helper
// ---------------------------------------------------------------------------

fn validate_interface_name_input(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("Interface name is required".into());
    }
    if value.chars().any(|c| c.is_whitespace() || c == '/') {
        return Some("Interface name cannot contain spaces or '/'".into());
    }
    None
}
