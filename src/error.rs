use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Invalid interface name: {reason}")]
    InvalidInterfaceName { reason: &'static str },

    #[error("Tunnel '{name}' already exists")]
    TunnelAlreadyExists { name: String },

    #[error("Config error: {0}")]
    Config(String),

    #[error("Command failed: {command}: {detail}")]
    CommandFailed {
        command: &'static str,
        detail: String,
    },

    #[error("{0}")]
    Validation(String),

    #[error("{0}")]
    Import(String),

    #[error("No tunnels to export")]
    NoTunnelsToExport,
}
