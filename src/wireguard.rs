use std::{
    collections::HashSet,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Command,
};

use zip::{ZipWriter, write::SimpleFileOptions};

use crate::{
    error::Error,
    types::{InterfaceInfo, NewServerDraft, NewTunnelDraft, PeerConfig, PeerInfo, Tunnel},
};

const CONFIG_DIR: &str = "/etc/wireguard";

const CMD_WG: &str = "wg";
const CMD_WG_QUICK: &str = "wg-quick";
const CMD_IP: &str = "ip";
const CMD_CURL: &str = "curl";
const CMD_WGET: &str = "wget";
const ENDPOINT_PLACEHOLDER: &str = "__ENDPOINT__";
const DNS_BLOCK_PLACEHOLDER: &str = "__DNS_BLOCK__";

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;

/// Checks if required WireGuard dependencies are installed.
/// Returns a list of missing commands.
pub fn check_dependencies() -> Vec<&'static str> {
    [CMD_WG, CMD_WG_QUICK, CMD_IP]
        .into_iter()
        .filter(|cmd| !command_exists(cmd))
        .collect()
}

fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

pub fn detect_public_ip() -> Option<String> {
    let output = if command_exists(CMD_CURL) {
        Command::new(CMD_CURL)
            .args(["-fsSL", "https://api.ipify.org"])
            .output()
            .ok()?
    } else if command_exists(CMD_WGET) {
        Command::new(CMD_WGET)
            .args(["-qO-", "https://api.ipify.org"])
            .output()
            .ok()?
    } else {
        return None;
    };

    if !output.status.success() {
        return None;
    }
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.parse::<IpAddr>().is_ok() {
        Some(ip)
    } else {
        None
    }
}

pub fn discover_tunnels() -> Vec<Tunnel> {
    let Ok(entries) = fs::read_dir(Path::new(CONFIG_DIR)) else {
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

pub fn generate_private_key() -> Result<String, Error> {
    let output = Command::new(CMD_WG).arg("genkey").output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        return Err(Error::WgTui(if msg.is_empty() {
            "wg genkey failed".into()
        } else {
            msg.to_string()
        }));
    }
    let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if key.is_empty() {
        return Err(Error::WgTui("wg genkey returned an empty key".into()));
    }
    Ok(key)
}

pub fn derive_public_key(private_key: &str) -> Result<String, Error> {
    let mut child = Command::new(CMD_WG)
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(private_key.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        return Err(Error::WgTui(if msg.is_empty() {
            "wg pubkey failed".into()
        } else {
            msg.to_string()
        }));
    }
    let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if key.is_empty() {
        return Err(Error::WgTui("wg pubkey returned an empty key".into()));
    }
    Ok(key)
}

pub fn generate_keypair() -> Result<(String, String), Error> {
    let private = generate_private_key()?;
    let public = derive_public_key(&private)?;
    Ok((private, public))
}

pub fn default_egress_interface() -> Option<String> {
    let outputs = [
        Command::new(CMD_IP)
            .args(["-4", "route", "show", "default"])
            .output()
            .ok(),
        Command::new(CMD_IP)
            .args(["route", "show", "default"])
            .output()
            .ok(),
    ];

    for output in outputs.into_iter().flatten() {
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(dev) = parse_default_route_dev(&stdout) {
            return Some(dev);
        }
    }
    None
}

fn parse_default_route_dev(output: &str) -> Option<String> {
    for line in output.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                return parts.next().map(str::to_string);
            }
        }
    }
    None
}

pub fn suggest_server_address() -> String {
    let used = used_interface_ipv4_addresses();
    for i in 0u8..=255 {
        let candidate = Ipv4Addr::new(10, 0, i, 1);
        if !used.contains(&candidate) {
            return format!("{candidate}/32");
        }
    }
    "10.0.0.1/32".into()
}

fn used_interface_ipv4_addresses() -> HashSet<Ipv4Addr> {
    let mut used = HashSet::new();
    for tunnel in discover_tunnels() {
        if let Ok(content) = fs::read_to_string(&tunnel.config_path) {
            for addr in parse_interface_addresses(&content) {
                if let Some(ip) = parse_ipv4_address(&addr) {
                    used.insert(ip);
                }
            }
        }
    }
    used
}

fn parse_interface_addresses(content: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let mut in_interface = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("Address") {
            addrs.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string),
            );
        }
    }

    addrs
}

fn parse_interface_value(content: &str, key: &str) -> Option<String> {
    let mut in_interface = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn parse_ipv4_address(value: &str) -> Option<Ipv4Addr> {
    let value = value.trim();
    let ip = value.split_once('/').map(|(ip, _)| ip).unwrap_or(value);
    ip.parse().ok()
}

pub fn is_interface_active(name: &str) -> bool {
    Command::new(CMD_IP)
        .arg("link")
        .arg("show")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

pub fn get_interface_info(name: &str) -> Option<InterfaceInfo> {
    let output = Command::new(CMD_WG).arg("show").arg(name).output().ok()?;

    output
        .status
        .success()
        .then(|| parse_wg_output(&String::from_utf8_lossy(&output.stdout)))
}

pub fn wg_quick(action: &str, name: &str) -> Result<(), Error> {
    let output = Command::new(CMD_WG_QUICK).arg(action).arg(name).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        return Err(Error::WgTui(if msg.is_empty() {
            format!("wg-quick {action} failed")
        } else {
            msg.to_string()
        }));
    }

    Ok(())
}

fn sync_interface_with_content(name: &str, content: &str) -> Result<(), Error> {
    let temp_dir = std::env::temp_dir();
    let temp_conf = temp_dir.join(format!("wg-tui-{name}.conf"));
    let temp_stripped = temp_dir.join(format!("wg-tui-{name}.stripped"));

    fs::write(&temp_conf, content)?;

    let strip_output = Command::new(CMD_WG_QUICK)
        .arg("strip")
        .arg(&temp_conf)
        .output()?;
    if !strip_output.status.success() {
        let stderr = String::from_utf8_lossy(&strip_output.stderr);
        let msg = stderr.trim();
        return Err(Error::WgTui(if msg.is_empty() {
            "wg-quick strip failed".into()
        } else {
            msg.to_string()
        }));
    }

    fs::write(&temp_stripped, &strip_output.stdout)?;

    let sync_output = Command::new(CMD_WG)
        .arg("syncconf")
        .arg(name)
        .arg(&temp_stripped)
        .output()?;
    if !sync_output.status.success() {
        let stderr = String::from_utf8_lossy(&sync_output.stderr);
        let msg = stderr.trim();
        return Err(Error::WgTui(if msg.is_empty() {
            "wg syncconf failed".into()
        } else {
            msg.to_string()
        }));
    }

    let _ = fs::remove_file(temp_conf);
    let _ = fs::remove_file(temp_stripped);
    Ok(())
}

pub fn delete_tunnel(name: &str, is_active: bool) -> Result<(), Error> {
    if is_active {
        wg_quick("down", name)?;
    }
    let path = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    fs::remove_file(path)?;
    Ok(())
}

pub fn expand_path(path: &str) -> PathBuf {
    let path = path.trim();
    PathBuf::from(shellexpand::tilde(path).into_owned())
}

pub fn import_tunnel(source_path: &str) -> Result<String, Error> {
    let source = expand_path(source_path);

    if !source.exists() {
        return Err(Error::WgTui("Source file does not exist".into()));
    }

    let extension = source.extension().and_then(|e| e.to_str());
    if extension != Some("conf") {
        return Err(Error::WgTui("File must have .conf extension".into()));
    }

    let name = source
        .file_stem()
        .and_then(|n| n.to_str())
        .ok_or(Error::WgTui(
            "Could not determine tunnel name from file".into(),
        ))?
        .to_string();

    let dest = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    if dest.exists() {
        return Err(Error::WgTui(format!("Tunnel '{name}' already exists")));
    }

    fs::copy(&source, &dest)?;
    Ok(name)
}

pub fn export_tunnels_to_zip(dest_path: &str) -> Result<PathBuf, Error> {
    let dest = expand_path(dest_path);

    let tunnels = discover_tunnels();
    if tunnels.is_empty() {
        return Err(Error::WgTui("No tunnels to export".into()));
    }

    let file = fs::File::create(&dest)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for tunnel in &tunnels {
        let content = fs::read_to_string(&tunnel.config_path)?;
        let filename = format!("{}.conf", tunnel.name);
        zip.start_file(&filename, options)?;
        zip.write_all(content.as_bytes())?;
    }

    zip.finish()?;

    Ok(dest)
}

pub fn is_full_tunnel_config(name: &str) -> bool {
    let path = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };

    content.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if key.trim().eq_ignore_ascii_case("AllowedIPs") {
            return value
                .split(',')
                .map(str::trim)
                .any(|v| v == "0.0.0.0/0" || v == "::/0");
        }
        false
    })
}

pub fn create_tunnel(draft: &NewTunnelDraft) -> Result<(), Error> {
    let name = draft.name.trim();
    if name.is_empty() {
        return Err(Error::WgTui("Interface name is required".into()));
    }
    if name.chars().any(|c| c.is_whitespace() || c == '/') {
        return Err(Error::WgTui(
            "Interface name cannot contain spaces or '/'".into(),
        ));
    }

    let private_key = draft.private_key.trim();
    let address = draft.address.trim();
    let peer_public_key = draft.peer_public_key.trim();
    let allowed_ips = normalize_list(&draft.allowed_ips);
    let endpoint = draft.endpoint.trim();

    if private_key.is_empty()
        || address.is_empty()
        || peer_public_key.is_empty()
        || allowed_ips.is_empty()
        || endpoint.is_empty()
    {
        return Err(Error::WgTui("Missing required fields".into()));
    }

    fs::create_dir_all(CONFIG_DIR)?;

    let path = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    if path.exists() {
        return Err(Error::WgTui(format!("Tunnel '{name}' already exists")));
    }

    let dns = normalize_list(&draft.dns);

    let mut content = String::new();
    content.push_str("[Interface]\n");
    content.push_str(&format!("PrivateKey = {private_key}\n"));
    content.push_str(&format!("Address = {address}\n"));
    if !dns.is_empty() {
        content.push_str(&format!("DNS = {dns}\n"));
    }
    content.push('\n');
    content.push_str("[Peer]\n");
    content.push_str(&format!("PublicKey = {peer_public_key}\n"));
    content.push_str(&format!("AllowedIPs = {allowed_ips}\n"));
    content.push_str(&format!("Endpoint = {endpoint}\n"));

    fs::write(path, content)?;
    Ok(())
}

pub fn create_server_tunnel(draft: &NewServerDraft) -> Result<(), Error> {
    let name = draft.name.trim();
    if name.is_empty() {
        return Err(Error::WgTui("Interface name is required".into()));
    }
    if name.chars().any(|c| c.is_whitespace() || c == '/') {
        return Err(Error::WgTui(
            "Interface name cannot contain spaces or '/'".into(),
        ));
    }

    let private_key = draft.private_key.trim();
    let address = draft.address.trim();
    let listen_port = draft.listen_port.trim();
    let egress_interface = draft.egress_interface.trim();

    if private_key.is_empty()
        || address.is_empty()
        || listen_port.is_empty()
        || egress_interface.is_empty()
    {
        return Err(Error::WgTui("Missing required fields".into()));
    }

    let listen_port: u16 = listen_port
        .parse()
        .map_err(|_| Error::WgTui("Listen port must be a valid number".into()))?;

    fs::create_dir_all(CONFIG_DIR)?;

    let path = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    if path.exists() {
        return Err(Error::WgTui(format!("Tunnel '{name}' already exists")));
    }

    let post_up = format!(
        "iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {egress_interface} -j MASQUERADE"
    );
    let post_down = format!(
        "iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {egress_interface} -j MASQUERADE"
    );

    let mut content = String::new();
    content.push_str("[Interface]\n");
    content.push_str(&format!("Address = {address}\n"));
    content.push_str("SaveConfig = true\n");
    content.push_str(&format!("PostUp = {post_up}\n"));
    content.push_str(&format!("PostDown = {post_down}\n"));
    content.push_str(&format!("ListenPort = {listen_port}\n"));
    content.push_str(&format!("PrivateKey = {private_key}\n"));

    fs::write(path, content)?;
    Ok(())
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

fn normalize_list(value: &str) -> String {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
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

fn parse_peer_allowed_ips(content: &str) -> Vec<String> {
    let mut in_peer = false;
    let mut allowed = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_peer = line.eq_ignore_ascii_case("[Peer]");
            continue;
        }
        if !in_peer {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("AllowedIPs") {
            allowed.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string),
            );
        }
    }

    allowed
}

fn is_server_config(content: &str) -> bool {
    let mut in_interface = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.eq_ignore_ascii_case("PostUp")
            || key.eq_ignore_ascii_case("PostDown")
            || key.eq_ignore_ascii_case("SaveConfig")
        {
            return true;
        }
    }
    false
}

fn next_peer_ipv4(base: Ipv4Addr, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    let [a, b, c, d] = base.octets();
    for step in 1u8..=253 {
        let candidate = d.wrapping_add(step);
        if candidate == 0 || candidate == 255 {
            continue;
        }
        let ip = Ipv4Addr::new(a, b, c, candidate);
        if !used.contains(&ip) {
            return Some(ip);
        }
    }
    None
}

pub fn add_server_peer(name: &str) -> Result<PeerConfig, Error> {
    let path = Path::new(CONFIG_DIR).join(format!("{name}.conf"));
    let content = fs::read_to_string(&path)
        .map_err(|_| Error::WgTui(format!("Could not read config for tunnel '{name}'")))?;

    if !is_server_config(&content) {
        return Err(Error::WgTui(
            "Selected tunnel is not a server config".into(),
        ));
    }

    let address = parse_interface_addresses(&content)
        .into_iter()
        .find(|addr| parse_ipv4_address(addr).is_some())
        .ok_or_else(|| Error::WgTui("Server config has no IPv4 address".into()))?;
    let base_ip = parse_ipv4_address(&address)
        .ok_or_else(|| Error::WgTui("Server IPv4 address is invalid".into()))?;

    let private_key = parse_interface_value(&content, "PrivateKey")
        .ok_or_else(|| Error::WgTui("Server config missing PrivateKey".into()))?;
    let listen_port = parse_interface_value(&content, "ListenPort")
        .ok_or_else(|| Error::WgTui("Server config missing ListenPort".into()))?;
    let listen_port: u16 = listen_port
        .parse()
        .map_err(|_| Error::WgTui("Listen port must be a valid number".into()))?;

    let mut used = HashSet::new();
    used.insert(base_ip);
    for allowed in parse_peer_allowed_ips(&content) {
        if let Some(ip) = parse_ipv4_address(&allowed) {
            used.insert(ip);
        }
    }

    let peer_ip = next_peer_ipv4(base_ip, &used)
        .ok_or_else(|| Error::WgTui("No available peer address in the server /24".into()))?;
    let peer_address = format!("{peer_ip}/32");

    let (peer_private_key, peer_public_key) = generate_keypair()?;
    let server_public_key = derive_public_key(&private_key)?;

    let mut new_content = content.clone();
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push('\n');
    new_content.push_str("[Peer]\n");
    new_content.push_str(&format!("PublicKey = {peer_public_key}\n"));
    new_content.push_str(&format!("AllowedIPs = {peer_address}\n"));
    if is_interface_active(name) {
        sync_interface_with_content(name, &new_content)?;
    }
    fs::write(&path, new_content)?;

    let client_config = format!(
        "[Interface]\nPrivateKey = {peer_private_key}\nAddress = {peer_address}\n{DNS_BLOCK_PLACEHOLDER}\n[Peer]\nPublicKey = {server_public_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ENDPOINT_PLACEHOLDER}\n"
    );

    Ok(PeerConfig {
        client_config_template: client_config,
        suggested_filename: format!("{name}-peer-{peer_ip}.conf"),
        listen_port,
    })
}
