# wg-tui

A terminal user interface for managing WireGuard VPN tunnels.

## Features

- List and manage WireGuard tunnels
- Start/stop tunnels with a single keypress
- View tunnel details (peers, endpoints, transfer statistics)
- Import tunnels from `.conf` files
- Export all tunnels to a zip archive
- Delete tunnels

## Requirements

- Linux
- WireGuard tools (`wg`, `wg-quick`)
- `ip` command (iproute2)
- Root privileges (the application will prompt for sudo if needed)

## Installation

### With Cargo

```bash
cargo install --path .
```

### For Linux

```bash
curl -fsSL https://raw.githubusercontent.com/excoffierleonard/wg-tui/main/scripts/install.sh | sh
```

## Usage

```bash
wg-tui
```

### Keybindings

| Key | Action |
|-----|--------|
| `j` / `Down` | Move selection down |
| `k` / `Up` | Move selection up |
| `Enter` / `Space` | Toggle tunnel (start/stop) |
| `d` | Toggle details panel |
| `a` | Add/import tunnel |
| `e` | Export all tunnels to zip |
| `x` | Delete selected tunnel |
| `r` | Refresh tunnel list |
| `g` | Jump to first tunnel |
| `G` | Jump to last tunnel |
| `?` | Show help |
| `q` / `Esc` | Quit |

## License

MIT License - see [LICENSE](LICENSE) for details.
