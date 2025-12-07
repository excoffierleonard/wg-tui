# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

wg-tui is a WireGuard Terminal User Interface Manager written in Rust. It provides an interactive TUI for managing WireGuard tunnels from the command line.

**Requirements**: Root access (auto-elevates with sudo), WireGuard CLI tools (`wg`, `wg-quick`), Linux.

**Note**: Uses Rust 2024 edition.

## Build Commands

```bash
cargo build              # Development build
cargo build --release    # Optimized release build
cargo run                # Build and run (will prompt for sudo)
cargo check              # Type check without building
cargo fmt                # Format code
cargo clippy             # Lint code
cargo test               # Run tests
```

## Architecture

The application follows an MVC-like pattern with a poll-based event loop:

```text
main.rs        → Entry point, root privilege check, terminal setup
app.rs         → Application state, event handling, main UI rendering
ui.rs          → Reusable UI components and rendering helpers
wireguard.rs   → WireGuard CLI integration (wg, wg-quick, ip commands)
types.rs       → Domain models (Tunnel, InterfaceInfo, PeerInfo, Message)
error.rs       → Custom Error enum using thiserror
lib.rs         → Public API exports
```

**Data Flow**: `main.rs` initializes the `App` struct → `App::handle_events()` processes keyboard input → state updates → `App::draw()` renders the UI using ratatui.

## Key Dependencies

- **ratatui**: TUI framework for terminal rendering
- **crossterm**: Cross-platform terminal control
- **color-eyre**: Enhanced error handling (in main.rs)
- **thiserror**: Derive macros for custom Error type
- **nix**: Unix system calls (used for root privilege detection via `geteuid()`)

## Module Responsibilities

- **app.rs**: Central state machine. Manages tunnel list, selection state, UI panel toggles (details, help, add menu, confirm dialogs), input mode for importing tunnels, and keyboard event handling. Contains the main draw loop.

- **wireguard.rs**: System integration layer. Key functions:
  - `discover_tunnels()` - scans `/etc/wireguard/*.conf`
  - `is_interface_active()` - checks via `ip link show`
  - `get_interface_info()` - parses `wg show` output
  - `wg_quick()` - executes up/down commands
  - `import_tunnel()` / `delete_tunnel()` - file operations

- **ui.rs**: Stateless rendering functions for reusable widgets (`bordered_block`, `label`, `section`) and modal dialogs (`render_help`, `render_confirm`, `render_add_menu`, `render_input`). Also provides `centered_rect()` for dialog positioning.

- **types.rs**: Domain types. `Tunnel` tracks config path and runtime status, `InterfaceInfo` holds interface details with peers, `Message` enum for styled status messages (Info/Success/Error).

- **error.rs**: Custom `Error` enum with `Io` and `WgTui` variants using thiserror derive.

## Conventions

- Use custom `Error` type from `error.rs` for fallible operations in the library
- WireGuard config directory is `/etc/wireguard` (constant `CONFIG_DIR`)
- Active interfaces shown with `●`, inactive with `○`
- Keys are truncated to first 8 + "…" + last 8 characters for display
- Path expansion supports `~/` for home directory in import paths
