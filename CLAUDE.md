# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

wg-tui is a WireGuard Terminal User Interface Manager written in Rust. It provides an interactive TUI for managing WireGuard tunnels from the command line.

**Requirements**: Root access (auto-elevates with sudo), WireGuard CLI tools (`wg`, `wg-quick`), Linux.

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
lib.rs         → Public API exports
```

**Data Flow**: `main.rs` initializes the `App` struct → `App::handle_events()` processes keyboard input → state updates → `App::draw()` renders the UI using ratatui.

## Key Dependencies

- **ratatui**: TUI framework for terminal rendering
- **crossterm**: Cross-platform terminal control
- **color-eyre**: Enhanced error handling
- **nix**: Unix system calls (used for root privilege detection via `geteuid()`)

## Module Responsibilities

- **app.rs**: Central state machine. Manages tunnel list, selection state, UI panel toggles, and keyboard event handling. Contains the main draw loop that delegates to UI helpers.

- **wireguard.rs**: System integration layer. `discover_tunnels()` scans `/etc/wireguard/*.conf`, `is_interface_active()` checks via `ip link show`, `get_interface_info()` parses `wg show` output, `wg_quick()` executes up/down commands.

- **ui.rs**: Stateless rendering functions. Provides `bordered_block()`, `label()`, `section()`, `render_help()`, and formatting utilities like `truncate_key()` and `format_bytes()`.

- **types.rs**: Domain types with Display implementations. `Tunnel` tracks config path and runtime status, `InterfaceInfo` holds interface details with peers, `Message` provides styled status messages.

## Conventions

- Use `Result` types for all fallible operations
- WireGuard config directory is `/etc/wireguard` (constant `CONFIG_DIR`)
- Active interfaces shown with `●`, inactive with `○`
- Keys are truncated to first 8 + "..." + last 8 characters for display
