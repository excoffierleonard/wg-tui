//! WireGuard TUI Manager

use std::{io::stdout, process::Command};

use color_eyre::Result;
use crossterm::{
    ExecutableCommand,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

use wg_tui::App;

fn main() -> Result<()> {
    color_eyre::install()?;

    // Re-exec with sudo if not root
    if !nix::unistd::geteuid().is_root() {
        let args: Vec<String> = std::env::args().collect();
        let status = Command::new("sudo").args(&args).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    // Terminal setup
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = ratatui::init();

    // Run app
    let mut app = App::new();
    while !app.should_quit {
        terminal.draw(|f| app.draw(f))?;
        app.handle_events()?;
    }

    // Cleanup
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    ratatui::restore();
    Ok(())
}
