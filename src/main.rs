use std::process::Command;

use color_eyre::{Result, eyre::bail};
use wg_tui::{App, check_dependencies};

const CMD_SUDO: &str = "sudo";

fn main() -> Result<()> {
    color_eyre::install()?;

    if !nix::unistd::geteuid().is_root() {
        let args: Vec<_> = std::env::args().collect();
        let status = Command::new(CMD_SUDO).args(&args).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let missing = check_dependencies();
    if !missing.is_empty() {
        bail!("Missing required dependencies: {}", missing.join(", "));
    }

    let mut terminal = ratatui::init();
    let mut app = App::new();

    while !app.should_quit {
        terminal.draw(|f| app.draw(f))?;
        app.handle_events()?;
    }

    ratatui::restore();
    Ok(())
}
