use std::process::Command;

use clap::Parser;
use color_eyre::{Result, eyre::bail};
use wg_tui::{App, check_dependencies};

#[derive(Parser)]
#[command(version, about)]
struct Cli {}

const CMD_SUDO: &str = "sudo";

fn main() -> Result<()> {
    Cli::parse();

    color_eyre::install()?;

    if !nix::unistd::geteuid().is_root() {
        let exe = std::env::current_exe()?;
        let args: Vec<_> = std::env::args().skip(1).collect();
        let status = Command::new(CMD_SUDO).arg(exe).args(&args).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let missing = check_dependencies();
    if !missing.is_empty() {
        bail!("Missing required dependencies: {}", missing.join(", "));
    }

    let mut terminal = ratatui::init();
    let mut app = App::new();

    while !app.should_quit() {
        terminal.draw(|f| app.draw(f))?;
        app.handle_events()?;
    }

    ratatui::restore();
    Ok(())
}
