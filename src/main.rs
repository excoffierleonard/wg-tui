use std::process::Command;

use color_eyre::Result;
use wg_tui::App;

fn main() -> Result<()> {
    color_eyre::install()?;

    if !nix::unistd::geteuid().is_root() {
        let status = Command::new("sudo").args(std::env::args()).status()?;
        std::process::exit(status.code().unwrap_or(1));
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
