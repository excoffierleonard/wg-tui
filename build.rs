use std::process::Command;

const REQUIRED_COMMANDS: &[&str] = &["wg", "wg-quick", "ip"];

fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn main() {
    let missing: Vec<_> = REQUIRED_COMMANDS
        .iter()
        .filter(|cmd| !command_exists(cmd))
        .collect();

    if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().copied().copied().collect();
        println!(
            "cargo:warning=Missing system dependencies: {}",
            names.join(", ")
        );
        println!("cargo:warning=Install WireGuard tools to use this application");
    }
}
