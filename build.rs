#[cfg(not(target_os = "linux"))]
compile_error!("wg-tui only supports Linux");

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
const REQUIRED_COMMANDS: &[&str] = &["wg", "wg-quick", "ip"];

#[cfg(target_os = "linux")]
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        // This block is unreachable due to compile_error! above,
        // but satisfies the compiler that main() has a body for all targets
    }

    #[cfg(target_os = "linux")]
    {
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
}
