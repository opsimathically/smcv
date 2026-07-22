#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use smcv_app::BuildInfo;

#[derive(Debug, Parser)]
#[command(name = "smcv", version, about = "SMCV administrative CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prints safe local build diagnostics.
    Diagnostics,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Diagnostics => {
            println!("smcv_version={}", BuildInfo::current().version);
            println!("implementation_phase=0");
            println!("production_ready=false");
        }
    }
}
