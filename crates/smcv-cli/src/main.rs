#![forbid(unsafe_code)]

use std::{
    error::Error,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use smcv_app::{BuildInfo, LocalSetupCapability, initialize_vault};
use smcv_core::{ProtectedString, RequestId};

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
    /// Initializes or verifies local encrypted vault custody.
    Init {
        /// `SQLite` vault path in its restrictive data directory.
        #[arg(long)]
        database: PathBuf,
        /// External root-key path in a distinct restrictive directory.
        #[arg(long)]
        root_key: PathBuf,
    },
    /// Enrolls the sole owner using a protected terminal prompt.
    EnrollOwner {
        /// `SQLite` vault path in its restrictive data directory.
        #[arg(long)]
        database: PathBuf,
        /// External root-key path in a distinct restrictive directory.
        #[arg(long)]
        root_key: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Diagnostics => {
            println!("smcv_version={}", BuildInfo::current().version);
            println!("implementation_phase=2");
            println!("production_ready=false");
        }
        Command::Init { database, root_key } => {
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            println!("vault_id={}", vault.vault_id);
            println!("installation_id={}", vault.installation_id);
            println!("status=ready");
        }
        Command::EnrollOwner { database, root_key } => {
            let first = rpassword::prompt_password("Owner password: ")?;
            let second = rpassword::prompt_password("Confirm owner password: ")?;
            if first != second {
                return Err("password confirmation did not match".into());
            }
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            let principal = vault.enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &ProtectedString::new(first),
                RequestId::random(),
                now_unix_ms(),
            )?;
            println!("owner_principal_id={principal}");
            println!("status=enrolled");
        }
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}
