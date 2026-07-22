#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    io::{self, Read},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use smcv_app::{
    BuildInfo, CredentialRestoreMode, InitializedVault, LocalSetupCapability, initialize_vault,
};
use smcv_backup::{ArchiveKey, KeyMode, RecoveryKey};
use smcv_core::{ProtectedString, RequestId};
use zeroize::Zeroizing;

mod recovery_web;

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
        /// Read the owner password from an already-open protected file descriptor.
        #[arg(long, value_name = "FD")]
        password_fd: Option<u32>,
    },
    /// Enrolls a destination password after local archive recovery when none is active.
    RecoverOwner {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        root_key: PathBuf,
        /// Read the new password from an already-open protected file descriptor.
        #[arg(long, value_name = "FD")]
        password_fd: Option<u32>,
    },
    /// Creates, reopens, verifies, and publishes a portable encrypted backup.
    BackupCreate {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Prompt for a confirmed passphrase instead of generating a recovery key.
        #[arg(long, conflicts_with = "key_fd")]
        passphrase: bool,
        /// Read protected key material from an already-open file descriptor.
        #[arg(long, value_name = "FD")]
        key_fd: Option<u32>,
    },
    /// Reads only safe public archive framing and KDF information.
    BackupInspect {
        #[arg(long)]
        archive: PathBuf,
    },
    /// Fully authenticates an archive without mutating a vault.
    BackupVerify {
        #[arg(long)]
        archive: PathBuf,
        /// Read protected key material from an already-open file descriptor.
        #[arg(long, value_name = "FD")]
        key_fd: Option<u32>,
    },
    /// Restores an archive into brand-new database and root-key paths.
    BackupRestore {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        root_key: PathBuf,
        /// Revoke all imported application credentials before activation.
        #[arg(long)]
        revoke_credentials: bool,
        /// Read protected key material from an already-open file descriptor.
        #[arg(long, value_name = "FD")]
        key_fd: Option<u32>,
    },
    /// Starts a short-lived, single-use loopback browser restore ceremony.
    BackupRestoreBrowser {
        /// Brand-new destination `SQLite` vault path.
        #[arg(long)]
        database: PathBuf,
        /// Brand-new destination root-key path.
        #[arg(long)]
        root_key: PathBuf,
    },
}

enum SuppliedKey {
    Passphrase(Zeroizing<String>),
    Recovery(RecoveryKey),
}

impl SuppliedKey {
    fn archive_key(&self) -> ArchiveKey<'_> {
        match self {
            Self::Passphrase(value) => ArchiveKey::Passphrase(value.as_bytes()),
            Self::Recovery(value) => ArchiveKey::Recovery(value),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed administrative command dispatch remains explicit and auditable"
)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Diagnostics => {
            println!("smcv_version={}", BuildInfo::current().version);
            println!("implementation_phase=5");
            println!("production_ready=false");
        }
        Command::Init { database, root_key } => {
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            println!("vault_id={}", vault.vault_id);
            println!("installation_id={}", vault.installation_id);
            println!("status=ready");
        }
        Command::EnrollOwner {
            database,
            root_key,
            password_fd,
        } => {
            let first =
                obtain_owner_password(password_fd, "Owner password: ", "Confirm owner password: ")?;
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            let principal = vault.enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &ProtectedString::new(first.to_string()),
                RequestId::random(),
                now_unix_ms(),
            )?;
            println!("owner_principal_id={principal}");
            println!("status=enrolled");
        }
        Command::RecoverOwner {
            database,
            root_key,
            password_fd,
        } => {
            let first = obtain_owner_password(
                password_fd,
                "New owner recovery password: ",
                "Confirm recovery password: ",
            )?;
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            let principal = vault.recover_local_owner(
                LocalSetupCapability::for_local_cli(),
                &ProtectedString::new(first.to_string()),
                RequestId::random(),
                now_unix_ms(),
            )?;
            println!("owner_principal_id={principal}");
            println!("status=recovered");
        }
        Command::BackupCreate {
            database,
            root_key,
            output,
            passphrase,
            key_fd,
        } => {
            let vault = initialize_vault(&database, &root_key, now_unix_ms())?;
            let key = if let Some(descriptor) = key_fd {
                if passphrase {
                    return Err("passphrase and key-fd cannot be combined".into());
                }
                SuppliedKey::Recovery(RecoveryKey::parse(&read_key_fd(descriptor)?)?)
            } else if passphrase {
                SuppliedKey::Passphrase(prompt_confirmed_passphrase()?)
            } else {
                let recovery = RecoveryKey::generate()?;
                println!("recovery_key={}", recovery.expose_once());
                println!("Store this key separately; SMCV will not retain it.");
                require_confirmation("Type BACKED-UP to confirm separate custody: ", "BACKED-UP")?;
                SuppliedKey::Recovery(recovery)
            };
            let report = vault.create_backup_file(&output, key.archive_key(), now_unix_ms())?;
            println!("archive_id={}", report.archive_id);
            println!("archive_bytes={}", report.archive_bytes);
            println!("record_count={}", report.record_count);
            println!("status=verified");
        }
        Command::BackupInspect { archive } => {
            let header = InitializedVault::inspect_backup_file(&archive)?;
            println!("archive_id={}", header.archive_id);
            println!("format_version={}", smcv_backup::FORMAT_VERSION);
            println!("key_mode={}", key_mode_name(header.key_mode));
            println!("chunk_bytes={}", header.chunk_bytes);
            println!("status=header-only");
        }
        Command::BackupVerify { archive, key_fd } => {
            let header = InitializedVault::inspect_backup_file(&archive)?;
            let key = obtain_existing_key(header.key_mode, key_fd)?;
            let verified = InitializedVault::verify_backup_file(&archive, key.archive_key())?;
            println!("archive_id={}", verified.header.archive_id);
            println!("logical_vault_id={}", verified.metadata.logical_vault_id);
            println!("record_count={}", verified.record_count);
            println!("logical_bytes={}", verified.logical_bytes);
            println!("status=fully-verified");
        }
        Command::BackupRestore {
            archive,
            database,
            root_key,
            revoke_credentials,
            key_fd,
        } => {
            let header = InitializedVault::inspect_backup_file(&archive)?;
            let key = obtain_existing_key(header.key_mode, key_fd)?;
            let mode = if revoke_credentials {
                CredentialRestoreMode::Revoke
            } else {
                CredentialRestoreMode::Preserve
            };
            let report = InitializedVault::restore_backup_file(
                &archive,
                &database,
                &root_key,
                key.archive_key(),
                mode,
                now_unix_ms(),
            )?;
            println!("archive_id={}", report.archive_id);
            println!("vault_id={}", report.vault_id);
            println!("installation_id={}", report.installation_id);
            println!("recovery_epoch={}", report.recovery_epoch);
            println!(
                "revoked_application_credentials={}",
                report.revoked_application_credentials
            );
            println!(
                "disabled_source_bound_authenticators={}",
                report.disabled_source_bound_authenticators
            );
            println!("status=ready");
            println!(
                "warning=decommission the source installation or rotate credentials as appropriate"
            );
        }
        Command::BackupRestoreBrowser { database, root_key } => {
            recovery_web::run(database, root_key).await?;
        }
    }
    Ok(())
}

fn prompt_confirmed_passphrase() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let first = Zeroizing::new(rpassword::prompt_password("Backup passphrase: ")?);
    let second = Zeroizing::new(rpassword::prompt_password("Confirm backup passphrase: ")?);
    if first.as_str() != second.as_str() || first.len() < 16 {
        return Err("passphrase confirmation or minimum length failed".into());
    }
    Ok(first)
}

fn obtain_owner_password(
    descriptor: Option<u32>,
    first_prompt: &str,
    confirmation_prompt: &str,
) -> Result<Zeroizing<String>, Box<dyn Error>> {
    if let Some(descriptor) = descriptor {
        return Ok(Zeroizing::new(
            read_key_fd(descriptor)?.trim_end().to_owned(),
        ));
    }
    let first = Zeroizing::new(rpassword::prompt_password(first_prompt)?);
    let second = Zeroizing::new(rpassword::prompt_password(confirmation_prompt)?);
    if first.as_str() != second.as_str() {
        return Err("password confirmation did not match".into());
    }
    Ok(first)
}

fn obtain_existing_key(
    mode: KeyMode,
    descriptor: Option<u32>,
) -> Result<SuppliedKey, Box<dyn Error>> {
    let protected = if let Some(descriptor) = descriptor {
        Zeroizing::new(read_key_fd(descriptor)?)
    } else {
        let prompt = match mode {
            KeyMode::PassphraseArgon2id => "Backup passphrase: ",
            KeyMode::RecoveryKey => "Backup recovery key: ",
        };
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    };
    match mode {
        KeyMode::PassphraseArgon2id => Ok(SuppliedKey::Passphrase(protected)),
        KeyMode::RecoveryKey => Ok(SuppliedKey::Recovery(RecoveryKey::parse(protected.trim())?)),
    }
}

fn read_key_fd(descriptor: u32) -> Result<String, Box<dyn Error>> {
    if descriptor <= 2 {
        return Err("protected key descriptor must be greater than 2".into());
    }
    let path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
    let metadata = fs::metadata(&path)?;
    if metadata.len() > 4096 {
        return Err("protected key input is too large".into());
    }
    let mut protected = String::new();
    fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut protected)?;
    if protected.len() > 4096 {
        return Err("protected key input is too large".into());
    }
    Ok(protected.trim_end().to_owned())
}

fn require_confirmation(prompt: &str, expected: &str) -> Result<(), Box<dyn Error>> {
    eprint!("{prompt}");
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if response.trim() != expected {
        return Err("confirmation was not accepted".into());
    }
    Ok(())
}

const fn key_mode_name(mode: KeyMode) -> &'static str {
    match mode {
        KeyMode::PassphraseArgon2id => "passphrase-argon2id",
        KeyMode::RecoveryKey => "recovery-key",
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}
