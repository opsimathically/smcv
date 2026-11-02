use std::{fs, path::PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use smcv_app::initialize_vault;
use smcv_backup::{ArchiveKey, RecoveryKey};
use uuid::Uuid;

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("fixture destination argument is required")?;
    let work = std::env::temp_dir().join(format!("smcv-v1-fixture-{}", Uuid::new_v4()));
    let data = work.join("data");
    let provider = work.join("provider");
    let artifacts = work.join("artifacts");
    for directory in [&data, &provider, &artifacts] {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let vault = initialize_vault(
        &data.join("vault.sqlite"),
        &provider.join("root.key"),
        1_800_000_000_000,
    )?;
    let key = RecoveryKey::generate()?;
    let temporary_archive = artifacts.join("v1-minimal.smcvault");
    let _report = vault.create_backup_file(
        &temporary_archive,
        ArchiveKey::Recovery(&key),
        1_800_000_000_001,
    )?;
    fs::copy(temporary_archive, destination)?;
    fs::remove_dir_all(work)?;
    println!("fixture_recovery_key={}", key.expose_once());
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("fixture generation requires the Unix custody implementation");
}
