use std::{fs, path::Path, time::SystemTime};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use smcv_app::{CredentialRestoreMode, InitializedVault};
use smcv_backup::ArchiveKey;
use uuid::Uuid;

pub(crate) struct RetentionReport {
    pub(crate) archive_id: Uuid,
    pub(crate) verified_copies: usize,
    pub(crate) removed_verified_copies: usize,
    pub(crate) unverified_files_retained: usize,
}

pub(crate) struct DrillReport {
    pub(crate) archive_id: Uuid,
    pub(crate) recovery_epoch: u64,
    pub(crate) disabled_source_bound_authenticators: u64,
}

pub(crate) fn maintain_backups(
    vault: &InitializedVault,
    output_directory: &Path,
    key: ArchiveKey<'_>,
    retain: usize,
    now_unix_ms: i64,
) -> Result<RetentionReport, Box<dyn std::error::Error>> {
    if retain == 0 || retain > 365 {
        return Err("backup retention count must be between 1 and 365".into());
    }
    prepare_restrictive_directory(output_directory)?;
    let output = output_directory.join(format!("backup-{}.smcvault", Uuid::new_v4()));
    let created = vault.create_backup_file(&output, key, now_unix_ms)?;

    let mut verified = Vec::new();
    let mut unverified_files_retained = 0_usize;
    let mut archive_candidates = 0_usize;
    for entry in fs::read_dir(output_directory)?.take(4_097) {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("smcvault") {
            continue;
        }
        archive_candidates = archive_candidates.saturating_add(1);
        let metadata = path.symlink_metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            unverified_files_retained = unverified_files_retained.saturating_add(1);
            continue;
        }
        if InitializedVault::verify_backup_file(&path, key).is_ok() {
            verified.push((metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH), path));
        } else {
            unverified_files_retained = unverified_files_retained.saturating_add(1);
        }
    }
    if archive_candidates > 4_096 || !verified.iter().any(|(_, path)| path == &output) {
        return Err(
            "backup directory inventory is unsafe or newly created archive is missing".into(),
        );
    }
    let verified_count = verified.len();
    verified.retain(|(_, path)| path != &output);
    verified.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let removal_count = verified_count.saturating_sub(retain);
    if removal_count > verified.len() {
        return Err("retention would remove the newly created verified backup".into());
    }
    for (_, path) in verified.iter().take(removal_count) {
        let metadata = path.symlink_metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("verified backup changed before retention cleanup".into());
        }
        fs::remove_file(path)?;
    }
    Ok(RetentionReport {
        archive_id: created.archive_id,
        verified_copies: verified_count.saturating_sub(removal_count),
        removed_verified_copies: removal_count,
        unverified_files_retained,
    })
}

pub(crate) fn restore_drill(
    archive: &Path,
    workspace: &Path,
    key: ArchiveKey<'_>,
    now_unix_ms: i64,
) -> Result<DrillReport, Box<dyn std::error::Error>> {
    validate_restrictive_directory(workspace)?;
    let staging = tempfile::Builder::new()
        .prefix("smcv-restore-drill-")
        .tempdir_in(workspace)?;
    let database = staging.path().join("data/vault.sqlite");
    let root_key = staging.path().join("provider/root.key");
    let restored = InitializedVault::restore_backup_file(
        archive,
        &database,
        &root_key,
        key,
        CredentialRestoreMode::Preserve,
        now_unix_ms,
    )?;
    let reopened = smcv_app::initialize_vault(&database, &root_key, now_unix_ms.saturating_add(1))?;
    if !reopened.store.quick_integrity_check()? {
        return Err("restore drill integrity check failed".into());
    }
    Ok(DrillReport {
        archive_id: restored.archive_id,
        recovery_epoch: restored.recovery_epoch,
        disabled_source_bound_authenticators: restored.disabled_source_bound_authenticators,
    })
}

#[cfg(unix)]
fn prepare_restrictive_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    validate_restrictive_directory(path)
}

#[cfg(unix)]
fn validate_restrictive_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("operational workspace permissions are unsafe".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_restrictive_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("supported production operations require Unix permission semantics".into())
}

#[cfg(not(unix))]
fn validate_restrictive_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("supported production operations require Unix permission semantics".into())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use smcv_app::initialize_vault;
    use smcv_backup::{ArchiveKey, RecoveryKey};
    use tempfile::TempDir;

    use super::{maintain_backups, restore_drill};

    #[test]
    fn retention_creates_before_deleting_and_never_removes_unverified_files() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let vault = initialize_vault(
            &root.path().join("data/vault.sqlite"),
            &root.path().join("provider/root.key"),
            1_800_000_000_000,
        )
        .unwrap_or_else(|error| panic!("synthetic vault: {error}"));
        let backups = root.path().join("backups");
        fs::create_dir(&backups).unwrap_or_else(|error| panic!("backup directory: {error}"));
        fs::set_permissions(&backups, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("backup permissions: {error}"));
        let key = RecoveryKey::generate().unwrap_or_else(|error| panic!("recovery key: {error}"));
        for offset in 0..3 {
            maintain_backups(
                &vault,
                &backups,
                ArchiveKey::Recovery(&key),
                2,
                1_800_000_000_001 + offset,
            )
            .unwrap_or_else(|error| panic!("retention pass: {error}"));
        }
        fs::write(
            backups.join("corrupt.smcvault"),
            b"synthetic corrupt archive",
        )
        .unwrap_or_else(|error| panic!("corrupt fixture: {error}"));
        let report = maintain_backups(
            &vault,
            &backups,
            ArchiveKey::Recovery(&key),
            2,
            1_800_000_000_010,
        )
        .unwrap_or_else(|error| panic!("final retention pass: {error}"));
        assert_eq!(report.verified_copies, 2);
        assert_eq!(report.unverified_files_retained, 1);
        assert!(backups.join("corrupt.smcvault").exists());
        assert!(
            fs::read_dir(&backups)
                .unwrap_or_else(|error| panic!("backup inventory: {error}"))
                .filter_map(Result::ok)
                .filter(
                    |entry| entry.path().extension().and_then(|value| value.to_str())
                        == Some("smcvault")
                )
                .any(|entry| {
                    smcv_app::InitializedVault::inspect_backup_file(&entry.path())
                        .is_ok_and(|header| header.archive_id == report.archive_id)
                })
        );
    }

    #[test]
    fn restore_drill_uses_and_removes_an_isolated_destination() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let vault = initialize_vault(
            &root.path().join("data/vault.sqlite"),
            &root.path().join("provider/root.key"),
            1_800_000_000_000,
        )
        .unwrap_or_else(|error| panic!("synthetic vault: {error}"));
        let workspace = root.path().join("drills");
        fs::create_dir(&workspace).unwrap_or_else(|error| panic!("drill directory: {error}"));
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("drill permissions: {error}"));
        let backup_directory = root.path().join("backups");
        fs::create_dir(&backup_directory)
            .unwrap_or_else(|error| panic!("backup directory: {error}"));
        fs::set_permissions(&backup_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("backup permissions: {error}"));
        let archive = backup_directory.join("vault.smcvault");
        let key = RecoveryKey::generate().unwrap_or_else(|error| panic!("recovery key: {error}"));
        vault
            .create_backup_file(&archive, ArchiveKey::Recovery(&key), 1_800_000_000_001)
            .unwrap_or_else(|error| panic!("backup: {error}"));
        let report = restore_drill(
            &archive,
            &workspace,
            ArchiveKey::Recovery(&key),
            1_800_000_000_002,
        )
        .unwrap_or_else(|error| panic!("restore drill: {error}"));
        assert_eq!(report.recovery_epoch, 1);
        assert_eq!(
            fs::read_dir(&workspace)
                .unwrap_or_else(|error| panic!("workspace inventory: {error}"))
                .count(),
            0
        );
    }
}
