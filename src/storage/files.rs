use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

/// Builds the canonical storage path so every upload of the same sha256 targets one file.
pub fn jar_path(storage_dir: &Path, sha256: &str) -> PathBuf {
    storage_dir.join(format!("{sha256}.jar"))
}

/// Writes the jar atomically enough for this single-process MVP by using a temporary file then rename.
pub async fn save_jar(storage_dir: &Path, sha256: &str, bytes: &Bytes) -> std::io::Result<PathBuf> {
    tokio::fs::create_dir_all(storage_dir).await?;
    let final_path = jar_path(storage_dir, sha256);
    let temporary_path = storage_dir.join(format!("{sha256}.jar.tmp"));

    let mut file = tokio::fs::File::create(&temporary_path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&temporary_path, &final_path).await?;
    Ok(final_path)
}

/// Removes a stored jar and treats an already-missing file as success for idempotent cleanup.
pub async fn delete_jar(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
