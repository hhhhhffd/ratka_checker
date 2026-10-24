use std::{
    io::Write,
    path::{Path, PathBuf},
};

use bytes::Bytes;

/// Builds the canonical storage path so every upload of the same sha256 targets one file.
pub fn jar_path(storage_dir: &Path, sha256: &str) -> PathBuf {
    storage_dir.join(format!("{sha256}.jar"))
}

/// Writes the jar to a uniquely named temporary file in the storage directory, then renames it
/// into place. Concurrent uploads of the same sha256 never share a temporary file, and since the
/// sha256 fixes the content, a target that already exists is equivalent to ours.
pub async fn save_jar(storage_dir: &Path, sha256: &str, bytes: &Bytes) -> std::io::Result<PathBuf> {
    tokio::fs::create_dir_all(storage_dir).await?;
    let final_path = jar_path(storage_dir, sha256);
    let storage_dir = storage_dir.to_owned();
    let bytes = bytes.clone();
    let target = final_path.clone();

    tokio::task::spawn_blocking(move || {
        let mut temporary = tempfile::Builder::new()
            .prefix(".upload-")
            .suffix(".tmp")
            .tempfile_in(&storage_dir)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        match temporary.persist(&target) {
            Ok(_) => Ok(()),
            // Same sha256 means same content, so another request winning the race is fine.
            Err(_) if target.exists() => Ok(()),
            Err(error) => Err(error.error),
        }
    })
    .await
    .map_err(std::io::Error::other)??;
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{jar_path, save_jar};

    #[tokio::test]
    async fn concurrent_saves_of_one_hash_succeed_and_leave_no_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = Bytes::from(vec![7u8; 64 * 1024]);

        let saves = (0..16).map(|_| save_jar(directory.path(), "abc123", &bytes));
        for result in futures::future::join_all(saves).await {
            result.unwrap();
        }

        assert_eq!(
            std::fs::read(jar_path(directory.path(), "abc123")).unwrap(),
            bytes.as_ref()
        );
        let entries: Vec<_> = std::fs::read_dir(directory.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
