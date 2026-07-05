use std::path::PathBuf;

use axum::{
    extract::{Multipart, Path, State},
    Json,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::AppState,
    error::AppError,
    scanner::archive,
    storage::{db, files},
};

/// Accepts a multipart jar upload, persists it by sha256, and enqueues a background scan.
pub async fn create_scan(
    State(state): State<AppState>,
    multipart: Multipart,
) -> Result<Json<crate::models::scan::ScanResponse>, AppError> {
    let upload = extract_upload(multipart).await?;
    validate_filename(&upload.filename)?;

    let sha256 = hex::encode(Sha256::digest(&upload.bytes));
    let storage_path = files::save_jar(&state.config.storage_dir, &sha256, &upload.bytes).await?;
    let storage_path_string = storage_path.to_string_lossy().to_string();

    if let Some(existing) = db::find_latest_scan_by_sha256(&state.db, &sha256)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        db::mark_file_available(&state.db, existing.scan_id, &storage_path_string).await?;
        return Ok(Json(existing));
    }

    let scan_id = Uuid::new_v4();
    db::create_pending_scan(
        &state.db,
        scan_id,
        &upload.filename,
        &sha256,
        &storage_path_string,
    )
    .await?;

    spawn_scan_worker(scan_id, storage_path, state.clone());

    let response = db::find_scan_by_id(&state.db, scan_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("created scan was not found"))?;
    Ok(Json(response))
}

/// Returns current scan state and result by id for polling clients.
pub async fn get_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<crate::models::scan::ScanResponse>, AppError> {
    let response = db::find_scan_by_id(&state.db, scan_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("scan not found"))?;
    Ok(Json(response))
}

/// Starts one detached worker for a scan; the worker owns all state it needs to finish DB updates.
fn spawn_scan_worker(scan_id: Uuid, storage_path: PathBuf, state: AppState) {
    tokio::spawn(async move {
        if let Err(error) = run_scan_worker(scan_id, storage_path, state.clone()).await {
            tracing::error!(scan_id = %scan_id, %error, "scan worker failed");
            if let Err(update_error) =
                db::fail_scan(&state.db, scan_id, "scan_worker_failed", &error.to_string()).await
            {
                tracing::error!(scan_id = %scan_id, %update_error, "failed to persist worker failure");
            }
        }
    });
}

/// Runs blocking archive/class parsing off the async runtime and persists the final scan state.
async fn run_scan_worker(
    scan_id: Uuid,
    storage_path: PathBuf,
    state: AppState,
) -> anyhow::Result<()> {
    let limits = state.config.scan_limits;
    let rules_engine = state.rules_engine.clone();
    let scan_path = storage_path.clone();
    let outcome =
        tokio::task::spawn_blocking(move || archive::scan_file(&scan_path, limits, &rules_engine))
            .await?;

    db::complete_scan(
        &state.db,
        scan_id,
        outcome.verdict,
        outcome.risk_score,
        &outcome.summary,
        &outcome.findings,
    )
    .await
    .map_err(Into::into)
}

/// Parsed upload payload from the expected `multipart/form-data` field named `file`.
struct Upload {
    filename: String,
    bytes: Bytes,
}

/// Extracts exactly the `file` part and rejects missing or empty uploads explicitly.
async fn extract_upload(mut multipart: Multipart) -> Result<Upload, AppError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::invalid_file(format!("invalid multipart upload: {error}")))?
    {
        if field.name() != Some("file") {
            continue;
        }

        let filename = field
            .file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "upload.jar".to_owned());
        let bytes = field.bytes().await.map_err(|error| {
            AppError::invalid_file(format!("failed to read uploaded file: {error}"))
        })?;
        if bytes.is_empty() {
            return Err(AppError::invalid_file("uploaded file is empty"));
        }
        return Ok(Upload { filename, bytes });
    }

    Err(AppError::invalid_file("multipart field 'file' is required"))
}

/// Enforces the MVP contract that only `.jar` uploads are accepted.
fn validate_filename(filename: &str) -> Result<(), AppError> {
    if filename.to_ascii_lowercase().ends_with(".jar") {
        Ok(())
    } else {
        Err(AppError::invalid_file(
            "uploaded file must have a .jar filename",
        ))
    }
}
