use axum::extract::{Path, State};

use crate::{api::AppState, error::AppError, response::PrettyJson, storage::db};

/// Looks up the newest known scan for a sha256 hash without requiring the file to be uploaded again.
pub async fn get_hash(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<PrettyJson<crate::models::scan::ScanResponse>, AppError> {
    validate_sha256(&sha256)?;
    let response = db::find_latest_scan_by_sha256(&state.db, &sha256)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("hash not found"))?;
    Ok(PrettyJson(response))
}

/// Validates hash shape before querying so malformed requests get a deterministic 400.
fn validate_sha256(value: &str) -> Result<(), AppError> {
    let valid = value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(AppError::invalid_file("sha256 must be 64 hex characters"))
    }
}
