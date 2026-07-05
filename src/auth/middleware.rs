use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{api::AppState, response::PrettyJson, storage::db};

const API_KEY_HEADER: &str = "X-API-Key";

/// Minimal auth error body required by the API contract.
#[derive(Debug, Serialize)]
struct UnauthorizedResponse {
    error: &'static str,
}

/// Verifies an internal API key before dispatching to protected `/v1` routes.
pub async fn require_internal_api_key(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(raw_key) = req
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return unauthorized();
    };

    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    match db::find_active_api_key(&state.db, &key_hash).await {
        Ok(Some(api_key)) if api_key.role == "internal" => next.run(req).await,
        Ok(_) => unauthorized(),
        Err(error) => {
            tracing::error!(%error, "failed to validate API key");
            unauthorized()
        }
    }
}

/// Returns the exact unauthorized envelope without leaking whether the key existed.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        PrettyJson(UnauthorizedResponse {
            error: "unauthorized",
        }),
    )
        .into_response()
}
