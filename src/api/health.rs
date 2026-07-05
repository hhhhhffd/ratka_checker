use axum::Json;
use serde::Serialize;

/// Health response kept tiny because it is used only as an unauthenticated liveness probe.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Returns liveness without touching Postgres so orchestration can distinguish process health.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
