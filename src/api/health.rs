use serde::Serialize;

use crate::response::PrettyJson;

/// Health response kept tiny because it is used only as an unauthenticated liveness probe.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Returns liveness without touching Postgres so orchestration can distinguish process health.
pub async fn health() -> PrettyJson<HealthResponse> {
    PrettyJson(HealthResponse { status: "ok" })
}
