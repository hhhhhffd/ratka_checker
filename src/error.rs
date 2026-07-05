use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Public API error body used by every non-auth failure response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Application error with an HTTP status and stable machine-readable code.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    /// Creates a 400 invalid_file error for upload and archive contract violations.
    pub fn invalid_file(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_file",
            message: message.into(),
        }
    }

    /// Creates a 404 not_found error for missing scan/hash resources.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    /// Creates a 500 internal_error while keeping implementation details out of JSON.
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    /// Converts domain errors into the single JSON error envelope required by the API contract.
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.code.to_owned(),
            message: Some(self.message),
        });
        (self.status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    /// Maps database errors to a generic 500 response while preserving details in tracing callers.
    fn from(error: sqlx::Error) -> Self {
        Self::internal(format!("database operation failed: {error}"))
    }
}

impl From<std::io::Error> for AppError {
    /// Maps filesystem errors to a generic 500 response for storage operations.
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("storage operation failed: {error}"))
    }
}
