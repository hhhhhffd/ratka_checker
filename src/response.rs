use axum::{
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::error::ErrorResponse;

/// JSON response wrapper that renders stable, human-readable output for curl/manual testing.
pub struct PrettyJson<T>(pub T);

impl<T> IntoResponse for PrettyJson<T>
where
    T: Serialize,
{
    /// Serializes response bodies with indentation and a trailing newline for terminal readability.
    fn into_response(self) -> Response {
        match serde_json::to_string_pretty(&self.0) {
            Ok(mut body) => {
                body.push('\n');
                ([(CONTENT_TYPE, "application/json; charset=utf-8")], body).into_response()
            }
            Err(error) => {
                tracing::error!(%error, "failed to serialize JSON response");
                let fallback = ErrorResponse {
                    error: "internal_error".to_owned(),
                    message: Some("failed to serialize response".to_owned()),
                };
                let body = serde_json::to_string_pretty(&fallback)
                    .unwrap_or_else(|_| "{\"error\":\"internal_error\"}".to_owned());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(CONTENT_TYPE, "application/json; charset=utf-8")],
                    format!("{body}\n"),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use serde::Serialize;

    use crate::response::PrettyJson;

    #[derive(Serialize)]
    struct ExampleResponse {
        status: &'static str,
        count: u8,
    }

    /// Locks API JSON output to pretty formatting because operators inspect responses in terminals.
    #[tokio::test]
    async fn pretty_json_uses_indentation_and_trailing_newline() {
        let response = PrettyJson(ExampleResponse {
            status: "ok",
            count: 1,
        })
        .into_response();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body must collect")
            .to_bytes();
        let body = String::from_utf8(bytes.to_vec()).expect("response must be utf8");

        assert!(body.contains("{\n  \"status\": \"ok\","));
        assert!(body.ends_with('\n'));
    }
}
