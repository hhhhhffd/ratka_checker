pub mod hashes;
pub mod health;
pub mod scans;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::{
    auth::middleware::require_internal_api_key, config::AppConfig, rules::engine::RulesEngine,
};

/// Shared application state cloned cheaply into handlers, middleware, and background tasks.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub rules_engine: Arc<RulesEngine>,
}

impl AppState {
    /// Wraps heavyweight config and rules in Arc so background workers can own cloned state safely.
    pub fn new(db: PgPool, config: AppConfig, rules_engine: RulesEngine) -> Self {
        Self {
            db,
            config: Arc::new(config),
            rules_engine: Arc::new(rules_engine),
        }
    }
}

/// Builds the complete API router with `/health` left unauthenticated and `/v1` protected.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/scans", post(scans::create_scan))
        .route("/scans/{id}", get(scans::get_scan))
        .route("/hashes/{sha256}", get(hashes::get_hash))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_internal_api_key,
        ));

    Router::new()
        .route("/health", get(health::health))
        .nest("/v1", protected)
        .layer(DefaultBodyLimit::max(state.config.upload_max_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
