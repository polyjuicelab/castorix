//! Health check endpoints

use axum::Json;
use serde_json::json;
use serde_json::Value;

/// Health check endpoint
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "castorix-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
