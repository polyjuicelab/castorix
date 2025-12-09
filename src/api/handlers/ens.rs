//! ENS API handlers

use axum::extract::Path;
use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::api::types::ApiError;
use crate::api::types::ApiResponse;

/// Shared state for ENS handlers
#[derive(Clone)]
pub struct EnsState {
    pub eth_rpc_url: String,
    pub base_rpc_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolveResponse {
    pub domain: String,
    pub address: String,
}

/// Resolve ENS domain
pub async fn resolve_domain(
    State(_state): State<EnsState>,
    Path(_domain): Path<String>,
) -> Result<Json<ApiResponse<ResolveResponse>>, ApiError> {
    // Placeholder - ENS resolution not implemented yet
    Err(ApiError::InternalError(
        "ENS resolution endpoint not implemented yet".to_string(),
    ))
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub domain: String,
    pub address: String,
    pub owns_domain: bool,
}

/// Verify domain ownership
pub async fn verify_ownership(
    State(_state): State<EnsState>,
    Path((_domain, _address)): Path<(String, String)>,
) -> Result<Json<ApiResponse<VerifyResponse>>, ApiError> {
    // Placeholder - ENS verification not implemented yet
    Err(ApiError::InternalError(
        "ENS verification endpoint not implemented yet".to_string(),
    ))
}
