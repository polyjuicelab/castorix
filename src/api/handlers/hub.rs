//! Hub API handlers

use std::sync::Arc;

use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::api::types::ApiError;
use crate::api::types::ApiResponse;
use crate::core::client::FarcasterClient;

/// Shared state for Hub handlers
#[derive(Clone)]
pub struct HubState {
    pub client: Arc<FarcasterClient>,
}

/// Query parameters for listing endpoints
#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Get user information by FID
pub async fn get_user(
    State(state): State<HubState>,
    Path(fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let user_data = state.client.get_user(fid).await?;
    Ok(Json(ApiResponse::success(user_data)))
}

/// Get user profile by FID
pub async fn get_profile(
    State(state): State<HubState>,
    Path(fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // For now, return the same as get_user (FarcasterClient doesn't have separate profile method)
    let profile = state.client.get_user(fid).await?;
    Ok(Json(ApiResponse::success(profile)))
}

/// Get user statistics
pub async fn get_stats(
    State(state): State<HubState>,
    Path(fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Return basic user stats (simplified version)
    let user = state.client.get_user(fid).await?;
    Ok(Json(ApiResponse::success(user)))
}

/// Get followers for a FID
pub async fn get_followers(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
    Query(_params): Query<ListParams>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "Followers endpoint not implemented yet".to_string(),
    ))
}

/// Get following for a FID
pub async fn get_following(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
    Query(_params): Query<ListParams>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "Following endpoint not implemented yet".to_string(),
    ))
}

/// Get verified Ethereum addresses
pub async fn get_eth_addresses(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "ETH addresses endpoint not implemented yet".to_string(),
    ))
}

/// Get ENS domains
pub async fn get_ens_domains(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "ENS domains endpoint not implemented yet".to_string(),
    ))
}

/// Get custody address
pub async fn get_custody_address(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "Custody address endpoint not implemented yet".to_string(),
    ))
}

/// Get casts by FID
pub async fn get_casts(
    State(_state): State<HubState>,
    Path(_fid): Path<u64>,
    Query(_params): Query<ListParams>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "Casts endpoint not implemented yet".to_string(),
    ))
}

/// Check spam status
#[derive(Debug, Serialize)]
pub struct SpamCheckResponse {
    pub fid: u64,
    pub is_spam: bool,
}

pub async fn check_spam(
    Path(fid): Path<u64>,
) -> Result<Json<ApiResponse<SpamCheckResponse>>, ApiError> {
    // Use the spam checker
    use crate::mcp::utils::SpamChecker;

    let is_spam = match SpamChecker::load() {
        Ok(checker) => checker.is_spam(fid),
        Err(_) => false, // If spam checker fails to load, assume not spam
    };

    Ok(Json(ApiResponse::success(SpamCheckResponse {
        fid,
        is_spam,
    })))
}

/// Get hub info
pub async fn get_hub_info(
    State(_state): State<HubState>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Placeholder - FarcasterClient doesn't have this method yet
    Err(ApiError::InternalError(
        "Hub info endpoint not implemented yet".to_string(),
    ))
}
