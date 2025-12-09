//! Contract API handlers

use std::sync::Arc;

use axum::extract::Path;
use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::api::types::ApiError;
use crate::api::types::ApiResponse;
use crate::farcaster::contracts::FarcasterContractClient;

/// Shared state for contract handlers
#[derive(Clone)]
pub struct ContractState {
    pub client: Arc<FarcasterContractClient>,
}

#[derive(Debug, Serialize)]
pub struct PriceResponse {
    pub price_wei: String,
    pub price_eth: String,
}

/// Get FID registration price
pub async fn get_fid_price(
    State(state): State<ContractState>,
) -> Result<Json<ApiResponse<PriceResponse>>, ApiError> {
    let price = state
        .client
        .get_registration_price()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get FID price: {}", e)))?;

    let price_eth = price.as_u128() as f64 / 1e18;

    Ok(Json(ApiResponse::success(PriceResponse {
        price_wei: price.to_string(),
        price_eth: format!("{:.6}", price_eth),
    })))
}

#[derive(Debug, Serialize)]
pub struct StoragePriceResponse {
    pub units: u64,
    pub price_wei: String,
    pub price_eth: String,
}

/// Get storage rental price
pub async fn get_storage_price(
    State(state): State<ContractState>,
    Path(units): Path<u64>,
) -> Result<Json<ApiResponse<StoragePriceResponse>>, ApiError> {
    let price = state
        .client
        .get_storage_price(units)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get storage price: {}", e)))?;

    let price_eth = price.as_u128() as f64 / 1e18;

    Ok(Json(ApiResponse::success(StoragePriceResponse {
        units,
        price_wei: price.to_string(),
        price_eth: format!("{:.6}", price_eth),
    })))
}

#[derive(Debug, Serialize)]
pub struct FidCheckResponse {
    pub address: String,
    pub has_fid: bool,
    pub fid: Option<u64>,
}

/// Check if address has FID
pub async fn check_address_fid(
    State(state): State<ContractState>,
    Path(address_str): Path<String>,
) -> Result<Json<ApiResponse<FidCheckResponse>>, ApiError> {
    // Convert string to Address
    let address = address_str
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("Invalid address: {}", e)))?;

    let fid = state
        .client
        .address_has_fid(address)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to check address: {}", e)))?;

    Ok(Json(ApiResponse::success(FidCheckResponse {
        address: address_str,
        has_fid: fid.is_some(),
        fid,
    })))
}
