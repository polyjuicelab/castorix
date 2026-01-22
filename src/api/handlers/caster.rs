//! Cast submission API handlers

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Deserialize;

use crate::api::types::ApiError;
use crate::api::types::ApiResponse;
use crate::core::client::hub_client::CastId;
use crate::core::client::FarcasterClient;

/// Shared state for cast submission handler
#[derive(Clone)]
pub struct CasterState {
    pub client: Arc<FarcasterClient>,
    pub fid: u64,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CastRequest {
    pub text: String,
    #[serde(default)]
    pub parent_cast_fid: Option<u64>,
    #[serde(default)]
    pub parent_cast_hash: Option<String>,
    #[serde(default)]
    pub parent_url: Option<String>,
    #[serde(default)]
    pub embed_urls: Vec<String>,
}

/// Submit a cast using JSON input
pub async fn submit_cast(
    State(state): State<CasterState>,
    Json(request): Json<CastRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let parent_cast_desc = match (&request.parent_cast_fid, &request.parent_cast_hash) {
        (Some(fid), Some(hash)) => format!("{fid}:{hash}"),
        _ => "none".to_string(),
    };
    let parent_url_desc = request
        .parent_url
        .clone()
        .unwrap_or_else(|| "none".to_string());

    println!(
        "ℹ️ Received cast request: fid={}, text_len={}, embeds={}, parent_cast={}, parent_url={}",
        state.fid,
        request.text.trim().len(),
        request.embed_urls.len(),
        parent_cast_desc,
        parent_url_desc
    );

    let text = request.text.trim().to_string();
    if text.is_empty() {
        return Err(ApiError::BadRequest(
            "Cast text cannot be empty".to_string(),
        ));
    }

    if request.parent_cast_fid.is_some() && request.parent_url.is_some() {
        return Err(ApiError::BadRequest(
            "parent_cast_* and parent_url are mutually exclusive".to_string(),
        ));
    }

    let parent_cast_id = match (request.parent_cast_fid, request.parent_cast_hash) {
        (Some(fid), Some(hash)) => Some(CastId { fid, hash }),
        (None, None) => None,
        _ => {
            return Err(ApiError::BadRequest(
                "Both parent_cast_fid and parent_cast_hash are required".to_string(),
            ))
        }
    };

    let password = state
        .password
        .clone()
        .ok_or_else(|| ApiError::InternalError("Caster password not configured".to_string()))?;

    let response = state
        .client
        .submit_cast_with_password(
            state.fid,
            text,
            parent_cast_id,
            request.parent_url,
            request.embed_urls,
            &password,
        )
        .await
        .map_err(|err| {
            let message = err.to_string();
            if message.contains("No Ed25519 key found for FID") {
                ApiError::BadRequest(message)
            } else if message.contains("Failed to decrypt key") {
                ApiError::BadRequest("Invalid password".to_string())
            } else {
                ApiError::InternalError(message)
            }
        })?;

    println!("✅ success full send cast");
    if let Some(data) = response.data.as_ref() {
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            println!("📦 Snapchain receipt:\n{pretty}");
        }
    }

    let payload = serde_json::json!({
        "fid": state.fid,
        "hub_response": response,
    });

    Ok(Json(ApiResponse::success(payload)))
}
