//! API route definitions

use axum::routing::get;
use axum::Router;

use super::handlers::contract;
use super::handlers::ens;
use super::handlers::health;
use super::handlers::hub;

/// Build the main API router
pub fn build_router(
    hub_state: hub::HubState,
    ens_state: Option<ens::EnsState>,
    contract_state: Option<contract::ContractState>,
) -> Router {
    // Create base router with Hub routes
    let mut app = Router::new()
        // Health check
        .route("/health", get(health::health_check))
        // Hub routes
        .route("/api/hub/info", get(hub::get_hub_info))
        .route("/api/hub/users/:fid", get(hub::get_user))
        .route("/api/hub/users/:fid/profile", get(hub::get_profile))
        .route("/api/hub/users/:fid/stats", get(hub::get_stats))
        .route("/api/hub/users/:fid/followers", get(hub::get_followers))
        .route("/api/hub/users/:fid/following", get(hub::get_following))
        .route("/api/hub/users/:fid/addresses", get(hub::get_eth_addresses))
        .route("/api/hub/users/:fid/ens", get(hub::get_ens_domains))
        .route("/api/hub/users/:fid/custody", get(hub::get_custody_address))
        .route("/api/hub/users/:fid/casts", get(hub::get_casts))
        .route("/api/hub/spam/:fid", get(hub::check_spam))
        .with_state(hub_state);

    // Merge ENS routes if available
    if let Some(ens_state) = ens_state {
        let ens_router = Router::new()
            .route("/api/ens/resolve/:domain", get(ens::resolve_domain))
            .route(
                "/api/ens/verify/:domain/:address",
                get(ens::verify_ownership),
            )
            .with_state(ens_state);

        app = app.merge(ens_router);
    }

    // Merge contract routes if available
    if let Some(contract_state) = contract_state {
        let contract_router = Router::new()
            .route("/api/contract/fid/price", get(contract::get_fid_price))
            .route(
                "/api/contract/storage/price/:units",
                get(contract::get_storage_price),
            )
            .route(
                "/api/contract/address/:address/fid",
                get(contract::check_address_fid),
            )
            .with_state(contract_state);

        app = app.merge(contract_router);
    }

    app
}
