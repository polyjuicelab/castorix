//! API server command handlers

use anyhow::Result;

use crate::api::server::ApiServer;

/// Handle API server commands
pub async fn handle_api_command(host: String, port: u16) -> Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();

    let hub_url = std::env::var("FARCASTER_HUB_URL")
        .unwrap_or_else(|_| "https://hub-api.neynar.com".to_string());

    let server = ApiServer {
        host,
        port,
        hub_url,
        eth_rpc_url: std::env::var("ETH_RPC_URL").ok(),
        eth_base_rpc_url: std::env::var("ETH_BASE_RPC_URL").ok(),
        eth_op_rpc_url: std::env::var("ETH_OP_RPC_URL").ok(),
    };

    server.serve().await
}
