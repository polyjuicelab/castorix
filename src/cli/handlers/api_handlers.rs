//! API server command handlers

use anyhow::Result;

use crate::api::server::ApiServer;
use crate::cli::types::ApiServeMode;

/// Handle API server commands
pub async fn handle_api_command(host: String, port: u16, mode: Option<ApiServeMode>) -> Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();

    let hub_url = std::env::var("FARCASTER_HUB_URL")
        .unwrap_or_else(|_| "https://hub-api.neynar.com".to_string());

    let default_host = host;
    let default_port = port;
    let (host, port, caster_fid) = match mode {
        Some(ApiServeMode::Caster { fid, host, port }) => (
            host.unwrap_or(default_host),
            port.unwrap_or(default_port),
            Some(fid),
        ),
        None => (default_host, default_port, None),
    };

    let server = ApiServer {
        host,
        port,
        hub_url,
        eth_rpc_url: std::env::var("ETH_RPC_URL").ok(),
        eth_base_rpc_url: std::env::var("ETH_BASE_RPC_URL").ok(),
        eth_op_rpc_url: std::env::var("ETH_OP_RPC_URL").ok(),
        caster_fid,
    };

    server.serve().await
}
