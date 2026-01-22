//! API server implementation

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::handlers::caster;
use crate::api::handlers::contract;
use crate::api::handlers::ens;
use crate::api::handlers::hub;
use crate::api::routes;
use crate::core::client::FarcasterClient;
use crate::core::crypto::encrypted_storage::prompt_password;
use crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager;
use crate::farcaster::contracts::ContractAddresses;
use crate::farcaster::contracts::FarcasterContractClient;

/// API server configuration
pub struct ApiServer {
    pub host: String,
    pub port: u16,
    pub hub_url: String,
    pub eth_rpc_url: Option<String>,
    pub eth_base_rpc_url: Option<String>,
    pub eth_op_rpc_url: Option<String>,
    pub caster_fid: Option<u64>,
}

impl Default for ApiServer {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            hub_url: std::env::var("FARCASTER_HUB_URL")
                .unwrap_or_else(|_| "https://hub-api.neynar.com".to_string()),
            eth_rpc_url: std::env::var("ETH_RPC_URL").ok(),
            eth_base_rpc_url: std::env::var("ETH_BASE_RPC_URL").ok(),
            eth_op_rpc_url: std::env::var("ETH_OP_RPC_URL").ok(),
            caster_fid: None,
        }
    }
}

impl ApiServer {
    /// Create a new API server with custom configuration
    pub fn new(host: impl Into<String>, port: u16, hub_url: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            hub_url: hub_url.into(),
            ..Default::default()
        }
    }

    /// Start the API server
    ///
    /// # Security
    ///
    /// This API server is READ-ONLY by default and NEVER touches private keys.
    /// When started in "caster" mode, it enables cast submission and uses local Ed25519 keys.
    ///
    /// ⚠️  Caster mode should NOT be exposed to the internet.
    pub async fn serve(self) -> Result<()> {
        info!("🚀 Starting Castorix REST API server");
        info!("   Host: {}", self.host);
        info!("   Port: {}", self.port);
        info!("   Hub URL: {}", self.hub_url);
        if let Some(fid) = self.caster_fid {
            info!("🔓 Security: CASTER mode enabled (FID: {fid})");
            info!("⚠️  Do NOT expose this server publicly");
        } else {
            info!("🔒 Security: READ-ONLY mode (no private key access)");
        }

        // SECURITY: Create Hub client WITHOUT key manager (read-only by default)
        let hub_client = Arc::new(FarcasterClient::new(self.hub_url.clone(), None));
        let hub_state = hub::HubState { client: hub_client };

        let caster_state = if let Some(fid) = self.caster_fid {
            let keys_file = EncryptedEd25519KeyManager::default_keys_file()?;
            let ed25519_manager = EncryptedEd25519KeyManager::load_from_file(&keys_file)?;

            if !ed25519_manager.has_key(fid) {
                anyhow::bail!(
                    "❌ No Ed25519 key found for FID: {}\n💡 Please generate or import an Ed25519 key first:\n   castorix hub key generate {}\n   castorix hub key import {}",
                    fid,
                    fid,
                    fid
                );
            }

            let password = match std::env::var("CASTORIX_CASTER_PASSWORD").ok() {
                Some(value) if !value.is_empty() => value,
                _ => prompt_password(&format!("Enter password for FID {fid}: "))?,
            };

            ed25519_manager
                .get_signing_key(fid, &password)
                .map_err(|err| {
                    anyhow::anyhow!("❌ Failed to decrypt Ed25519 key for FID {}: {}", fid, err)
                })?;

            info!("✅ Ed25519 key unlocked for FID: {fid}");
            println!("✅ Ed25519 key unlocked for FID: {fid}");

            Some(caster::CasterState {
                client: hub_state.client.clone(),
                fid,
                password: Some(password),
            })
        } else {
            None
        };

        // Create ENS state if RPC URL is available
        let ens_state = if self.eth_rpc_url.is_some() {
            info!("✅ ENS endpoints enabled");
            Some(ens::EnsState {
                eth_rpc_url: self.eth_rpc_url.clone().unwrap(),
                base_rpc_url: self.eth_base_rpc_url.clone(),
            })
        } else {
            info!("⚠️  ENS endpoints disabled (no ETH_RPC_URL)");
            None
        };

        // Create Contract state if Optimism RPC URL is available
        // SECURITY: Contract client is for QUERY operations only (no signing)
        let contract_state = if let Some(op_rpc_url) = &self.eth_op_rpc_url {
            info!("✅ Contract endpoints enabled (query-only)");
            let addresses = ContractAddresses::default();
            let client = FarcasterContractClient::new(op_rpc_url.to_string(), addresses)
                .context("Failed to create contract client")?;
            Some(contract::ContractState {
                client: Arc::new(client),
            })
        } else {
            info!("⚠️  Contract endpoints disabled (no ETH_OP_RPC_URL)");
            None
        };

        // Log available endpoints based on enabled features
        let has_ens = ens_state.is_some();
        let has_contract = contract_state.is_some();

        // Build router
        let app = routes::build_router(hub_state, ens_state, contract_state, caster_state)
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            )
            .layer(TraceLayer::new_for_http());

        // Create server address
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .context("Invalid host:port combination")?;

        info!("🎯 API server listening on http://{}", addr);
        info!("📚 Available endpoints:");
        println!("🚀 Server listening on http://{}", addr);
        println!("📚 Available endpoints:");
        info!("   GET  /health - Health check");
        info!("   GET  /api/hub/info - Hub information");
        info!("   GET  /api/hub/users/:fid - User info");
        info!("   GET  /api/hub/users/:fid/profile - User profile");
        info!("   GET  /api/hub/users/:fid/stats - User stats");
        info!("   GET  /api/hub/users/:fid/followers - Followers");
        info!("   GET  /api/hub/users/:fid/following - Following");
        info!("   GET  /api/hub/users/:fid/casts - User casts");
        info!("   GET  /api/hub/spam/:fid - Spam check");

        if let Some(fid) = self.caster_fid {
            info!("   POST /api/caster/cast - Submit cast (JSON)");
            println!("   POST /api/caster/cast - Submit cast (JSON)");
            println!("🔗 Caster FID: {fid}");
        }

        if has_ens {
            info!("   GET  /api/ens/resolve/:domain - Resolve ENS");
            info!("   GET  /api/ens/verify/:domain/:address - Verify ownership");
        }

        if has_contract {
            info!("   GET  /api/contract/fid/price - FID price");
            info!("   GET  /api/contract/storage/price/:units - Storage price");
            info!("   GET  /api/contract/address/:address/fid - Check address FID");
        }

        // Start server
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("Failed to bind to address")?;

        axum::serve(listener, app).await.context("Server error")?;

        Ok(())
    }
}
