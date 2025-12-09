pub mod api_handlers;
pub mod custody_handlers;
pub mod ens_handlers;
pub mod fid_handlers;
pub mod hub_handlers;
pub mod key_handlers;
pub mod mcp_handlers;
pub mod signers_handlers;
pub mod storage_handlers;

use anyhow::Result;

use crate::cli::types::ApiCommands;
use crate::cli::types::CustodyCommands;
use crate::cli::types::EnsCommands;
use crate::cli::types::FidCommands;
use crate::cli::types::HubCommands;
use crate::cli::types::HubKeyCommands;
use crate::cli::types::KeyCommands;
use crate::cli::types::McpCommands;
use crate::cli::types::SignersCommands;
use crate::cli::types::StorageCommands;

/// CLI command handler
pub struct CliHandler;

impl CliHandler {
    /// Handle key management commands (legacy)
    pub async fn handle_key_command(
        command: KeyCommands,
        key_manager: &crate::core::crypto::key_manager::KeyManager,
        storage_path: Option<&str>,
    ) -> Result<()> {
        crate::cli::handlers::key_handlers::core::handle_key_command(
            command,
            key_manager,
            storage_path,
        )
        .await
    }

    /// Handle Hub Ed25519 key management commands
    pub async fn handle_hub_key_command(command: HubKeyCommands) -> Result<()> {
        crate::cli::handlers::key_handlers::hub::handle_hub_key_command(command).await
    }

    /// Handle ENS commands
    pub async fn handle_ens_command(
        command: EnsCommands,
        ens_proof: &crate::ens_proof::EnsProof,
    ) -> Result<()> {
        ens_handlers::handle_ens_command(command, ens_proof).await
    }

    /// Handle Farcaster Hub commands
    pub async fn handle_hub_command(
        command: HubCommands,
        hub_client: &crate::core::client::hub_client::FarcasterClient,
    ) -> Result<()> {
        hub_handlers::handle_hub_command(command, hub_client).await
    }

    /// Handle ECDSA custody key management commands
    pub async fn handle_custody_command(command: CustodyCommands) -> Result<()> {
        custody_handlers::handle_custody_command(command).await
    }

    /// Handle signer management commands
    pub async fn handle_signers_command(
        command: SignersCommands,
        hub_client: &crate::core::client::hub_client::FarcasterClient,
    ) -> Result<()> {
        signers_handlers::handle_signers_command(command, hub_client).await
    }

    /// Handle FID registration and management commands
    pub async fn handle_fid_command(
        command: FidCommands,
        storage_path: Option<&str>,
    ) -> Result<()> {
        fid_handlers::handle_fid_command(command, storage_path).await
    }

    /// Handle storage rental and management commands
    pub async fn handle_storage_command(
        command: StorageCommands,
        storage_path: Option<&str>,
    ) -> Result<()> {
        storage_handlers::handle_storage_command(command, storage_path).await
    }

    /// Handle MCP server commands
    pub async fn handle_mcp_command(command: McpCommands, hub_url: String) -> Result<()> {
        mcp_handlers::handle_mcp_command(command, hub_url).await
    }

    /// Handle API server commands
    pub async fn handle_api_command(command: ApiCommands) -> Result<()> {
        match command {
            ApiCommands::Serve { host, port } => api_handlers::handle_api_command(host, port).await,
        }
    }
}
