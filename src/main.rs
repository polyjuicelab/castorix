// Castorix CLI - Command line interface for Farcaster protocol interaction
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

use anyhow::Result;
use castorix::cli::commands::Commands;
use castorix::cli::types::HubCommands;
use castorix::cli::types::KeyCommands;
use castorix::cli::Cli;
use castorix::cli::CliHandler;
use castorix::consts;
use castorix::core::client::hub_client::FarcasterClient;
use castorix::core::crypto::key_manager::init_env;
use castorix::core::crypto::key_manager::KeyManager;
use castorix::ens_proof::EnsProof;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize environment variables from .env file
    init_env()?;

    // Parse command line arguments
    let cli = Cli::parse();

    match cli.command {
        Commands::Key { action } => {
            // For encrypted key commands, we don't need to load from env
            match action {
                KeyCommands::Info
                | KeyCommands::GenerateEncrypted
                | KeyCommands::Import
                | KeyCommands::Load { .. }
                | KeyCommands::List
                | KeyCommands::Delete { .. } => {
                    // These commands handle their own key management
                    CliHandler::handle_key_command(
                        action,
                        &KeyManager::from_private_key(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        )?,
                        cli.path.as_deref(),
                    )
                    .await?;
                }
                _ => {
                    println!("❌ Key command requires a wallet name.");
                    println!("💡 Use 'castorix key generate-encrypted <name>' to create an encrypted key, or");
                    println!(
                        "   use 'castorix key load <key-name>' to load an existing encrypted key."
                    );
                }
            }
        }
        Commands::Hub { action } => {
            let hub_url = crate::consts::get_config().farcaster_hub_url().to_string();

            // For read-only operations, we don't need a key manager
            match action {
                HubCommands::User { .. }
                | HubCommands::EthAddresses { .. }
                | HubCommands::EnsDomains { .. }
                | HubCommands::CustodyAddress { .. }
                | HubCommands::Info
                | HubCommands::Followers { .. }
                | HubCommands::Following { .. }
                | HubCommands::Profile { .. }
                | HubCommands::Stats { .. }
                | HubCommands::Spam { .. }
                | HubCommands::SpamStat
                | HubCommands::Casts { .. } => {
                    let hub_client = FarcasterClient::read_only(hub_url);
                    CliHandler::handle_hub_command(action, &hub_client).await?;
                }
                HubCommands::SubmitProof { .. } | HubCommands::Cast { .. } => {
                    // These commands handle their own key management
                    let hub_client = FarcasterClient::read_only(hub_url);
                    CliHandler::handle_hub_command(action, &hub_client).await?;
                }
            }
        }
        Commands::Custody { action } => {
            CliHandler::handle_custody_command(action).await?;
        }
        Commands::Signers { action } => {
            let hub_url = crate::consts::get_config().farcaster_hub_url().to_string();
            let hub_client = FarcasterClient::read_only(hub_url);
            CliHandler::handle_signers_command(action, &hub_client).await?;
        }
        Commands::Ens { action } => {
            let rpc_url = consts::get_config().eth_rpc_url().to_string();

            // Create a dummy key manager for ENS operations
            let dummy_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            if let Ok(key_manager) = KeyManager::from_private_key(dummy_key) {
                let ens_proof = EnsProof::new(key_manager, rpc_url);
                CliHandler::handle_ens_command(action, &ens_proof).await?;
            } else {
                println!("❌ Failed to create key manager for ENS operations");
            }
        }
        Commands::Fid { action } => {
            CliHandler::handle_fid_command(action, cli.path.as_deref()).await?;
        }
        Commands::Storage { action } => {
            CliHandler::handle_storage_command(action, cli.path.as_deref()).await?;
        }
        Commands::Mcp { action } => {
            let hub_url = consts::get_config().farcaster_hub_url().to_string();
            CliHandler::handle_mcp_command(action, hub_url).await?;
        }
        Commands::Api { action } => {
            CliHandler::handle_api_command(action).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use ethers::signers::LocalWallet;
    use ethers::signers::Signer;

    #[test]
    fn test_ecdsa_to_ed25519_conversion() {
        println!("🔑 Testing: ECDSA and Ed25519 private key length verification");
        println!("{}", "=".repeat(60));

        // Generate an ECDSA private key
        let ecdsa_wallet = LocalWallet::new(&mut rand::thread_rng());
        let ecdsa_private_key = ecdsa_wallet.signer().to_bytes();

        println!("📊 ECDSA Private Key Information:");
        println!("   Private Key (hex): {}", hex::encode(ecdsa_private_key));
        println!("   Private Key Length: {} bytes", ecdsa_private_key.len());
        println!("   Private Key Bits: {} bits", ecdsa_private_key.len() * 8);
        println!("   Address: {:?}", ecdsa_wallet.address());

        // Assert that the private key is exactly 32 bytes (256 bits)
        assert_eq!(
            ecdsa_private_key.len(),
            32,
            "ECDSA private key must be exactly 32 bytes (256 bits)"
        );
        assert_eq!(
            ecdsa_private_key.len() * 8,
            256,
            "ECDSA private key must be exactly 256 bits"
        );
        println!(
            "✅ ECDSA private key length verification passed: {} bytes ({} bits)",
            ecdsa_private_key.len(),
            ecdsa_private_key.len() * 8
        );

        // Use the same 256-bit private key for both algorithms
        let ed25519_key = SigningKey::from_bytes(&ecdsa_private_key[..32].try_into().unwrap());
        let ed25519_public = ed25519_key.verifying_key();

        println!("\n📊 Ed25519 Private Key Information:");
        println!(
            "   Public Key (hex): {}",
            hex::encode(ed25519_public.to_bytes())
        );
        println!(
            "   Private Key Length: {} bytes",
            ed25519_key.to_bytes().len()
        );
        println!(
            "   Private Key Bits: {} bits",
            ed25519_key.to_bytes().len() * 8
        );

        // Assert that Ed25519 also uses 32-byte private key
        assert_eq!(
            ed25519_key.to_bytes().len(),
            32,
            "Ed25519 private key must be exactly 32 bytes (256 bits)"
        );
        assert_eq!(
            ed25519_key.to_bytes().len() * 8,
            256,
            "Ed25519 private key must be exactly 256 bits"
        );
        println!(
            "✅ Ed25519 private key length verification passed: {} bytes ({} bits)",
            ed25519_key.to_bytes().len(),
            ed25519_key.to_bytes().len() * 8
        );

        // Verify that both private keys are identical
        assert_eq!(
            ecdsa_private_key,
            ed25519_key.to_bytes().into(),
            "Both private keys must be identical 256-bit integers"
        );
        println!("✅ Private key consistency verification passed: Same 256-bit integer");

        // The private key is the same 256-bit integer, but public keys are different
        println!("\n🎯 Conclusion:");
        println!("   ✅ Same 256-bit private key can be used for both algorithms!");
        println!("   📏 Private key space: [0, 2^256-1] (same for both)");
        println!("   🔐 ECDSA public key: Derived using secp256k1 curve");
        println!("   🔐 Ed25519 public key: Derived using Edwards curve");
        println!("   🔄 The difference is in the public key derivation algorithm, not the private key space");
    }
}
