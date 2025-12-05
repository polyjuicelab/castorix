use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;
use ethers::types::Address;

use crate::core::crypto::key_manager::KeyManager;
use crate::core::protocol::username_proof::UserNameProof;
use crate::core::protocol::username_proof::UserNameType;
use crate::encrypted_key_manager::EncryptedKeyManager;

/// ENS domain proof implementation
pub struct EnsProof {
    pub key_manager: KeyManager,
    pub rpc_url: String,
}

impl EnsProof {
    /// Create a new ENS proof instance
    ///
    /// # Arguments
    /// * `key_manager` - The key manager instance
    /// * `rpc_url` - Ethereum RPC URL for ENS resolution
    ///
    /// # Returns
    /// * `Result<Self>` - The EnsProof instance or an error
    pub fn new(key_manager: KeyManager, rpc_url: String) -> Self {
        Self {
            key_manager,
            rpc_url,
        }
    }

    /// Create a new ENS proof instance from environment variables
    ///
    /// # Returns
    /// * `Result<Self>` - The EnsProof instance or an error
    pub fn from_env() -> Result<Self> {
        Err(anyhow::anyhow!(
            "ENS proof requires a wallet name. Use EnsProof::new() instead."
        ))
    }

    /// Resolve ENS domain to address
    ///
    /// # Arguments
    /// * `domain` - The ENS domain to resolve (e.g., "vitalik.eth")
    ///
    /// # Returns
    /// * `Result<Address>` - The resolved address or an error
    pub async fn resolve_ens(&self, domain: &str) -> Result<Address> {
        // Use the Base ENS implementation for resolution
        match self.query_base_ens_contract(domain).await? {
            Some(address_str) => {
                Address::from_str(&address_str).with_context(|| "Failed to parse resolved address")
            }
            None => Err(anyhow::anyhow!("Domain not found: {}", domain)),
        }
    }

    /// Create a username proof for an ENS domain
    ///
    /// # Arguments
    /// * `domain` - The ENS domain name
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<UserNameProof>` - The signed username proof
    pub async fn create_ens_proof(&self, domain: &str, fid: u64) -> Result<UserNameProof> {
        self.create_ens_proof_with_wallet(domain, fid, None).await
    }

    /// Create a username proof for an ENS domain with specific wallet
    ///
    /// # Arguments
    /// * `domain` - The ENS domain name
    /// * `fid` - The Farcaster ID
    /// * `wallet_name` - Optional wallet name for encrypted key
    ///
    /// # Returns
    /// * `Result<UserNameProof>` - The signed username proof
    pub async fn create_ens_proof_with_wallet(
        &self,
        domain: &str,
        fid: u64,
        wallet_name: Option<&str>,
    ) -> Result<UserNameProof> {
        // Get the appropriate key manager
        let key_manager = if let Some(wallet_name) = wallet_name {
            // Load encrypted key manager and decrypt the key
            let mut encrypted_manager = EncryptedKeyManager::default_config();

            // Prompt for password
            let password = crate::encrypted_key_manager::prompt_password(&format!(
                "Enter password for wallet '{wallet_name}': "
            ))?;

            // Load and decrypt the key
            encrypted_manager
                .load_and_decrypt(&password, wallet_name)
                .await?;

            // Get the decrypted key manager
            encrypted_manager
                .key_manager()
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to load key manager for wallet: {}", wallet_name)
                })?
                .clone()
        } else {
            // Try to automatically load custody key for the FID
            let custody_key_file = match crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::custody_key_file(fid) {
                Ok(path) => path,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "❌ Failed to get custody key file path for FID {}: {}\n💡 Please import your custody key first: castorix custody import {}",
                        fid, e, fid
                    ));
                }
            };

            if !std::path::Path::new(&custody_key_file).exists() {
                return Err(anyhow::anyhow!(
                    "❌ No custody key found for FID: {}\n💡 Please import your custody key first: castorix custody import {}\n💡 Or use '--wallet-name' to specify a different wallet",
                    fid, fid
                ));
            }

            // Load the encrypted custody key manager
            let encrypted_manager = match crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::load_from_file(
                &custody_key_file,
            ) {
                Ok(manager) => manager,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "❌ Failed to load custody key file for FID {}: {}\n💡 Please import your custody key again: castorix custody import {}",
                        fid, e, fid
                    ));
                }
            };

            // Check if key exists for this FID
            if !encrypted_manager.has_key(fid) {
                return Err(anyhow::anyhow!(
                    "❌ No custody key found for FID: {}\n💡 Please import your custody key first: castorix custody import {}",
                    fid, fid
                ));
            }

            // Prompt for password
            let password = match crate::core::crypto::encrypted_storage::prompt_password(&format!(
                "Enter password for custody wallet (FID {fid}): "
            )) {
                Ok(pwd) => pwd,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "❌ Failed to prompt for password: {}\n💡 Please try again or import your custody key: castorix custody import {}",
                        e, fid
                    ));
                }
            };

            // Get the wallet
            let wallet = match encrypted_manager.get_wallet(fid, &password) {
                Ok(w) => w,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "❌ Failed to decrypt custody key for FID {}: {}\n💡 Please check your password or import your custody key again: castorix custody import {}",
                        fid, e, fid
                    ));
                }
            };

            // Extract private key from wallet and create KeyManager
            let private_key_bytes = wallet.signer().to_bytes();
            KeyManager::from_private_key(&hex::encode(private_key_bytes))
                .map_err(|e| anyhow::anyhow!(
                    "❌ Failed to create key manager from custody key for FID {}: {}\n💡 Please import your custody key again: castorix custody import {}",
                    fid, e, fid
                ))?
        };

        // Verify domain ownership with the selected key manager
        let resolved_address = self.query_base_ens_contract(domain).await?;
        let owner_address = key_manager.address();

        let is_owned = match resolved_address {
            Some(addr) => {
                let resolved_addr =
                    Address::from_str(&addr).with_context(|| "Failed to parse resolved address")?;
                resolved_addr == owner_address
            }
            None => false,
        };

        if !is_owned {
            return Err(anyhow::anyhow!(
                "Domain {} is not owned by the selected wallet address: {:?}",
                domain,
                owner_address
            ));
        }

        // Create the proof data
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut proof = UserNameProof::new();
        proof.set_timestamp(timestamp);
        proof.set_name(domain.as_bytes().to_vec());
        proof.set_owner(owner_address.as_bytes().to_vec());
        proof.set_fid(fid);

        // Set the correct field type based on domain
        let field_type = if domain.ends_with(".base.eth") {
            UserNameType::USERNAME_TYPE_BASENAME
        } else {
            UserNameType::USERNAME_TYPE_ENS_L1
        };
        proof.set_field_type(field_type);

        // Create the message to sign
        let message = self.create_proof_message(&proof)?;

        // Sign the message with the selected key manager
        let signature = key_manager.sign_message(&message).await?;
        proof.set_signature(signature.to_vec());

        Ok(proof)
    }

    /// Create the message that needs to be signed for the proof
    ///
    /// # Arguments
    /// * `proof` - The username proof (without signature)
    ///
    /// # Returns
    /// * `Result<String>` - The message to sign
    pub fn create_proof_message(&self, proof: &UserNameProof) -> Result<String> {
        // Create a structured message for signing
        // This follows the Farcaster username proof specification
        let message = format!(
            "Farcaster Username Proof\nDomain: {}\nOwner: {}\nFID: {}\nTimestamp: {}",
            String::from_utf8_lossy(proof.get_name()),
            hex::encode(proof.get_owner()),
            proof.get_fid(),
            proof.get_timestamp()
        );

        Ok(message)
    }

    /// Serialize a username proof to JSON
    ///
    /// # Arguments
    /// * `proof` - The username proof to serialize
    ///
    /// # Returns
    /// * `Result<String>` - The JSON representation
    pub fn serialize_proof(&self, proof: &UserNameProof) -> Result<String> {
        let proof_data = ProofData {
            timestamp: proof.get_timestamp(),
            name: String::from_utf8_lossy(proof.get_name()).to_string(),
            owner: hex::encode(proof.get_owner()),
            signature: hex::encode(proof.get_signature()),
            fid: proof.get_fid(),
            field_type: format!("{:?}", proof.get_field_type()),
        };

        serde_json::to_string_pretty(&proof_data).with_context(|| "Failed to serialize proof")
    }

    /// Get the key manager instance
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
}

/// Helper struct for JSON serialization
#[derive(serde::Serialize)]
struct ProofData {
    timestamp: u64,
    name: String,
    owner: String,
    signature: String,
    fid: u64,
    field_type: String,
}
