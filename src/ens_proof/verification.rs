use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;
use ethers::prelude::*;
use ethers::types::Address;

use super::core::EnsProof;
use crate::core::protocol::username_proof::UserNameProof;

impl EnsProof {
    /// Verify ENS domain ownership
    ///
    /// # Arguments
    /// * `domain` - The ENS domain to verify
    ///
    /// # Returns
    /// * `Result<bool>` - True if the domain is owned by the key manager's address
    pub async fn verify_ens_ownership(&self, domain: &str) -> Result<bool> {
        let resolved_address = self.query_base_ens_contract(domain).await?;
        let owner_address = self.key_manager.address();

        match resolved_address {
            Some(addr) => {
                let resolved_addr =
                    Address::from_str(&addr).with_context(|| "Failed to parse resolved address")?;
                Ok(resolved_addr == owner_address)
            }
            None => Ok(false),
        }
    }

    /// Verify a username proof
    ///
    /// # Arguments
    /// * `proof` - The username proof to verify
    ///
    /// # Returns
    /// * `Result<bool>` - True if the proof is valid
    pub async fn verify_proof(&self, proof: &UserNameProof) -> Result<bool> {
        // Recreate the message that was signed
        let message = self.create_proof_message(proof)?;

        // Get the signature
        let signature_bytes = proof.get_signature();
        if signature_bytes.is_empty() {
            return Ok(false);
        }

        // Convert signature bytes to Signature type
        let signature =
            Signature::try_from(signature_bytes).with_context(|| "Failed to parse signature")?;

        // Recover the address from the signature
        let recovered_address = signature
            .recover(message)
            .with_context(|| "Failed to recover address from signature")?;

        // Get the owner address from the proof
        let owner_bytes = proof.get_owner();
        if owner_bytes.len() != 20 {
            return Ok(false);
        }
        let owner_address = Address::from_slice(owner_bytes);

        // Verify that the recovered address matches the owner address in the proof
        Ok(recovered_address == owner_address)
    }
}
