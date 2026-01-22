use anyhow::Context;
use anyhow::Result;
use chrono::Utc;
use ed25519_dalek::Signer as Ed25519Signer;
use ed25519_dalek::SigningKey;
use protobuf::Message as ProtobufMessage;
use protobuf::RepeatedField;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;

use crate::core::crypto::key_manager::KeyManager;
use crate::core::protocol::message::CastAddBody;
use crate::core::protocol::message::CastId as ProtoCastId;
use crate::core::protocol::message::CastType;
use crate::core::protocol::message::Embed;
use crate::core::protocol::message::FarcasterNetwork;
use crate::core::protocol::message::HashScheme;
use crate::core::protocol::message::Message;
use crate::core::protocol::message::MessageData;
use crate::core::protocol::message::MessageType;
use crate::core::protocol::message::SignatureScheme;
use crate::core::protocol::username_proof::UserNameProof;
use crate::core::protocol::username_proof::UserNameType;

/// Farcaster Hub client for submitting messages and proofs
pub struct FarcasterClient {
    client: Client,
    hub_url: String,
    key_manager: Option<KeyManager>,
}

/// Farcaster message structure (using protobuf Message)
pub type FarcasterMessage = Message;

/// Signer information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// The signer public key (Ed25519)
    pub key: String,
    /// The key type (1 for Ed25519)
    pub key_type: u32,
    /// The event type (SIGNER_EVENT_TYPE_ADD for active signers)
    pub event_type: String,
}

/// Username proof data for Farcaster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameProofData {
    pub timestamp: u64,
    pub name: String,
    pub owner: String,
    pub signature: String,
    pub fid: u64,
    #[serde(rename = "type")]
    pub proof_type: String,
}

/// Cast message data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastData {
    pub text: String,
    pub mentions: Vec<u64>,
    pub mentions_positions: Vec<u32>,
    pub embeds: Vec<serde_json::Value>,
    pub parent_cast_id: Option<CastId>,
}

/// Cast ID structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastId {
    pub fid: u64,
    pub hash: String,
}

/// Hub response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubResponse {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<serde_json::Value>,
}

impl FarcasterClient {
    /// Create a new Farcaster client
    ///
    /// # Arguments
    /// * `hub_url` - The Farcaster Hub URL
    /// * `key_manager` - Optional key manager instance (required for write operations)
    ///
    /// # Returns
    /// * `Self` - The FarcasterClient instance
    pub fn new(hub_url: String, key_manager: Option<KeyManager>) -> Self {
        Self {
            client: Client::new(),
            hub_url,
            key_manager,
        }
    }

    /// Create a new Farcaster client with key manager
    ///
    /// # Arguments
    /// * `hub_url` - The Farcaster Hub URL
    /// * `key_manager` - The key manager instance
    ///
    /// # Returns
    /// * `Self` - The FarcasterClient instance
    pub fn with_key_manager(hub_url: String, key_manager: KeyManager) -> Self {
        Self::new(hub_url, Some(key_manager))
    }

    /// Create a new Farcaster client from environment variables
    ///
    /// # Returns
    /// * `Result<Self>` - The FarcasterClient instance or an error
    pub fn from_env() -> Result<Self> {
        Err(anyhow::anyhow!(
            "Hub client requires a wallet name. Use FarcasterClient::with_key_manager() instead."
        ))
    }

    /// Create a new Farcaster client without authentication (read-only operations)
    ///
    /// # Arguments
    /// * `hub_url` - The Farcaster Hub URL
    ///
    /// # Returns
    /// * `Self` - The FarcasterClient instance
    pub fn read_only(hub_url: String) -> Self {
        Self::new(hub_url, None)
    }

    /// Submit a username proof to Farcaster Hub using EIP-712 signature
    ///
    /// # Arguments
    /// * `proof` - The username proof to submit
    ///
    /// # Returns
    /// * `Result<HubResponse>` - The hub response or an error
    pub async fn submit_username_proof_with_eip712(
        &self,
        proof: &UserNameProof,
    ) -> Result<HubResponse> {
        if self.key_manager.is_none() {
            anyhow::bail!("Key manager required for EIP-712 signing");
        }

        // Get the correct Ed25519 public key for this FID from the Hub
        let fid = proof.get_fid();
        let ed25519_public_key_hex = self.get_ed25519_public_key_from_hub(fid).await?;

        // Remove 0x prefix if present and decode the public key
        let clean_key = if let Some(stripped) = ed25519_public_key_hex.strip_prefix("0x") {
            stripped
        } else {
            &ed25519_public_key_hex
        };

        let _ed25519_public_key_bytes = hex::decode(clean_key)
            .with_context(|| "Failed to decode Ed25519 public key from hex")?;

        // Create MessageData with username proof
        let mut message_data = MessageData::new();
        // Use Farcaster time (seconds since January 1, 2021)
        const FARCASTER_EPOCH: u64 = 1609459200; // January 1, 2021 UTC in seconds
        let current_timestamp = Utc::now().timestamp() as u64;
        let farcaster_timestamp = (current_timestamp - FARCASTER_EPOCH) as u32;

        message_data.set_field_type(MessageType::MESSAGE_TYPE_USERNAME_PROOF);
        message_data.set_fid(proof.get_fid());
        message_data.set_timestamp(farcaster_timestamp);
        message_data.set_network(FarcasterNetwork::FARCASTER_NETWORK_MAINNET);

        // Set the username proof in the body with current timestamp
        let mut username_proof = proof.clone();
        username_proof.set_timestamp(farcaster_timestamp as u64);
        // Set the correct username type for Base domains
        username_proof.set_field_type(UserNameType::USERNAME_TYPE_BASENAME);
        message_data.set_username_proof_body(username_proof);

        // Create the Message wrapper
        let mut message = Message::new();
        message.set_data(message_data);

        // Calculate hash of the MessageData (using first 20 bytes of blake3 hash like Snapchain)
        let message_data_bytes = message.get_data().write_to_bytes()?;
        let hash = blake3::hash(&message_data_bytes);
        let hash_20 = hash.as_bytes()[..20].to_vec();
        message.set_hash(hash_20.clone());
        message.set_hash_scheme(HashScheme::HASH_SCHEME_BLAKE3);
        message.set_signature_scheme(SignatureScheme::SIGNATURE_SCHEME_ED25519);

        // Sign using Ed25519 with the Ethereum private key converted to Ed25519
        let key_manager = self.key_manager.as_ref().unwrap();
        let wallet = key_manager.wallet();

        // Convert Ethereum private key to Ed25519 for Farcaster
        let private_key_bytes = wallet.signer().to_bytes();
        let ed25519_signing_key =
            SigningKey::from_bytes(&private_key_bytes[..32].try_into().unwrap());
        let signature = ed25519_signing_key.sign(&hash_20);
        message.set_signature(signature.to_bytes().to_vec());

        // For Ed25519 signature scheme, the signer should be the Ed25519 public key
        message.set_signer(ed25519_signing_key.verifying_key().to_bytes().to_vec());

        // Set data_bytes field (required by Farcaster Hub)
        // According to Snapchain docs, when dataBytes is set, data should be undefined
        message.set_data_bytes(message_data_bytes);
        message.clear_data(); // Clear the data field as per Snapchain requirements

        self.submit_message(&message).await
    }

    /// Submit a username proof to Farcaster Hub using Ed25519 key
    ///
    /// # Arguments
    /// * `proof` - The username proof to submit
    /// * `ed25519_key_name` - Name of the Ed25519 key to use for signing
    ///
    /// # Returns
    /// * `Result<HubResponse>` - The hub response or an error
    pub async fn submit_username_proof_with_ed25519(
        &self,
        proof: &UserNameProof,
        fid: u64,
    ) -> Result<HubResponse> {
        // Load encrypted Ed25519 key manager
        let keys_file =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file(
            )?;
        let ed25519_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
                &keys_file,
            )?;

        // Check if Ed25519 key exists for this FID
        if !ed25519_manager.has_key(fid) {
            anyhow::bail!("❌ No Ed25519 key found for FID: {}\n💡 Please generate or import an Ed25519 key for this FID first:\n   castorix hub key generate {}\n   castorix hub key import {}", fid, fid, fid);
        }

        // Prompt for password
        let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
            "Enter password for FID {fid}: "
        ))?;

        // Get the Ed25519 signing key
        let signing_key = ed25519_manager.get_signing_key(fid, &password)?;

        // Create MessageData with username proof
        let mut message_data = MessageData::new();
        // Use Farcaster time (seconds since January 1, 2021)
        const FARCASTER_EPOCH: u64 = 1609459200; // January 1, 2021 UTC in seconds
        let current_timestamp = Utc::now().timestamp() as u64;
        let farcaster_timestamp = (current_timestamp - FARCASTER_EPOCH) as u32;

        message_data.set_field_type(MessageType::MESSAGE_TYPE_USERNAME_PROOF);
        message_data.set_fid(proof.get_fid());
        message_data.set_timestamp(farcaster_timestamp);
        message_data.set_network(FarcasterNetwork::FARCASTER_NETWORK_MAINNET);

        // Set the username proof in the body with current timestamp
        let mut username_proof = proof.clone();
        username_proof.set_timestamp(farcaster_timestamp as u64);
        // Set the correct username type for Base domains
        username_proof.set_field_type(UserNameType::USERNAME_TYPE_BASENAME);
        message_data.set_username_proof_body(username_proof);

        // Create the Message wrapper
        let mut message = Message::new();
        message.set_data(message_data);

        // Calculate hash of the MessageData (using first 20 bytes of blake3 hash like Snapchain)
        let message_data_bytes = message.get_data().write_to_bytes()?;
        let hash = blake3::hash(&message_data_bytes);
        let hash_20 = hash.as_bytes()[..20].to_vec();
        message.set_hash(hash_20.clone());
        message.set_hash_scheme(HashScheme::HASH_SCHEME_BLAKE3);
        message.set_signature_scheme(SignatureScheme::SIGNATURE_SCHEME_ED25519);

        // Sign the hash using the Ed25519 signing key
        let signature = signing_key.sign(&hash_20);
        message.set_signature(signature.to_bytes().to_vec());
        message.set_signer(signing_key.verifying_key().to_bytes().to_vec());

        // Set data_bytes field (required by Farcaster Hub)
        // According to Snapchain docs, when dataBytes is set, data should be undefined
        message.set_data_bytes(message_data_bytes);
        message.clear_data(); // Clear the data field as per Snapchain requirements

        self.submit_message(&message).await
    }

    /// Submit a cast to Farcaster Hub using Ed25519 key
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID to post as
    /// * `text` - Cast text content
    /// * `parent_cast_id` - Optional parent cast (for replies)
    /// * `parent_url` - Optional parent URL (mutually exclusive with parent cast)
    /// * `embed_urls` - Optional embed URLs to attach
    ///
    /// # Returns
    /// * `Result<HubResponse>` - The hub response or an error
    pub async fn submit_cast(
        &self,
        fid: u64,
        text: String,
        parent_cast_id: Option<CastId>,
        parent_url: Option<String>,
        embed_urls: Vec<String>,
    ) -> Result<HubResponse> {
        // Prompt for password
        let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
            "Enter password for FID {fid}: "
        ))?;

        self.submit_cast_with_password(fid, text, parent_cast_id, parent_url, embed_urls, &password)
            .await
    }

    /// Submit a cast to Farcaster Hub using Ed25519 key with a provided password
    pub async fn submit_cast_with_password(
        &self,
        fid: u64,
        text: String,
        parent_cast_id: Option<CastId>,
        parent_url: Option<String>,
        embed_urls: Vec<String>,
        password: &str,
    ) -> Result<HubResponse> {
        if parent_cast_id.is_some() && parent_url.is_some() {
            anyhow::bail!("❌ parent_cast_id and parent_url are mutually exclusive");
        }

        // Load encrypted Ed25519 key manager
        let keys_file =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file(
            )?;
        let ed25519_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
                &keys_file,
            )?;

        // Check if Ed25519 key exists for this FID
        if !ed25519_manager.has_key(fid) {
            anyhow::bail!("❌ No Ed25519 key found for FID: {}\n💡 Please generate or import an Ed25519 key for this FID first:\n   castorix hub key generate {}\n   castorix hub key import {}", fid, fid, fid);
        }

        // Get the Ed25519 signing key
        let signing_key = ed25519_manager.get_signing_key(fid, password)?;

        // Create MessageData with cast add body
        let mut message_data = MessageData::new();
        // Use Farcaster time (seconds since January 1, 2021)
        const FARCASTER_EPOCH: u64 = 1609459200; // January 1, 2021 UTC in seconds
        let current_timestamp = Utc::now().timestamp() as u64;
        let farcaster_timestamp = (current_timestamp - FARCASTER_EPOCH) as u32;

        message_data.set_field_type(MessageType::MESSAGE_TYPE_CAST_ADD);
        message_data.set_fid(fid);
        message_data.set_timestamp(farcaster_timestamp);
        message_data.set_network(FarcasterNetwork::FARCASTER_NETWORK_MAINNET);

        let mut cast_body = CastAddBody::new();
        cast_body.set_text(text);
        cast_body.set_field_type(CastType::CAST);

        if let Some(parent_cast) = parent_cast_id {
            let clean_hash = parent_cast
                .hash
                .strip_prefix("0x")
                .unwrap_or(&parent_cast.hash);
            let hash_bytes = hex::decode(clean_hash)
                .with_context(|| "Failed to decode parent cast hash from hex")?;

            if hash_bytes.len() != 20 {
                anyhow::bail!("❌ Parent cast hash must be 20 bytes (40 hex chars)");
            }

            let mut proto_cast_id = ProtoCastId::new();
            proto_cast_id.set_fid(parent_cast.fid);
            proto_cast_id.set_hash(hash_bytes);
            cast_body.set_parent_cast_id(proto_cast_id);
        }

        if let Some(parent_url) = parent_url {
            cast_body.set_parent_url(parent_url);
        }

        if !embed_urls.is_empty() {
            let mut embeds = RepeatedField::new();
            for url in embed_urls {
                let mut embed = Embed::new();
                embed.set_url(url);
                embeds.push(embed);
            }
            cast_body.set_embeds(embeds);
        }

        message_data.set_cast_add_body(cast_body);

        // Create the Message wrapper
        let mut message = Message::new();
        message.set_data(message_data);

        // Calculate hash of the MessageData (using first 20 bytes of blake3 hash like Snapchain)
        let message_data_bytes = message.get_data().write_to_bytes()?;
        let hash = blake3::hash(&message_data_bytes);
        let hash_20 = hash.as_bytes()[..20].to_vec();
        message.set_hash(hash_20.clone());
        message.set_hash_scheme(HashScheme::HASH_SCHEME_BLAKE3);
        message.set_signature_scheme(SignatureScheme::SIGNATURE_SCHEME_ED25519);

        // Sign the hash using the Ed25519 signing key
        let signature = signing_key.sign(&hash_20);
        message.set_signature(signature.to_bytes().to_vec());
        message.set_signer(signing_key.verifying_key().to_bytes().to_vec());

        // Set data_bytes field (required by Farcaster Hub)
        // According to Snapchain docs, when dataBytes is set, data should be undefined
        message.set_data_bytes(message_data_bytes);
        message.clear_data(); // Clear the data field as per Snapchain requirements

        self.submit_message(&message).await
    }

    /// Submit a username proof to Farcaster Hub (legacy method using Ethereum key)
    ///
    /// # Arguments
    /// * `proof` - The username proof to submit
    ///
    /// # Returns
    /// * `Result<HubResponse>` - The hub response or an error
    pub async fn submit_username_proof(&self, proof: &UserNameProof) -> Result<HubResponse> {
        if self.key_manager.is_none() {
            return Err(anyhow::anyhow!(
                "Key manager required for submitting proofs"
            ));
        }

        // Create MessageData with username proof
        let mut message_data = MessageData::new();
        // Use Farcaster time (seconds since January 1, 2021)
        const FARCASTER_EPOCH: u64 = 1609459200; // January 1, 2021 UTC in seconds
        let current_timestamp = Utc::now().timestamp() as u64;
        let farcaster_timestamp = (current_timestamp - FARCASTER_EPOCH) as u32;

        message_data.set_field_type(MessageType::MESSAGE_TYPE_USERNAME_PROOF);
        message_data.set_fid(proof.get_fid());
        message_data.set_timestamp(farcaster_timestamp);
        message_data.set_network(FarcasterNetwork::FARCASTER_NETWORK_MAINNET);

        // Set the username proof in the body with current timestamp
        let mut username_proof = proof.clone();
        username_proof.set_timestamp(farcaster_timestamp as u64);
        // Set the correct username type for Base domains
        username_proof.set_field_type(UserNameType::USERNAME_TYPE_BASENAME);
        message_data.set_username_proof_body(username_proof);

        // Create the Message wrapper
        let mut message = Message::new();
        message.set_data(message_data);

        // Calculate hash of the MessageData (using first 20 bytes of blake3 hash like Snapchain)
        let message_data_bytes = message.get_data().write_to_bytes()?;
        let hash = blake3::hash(&message_data_bytes);
        let hash_20 = hash.as_bytes()[..20].to_vec();
        message.set_hash(hash_20.clone());
        message.set_hash_scheme(HashScheme::HASH_SCHEME_BLAKE3);
        message.set_signature_scheme(SignatureScheme::SIGNATURE_SCHEME_ED25519);

        // Sign the hash using the private key
        let key_manager = self
            .key_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key manager required for signing"))?;
        let wallet = key_manager.wallet();

        // Convert Ethereum private key to Ed25519 for Farcaster
        // We need to use the same private key bytes for both
        let private_key_bytes = wallet.signer().to_bytes();
        let ed25519_signing_key =
            SigningKey::from_bytes(&private_key_bytes[..32].try_into().unwrap());
        let signature = ed25519_signing_key.sign(&hash_20);
        message.set_signature(signature.to_bytes().to_vec());
        message.set_signer(ed25519_signing_key.verifying_key().to_bytes().to_vec());

        // Set data_bytes field (required by Farcaster Hub)
        // According to Snapchain docs, when dataBytes is set, data should be undefined
        message.set_data_bytes(message_data_bytes);
        message.clear_data(); // Clear the data field as per Snapchain requirements

        self.submit_message(&message).await
    }

    /// Submit a message to Farcaster Hub
    ///
    /// # Arguments
    /// * `message` - The message to submit
    ///
    /// # Returns
    /// * `Result<HubResponse>` - The hub response or an error
    async fn submit_message(&self, message: &FarcasterMessage) -> Result<HubResponse> {
        let url = format!("{}/v1/submitMessage", self.hub_url);

        // Serialize the message to protobuf format
        let message_data = message.write_to_bytes()?;

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(message_data)
            .send()
            .await
            .with_context(|| "Failed to send request to Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response_text) {
                let message = value
                    .get("message")
                    .and_then(|msg| msg.as_str())
                    .map(|msg| msg.to_string());
                let data = value.get("data").cloned().or(Some(value));
                Ok(HubResponse {
                    success: true,
                    message,
                    data,
                })
            } else {
                Ok(HubResponse {
                    success: true,
                    message: Some("Message submitted successfully".to_string()),
                    data: Some(serde_json::json!({ "raw_response": response_text })),
                })
            }
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }

    /// Get user information from Farcaster Hub
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<serde_json::Value>` - The user information or an error
    pub async fn get_user(&self, fid: u64) -> Result<serde_json::Value> {
        let url = format!("{}/v1/userDataByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get user data from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse user data response")
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }

    /// Get Ed25519 public key for a FID from local storage
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<String>` - Ed25519 public key in hex format or an error
    pub async fn get_ed25519_public_key(&self, fid: u64) -> Result<String> {
        get_ed25519_public_key_for_fid(fid).await
    }

    /// Get Ed25519 public key for a FID from Farcaster Hub
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<String>` - Ed25519 public key in hex format or an error
    pub async fn get_ed25519_public_key_from_hub(&self, fid: u64) -> Result<String> {
        // Use the Farcaster Hub API to get user data
        let url = format!("{}/v1/userDataByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get user data from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse user data response")?;

            // Look for Ed25519 public key in the response
            if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                // Get the signer from the first message (all messages should have the same signer)
                if let Some(first_message) = messages.first() {
                    if let Some(signer) = first_message.get("signer").and_then(|s| s.as_str()) {
                        return Ok(signer.to_string());
                    }
                }
            }

            anyhow::bail!("❌ No Ed25519 public key found for FID: {}\n💡 This FID may not have registered an Ed25519 signer", fid);
        } else {
            anyhow::bail!(
                "❌ Failed to get user data from Farcaster Hub: {} - {}",
                status,
                response_text
            );
        }
    }

    /// Get custody address for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<String>` - Custody address (Ethereum address) or an error
    pub async fn get_custody_address(&self, fid: u64) -> Result<String> {
        // Use the Farcaster Hub API to get onchain events for the FID
        let url = format!(
            "{}/v1/onChainEventsByFid?fid={}&event_type=EVENT_TYPE_ID_REGISTER",
            self.hub_url, fid
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get onchain events from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse onchain events response")?;

            // Look for ID_REGISTER events in the response
            if let Some(events) = data.get("events").and_then(|e| e.as_array()) {
                for event in events {
                    if let Some(event_type) = event.get("type").and_then(|t| t.as_str()) {
                        if event_type == "EVENT_TYPE_ID_REGISTER" {
                            if let Some(id_register_body) = event.get("idRegisterEventBody") {
                                if let Some(to_address) =
                                    id_register_body.get("to").and_then(|a| a.as_str())
                                {
                                    return Ok(to_address.to_string());
                                }
                            }
                        }
                    }
                }
            }

            anyhow::bail!("❌ No custody address found for FID: {}\n💡 This FID may not be registered or the address may not be available", fid);
        } else {
            anyhow::bail!(
                "❌ Failed to get onchain events from Farcaster Hub: {} - {}",
                status,
                response_text
            );
        }
    }

    /// Get Ethereum addresses bound to a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<Vec<String>>` - List of Ethereum addresses or an error
    pub async fn get_eth_addresses(&self, fid: u64) -> Result<Vec<String>> {
        // Use the correct Farcaster Hub API endpoint for verifications
        let url = format!("{}/v1/verificationsByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get verification data from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse verification data response")?;

            // Extract Ethereum addresses from the response
            let mut addresses = Vec::new();

            // Parse the Farcaster message format correctly
            if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                for message in messages {
                    // Check if this is a verification message
                    if let Some(data_obj) = message.get("data") {
                        if let Some(message_type) = data_obj.get("type").and_then(|t| t.as_str()) {
                            if message_type == "MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS" {
                                // Extract the verification body
                                if let Some(verification_body) =
                                    data_obj.get("verificationAddAddressBody")
                                {
                                    if let Some(protocol) =
                                        verification_body.get("protocol").and_then(|p| p.as_str())
                                    {
                                        // Only include Ethereum addresses, not Solana
                                        if protocol == "PROTOCOL_ETHEREUM" {
                                            if let Some(address) = verification_body.get("address")
                                            {
                                                if let Some(addr_str) = address.as_str() {
                                                    addresses.push(addr_str.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(addresses)
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }

    /// Get the key manager instance
    pub fn key_manager(&self) -> Option<&KeyManager> {
        self.key_manager.as_ref()
    }

    /// Get casts by FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    /// * `limit` - Maximum number of casts to retrieve (0 for all, default: 100)
    ///
    /// # Returns
    /// * `Result<Vec<serde_json::Value>>` - List of casts or an error
    pub async fn get_casts_by_fid(&self, fid: u64, limit: u32) -> Result<Vec<serde_json::Value>> {
        let mut all_casts = Vec::new();
        let mut page_token: Option<String> = None;
        let page_size = if limit > 0 && limit < 100 { limit } else { 100 };
        let mut total_retrieved = 0;

        loop {
            let mut url = format!(
                "{}/v1/castsByFid?fid={}&pageSize={}&reverse=true",
                self.hub_url, fid, page_size
            );

            if let Some(ref token) = page_token {
                url.push_str(&format!("&pageToken={}", token));
            }

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .with_context(|| "Failed to get casts from Farcaster Hub")?;

            let status = response.status();
            let response_text = response.text().await?;

            if status.is_success() {
                let data: serde_json::Value = serde_json::from_str(&response_text)
                    .with_context(|| "Failed to parse casts response")?;

                if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                    let page_casts = messages.clone();
                    let page_count = page_casts.len();

                    // Check if we would exceed the limit
                    if limit > 0 && total_retrieved + page_count as u32 > limit {
                        let remaining = limit - total_retrieved;
                        let mut truncated = page_casts;
                        truncated.truncate(remaining as usize);
                        all_casts.extend(truncated);
                        break;
                    }

                    all_casts.extend(page_casts);
                    total_retrieved = all_casts.len() as u32;

                    // Check for next page
                    if let Some(next_token) = data.get("nextPageToken").and_then(|t| t.as_str()) {
                        if !next_token.is_empty() && (limit == 0 || total_retrieved < limit) {
                            page_token = Some(next_token.to_string());
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Farcaster Hub returned error {}: {}",
                    status,
                    response_text
                ));
            }
        }

        // No need to reverse since API returns in reverse order when reverse=true
        Ok(all_casts)
    }

    /// Get signers for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<Vec<SignerInfo>>` - List of signer information or an error
    pub async fn get_signers(&self, fid: u64) -> Result<Vec<SignerInfo>> {
        // Use the Farcaster Hub API to get onchain signers
        let url = format!("{}/v1/onChainSignersByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get signers from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse signers response")?;

            let mut signers = Vec::new();

            if let Some(events) = data.get("events").and_then(|e| e.as_array()) {
                for event in events {
                    if let Some(signer_event_body) = event.get("signerEventBody") {
                        if let Some(key) = signer_event_body.get("key").and_then(|k| k.as_str()) {
                            let key_type = signer_event_body
                                .get("keyType")
                                .and_then(|kt| kt.as_u64())
                                .unwrap_or(0);

                            let event_type = signer_event_body
                                .get("eventType")
                                .and_then(|et| et.as_str())
                                .unwrap_or("UNKNOWN");

                            // Only include ADD events (active signers)
                            if event_type == "SIGNER_EVENT_TYPE_ADD" {
                                signers.push(SignerInfo {
                                    key: key.to_string(),
                                    key_type: key_type as u32,
                                    event_type: event_type.to_string(),
                                });
                            }
                        }
                    }
                }
            }

            Ok(signers)
        } else {
            anyhow::bail!(
                "❌ Failed to get signers from Farcaster Hub: {} - {}",
                status,
                response_text
            );
        }
    }

    /// Get the hub URL
    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    /// Get Ed25519 private key for a FID from local storage
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - Ed25519 private key bytes or an error
    #[allow(dead_code)]
    async fn get_ed25519_private_key_for_fid(&self, fid: u64) -> Result<Vec<u8>> {
        // Load encrypted Ed25519 key manager
        let keys_file =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file(
            )?;
        let ed25519_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
                &keys_file,
            )?;

        // Check if Ed25519 key exists for this FID
        if !ed25519_manager.has_key(fid) {
            anyhow::bail!("❌ No Ed25519 key found for FID: {}\n💡 Please generate or import an Ed25519 key for this FID first:\n   castorix hub key generate {}\n   castorix hub key import {}", fid, fid, fid);
        }

        // Prompt for password
        let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
            "Enter password for FID {fid}: "
        ))?;

        // Get the Ed25519 signing key
        let signing_key = ed25519_manager.get_signing_key(fid, &password)?;

        Ok(signing_key.to_bytes().to_vec())
    }

    /// Get Hub information and sync status
    ///
    /// # Returns
    /// * `Result<serde_json::Value>` - The hub information including shard sync status
    pub async fn get_hub_info(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/info", self.hub_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get hub info from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse hub info response")
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }

    /// Get followers for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    /// * `limit` - Maximum number of followers to retrieve (0 for all)
    ///
    /// # Returns
    /// * `Result<Vec<serde_json::Value>>` - List of follower information or an error
    pub async fn get_followers(&self, fid: u64, limit: u32) -> Result<Vec<serde_json::Value>> {
        let mut all_followers = Vec::new();
        let mut page_token: Option<String> = None;
        let page_size = 100; // Fixed page size for better performance
        let mut total_retrieved = 0;
        let mut page_count = 0;

        println!("🔄 Starting to fetch followers for FID: {fid}");

        loop {
            page_count += 1;
            let mut url = format!(
                "{}/v1/linksByTargetFid?target_fid={}&link_type=follow&pageSize={}",
                self.hub_url, fid, page_size
            );

            if let Some(ref token) = page_token {
                url.push_str(&format!("&pageToken={}", token));
            }

            println!("📄 Fetching page {page_count} (page size: {page_size})...");
            println!("🔗 URL: {}", url);

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .with_context(|| "Failed to get followers from Farcaster Hub")?;

            let status = response.status();
            let response_text = response.text().await?;

            if status.is_success() {
                let data: serde_json::Value = serde_json::from_str(&response_text)
                    .with_context(|| "Failed to parse followers response")?;

                if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                    let page_followers = messages.clone();
                    let page_follower_count = page_followers.len();

                    println!("✅ Page {page_count}: Retrieved {page_follower_count} followers");

                    // If we have a limit, check if we would exceed it
                    if limit > 0 && total_retrieved + page_follower_count as u32 > limit {
                        let remaining = limit - total_retrieved;
                        let mut truncated_followers = page_followers;
                        truncated_followers.truncate(remaining as usize);
                        let truncated_count = truncated_followers.len();
                        all_followers.extend(truncated_followers);
                        println!(
                            "🛑 Reached limit of {limit}, stopping at {} total followers",
                            total_retrieved + truncated_count as u32
                        );
                        break;
                    }

                    all_followers.extend(page_followers);
                    total_retrieved = all_followers.len() as u32;
                    println!("📊 Total followers so far: {total_retrieved}");

                    // Check if there's a next page
                    if let Some(next_token) = data.get("nextPageToken").and_then(|t| t.as_str()) {
                        if !next_token.is_empty() {
                            page_token = Some(next_token.to_string());
                            println!("➡️  More pages available, continuing...");
                        } else {
                            println!("🏁 No more pages available");
                            break;
                        }
                    } else {
                        println!("🏁 No nextPageToken found, stopping");
                        break;
                    }
                } else {
                    println!("⚠️  No messages found in response, stopping");
                    break;
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Farcaster Hub returned error {}: {}",
                    status,
                    response_text
                ));
            }
        }

        println!("✅ Completed fetching followers: {total_retrieved} total followers from {page_count} pages");
        Ok(all_followers)
    }

    /// Get following for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    /// * `limit` - Maximum number of following to retrieve (0 for all)
    ///
    /// # Returns
    /// * `Result<Vec<serde_json::Value>>` - List of following information or an error
    pub async fn get_following(&self, fid: u64, limit: u32) -> Result<Vec<serde_json::Value>> {
        let mut all_following = Vec::new();
        let mut page_token: Option<String> = None;
        let page_size = 100; // Fixed page size for better performance
        let mut total_retrieved = 0;
        let mut page_count = 0;

        println!("🔄 Starting to fetch following for FID: {fid}");

        loop {
            page_count += 1;
            let mut url = format!(
                "{}/v1/linksByFid?fid={}&link_type=follow&pageSize={}",
                self.hub_url, fid, page_size
            );

            if let Some(ref token) = page_token {
                url.push_str(&format!("&pageToken={}", token));
            }

            println!("📄 Fetching page {page_count} (page size: {page_size})...");
            println!("🔗 URL: {}", url);

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .with_context(|| "Failed to get following from Farcaster Hub")?;

            let status = response.status();
            let response_text = response.text().await?;

            if status.is_success() {
                let data: serde_json::Value = serde_json::from_str(&response_text)
                    .with_context(|| "Failed to parse following response")?;

                if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                    let page_following = messages.clone();
                    let page_following_count = page_following.len();

                    println!("✅ Page {page_count}: Retrieved {page_following_count} following");

                    // If we have a limit, check if we would exceed it
                    if limit > 0 && total_retrieved + page_following_count as u32 > limit {
                        let remaining = limit - total_retrieved;
                        let mut truncated_following = page_following;
                        truncated_following.truncate(remaining as usize);
                        let truncated_count = truncated_following.len();
                        all_following.extend(truncated_following);
                        println!(
                            "🛑 Reached limit of {limit}, stopping at {} total following",
                            total_retrieved + truncated_count as u32
                        );
                        break;
                    }

                    all_following.extend(page_following);
                    total_retrieved = all_following.len() as u32;
                    println!("📊 Total following so far: {total_retrieved}");

                    // Check if there's a next page
                    if let Some(next_token) = data.get("nextPageToken").and_then(|t| t.as_str()) {
                        if !next_token.is_empty() {
                            page_token = Some(next_token.to_string());
                            println!("➡️  More pages available, continuing...");
                        } else {
                            println!("🏁 No more pages available");
                            break;
                        }
                    } else {
                        println!("🏁 No nextPageToken found, stopping");
                        break;
                    }
                } else {
                    println!("⚠️  No messages found in response, stopping");
                    break;
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Farcaster Hub returned error {}: {}",
                    status,
                    response_text
                ));
            }
        }

        println!("✅ Completed fetching following: {total_retrieved} total following from {page_count} pages");
        Ok(all_following)
    }

    /// Get storage limits for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<serde_json::Value>` - Storage limits information or an error
    pub async fn get_storage_limits(&self, fid: u64) -> Result<serde_json::Value> {
        let url = format!("{}/v1/storageLimitsByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get storage limits from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse storage limits response")?;
            Ok(data)
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }

    /// Get user profile for a FID
    ///
    /// # Arguments
    /// * `fid` - The Farcaster ID
    ///
    /// # Returns
    /// * `Result<Vec<serde_json::Value>>` - List of user profile data or an error
    pub async fn get_user_profile(&self, fid: u64) -> Result<Vec<serde_json::Value>> {
        let url = format!("{}/v1/userDataByFid?fid={}", self.hub_url, fid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to get user profile from Farcaster Hub")?;

        let status = response.status();
        let response_text = response.text().await?;

        if status.is_success() {
            let data: serde_json::Value = serde_json::from_str(&response_text)
                .with_context(|| "Failed to parse user profile response")?;

            if let Some(messages) = data.get("messages").and_then(|m| m.as_array()) {
                Ok(messages.clone())
            } else {
                Ok(vec![])
            }
        } else {
            Err(anyhow::anyhow!(
                "Farcaster Hub returned error {}: {}",
                status,
                response_text
            ))
        }
    }
}

/// Get Ed25519 public key for a specific FID from encrypted storage
///
/// # Arguments
/// * `fid` - The Farcaster ID
///
/// # Returns
/// * `Result<String>` - Ed25519 public key in hex format or an error
pub async fn get_ed25519_public_key_for_fid(fid: u64) -> Result<String> {
    // Load encrypted Ed25519 key manager
    let keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    let ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
            &keys_file,
        )?;

    // Check if Ed25519 key exists for this FID
    if !ed25519_manager.has_key(fid) {
        anyhow::bail!("❌ No Ed25519 key found for FID: {}\n💡 Please generate or import an Ed25519 key for this FID first:\n   castorix hub key generate {}\n   castorix hub key import {}", fid, fid, fid);
    }

    // Get the Ed25519 public key for this FID
    let verifying_key = ed25519_manager.get_verifying_key(fid, "")?;
    Ok(hex::encode(verifying_key.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_farcaster_client_creation() {
        let test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key_manager = KeyManager::from_private_key(test_key).unwrap();
        let client =
            FarcasterClient::new("https://hub-api.neynar.com".to_string(), Some(key_manager));

        assert_eq!(client.hub_url(), "https://hub-api.neynar.com");
    }

    #[tokio::test]
    async fn test_farcaster_client_from_env() {
        // Test that from_env now returns an error (environment variables are no longer allowed)
        let result = FarcasterClient::from_env();
        assert!(result.is_err());
    }
}
