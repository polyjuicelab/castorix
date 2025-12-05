use aes_gcm::aead::Aead;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use aes_gcm::Nonce;
use anyhow::Result;
use argon2::password_hash::SaltString;
use argon2::Argon2;
use argon2::PasswordHasher;
use base64::engine::general_purpose;
use base64::Engine as _;
use ethers::prelude::Middleware;
use ethers::signers::Signer;

use crate::cli::types::SignersCommands;
use crate::core::client::hub_client::FarcasterClient;
use crate::farcaster::contracts::types::ContractResult;

#[derive(Debug, Clone)]
struct LocalEd25519Key {
    name: String,
    public_key: String,
}

/// Handle signers commands
pub async fn handle_signers_command(
    command: SignersCommands,
    hub_client: &FarcasterClient,
) -> Result<()> {
    match command {
        SignersCommands::List => {
            handle_signers_list().await?;
        }
        SignersCommands::Info { fid } => {
            handle_signers_info(hub_client, fid).await?;
        }
        SignersCommands::Register {
            fid,
            wallet,
            payment_wallet,
            dry_run,
            yes,
        } => {
            handle_add_signer(
                hub_client,
                fid,
                wallet.as_deref(),
                payment_wallet.as_deref(),
                dry_run,
                yes,
            )
            .await?;
        }
        SignersCommands::Unregister {
            fid,
            wallet,
            payment_wallet,
            dry_run,
        } => {
            handle_del_signer(
                hub_client,
                fid,
                wallet.as_deref(),
                payment_wallet.as_deref(),
                dry_run,
            )
            .await?;
        }
        SignersCommands::Import { fid } => {
            handle_signers_import(fid).await?;
        }
        SignersCommands::Export { identifier } => {
            handle_signers_export(&identifier).await?;
        }
        SignersCommands::Delete { identifier } => {
            handle_signers_delete(&identifier).await?;
        }
    }
    Ok(())
}

async fn handle_signers_info(hub_client: &FarcasterClient, fid: u64) -> Result<()> {
    println!("🔐 Getting signers for FID: {fid}");
    match hub_client.get_signers(fid).await {
        Ok(signers) => {
            if signers.is_empty() {
                println!("ℹ️  No active signers found for FID: {fid}");
                println!("   This FID may not have any registered signers yet.");
            } else {
                println!(
                    "✅ Found {} active signer(s) for FID {}:",
                    signers.len(),
                    fid
                );

                // Get locally stored Ed25519 keys for this FID
                let local_keys = get_local_ed25519_keys_for_fid(fid).await?;

                for (i, signer) in signers.iter().enumerate() {
                    println!("\n🔑 Signer #{}:", i + 1);
                    println!("   Public Key: {}", signer.key);
                    println!("   Key Type: {} (1 = Ed25519)", signer.key_type);
                    println!("   Status: {} (Active)", signer.event_type);

                    // Check if this public key has a corresponding local private key
                    let has_local_key = local_keys.iter().any(|local_key| {
                        // Compare public keys (remove 0x prefix if present)
                        let hub_key = signer.key.trim_start_matches("0x");
                        let local_key = local_key.public_key.trim_start_matches("0x");
                        hub_key == local_key
                    });

                    if has_local_key {
                        println!("   💾 Local Storage: ✅ Private key available locally");
                    } else {
                        println!("   💾 Local Storage: ❌ No private key found locally");
                    }
                }

                // Show summary of local keys
                if !local_keys.is_empty() {
                    println!("\n📋 Local Ed25519 Keys Summary:");
                    for local_key in &local_keys {
                        println!("   🔑 {} - {}", local_key.name, local_key.public_key);
                    }
                } else {
                    println!("\n💡 No local Ed25519 keys found for FID {fid}");
                    println!("   Use 'castorix signers register {fid} --wallet <wallet>' to add a signer");
                }
            }
        }
        Err(e) => println!("❌ Failed to get signers: {e}"),
    }
    Ok(())
}

async fn handle_add_signer(
    _hub_client: &FarcasterClient,
    fid: u64,
    wallet_name: Option<&str>,
    payment_wallet_name: Option<&str>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    println!("➕ Adding signer for FID: {fid}");

    // Determine the custody wallet name
    let wallet_name = match wallet_name {
        Some(name) => name.to_string(),
        None => {
            // Auto-detect custody wallet for this FID
            match find_custody_wallet_for_fid(fid).await? {
                Some(name) => {
                    println!("🔍 Auto-detected custody wallet: {name}");
                    name
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "❌ No custody wallet found for FID {fid}. Please create one first using:\n   castorix custody import {fid}\n   or\n   castorix custody from-mnemonic {fid}"
                    ));
                }
            }
        }
    };

    println!("🔑 Using custody wallet: {wallet_name}");

    // Determine payment wallet
    let payment_wallet_name = payment_wallet_name.unwrap_or(&wallet_name);
    if payment_wallet_name != wallet_name {
        println!("💰 Using payment wallet: {payment_wallet_name}");
        println!("   (Third-party gas payment enabled)");
    } else {
        println!("💰 Using custody wallet for gas payment");
    }

    // Load FID-specific custody key file
    let custody_key_file =
        crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::custody_key_file(fid)?;

    if !std::path::Path::new(&custody_key_file).exists() {
        return Err(anyhow::anyhow!(
            "❌ No custody key found for FID {fid}. Please create one first using:\n   castorix custody import {fid}\n   or\n   castorix custody from-mnemonic {fid}"
        ));
    }

    // Load encrypted ETH key manager
    let encrypted_manager =
        crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::load_from_file(
            &custody_key_file,
        )?;

    // Prompt for password
    let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
        "Enter password for custody wallet (FID {fid}): "
    ))?;

    // Get the wallet directly
    let wallet = encrypted_manager
        .get_wallet(fid, &password)
        .map_err(|e| anyhow::anyhow!("Failed to load wallet for FID {}: {}", fid, e))?;

    // Create FarcasterContractClient with the custody wallet for authorization
    let contract_client = create_contract_client_with_local_wallet(wallet).await?;

    // If using third-party payment, create a separate client for the payment wallet
    let payment_contract_client = if payment_wallet_name != wallet_name {
        // Load payment wallet
        let mut payment_encrypted_manager =
            crate::encrypted_key_manager::EncryptedKeyManager::default_config();
        let payment_password = crate::encrypted_key_manager::prompt_password(&format!(
            "Enter password for payment wallet '{payment_wallet_name}': "
        ))?;

        payment_encrypted_manager
            .load_and_decrypt(&payment_password, payment_wallet_name)
            .await?;

        let payment_key_manager = payment_encrypted_manager
            .key_manager()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to load key manager for payment wallet: {}",
                    payment_wallet_name
                )
            })?
            .clone();

        Some(create_contract_client_with_wallet(payment_key_manager).await?)
    } else {
        None
    };

    // Generate a new Ed25519 key pair
    let signing_key = crate::farcaster::contracts::key_utils::generate_ed25519_keypair();
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    println!(
        "🔑 Generated Ed25519 public key: {}",
        hex::encode(&public_key)
    );

    // Get FID information to verify ownership
    let fid_info = contract_client.get_fid_info(fid).await?;
    println!("👤 FID {fid} Information:");
    println!("   Custody: {}", fid_info.custody);
    println!("   Recovery: {}", fid_info.recovery);
    println!("   Active Keys: {}", fid_info.active_keys);
    println!("   Inactive Keys: {}", fid_info.inactive_keys);
    println!("   Pending Keys: {}", fid_info.pending_keys);

    // Verify that the wallet can manage this FID's keys
    let wallet_address = contract_client
        .wallet_address()
        .ok_or_else(|| anyhow::anyhow!("No wallet address available"))?;

    if wallet_address != fid_info.custody {
        return Err(anyhow::anyhow!(
            "❌ Wallet address {} does not match custody address {} for FID {}\n\n\
            💡 To manage signers for this FID, you need the correct custody wallet.\n\
            📝 The custody address for FID {} is: {}\n\
            🔑 If you have the private key for this address, import it using:\n\
               castorix custody import {} --address {}\n\
            🔑 Or if you have the mnemonic for this address, use:\n\
               castorix custody from-mnemonic {}",
            wallet_address,
            fid_info.custody,
            fid,
            fid,
            fid_info.custody,
            fid,
            fid_info.custody,
            fid
        ));
    }

    println!("✅ Wallet authorized to manage FID {fid}");

    if dry_run {
        println!("\n🧪 DRY-RUN MODE: Simulating transaction without sending to chain");
        println!("   • This would register a new Ed25519 signer on the Farcaster network");
        println!("   • This would consume gas fees");
        println!("   • The signer would be permanently associated with FID {fid}");
        println!("   • This action cannot be easily undone");

        if payment_wallet_name != wallet_name {
            println!("   • Third-party gas payment enabled");
            println!("   • Custody wallet: {wallet_name} (for authorization)");
            println!("   • Payment wallet: {payment_wallet_name} (for gas fees)");
        } else {
            println!("   • Using custody wallet for both authorization and gas payment");
        }

        // Create EIP-712 signature for signer registration (simulation)
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs()
            + 3600; // 1 hour from now

        let signature = create_signer_add_signature(
            &contract_client,
            fid,
            fid_info.custody,
            &public_key,
            deadline,
        )
        .await?;

        println!("📝 Created EIP-712 signature for signer registration");
        println!(
            "🔑 Generated Ed25519 public key: {}",
            hex::encode(&public_key)
        );
        println!("📝 Signature: {}", hex::encode(&signature));
        println!("⏰ Deadline: {}", deadline);

        // Simulate the transaction call without sending
        println!("⛓️  Simulating on-chain registration...");
        println!("   • Contract: KeyGateway");
        println!("   • Method: add_for");
        println!("   • FID Owner: {}", fid_info.custody);
        println!("   • Key Type: 1 (Ed25519)");
        println!("   • Public Key: {}", hex::encode(&public_key));
        println!("   • Metadata Type: 1");
        println!("   • Metadata: []");
        println!("   • Deadline: {}", deadline);

        println!("\n✅ DRY-RUN COMPLETE: Transaction would be sent successfully!");
        println!("💡 To actually send the transaction, run without --dry-run flag");

        // Still store the Ed25519 private key encrypted locally for dry-run
        println!("\n🔐 Storing Ed25519 private key encrypted locally...");

        // Convert Ed25519 private key to hex string for storage
        let private_key_hex = hex::encode(signing_key.to_bytes());

        // Create a new encrypted manager for the Ed25519 key
        let mut ed25519_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::new();

        // Prompt for Ed25519 key password (twice for confirmation)
        let ed25519_password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
            "Enter password to encrypt Ed25519 key for FID {fid}: "
        ))?;

        let ed25519_password_confirm = crate::core::crypto::encrypted_storage::prompt_password(
            &format!("Confirm password for Ed25519 key for FID {fid}: "),
        )?;

        if ed25519_password != ed25519_password_confirm {
            anyhow::bail!("Passwords do not match. Please try again.");
        }

        // Store the Ed25519 key encrypted
        ed25519_manager
            .import_and_encrypt(fid, &private_key_hex, &ed25519_password)
            .await?;

        // Save to the correct file
        let ed25519_keys_file =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file(
            )?;
        ed25519_manager.save_to_file(&ed25519_keys_file)?;

        println!("✅ Ed25519 private key stored encrypted for FID: {fid}");
        println!("🔑 Public key: {}", hex::encode(&public_key));
        println!("📝 You can now use this signer for Farcaster operations with FID {fid}");
        println!("💡 Run 'castorix signers register {fid}' to actually register on-chain");

        return Ok(());
    }

    // ⚠️  IMPORTANT: This will trigger on-chain operations
    println!("\n⚠️  ON-CHAIN OPERATION WARNING:");
    println!("   • This will register a new Ed25519 signer on the Farcaster network");
    println!("   • The operation will consume gas fees");
    println!("   • The signer will be permanently associated with FID {fid}");
    println!("   • This action cannot be easily undone");

    if payment_wallet_name != wallet_name {
        println!("   • Third-party gas payment enabled");
        println!("   • Custody wallet: {wallet_name} (for authorization)");
        println!("   • Payment wallet: {payment_wallet_name} (for gas fees)");
    } else {
        println!("   • Using custody wallet for both authorization and gas payment");
    }

    // Ask for user confirmation (skip if --yes is provided)
    if !yes {
        print!("\n❓ Do you want to proceed with the on-chain registration? (yes/no): ");
        use std::io::Write;
        use std::io::{
            self,
        };
        io::stdout().flush()?;

        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        let confirmation = confirmation.trim().to_lowercase();

        if confirmation != "yes" && confirmation != "y" {
            println!("❌ Operation cancelled by user");
            return Ok(());
        }
    } else {
        println!("\n✅ Auto-confirmed with --yes flag");
    }

    println!("✅ Proceeding with on-chain registration...");

    // Create deadline
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_secs()
        + 3600; // 1 hour from now

    // Register the signer on-chain
    println!("⛓️  Registering signer on-chain...");

    // Use payment wallet if provided, otherwise use custody wallet
    let (result, actual_wallet_address) = if let Some(payment_client) = payment_contract_client {
        println!("💰 Using third-party payment wallet for transaction...");

        // Debug: Print wallet addresses
        let custody_address = contract_client.wallet_address().unwrap_or_default();
        let payment_address = payment_client.wallet_address().unwrap_or_default();
        println!("   • Custody wallet (for signing): {}", custody_address);
        println!("   • Payment wallet (for gas): {}", payment_address);

        // For third-party payment, create SignedKeyRequest signature first
        let signed_key_request_signature = contract_client
            .create_signed_key_request_signature(fid, fid_info.custody, &public_key, deadline)
            .await?;

        // Then create metadata using SignedKeyRequestValidator with the signature
        let metadata = contract_client
            .create_signed_key_request_metadata(
                fid,
                fid_info.custody,
                &public_key,
                deadline,
                signed_key_request_signature,
            )
            .await?;

        // Create EIP-712 signature for KeyGateway.addFor
        let add_for_signature = contract_client
            .create_add_for_signature(
                fid_info.custody,
                1u32, // Ed25519 key type
                &public_key,
                1u8, // Metadata type
                &metadata,
                deadline,
            )
            .await?;

        println!(
            "📝 Created metadata using SignedKeyRequestValidator: {} bytes",
            metadata.len()
        );

        // Get the payment wallet for raw transaction
        let payment_wallet = payment_client
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Payment wallet not available"))?;

        let result = payment_client
            .key_gateway
            .add_for_raw(
                &payment_client.provider,
                payment_wallet,
                fid_info.custody,
                1, // Ed25519 key type
                public_key.clone(),
                1,        // Metadata type
                metadata, // Use the encoded metadata
                deadline.into(),
                add_for_signature, // Use the correct EIP-712 signature
            )
            .await?;

        (result, payment_address)
    } else {
        println!("💰 Using custody wallet for transaction...");

        // Debug: Print wallet address
        let custody_address = contract_client.wallet_address().unwrap_or_default();
        println!(
            "   • Custody wallet (for both signing and gas): {}",
            custody_address
        );

        // For direct payment, create SignedKeyRequest signature first
        let signed_key_request_signature = contract_client
            .create_signed_key_request_signature(fid, fid_info.custody, &public_key, deadline)
            .await?;

        // Then create metadata using SignedKeyRequestValidator with the signature
        let metadata = contract_client
            .create_signed_key_request_metadata(
                fid,
                fid_info.custody,
                &public_key,
                deadline,
                signed_key_request_signature,
            )
            .await?;

        // Create EIP-712 signature for KeyGateway.addFor
        let add_for_signature = contract_client
            .create_add_for_signature(
                fid_info.custody,
                1u32, // Ed25519 key type
                &public_key,
                1u8, // Metadata type
                &metadata,
                deadline,
            )
            .await?;

        println!(
            "📝 Created metadata using SignedKeyRequestValidator: {} bytes",
            metadata.len()
        );

        // Get the custody wallet for raw transaction
        let custody_wallet = contract_client
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Custody wallet not available"))?;

        let result = contract_client
            .key_gateway
            .add_for_raw(
                &contract_client.provider,
                custody_wallet,
                fid_info.custody,
                1, // Ed25519 key type
                public_key.clone(),
                1,        // Metadata type
                metadata, // Use the encoded metadata
                deadline.into(),
                add_for_signature, // Use the correct EIP-712 signature
            )
            .await?;

        (result, custody_address)
    };

    match result {
        ContractResult::Success(receipt) => {
            println!("✅ Signer registered successfully on-chain!");
            println!("🔗 Transaction Hash: {:?}", receipt.transaction_hash);
            println!("⛽ Gas Used: {}", receipt.gas_used.unwrap_or_default());
            println!(
                "📊 Block Number: {}",
                receipt.block_number.unwrap_or_default()
            );
            println!("⛽ Gas Price: {:?}", receipt.effective_gas_price);
            println!(
                "📈 Status: {}",
                if receipt.status == Some(1.into()) {
                    "Success"
                } else {
                    "Failed"
                }
            );
        }
        ContractResult::Error(e) => {
            println!("❌ Contract call failed with error: {}", e);

            // Check if it's a gas-related error
            let error_str = e.to_string();
            if error_str.contains("insufficient funds")
                || error_str.contains("gas required exceeds allowance")
                || error_str.contains("out of gas")
                || error_str.contains("0x8baa579f")
            {
                println!(
                    "\n💡 This appears to be a gas-related error. Let's check your wallet balance:"
                );

                // Get wallet balance for the actual wallet used for the transaction
                let balance = contract_client
                    .provider()
                    .get_balance(actual_wallet_address, None)
                    .await
                    .unwrap_or_else(|_| 0.into());
                let balance_eth = ethers::utils::format_units(balance, "ether")
                    .unwrap_or_else(|_| "Unknown".to_string());

                println!("   • Wallet Address: {}", actual_wallet_address);
                println!("   • Current Balance: {} ETH", balance_eth);

                let min_balance =
                    ethers::utils::parse_units("0.001", "ether").unwrap_or_else(|_| {
                        ethers::utils::ParseUnits::U256(ethers::types::U256::from(
                            1000000000000000u64,
                        ))
                    }); // 0.001 ETH in wei
                if balance < min_balance.into() {
                    println!("\n⚠️  WARNING: Your wallet balance is very low!");
                    println!("   • You need at least 0.001 ETH to cover gas fees");
                    println!("   • Current balance: {} ETH", balance_eth);
                    println!("   • Please add funds to your wallet and try again");
                } else {
                    println!(
                        "\n💡 Your balance seems sufficient. This might be a different issue:"
                    );
                    println!("   • Check if the contract is paused");
                    println!("   • Verify the signature is correct");
                    println!("   • Ensure the deadline hasn't expired");
                }
            }

            println!("\n🔍 Debug information:");
            println!("   • FID: {}", fid);
            println!("   • Custody: {}", fid_info.custody);
            println!("   • Public Key: {}", hex::encode(&public_key));
            println!("   • Deadline: {}", deadline);

            // Try to decode the error if it's a hex string
            if error_str.contains("0x") {
                println!("   • Raw Error: {}", error_str);
                println!("   • This might be a contract-specific error code");
            }

            return Err(anyhow::anyhow!("❌ Failed to register signer: {}", e));
        }
    }

    // Store the Ed25519 private key encrypted locally
    println!("🔐 Storing Ed25519 private key encrypted...");

    // Convert Ed25519 private key to hex string for storage
    let private_key_hex = hex::encode(signing_key.to_bytes());

    // Create a new encrypted Ed25519 manager
    let mut ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::new();

    // Load existing keys if any
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    if std::path::Path::new(&ed25519_keys_file).exists() {
        ed25519_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
                &ed25519_keys_file,
            )?;
    }

    // Prompt for Ed25519 key password
    let ed25519_password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
        "Enter password to encrypt Ed25519 key for FID {fid}: "
    ))?;

    // Store the Ed25519 key encrypted
    ed25519_manager
        .import_and_encrypt(fid, &private_key_hex, &ed25519_password)
        .await?;

    // Save to file
    ed25519_manager.save_to_file(&ed25519_keys_file)?;

    println!("✅ Ed25519 private key stored encrypted for FID: {fid}");
    println!("🔑 Public key: {}", hex::encode(&public_key));
    println!("📝 You can now use this signer for Farcaster operations with FID {fid}");

    Ok(())
}

async fn handle_del_signer(
    hub_client: &FarcasterClient,
    fid: u64,
    wallet_name: Option<&str>,
    payment_wallet_name: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    println!("➖ Removing signer for FID: {fid}");

    // Determine the custody wallet name
    let wallet_name = match wallet_name {
        Some(name) => name.to_string(),
        None => {
            // Auto-detect custody wallet for this FID
            match find_custody_wallet_for_fid(fid).await? {
                Some(name) => {
                    println!("🔍 Auto-detected custody wallet: {name}");
                    name
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "❌ No custody wallet found for FID {fid}. Please create one first using:\n   castorix custody import {fid}\n   or\n   castorix custody from-mnemonic {fid}"
                    ));
                }
            }
        }
    };

    println!("🔑 Using custody wallet: {wallet_name}");

    // Determine payment wallet
    let payment_wallet_name = payment_wallet_name.unwrap_or(&wallet_name);
    if payment_wallet_name != wallet_name {
        println!("💰 Using payment wallet: {payment_wallet_name}");
        println!("   (Third-party gas payment enabled)");
    } else {
        println!("💰 Using custody wallet for gas payment");
    }

    // Load FID-specific custody key file
    let custody_key_file =
        crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::custody_key_file(fid)?;

    if !std::path::Path::new(&custody_key_file).exists() {
        return Err(anyhow::anyhow!(
            "❌ No custody key found for FID {fid}. Please create one first using:\n   castorix custody import {fid}\n   or\n   castorix custody from-mnemonic {fid}"
        ));
    }

    // Load encrypted ETH key manager
    let encrypted_manager =
        crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::load_from_file(
            &custody_key_file,
        )?;

    // Prompt for password
    let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
        "Enter password for custody wallet (FID {fid}): "
    ))?;

    // Get the wallet directly
    let wallet = encrypted_manager
        .get_wallet(fid, &password)
        .map_err(|e| anyhow::anyhow!("Failed to load wallet for FID {}: {}", fid, e))?;

    // Create FarcasterContractClient with the custody wallet for authorization
    let contract_client = create_contract_client_with_local_wallet(wallet).await?;

    // If using third-party payment, create a separate client for the payment wallet
    let payment_contract_client = if payment_wallet_name != wallet_name {
        // Load payment wallet
        let mut payment_encrypted_manager =
            crate::encrypted_key_manager::EncryptedKeyManager::default_config();
        let payment_password = crate::encrypted_key_manager::prompt_password(&format!(
            "Enter password for payment wallet '{payment_wallet_name}': "
        ))?;

        payment_encrypted_manager
            .load_and_decrypt(&payment_password, payment_wallet_name)
            .await?;

        let payment_key_manager = payment_encrypted_manager
            .key_manager()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to load key manager for payment wallet: {}",
                    payment_wallet_name
                )
            })?
            .clone();

        Some(create_contract_client_with_wallet(payment_key_manager).await?)
    } else {
        None
    };

    // Get current signers for the FID
    println!("🔍 Getting current signers for FID {fid}...");
    let signers = hub_client.get_signers(fid).await?;

    if signers.is_empty() {
        return Err(anyhow::anyhow!("❌ No active signers found for FID {fid}"));
    }

    println!(
        "📋 Found {} active signer(s) for FID {}:",
        signers.len(),
        fid
    );
    for (i, signer) in signers.iter().enumerate() {
        println!("   {}. Public Key: {}", i + 1, signer.key);
    }

    // For now, we'll remove the first signer (in a real implementation, you might want to prompt which one)
    let signer_to_remove = &signers[0];
    let public_key_bytes = hex::decode(&signer_to_remove.key)
        .map_err(|_| anyhow::anyhow!("Invalid public key hex: {}", signer_to_remove.key))?;

    println!("🗑️  Removing signer: {}", signer_to_remove.key);

    // Get FID information
    let fid_info = contract_client.get_fid_info(fid).await?;

    // Verify that the wallet can manage this FID's keys
    let wallet_address = contract_client
        .wallet_address()
        .ok_or_else(|| anyhow::anyhow!("No wallet address available"))?;

    if wallet_address != fid_info.custody {
        return Err(anyhow::anyhow!(
            "❌ Wallet address {} does not match custody address {} for FID {}\n\n\
            💡 To manage signers for this FID, you need the correct custody wallet.\n\
            📝 The custody address for FID {} is: {}\n\
            🔑 If you have the private key for this address, import it using:\n\
               castorix custody import {} --address {}\n\
            🔑 Or if you have the mnemonic for this address, use:\n\
               castorix custody from-mnemonic {}",
            wallet_address,
            fid_info.custody,
            fid,
            fid,
            fid_info.custody,
            fid,
            fid_info.custody,
            fid
        ));
    }

    println!("✅ Wallet authorized to manage FID {fid}");

    if dry_run {
        println!("\n🧪 DRY-RUN MODE: Simulating transaction without sending to chain");
        println!("   • This would remove an Ed25519 signer from the Farcaster network");
        println!("   • This would consume gas fees");
        println!("   • The signer would be permanently removed from FID {fid}");
        println!("   • This action cannot be easily undone");
        println!("   • Signer to remove: {}", signer_to_remove.key);

        if payment_wallet_name != wallet_name {
            println!("   • Third-party gas payment enabled");
            println!("   • Custody wallet: {wallet_name} (for authorization)");
            println!("   • Payment wallet: {payment_wallet_name} (for gas fees)");
        } else {
            println!("   • Using custody wallet for both authorization and gas payment");
        }

        // Create EIP-712 signature for signer removal (simulation)
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs()
            + 3600; // 1 hour from now

        let signature = create_signer_remove_signature(
            &contract_client,
            fid_info.custody,
            &public_key_bytes,
            deadline,
        )
        .await?;

        println!("📝 Created EIP-712 signature for signer removal");
        println!("🔑 Signer to remove: {}", signer_to_remove.key);
        println!("📝 Signature: {}", hex::encode(&signature));
        println!("⏰ Deadline: {}", deadline);

        // Simulate the transaction call without sending
        println!("⛓️  Simulating on-chain removal...");
        println!("   • Contract: KeyRegistry");
        println!("   • Method: remove_for");
        println!("   • FID Owner: {}", fid_info.custody);
        println!("   • Public Key: {}", signer_to_remove.key);
        println!("   • Deadline: {}", deadline);

        println!("\n✅ DRY-RUN COMPLETE: Transaction would be sent successfully!");
        println!("💡 To actually send the transaction, run without --dry-run flag");
        println!("📝 The local encrypted key remains stored for potential future use");

        return Ok(());
    }

    // ⚠️  IMPORTANT: This will trigger on-chain operations
    println!("\n⚠️  ON-CHAIN OPERATION WARNING:");
    println!("   • This will remove an Ed25519 signer from the Farcaster network");
    println!("   • The operation will consume gas fees");
    println!("   • The signer will be permanently removed from FID {fid}");
    println!("   • This action cannot be easily undone");
    println!("   • Signer to remove: {}", signer_to_remove.key);

    if payment_wallet_name != wallet_name {
        println!("   • Third-party gas payment enabled");
        println!("   • Custody wallet: {wallet_name} (for authorization)");
        println!("   • Payment wallet: {payment_wallet_name} (for gas fees)");
    } else {
        println!("   • Using custody wallet for both authorization and gas payment");
    }

    // Ask for user confirmation
    print!("\n❓ Do you want to proceed with the on-chain removal? (yes/no): ");
    use std::io::Write;
    use std::io::{
        self,
    };
    io::stdout().flush()?;

    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    let confirmation = confirmation.trim().to_lowercase();

    if confirmation != "yes" && confirmation != "y" {
        println!("❌ Operation cancelled by user");
        return Ok(());
    }

    println!("✅ Proceeding with on-chain removal...");

    // Create EIP-712 signature for signer removal
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_secs()
        + 3600; // 1 hour from now

    let signature = create_signer_remove_signature(
        &contract_client,
        fid_info.custody,
        &public_key_bytes,
        deadline,
    )
    .await?;

    println!("📝 Created EIP-712 signature for signer removal");

    // Remove the signer on-chain
    println!("⛓️  Removing signer on-chain...");

    // Use payment wallet if provided, otherwise use custody wallet
    let result = if let Some(payment_client) = payment_contract_client {
        println!("💰 Using third-party payment wallet for transaction...");
        payment_client
            .key_registry
            .remove_for(
                fid_info.custody,
                public_key_bytes.clone(),
                deadline,
                signature.clone(),
            )
            .await?
    } else {
        println!("💰 Using custody wallet for transaction...");
        contract_client
            .key_registry
            .remove_for(
                fid_info.custody,
                public_key_bytes.clone(),
                deadline,
                signature.clone(),
            )
            .await?
    };

    match result {
        ContractResult::Success(receipt) => {
            println!("✅ Signer removed successfully from on-chain registry!");
            println!("🔗 Transaction Hash: {:?}", receipt.transaction_hash);
            println!("⛽ Gas Used: {}", receipt.gas_used.unwrap_or_default());
            println!(
                "📊 Block Number: {}",
                receipt.block_number.unwrap_or_default()
            );
            println!("⛽ Gas Price: {:?}", receipt.effective_gas_price);
            println!(
                "📈 Status: {}",
                if receipt.status == Some(1.into()) {
                    "Success"
                } else {
                    "Failed"
                }
            );
            println!("🔑 Removed public key: {}", signer_to_remove.key);
            println!("📝 The local encrypted key remains stored for potential future use");
        }
        ContractResult::Error(e) => {
            println!("❌ Contract call failed with error: {}", e);
            println!("🔍 Debug information:");
            println!("   • FID: {}", fid);
            println!("   • Custody: {}", fid_info.custody);
            println!("   • Public Key: {}", signer_to_remove.key);
            println!("   • Deadline: {}", deadline);
            println!("   • Signature Length: {} bytes", signature.len());
            return Err(anyhow::anyhow!("❌ Failed to remove signer: {}", e));
        }
    }

    Ok(())
}

/// Create a FarcasterContractClient with the specified wallet
async fn create_contract_client_with_wallet(
    key_manager: crate::core::crypto::key_manager::KeyManager,
) -> Result<crate::farcaster::contracts::contract_client::FarcasterContractClient> {
    // Get the wallet from the key manager
    let wallet = key_manager.wallet();

    // Use contract addresses from the default implementation (Optimism mainnet)
    let addresses = crate::farcaster::contracts::types::ContractAddresses::default();

    // Use RPC URL from configuration (supports environment variables)
    let config = crate::consts::get_config();
    let rpc_url = config.eth_op_rpc_url().to_string();

    crate::farcaster::contracts::contract_client::FarcasterContractClient::new_with_wallet(
        rpc_url,
        addresses,
        wallet.clone(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create contract client: {}", e))
}

/// Create a FarcasterContractClient with a LocalWallet directly
async fn create_contract_client_with_local_wallet(
    wallet: ethers::signers::LocalWallet,
) -> Result<crate::farcaster::contracts::contract_client::FarcasterContractClient> {
    // Use contract addresses from the default implementation (Optimism mainnet)
    let addresses = crate::farcaster::contracts::types::ContractAddresses::default();

    // Use RPC URL from configuration (supports environment variables)
    let config = crate::consts::get_config();
    let rpc_url = config.eth_op_rpc_url().to_string();

    crate::farcaster::contracts::contract_client::FarcasterContractClient::new_with_wallet(
        rpc_url,
        addresses,
        wallet.clone(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create contract client: {}", e))
}

/// Create EIP-712 signature for signer addition
async fn create_signer_add_signature(
    contract_client: &crate::farcaster::contracts::contract_client::FarcasterContractClient,
    _fid: u64,
    fid_owner: ethers::types::Address,
    public_key: &[u8],
    deadline: u64,
) -> Result<Vec<u8>> {
    let wallet = contract_client
        .wallet()
        .ok_or_else(|| anyhow::anyhow!("No wallet available"))?;

    // Get the current nonce for the FID owner
    let nonce_result = contract_client.key_gateway.nonces(fid_owner).await?;
    let nonce = match nonce_result {
        crate::farcaster::contracts::types::ContractResult::Success(nonce) => nonce,
        crate::farcaster::contracts::types::ContractResult::Error(e) => {
            return Err(anyhow::anyhow!("Failed to get nonce: {}", e));
        }
    };

    // Get chain ID and contract address
    let chain_id = contract_client.provider.get_chainid().await?.as_u64();
    let key_gateway_address = contract_client.addresses.key_gateway;

    // Create the EIP-712 typed data structure
    let typed_data = create_add_typed_data(
        fid_owner,
        1u32, // Ed25519 key type
        public_key,
        1u8, // Metadata type
        &[], // Empty metadata
        nonce.as_u64(),
        deadline,
        key_gateway_address,
        chain_id,
    )?;

    // Sign the typed data using EIP-712
    let signature = wallet.sign_typed_data(&typed_data).await?;

    // Return the signature as bytes
    Ok(signature.to_vec())
}

/// Create EIP-712 typed data for Add operation
#[allow(clippy::too_many_arguments)]
fn create_add_typed_data(
    fid_owner: ethers::types::Address,
    key_type: u32,
    key: &[u8],
    metadata_type: u8,
    metadata: &[u8],
    nonce: u64,
    deadline: u64,
    key_gateway_address: ethers::types::Address,
    chain_id: u64,
) -> Result<ethers::types::transaction::eip712::TypedData> {
    use std::collections::BTreeMap;

    use ethers::types::transaction::eip712::EIP712Domain;
    use ethers::types::transaction::eip712::Eip712DomainType;
    use ethers::types::transaction::eip712::TypedData;

    // Domain separator for Farcaster KeyGateway
    let domain = EIP712Domain {
        name: Some("Farcaster KeyGateway".to_string()),
        version: Some("1".to_string()),
        chain_id: Some(ethers::types::U256::from(chain_id)),
        verifying_contract: Some(key_gateway_address),
        salt: None,
    };

    // Type definition for Add struct
    let mut types = BTreeMap::new();
    types.insert(
        "EIP712Domain".to_string(),
        vec![
            Eip712DomainType {
                name: "name".to_string(),
                r#type: "string".to_string(),
            },
            Eip712DomainType {
                name: "version".to_string(),
                r#type: "string".to_string(),
            },
            Eip712DomainType {
                name: "chainId".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "verifyingContract".to_string(),
                r#type: "address".to_string(),
            },
        ],
    );
    types.insert(
        "Add".to_string(),
        vec![
            Eip712DomainType {
                name: "owner".to_string(),
                r#type: "address".to_string(),
            },
            Eip712DomainType {
                name: "keyType".to_string(),
                r#type: "uint32".to_string(),
            },
            Eip712DomainType {
                name: "key".to_string(),
                r#type: "bytes".to_string(),
            },
            Eip712DomainType {
                name: "metadataType".to_string(),
                r#type: "uint8".to_string(),
            },
            Eip712DomainType {
                name: "metadata".to_string(),
                r#type: "bytes".to_string(),
            },
            Eip712DomainType {
                name: "nonce".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "deadline".to_string(),
                r#type: "uint256".to_string(),
            },
        ],
    );

    // Data for Add struct
    let mut message = BTreeMap::new();
    message.insert(
        "owner".to_string(),
        serde_json::Value::String(format!("0x{:040x}", fid_owner)),
    );
    message.insert(
        "keyType".to_string(),
        serde_json::Value::String(key_type.to_string()),
    );
    message.insert(
        "key".to_string(),
        serde_json::Value::String(format!("0x{}", hex::encode(key))),
    );
    message.insert(
        "metadataType".to_string(),
        serde_json::Value::String(metadata_type.to_string()),
    );
    message.insert(
        "metadata".to_string(),
        serde_json::Value::String(format!("0x{}", hex::encode(metadata))),
    );
    message.insert(
        "nonce".to_string(),
        serde_json::Value::String(nonce.to_string()),
    );
    message.insert(
        "deadline".to_string(),
        serde_json::Value::String(deadline.to_string()),
    );

    Ok(TypedData {
        domain,
        types,
        primary_type: "Add".to_string(),
        message,
    })
}

/// Create EIP-712 signature for signer removal
async fn create_signer_remove_signature(
    contract_client: &crate::farcaster::contracts::contract_client::FarcasterContractClient,
    fid_owner: ethers::types::Address,
    public_key: &[u8],
    deadline: u64,
) -> Result<Vec<u8>> {
    // This is a simplified implementation
    // In a real implementation, you would create the proper EIP-712 typed data structure

    let wallet = contract_client
        .wallet()
        .ok_or_else(|| anyhow::anyhow!("No wallet available"))?;

    // Create the message to sign
    let message = format!(
        "remove_signer:{}:{}:{}",
        fid_owner,
        hex::encode(public_key),
        deadline
    );

    // Sign the message
    let signature = wallet.sign_message(message.as_bytes()).await?;

    // Return the signature as bytes
    Ok(signature.to_vec())
}

/// Find custody wallet for a specific FID
async fn find_custody_wallet_for_fid(fid: u64) -> Result<Option<String>> {
    // Check for FID-specific custody key file
    let custody_key_file =
        crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::custody_key_file(fid)?;

    if std::path::Path::new(&custody_key_file).exists() {
        // Load the FID-specific custody key file
        let eth_manager =
            crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::load_from_file(
                &custody_key_file,
            )?;

        // Check if this FID has a key in the file
        if eth_manager.has_key(fid) {
            // Return the wallet name for this FID
            Ok(Some(format!("fid-{}-eth", fid)))
        } else {
            Ok(None)
        }
    } else {
        // Fallback: check the old default keys file for backward compatibility
        let eth_keys_file =
            crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::default_keys_file()?;
        if std::path::Path::new(&eth_keys_file).exists() {
            let eth_manager =
                crate::core::crypto::encrypted_storage::EncryptedEthKeyManager::load_from_file(
                    &eth_keys_file,
                )?;

            // Get all ECDSA keys with info (no password needed for public keys)
            match eth_manager.list_keys_with_info("") {
                Ok(key_infos) => {
                    // Find keys that match this FID
                    let matching_keys: Vec<_> = key_infos
                        .iter()
                        .filter(|key_info| key_info.fid == fid)
                        .collect();

                    if matching_keys.is_empty() {
                        Ok(None)
                    } else {
                        // Found a matching key
                        Ok(Some(format!("fid-{}-eth", fid)))
                    }
                }
                Err(_) => {
                    // If we can't load the keys, return None
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }
}

/// Get locally stored Ed25519 keys for a specific FID
async fn get_local_ed25519_keys_for_fid(fid: u64) -> Result<Vec<LocalEd25519Key>> {
    let mut local_keys = Vec::new();

    // Load the Ed25519 key manager
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    let ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
            &ed25519_keys_file,
        )?;

    // Get all Ed25519 keys with info (no password needed for public keys)
    match ed25519_manager.list_keys_with_info("") {
        Ok(key_infos) => {
            for key_info in key_infos {
                if key_info.fid == fid {
                    local_keys.push(LocalEd25519Key {
                        name: format!("fid-{}-ed25519", key_info.fid),
                        public_key: key_info.public_key,
                    });
                }
            }
        }
        Err(e) => {
            // If we can't load the keys, just return empty list
            println!("⚠️  Warning: Could not load Ed25519 keys: {}", e);
        }
    }

    Ok(local_keys)
}

/// Decrypt a legacy Ed25519 key using the same method as EncryptedKeyManager
fn decrypt_legacy_key(
    encrypted_key: &str,
    salt_str: &str,
    nonce_str: &str,
    password: &str,
) -> Result<Vec<u8>> {
    // Decode base64
    let ciphertext = general_purpose::STANDARD
        .decode(encrypted_key)
        .map_err(|e| anyhow::anyhow!("Failed to decode encrypted key: {}", e))?;
    let nonce_bytes = general_purpose::STANDARD
        .decode(nonce_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode nonce: {}", e))?;

    // Recreate salt and nonce
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| anyhow::anyhow!("Failed to recreate salt: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Derive key from password
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

    let hash_bytes = password_hash.hash.unwrap();
    let key = Key::<Aes256Gcm>::from_slice(&hash_bytes.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(key);

    // Decrypt the key
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {}", e))?;

    Ok(plaintext)
}

async fn handle_signers_import(fid: u64) -> Result<()> {
    println!("📥 Importing Ed25519 signer key for FID: {fid}");

    // Check for legacy Ed25519 key first
    let legacy_key_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".castorix")
        .join("keys")
        .join(format!("fid-{}-ed25519.json", fid));

    let private_key = if legacy_key_path.exists() {
        println!("🔍 Found legacy Ed25519 key for FID: {fid}");
        println!("🔄 Attempting to migrate legacy key...");

        // Load the legacy key file
        let legacy_content = std::fs::read_to_string(&legacy_key_path)?;
        let legacy_data: serde_json::Value = serde_json::from_str(&legacy_content)?;

        // Get the encrypted key, salt, and nonce
        let encrypted_key = legacy_data["encrypted_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid legacy key format: missing encrypted_key"))?;
        let salt = legacy_data["salt"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid legacy key format: missing salt"))?;
        let nonce = legacy_data["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid legacy key format: missing nonce"))?;

        // Prompt for the password to decrypt the legacy key
        let password = crate::encrypted_key_manager::prompt_password(&format!(
            "Enter password to decrypt legacy Ed25519 key for FID {fid}: "
        ))?;

        // Decrypt the legacy key using the same method as EncryptedKeyManager
        let decrypted_key = decrypt_legacy_key(encrypted_key, salt, nonce, &password)?;

        // Convert to hex string
        hex::encode(decrypted_key)
    } else {
        // No legacy key found, prompt for manual input
        crate::encrypted_key_manager::prompt_password(
            "Enter Ed25519 private key (hex format, 64 characters): ",
        )?
    };

    // Prompt for password
    let password = crate::core::crypto::encrypted_storage::prompt_password(
        "Enter password to encrypt the key: ",
    )?;

    // Create the encrypted Ed25519 key manager
    let mut encrypted_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::new();

    // Load existing keys
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    if std::path::Path::new(&ed25519_keys_file).exists() {
        encrypted_manager =
            crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
                &ed25519_keys_file,
            )?;
    }

    // Check if key already exists for this FID
    if encrypted_manager.has_key(fid) {
        println!("⚠️  Ed25519 key already exists for FID: {fid}");

        print!("\nDo you want to replace the existing key? (y/N): ");
        use std::io::Write;
        use std::io::{
            self,
        };
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let response = input.trim().to_lowercase();

        if response != "y" && response != "yes" {
            println!("❌ Operation cancelled. Existing key will not be replaced.");
            return Ok(());
        }

        // Remove existing key
        encrypted_manager.remove_key(fid)?;
        println!("🗑️  Removed existing Ed25519 key");
    }

    // Import and encrypt the key
    encrypted_manager
        .import_and_encrypt(fid, &private_key, &password)
        .await?;

    // Save the updated keys
    encrypted_manager.save_to_file(&ed25519_keys_file)?;

    // Get the public key for display
    let key_info = encrypted_manager.list_keys_with_info("")?;
    let imported_key = key_info.iter().find(|k| k.fid == fid);

    if let Some(key) = imported_key {
        println!("✅ Ed25519 signer key imported and encrypted successfully!");
        println!("🔑 Public Key: {}", key.public_key);
        println!("📁 FID: {}", fid);
        println!("💾 Key stored securely with password protection");
        println!("📝 You can now use this signer for Farcaster operations with FID {fid}");
    } else {
        println!("✅ Ed25519 signer key imported and encrypted successfully!");
        println!("📁 FID: {}", fid);
        println!("💾 Key stored securely with password protection");
    }

    Ok(())
}

async fn handle_signers_list() -> Result<()> {
    println!("📋 All Local Ed25519 Signer Keys");
    println!("{}", "=".repeat(50));

    // Load the Ed25519 key manager
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    let ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
            &ed25519_keys_file,
        )?;

    // Check for legacy Ed25519 keys in the old format and migrate them
    let legacy_keys_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".castorix")
        .join("keys");

    if legacy_keys_dir.exists() {
        println!("🔍 Checking for legacy Ed25519 keys...");
        let mut migrated_count = 0;

        for entry in std::fs::read_dir(&legacy_keys_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                    if filename.starts_with("fid-") && filename.ends_with("-ed25519") {
                        // Extract FID from filename (fid-{fid}-ed25519)
                        if let Some(fid_str) = filename
                            .strip_prefix("fid-")
                            .and_then(|s| s.strip_suffix("-ed25519"))
                        {
                            if let Ok(fid) = fid_str.parse::<u64>() {
                                println!("   Found legacy Ed25519 key for FID: {}", fid);

                                // Check if this FID already exists in the new format
                                if !ed25519_manager.has_key(fid) {
                                    println!("   ⚠️  Legacy key found but cannot auto-migrate (requires password)");
                                    println!("   💡 Use 'castorix signers import {}' to migrate this key", fid);
                                } else {
                                    println!("   ✅ Already migrated to new format");
                                }
                                migrated_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if migrated_count > 0 {
            println!(
                "   Found {} legacy Ed25519 key(s) that need migration",
                migrated_count
            );
            println!("   💡 Use 'castorix signers import <fid>' to migrate each key");
        }
    }

    let ed25519_keys = ed25519_manager.list_keys();
    if ed25519_keys.is_empty() {
        println!("❌ No Ed25519 signer keys found.");
        println!("💡 Use 'castorix signers import <fid>' to import your first signer key!");
        println!("💡 Use 'castorix signers register <fid> --wallet <wallet>' to add a new signer!");
    } else {
        println!("🔒 Ed25519 signer keys found:");

        // Show detailed info with public keys (no password needed)
        match ed25519_manager.list_keys_with_info("") {
            Ok(key_infos) => {
                println!(
                    "\n{:<4} {:<8} {:<66} {:<20} Status",
                    "#", "FID", "Public Key", "Created"
                );
                println!("{}", "-".repeat(110));

                // Group keys by FID to check registration status efficiently
                let mut fid_groups: std::collections::HashMap<u64, Vec<_>> =
                    std::collections::HashMap::new();
                for info in key_infos {
                    fid_groups
                        .entry(info.fid)
                        .or_insert_with(Vec::new)
                        .push(info);
                }

                let mut index = 1;
                for (fid, keys) in fid_groups {
                    // Check if this FID has registered signers on-chain
                    // Try local hub first, fallback to Neynar if not available
                    let hub_url = crate::consts::get_config().farcaster_hub_url().to_string();
                    let hub_client = FarcasterClient::new(hub_url, None);
                    let registered_status = match hub_client.get_signers(fid).await {
                        Ok(signers) => {
                            if signers.is_empty() {
                                "Not Registered"
                            } else {
                                // Check if any of the local keys match the on-chain keys
                                let has_matching_key = keys.iter().any(|key_info| {
                                    let local_key = key_info.public_key.trim_start_matches("0x");
                                    signers.iter().any(|signer| {
                                        let chain_key = signer.key.trim_start_matches("0x");
                                        local_key == chain_key
                                    })
                                });

                                if has_matching_key {
                                    "Registered"
                                } else {
                                    "FID Has Other Keys"
                                }
                            }
                        }
                        Err(e) => {
                            // Check for different types of errors
                            let error_msg = e.to_string();
                            if error_msg.contains("402 Payment Required") {
                                "Hub API Paid"
                            } else if error_msg.contains("Connection refused")
                                || error_msg.contains("localhost")
                            {
                                "Local Hub Down"
                            } else if error_msg.contains("timeout") {
                                "Timeout"
                            } else {
                                "Unknown"
                            }
                        }
                    };

                    for info in keys {
                        let created_date =
                            chrono::DateTime::from_timestamp(info.created_at as i64, 0)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                        println!(
                            "{:<4} {:<8} {:<66} {:<20} {}",
                            index, info.fid, info.public_key, created_date, registered_status
                        );
                        index += 1;
                    }
                }
            }
            Err(e) => {
                println!("❌ Failed to get detailed key info: {}", e);
                // Fallback to basic info
                for key_info in ed25519_keys {
                    let created_date =
                        chrono::DateTime::from_timestamp(key_info.created_at as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                    println!("FID: {}, Created: {}", key_info.fid, created_date);
                }
            }
        }

        println!("\n💡 Status meanings:");
        println!("   • Registered: This local key is registered on-chain");
        println!("   • Not Registered: FID has no keys registered on-chain");
        println!("   • FID Has Other Keys: FID has keys on-chain, but not this local key");
        println!("   • Hub API Paid: Cannot check status (requires paid Hub API)");
        println!("   • Local Hub Down: Local Hub is not running (try: FARCASTER_HUB_URL=http://localhost:2283)");
        println!("   • Timeout: Network timeout occurred");
        println!("   • Unknown: Network error or other issue");
        println!("\n💡 Use 'castorix signers info <fid>' to check detailed on-chain status");
        println!("💡 Use 'castorix signers unregister <fid> --wallet <wallet>' to remove a key");
        println!("💡 Use 'castorix signers import <fid>' to add a new key");
    }

    Ok(())
}

async fn handle_signers_export(identifier: &str) -> Result<()> {
    println!("📤 Exporting Ed25519 signer key...");

    // Load the Ed25519 key manager
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    let ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
            &ed25519_keys_file,
        )?;

    // Get all keys
    let all_keys = ed25519_manager.list_keys_with_info("")?;

    if all_keys.is_empty() {
        println!("❌ No Ed25519 signer keys found.");
        println!(
            "💡 Use 'castorix signers register <fid> --wallet <wallet>' to add a signer first"
        );
        return Ok(());
    }

    // Try to parse as index number first
    let (fid, public_key) = if let Ok(index) = identifier.parse::<usize>() {
        if index < 1 || index > all_keys.len() {
            println!(
                "❌ Invalid index number: {}. Available range: 1-{}",
                index,
                all_keys.len()
            );
            println!("💡 Use 'castorix signers list' to see all available keys");
            return Ok(());
        }

        let key_info = &all_keys[index - 1];
        (key_info.fid, key_info.public_key.clone())
    } else {
        // Try to parse as public key
        let clean_pubkey = identifier.trim_start_matches("0x");

        // Validate the public key format
        if clean_pubkey.len() != 64 {
            println!("❌ Invalid identifier format. Expected index number (1-{}) or 64-character hex public key, got: {}", all_keys.len(), identifier);
            println!("💡 Use 'castorix signers list' to see all available keys");
            return Ok(());
        }

        let matching_key = all_keys.iter().find(|key_info| {
            let stored_clean = key_info.public_key.trim_start_matches("0x");
            stored_clean == clean_pubkey
        });

        match matching_key {
            Some(key_info) => (key_info.fid, key_info.public_key.clone()),
            None => {
                println!(
                    "❌ No local Ed25519 key found with public key: {}",
                    identifier
                );
                println!("💡 Use 'castorix signers list' to see all available keys");
                return Ok(());
            }
        }
    };

    println!("✅ Found key for FID: {}", fid);
    println!("🔑 Public key: {}", public_key);

    // Prompt for password to decrypt the private key
    let password = crate::core::crypto::encrypted_storage::prompt_password(&format!(
        "Enter password for FID {fid}: "
    ))?;

    // Get the private key
    match ed25519_manager.get_signing_key(fid, &password) {
        Ok(signing_key) => {
            let private_key_hex = hex::encode(signing_key.to_bytes());

            println!("\n🔐 Ed25519 Private Key Export:");
            println!("{}", "=".repeat(60));
            println!("FID: {}", fid);
            println!("Public Key: {}", public_key);
            println!("Private Key: {}", private_key_hex);
            println!("{}", "=".repeat(60));

            println!("\n⚠️  SECURITY WARNING:");
            println!("   • Keep this private key secure and never share it");
            println!("   • Store it in a safe place (password manager, hardware wallet, etc.)");
            println!("   • Anyone with this private key can control your Farcaster account");
            println!("   • This private key is not encrypted in this export");

            println!("\n💡 You can now safely delete the local key using:");
            println!("   castorix signers delete {}", identifier);
        }
        Err(e) => {
            println!("❌ Failed to decrypt private key: {}", e);
            println!("💡 Make sure you entered the correct password");
        }
    }

    Ok(())
}

async fn handle_signers_delete(identifier: &str) -> Result<()> {
    println!("🗑️  Deleting local Ed25519 signer key...");
    println!("🔍 Identifier: {}", identifier);

    // Load the Ed25519 key manager
    let ed25519_keys_file =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::default_keys_file()?;
    let mut ed25519_manager =
        crate::core::crypto::encrypted_storage::EncryptedEd25519KeyManager::load_from_file(
            &ed25519_keys_file,
        )?;

    // Get all keys to work with
    let all_keys = ed25519_manager.list_keys_with_info("")?;

    // Check if identifier is a number (index) or a public key
    let (fid, public_key) = if let Ok(index) = identifier.parse::<usize>() {
        // Index-based deletion
        if index < 1 || index > all_keys.len() {
            println!(
                "❌ Invalid index: {}. Valid range is 1-{}",
                index,
                all_keys.len()
            );
            println!("💡 Use 'castorix signers list' to see all available keys with their indices");
            return Ok(());
        }

        let key_info = &all_keys[index - 1]; // Convert to 0-based index
        println!(
            "🔑 Selected key by index {}: {}",
            index, key_info.public_key
        );
        (key_info.fid, key_info.public_key.clone())
    } else {
        // Public key-based deletion
        let clean_pubkey = identifier.trim_start_matches("0x");

        // Validate the public key format
        if clean_pubkey.len() != 64 {
            return Err(anyhow::anyhow!("❌ Invalid identifier format. Expected either a number (1-{}) or a 64-character hex public key, got: {}", all_keys.len(), identifier));
        }

        let matching_key = all_keys.iter().find(|key_info| {
            let stored_clean = key_info.public_key.trim_start_matches("0x");
            stored_clean == clean_pubkey
        });

        match matching_key {
            Some(key_info) => {
                println!("🔑 Selected key by public key: {}", key_info.public_key);
                (key_info.fid, key_info.public_key.clone())
            }
            None => {
                println!(
                    "❌ No local Ed25519 key found with public key: {}",
                    identifier
                );
                println!("💡 Use 'castorix signers list' to see all available keys");
                return Ok(());
            }
        }
    };

    println!("✅ Found matching key for FID: {}", fid);

    // ⚠️  IMPORTANT: Confirmation with backup warning
    println!("\n⚠️  PERMANENT DELETION WARNING:");
    println!("   • This will permanently delete the Ed25519 private key from local storage");
    println!("   • The key will be completely removed and cannot be recovered");
    println!("   • This does NOT affect on-chain registration (key remains registered on-chain)");
    println!("   • Make sure you have backed up the private key if needed");
    println!("   • Public key: {}", public_key);
    println!("   • FID: {}", fid);

    // Ask for confirmation with backup verification
    print!("\n❓ Have you backed up this private key? (yes/no): ");
    use std::io::Write;
    use std::io::{
        self,
    };
    io::stdout().flush()?;

    let mut backup_confirmation = String::new();
    io::stdin().read_line(&mut backup_confirmation)?;
    let backup_confirmation = backup_confirmation.trim().to_lowercase();

    if backup_confirmation != "yes" && backup_confirmation != "y" {
        println!("❌ Operation cancelled. Please backup the private key first.");
        println!(
            "💡 Use 'castorix signers export {}' to export the private key",
            public_key
        );
        return Ok(());
    }

    // Final confirmation
    print!("\n❓ Are you absolutely sure you want to permanently delete this key? (yes/no): ");
    io::stdout().flush()?;

    let mut final_confirmation = String::new();
    io::stdin().read_line(&mut final_confirmation)?;
    let final_confirmation = final_confirmation.trim().to_lowercase();

    if final_confirmation != "yes" && final_confirmation != "y" {
        println!("❌ Operation cancelled by user");
        return Ok(());
    }

    // Delete the key
    println!("🗑️  Deleting Ed25519 key for FID {}...", fid);

    match ed25519_manager.remove_key(fid) {
        Ok(_) => {
            // Save the changes to file
            if let Err(e) = ed25519_manager.save_to_file(&ed25519_keys_file) {
                println!("⚠️  Warning: Failed to save changes to file: {}", e);
                println!("   The key was removed from memory but may not be permanently deleted");
            } else {
                println!("✅ Ed25519 key successfully deleted from local storage!");
                println!("🔑 Deleted public key: {}", public_key);
                println!("📝 Note: The key remains registered on-chain (if it was registered)");
                println!("💡 Use 'castorix signers unregister {} --wallet <wallet>' to remove from chain", fid);
            }
        }
        Err(e) => {
            println!("❌ Failed to delete Ed25519 key: {}", e);
        }
    }

    Ok(())
}
