use anyhow::Result;

use crate::cli::types::HubCommands;

/// Handle Farcaster Hub commands
pub async fn handle_hub_command(
    command: HubCommands,
    hub_client: &crate::core::client::hub_client::FarcasterClient,
) -> Result<()> {
    match command {
        HubCommands::User { fid } => {
            println!("👤 Getting user information for FID: {fid}");
            match hub_client.get_user(fid).await {
                Ok(user_data) => {
                    println!("✅ User data retrieved:");
                    println!("{}", serde_json::to_string_pretty(&user_data)?);
                }
                Err(e) => println!("❌ Failed to get user data: {e}"),
            }
        }
        HubCommands::SubmitProof {
            proof_file,
            fid,
            wallet_name,
        } => {
            handle_submit_proof(hub_client, proof_file, fid, wallet_name).await?;
        }
        HubCommands::EthAddresses { fid } => {
            println!("🔍 Getting Ethereum addresses for FID: {fid}");
            match hub_client.get_eth_addresses(fid).await {
                Ok(addresses) => {
                    if addresses.is_empty() {
                        println!("❌ No Ethereum addresses found for FID: {fid}");
                    } else {
                        println!("✅ Found {} Ethereum address(es):", addresses.len());
                        for (i, address) in addresses.iter().enumerate() {
                            println!("   {}. {}", i + 1, address);
                        }
                    }
                }
                Err(e) => println!("❌ Failed to get Ethereum addresses: {e}"),
            }
        }
        HubCommands::EnsDomains { fid } => {
            println!("🌐 Getting ENS domains with proofs for FID: {fid}");
            // Create a dummy EnsProof for the API call
            let dummy_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            if let Ok(key_manager) =
                crate::core::crypto::key_manager::KeyManager::from_private_key(dummy_key)
            {
                let ens_proof = crate::ens_proof::EnsProof::new(
                    key_manager,
                    "https://eth-mainnet.g.alchemy.com/v2/dummy".to_string(),
                );
                match ens_proof
                    .get_ens_domains_by_fid(hub_client.hub_url(), fid)
                    .await
                {
                    Ok(domains) => {
                        if domains.is_empty() {
                            println!("❌ No ENS domains with proofs found for FID: {fid}");
                        } else {
                            println!("✅ Found {} ENS domain(s) with proofs:", domains.len());
                            for (i, domain) in domains.iter().enumerate() {
                                println!("   {}. {}", i + 1, domain);
                            }
                        }
                    }
                    Err(e) => println!("❌ Failed to get ENS domains: {e}"),
                }
            } else {
                println!("❌ Failed to create key manager for ENS query");
            }
        }
        HubCommands::CustodyAddress { fid } => {
            println!("🏠 Getting custody address for FID: {fid}");
            match hub_client.get_custody_address(fid).await {
                Ok(custody_address) => {
                    println!("✅ Custody address for FID {fid}:");
                    println!("   Address: {custody_address}");
                    println!("   Type: Ethereum address (custody key)");
                    println!("   Source: Farcaster Hub (onchain events)");
                }
                Err(e) => println!("❌ Failed to get custody address: {e}"),
            }
        }
        HubCommands::Info => {
            handle_hub_info(hub_client).await?;
        }
        HubCommands::Followers { fid, limit } => {
            handle_followers(hub_client, fid, limit).await?;
        }
        HubCommands::Following { fid, limit } => {
            handle_following(hub_client, fid, limit).await?;
        }
        HubCommands::Profile { fid, all } => {
            handle_profile(hub_client, fid, all).await?;
        }
        HubCommands::Stats { fid } => {
            handle_stats(hub_client, fid).await?;
        }
        HubCommands::Spam { fids } => {
            handle_spam_check(fids).await?;
        }
        HubCommands::SpamStat => {
            handle_spam_stat(hub_client).await?;
        }
        HubCommands::Casts { fid, limit, json } => {
            handle_casts(hub_client, fid, limit, json).await?;
        }
        HubCommands::Cast {
            fid,
            text,
            parent_cast_fid,
            parent_cast_hash,
            parent_url,
            embed_url,
        } => {
            handle_submit_cast(
                hub_client,
                fid,
                text,
                parent_cast_fid,
                parent_cast_hash,
                parent_url,
                embed_url,
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_submit_proof(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    proof_file: String,
    fid: u64,
    wallet_name: Option<String>,
) -> Result<()> {
    println!("📤 Submitting username proof from file: {proof_file} for FID: {fid}");

    let proof_content = std::fs::read_to_string(&proof_file)?;
    let proof_data: serde_json::Value = serde_json::from_str(&proof_content)?;

    // Create UserNameProof from JSON
    let mut proof = crate::core::protocol::username_proof::UserNameProof::new();
    proof.set_timestamp(proof_data["timestamp"].as_u64().unwrap_or(0));
    proof.set_name(
        proof_data["name"]
            .as_str()
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
    );
    proof.set_owner(hex::decode(proof_data["owner"].as_str().unwrap_or(""))?);
    proof.set_signature(hex::decode(proof_data["signature"].as_str().unwrap_or(""))?);
    proof.set_fid(proof_data["fid"].as_u64().unwrap_or(0));

    // Create a new FarcasterClient with the specified wallet if provided
    let client = if let Some(wallet_name) = wallet_name {
        // Load encrypted key manager and decrypt the key
        let mut encrypted_manager =
            crate::encrypted_key_manager::EncryptedKeyManager::default_config();

        // Prompt for password
        let password = crate::encrypted_key_manager::prompt_password(&format!(
            "Enter password for wallet '{wallet_name}': "
        ))?;

        // Load and decrypt the key
        encrypted_manager
            .load_and_decrypt(&password, &wallet_name)
            .await?;

        // Get the decrypted key manager
        let key_manager = encrypted_manager
            .key_manager()
            .ok_or_else(|| {
                anyhow::anyhow!("Failed to load key manager for wallet: {}", wallet_name)
            })?
            .clone();

        crate::core::client::hub_client::FarcasterClient::new(
            hub_client.hub_url().to_string(),
            Some(key_manager),
        )
    } else {
        crate::core::client::hub_client::FarcasterClient::new(
            hub_client.hub_url().to_string(),
            hub_client.key_manager().cloned(),
        )
    };

    // Submit using Ed25519 key for the specified FID
    let result = client.submit_username_proof_with_ed25519(&proof, fid).await;

    match result {
        Ok(response) => {
            println!("✅ Username proof submitted successfully!");
            println!("📋 Response: {response:?}");
        }
        Err(e) => println!("❌ Failed to submit username proof: {e}"),
    }

    Ok(())
}

async fn handle_hub_info(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
) -> Result<()> {
    println!("📊 Getting Hub information and sync status...");

    // Get Hub info from the API
    match hub_client.get_hub_info().await {
        Ok(hub_info) => {
            println!("✅ Hub information retrieved:");
            println!("{}", serde_json::to_string_pretty(&hub_info)?);
        }
        Err(e) => {
            println!("❌ Failed to get Hub information: {e}");
            println!("💡 This might be because the Hub doesn't support the info endpoint");
        }
    }

    Ok(())
}

async fn handle_followers(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
    limit: u32,
) -> Result<()> {
    let limit_text = if limit == 0 {
        "all".to_string()
    } else {
        limit.to_string()
    };
    println!("👥 Getting followers for FID: {fid} (limit: {limit_text})");

    match hub_client.get_followers(fid, limit).await {
        Ok(followers) => {
            if followers.is_empty() {
                println!("❌ No followers found for FID: {fid}");
            } else {
                println!("✅ Found {} follower(s):", followers.len());
                for (i, follower) in followers.iter().enumerate() {
                    // Extract FID from the link message
                    let follower_fid = follower
                        .get("data")
                        .and_then(|d| d.get("fid"))
                        .and_then(|f| f.as_u64())
                        .unwrap_or(0);

                    // Extract timestamp for when they followed
                    let timestamp = follower
                        .get("data")
                        .and_then(|d| d.get("timestamp"))
                        .and_then(|t| t.as_u64())
                        .unwrap_or(0);

                    println!(
                        "   {}. FID: {} (followed at timestamp: {})",
                        i + 1,
                        follower_fid,
                        timestamp
                    );
                }
            }
        }
        Err(e) => println!("❌ Failed to get followers: {e}"),
    }

    Ok(())
}

async fn handle_following(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
    limit: u32,
) -> Result<()> {
    let limit_text = if limit == 0 {
        "all".to_string()
    } else {
        limit.to_string()
    };
    println!("👤 Getting following for FID: {fid} (limit: {limit_text})");

    match hub_client.get_following(fid, limit).await {
        Ok(following) => {
            if following.is_empty() {
                println!("❌ No following found for FID: {fid}");
            } else {
                println!("✅ Found {} following:", following.len());
                for (i, user) in following.iter().enumerate() {
                    // Extract target FID from the link message
                    let target_fid = user
                        .get("data")
                        .and_then(|d| d.get("linkBody"))
                        .and_then(|lb| lb.get("targetFid"))
                        .and_then(|f| f.as_u64())
                        .unwrap_or(0);

                    // Extract timestamp for when they followed
                    let timestamp = user
                        .get("data")
                        .and_then(|d| d.get("timestamp"))
                        .and_then(|t| t.as_u64())
                        .unwrap_or(0);

                    println!(
                        "   {}. FID: {} (followed at timestamp: {})",
                        i + 1,
                        target_fid,
                        timestamp
                    );
                }
            }
        }
        Err(e) => println!("❌ Failed to get following: {e}"),
    }

    Ok(())
}

async fn handle_profile(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
    show_all: bool,
) -> Result<()> {
    println!("👤 Getting profile for FID: {fid}");

    match hub_client.get_user_profile(fid).await {
        Ok(profile_data) => {
            if profile_data.is_empty() {
                println!("❌ No profile data found for FID: {fid}");
            } else {
                println!("✅ Profile for FID: {fid}");
                println!("{}", "─".repeat(50));

                // Parse and display profile information
                let mut username = "Unknown".to_string();
                let mut display_name = "Unknown".to_string();
                let mut bio = "No bio".to_string();
                let mut pfp_url = "No profile picture".to_string();
                let mut location = "No location".to_string();
                let mut twitter = "No Twitter".to_string();
                let mut github = "No GitHub".to_string();
                let mut url = "No website".to_string();
                let mut eth_address = "No Ethereum address".to_string();
                let mut sol_address = "No Solana address".to_string();

                for data in &profile_data {
                    if let Some(user_data_body) =
                        data.get("data").and_then(|d| d.get("userDataBody"))
                    {
                        if let Some(data_type) = user_data_body.get("type").and_then(|t| t.as_str())
                        {
                            if let Some(value) =
                                user_data_body.get("value").and_then(|v| v.as_str())
                            {
                                match data_type {
                                    "USER_DATA_TYPE_USERNAME" => username = value.to_string(),
                                    "USER_DATA_TYPE_DISPLAY" => display_name = value.to_string(),
                                    "USER_DATA_TYPE_BIO" => bio = value.to_string(),
                                    "USER_DATA_TYPE_PFP" => pfp_url = value.to_string(),
                                    "USER_DATA_TYPE_LOCATION" => location = value.to_string(),
                                    "USER_DATA_TYPE_TWITTER" => twitter = format!("@{}", value),
                                    "USER_DATA_TYPE_GITHUB" => github = format!("@{}", value),
                                    "USER_DATA_TYPE_URL" => url = value.to_string(),
                                    "USER_DATA_PRIMARY_ADDRESS_ETHEREUM" => {
                                        eth_address = value.to_string()
                                    }
                                    "USER_DATA_PRIMARY_ADDRESS_SOLANA" => {
                                        sol_address = value.to_string()
                                    }
                                    _ => {} // Ignore other types
                                }
                            }
                        }
                    }
                }

                if show_all {
                    // Display all profile information
                    println!("📝 Display Name: {}", display_name);
                    println!("👤 Username: @{}", username);
                    println!("📄 Bio: {}", bio);
                    println!("📍 Location: {}", location);
                    println!("🐦 Twitter: {}", twitter);
                    println!("💻 GitHub: {}", github);
                    println!("🌐 Website: {}", url);
                    println!("🔗 Ethereum: {}", eth_address);
                    println!("🔗 Solana: {}", sol_address);
                    println!("🖼️  Profile Picture: {}", pfp_url);

                    // Display profile picture if available
                    if pfp_url != "No profile picture" && !pfp_url.is_empty() {
                        if let Err(e) =
                            crate::image_display::ImageDisplay::smart_display(&pfp_url).await
                        {
                            println!("❌ Failed to display profile picture: {}", e);
                        }
                    }

                    println!("{}", "─".repeat(50));
                    println!("📊 Total profile fields: {}", profile_data.len());
                } else {
                    // Display only basic information
                    println!("👤 @{}", username);
                    println!("📝 {}", display_name);
                    println!("📄 {}", bio);

                    // Display profile picture if available
                    if pfp_url != "No profile picture" && !pfp_url.is_empty() {
                        if let Err(e) =
                            crate::image_display::ImageDisplay::smart_display(&pfp_url).await
                        {
                            println!("❌ Failed to display profile picture: {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => println!("❌ Failed to get profile: {e}"),
    }

    Ok(())
}

async fn handle_stats(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
) -> Result<()> {
    println!("📊 Getting statistics for FID: {fid}");

    // Get storage limits which includes following count
    match hub_client.get_storage_limits(fid).await {
        Ok(storage_data) => {
            println!("✅ Storage limits retrieved:");

            if let Some(limits) = storage_data.get("limits").and_then(|l| l.as_array()) {
                for limit in limits {
                    if let (Some(store_type), Some(name), Some(limit_val), Some(used)) = (
                        limit.get("storeType").and_then(|s| s.as_str()),
                        limit.get("name").and_then(|n| n.as_str()),
                        limit.get("limit").and_then(|l| l.as_u64()),
                        limit.get("used").and_then(|u| u.as_u64()),
                    ) {
                        match name {
                            "LINKS" => {
                                println!(
                                    "   👥 Following: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            "CASTS" => {
                                println!(
                                    "   📝 Casts: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            "REACTIONS" => {
                                println!(
                                    "   ❤️  Reactions: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            "USER_DATA" => {
                                println!(
                                    "   👤 Profile Data: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            "VERIFICATIONS" => {
                                println!(
                                    "   ✅ Verifications: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            "USERNAME_PROOFS" => {
                                println!(
                                    "   🏷️  Username Proofs: {}/{} ({}%)",
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                            _ => {
                                println!(
                                    "   {} {}: {}/{} ({}%)",
                                    store_type,
                                    name,
                                    used,
                                    limit_val,
                                    if limit_val > 0 {
                                        (used * 100) / limit_val
                                    } else {
                                        0
                                    }
                                );
                            }
                        }
                    }
                }
            }

            // Show tier information if available
            if let Some(tier_subscriptions) = storage_data
                .get("tier_subscriptions")
                .and_then(|t| t.as_array())
            {
                if !tier_subscriptions.is_empty() {
                    println!("\n💎 Tier Information:");
                    for tier in tier_subscriptions {
                        if let (Some(tier_type), Some(expires_at)) = (
                            tier.get("tier_type").and_then(|t| t.as_str()),
                            tier.get("expires_at").and_then(|e| e.as_u64()),
                        ) {
                            if expires_at > 0 {
                                let expire_date =
                                    chrono::DateTime::from_timestamp(expires_at as i64, 0)
                                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                        .unwrap_or_else(|| "Unknown".to_string());
                                println!("   {} (expires: {})", tier_type, expire_date);
                            } else {
                                println!("   {} (permanent)", tier_type);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => println!("❌ Failed to get storage limits: {e}"),
    }

    Ok(())
}

async fn handle_spam_check(fids: Vec<u64>) -> Result<()> {
    println!("🚫 Checking spam status for FIDs: {:?}", fids);

    // Load spam checker
    let spam_checker = match crate::core::protocol::spam_checker::SpamChecker::load_from_file(
        "labels/labels/spam.jsonl",
    ) {
        Ok(checker) => checker,
        Err(e) => {
            println!("❌ Failed to load spam labels: {e}");
            println!("💡 Make sure the labels submodule is properly initialized");
            return Ok(());
        }
    };

    // Get statistics
    let (total, spam_count, non_spam_count) = spam_checker.get_stats();
    println!(
        "📊 Spam labels loaded: {} total, {} spam, {} non-spam",
        total, spam_count, non_spam_count
    );

    // Check each FID
    for fid in fids {
        match spam_checker.get_label(fid) {
            Some(label) => {
                let status = match label.label_value {
                    0 => "🚫 SPAM",
                    2 => "✅ CLEAN",
                    _ => "❓ UNKNOWN",
                };
                println!(
                    "   FID {}: {} (label_value: {})",
                    fid, status, label.label_value
                );
            }
            None => {
                println!("   FID {}: ❓ NOT FOUND (not in dataset)", fid);
            }
        }
    }

    Ok(())
}

async fn handle_spam_stat(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
) -> Result<()> {
    println!("📊 Getting comprehensive spam statistics...");

    // Load spam checker
    let spam_checker = match crate::core::protocol::spam_checker::SpamChecker::load_from_file(
        "labels/labels/spam.jsonl",
    ) {
        Ok(checker) => checker,
        Err(e) => {
            println!("❌ Failed to load spam labels: {e}");
            println!("💡 Make sure the labels submodule is properly initialized");
            return Ok(());
        }
    };

    // Get spam statistics
    let (total_labels, spam_count, non_spam_count) = spam_checker.get_stats();
    let unknown_count = total_labels - spam_count - non_spam_count;

    // Calculate percentages
    let spam_percentage = if total_labels > 0 {
        (spam_count * 100) / total_labels
    } else {
        0
    };
    let non_spam_percentage = if total_labels > 0 {
        (non_spam_count * 100) / total_labels
    } else {
        0
    };
    let unknown_percentage = if total_labels > 0 {
        (unknown_count * 100) / total_labels
    } else {
        0
    };

    println!("\n🚫 Spam Labels Statistics:");
    println!("{}", "─".repeat(50));
    println!("📊 Total Spam Labels: {}", total_labels);
    println!("🚫 Spam: {} ({:.1}%)", spam_count, spam_percentage as f64);
    println!(
        "✅ Non-Spam: {} ({:.1}%)",
        non_spam_count, non_spam_percentage as f64
    );
    println!(
        "❓ Unknown: {} ({:.1}%)",
        unknown_count, unknown_percentage as f64
    );

    // Get hub information for additional context
    println!("\n🌐 Hub Information:");
    println!("{}", "─".repeat(50));

    match hub_client.get_hub_info().await {
        Ok(hub_info) => {
            // Try to extract total user count from hub info
            let total_users = hub_info
                .get("totalUsers")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    // Try alternative field names
                    hub_info
                        .get("total_users")
                        .and_then(|v| v.as_u64())
                        .or_else(|| hub_info.get("userCount").and_then(|v| v.as_u64()))
                });

            if let Some(total_users) = total_users {
                println!("👥 Total Users in Hub: {}", total_users);

                // Calculate coverage percentage
                let coverage_percentage = if total_users > 0 {
                    (total_labels * 100) / total_users as usize
                } else {
                    0
                };

                println!(
                    "📈 Label Coverage: {:.1}% of total users",
                    coverage_percentage as f64
                );

                // Calculate spam rate among total users
                let spam_rate_total = if total_users > 0 {
                    (spam_count * 100) / total_users as usize
                } else {
                    0
                };

                println!(
                    "🚫 Spam Rate (vs total users): {:.1}%",
                    spam_rate_total as f64
                );

                // Show additional context
                let unlabeled_users = total_users as usize - total_labels;
                println!(
                    "❓ Unlabeled Users: {} ({:.1}%)",
                    unlabeled_users,
                    if total_users > 0 {
                        (unlabeled_users * 100) / total_users as usize
                    } else {
                        0
                    } as f64
                );
            } else {
                // Try to extract total users from dbStats
                if let Some(db_stats) = hub_info.get("dbStats") {
                    if let Some(num_fid_registrations) =
                        db_stats.get("numFidRegistrations").and_then(|v| v.as_u64())
                    {
                        println!("👥 Total FID Registrations: {}", num_fid_registrations);

                        // Calculate coverage percentage
                        let coverage_percentage = if num_fid_registrations > 0 {
                            (total_labels * 100) / num_fid_registrations as usize
                        } else {
                            0
                        };

                        println!(
                            "📈 Label Coverage: {:.1}% of registered FIDs",
                            coverage_percentage as f64
                        );

                        // Calculate spam rate among total users
                        let spam_rate_total = if num_fid_registrations > 0 {
                            (spam_count * 100) / num_fid_registrations as usize
                        } else {
                            0
                        };

                        println!(
                            "🚫 Spam Rate (vs registered FIDs): {:.1}%",
                            spam_rate_total as f64
                        );

                        // Show additional context
                        let unlabeled_users = num_fid_registrations as usize - total_labels;
                        println!(
                            "❓ Unlabeled FIDs: {} ({:.1}%)",
                            unlabeled_users,
                            if num_fid_registrations > 0 {
                                (unlabeled_users * 100) / num_fid_registrations as usize
                            } else {
                                0
                            } as f64
                        );
                    } else {
                        println!("❓ Total user count not available in hub info");
                        println!("📋 Hub Info: {}", serde_json::to_string_pretty(&hub_info)?);
                    }
                } else {
                    println!("❓ Total user count not available in hub info");
                    println!("📋 Hub Info: {}", serde_json::to_string_pretty(&hub_info)?);
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to get hub information: {e}");
            println!("💡 This might be because the Hub doesn't support the info endpoint");
        }
    }

    // Show additional statistics
    println!("\n📈 Additional Statistics:");
    println!("{}", "─".repeat(50));

    if total_labels > 0 {
        let spam_ratio = spam_count as f64 / total_labels as f64;
        let non_spam_ratio = non_spam_count as f64 / total_labels as f64;

        println!(
            "📊 Spam to Non-Spam Ratio: {:.2}:1",
            spam_ratio / non_spam_ratio
        );
        println!("📊 Clean Rate: {:.1}%", non_spam_percentage as f64);
        println!("📊 Spam Rate: {:.1}%", spam_percentage as f64);
    }

    // Show data freshness info if available
    if let Some(first_timestamp) = spam_checker.get_oldest_timestamp() {
        let first_date = chrono::DateTime::from_timestamp(first_timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        println!("📅 Oldest Label: {}", first_date);
    }

    if let Some(last_timestamp) = spam_checker.get_newest_timestamp() {
        let last_date = chrono::DateTime::from_timestamp(last_timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        println!("📅 Newest Label: {}", last_date);
    }

    println!("\n✅ Spam statistics retrieved successfully!");

    Ok(())
}

async fn handle_casts(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
    limit: u32,
    show_json: bool,
) -> Result<()> {
    let limit_text = if limit == 0 {
        "all".to_string()
    } else {
        limit.to_string()
    };
    println!("📝 Getting casts for FID: {fid} (limit: {limit_text})");

    match hub_client.get_casts_by_fid(fid, limit).await {
        Ok(casts) => {
            if casts.is_empty() {
                println!("❌ No casts found for FID: {fid}");
            } else if show_json {
                // Show full JSON structure
                println!("✅ Found {} cast(s) - showing full JSON:", casts.len());
                println!("{}", serde_json::to_string_pretty(&casts)?);
            } else {
                println!("✅ Found {} cast(s):", casts.len());
                println!("{}", "─".repeat(80));

                for (i, cast) in casts.iter().enumerate() {
                    // Extract cast data
                    let timestamp = cast
                        .get("data")
                        .and_then(|d| d.get("timestamp"))
                        .and_then(|t| t.as_u64())
                        .unwrap_or(0);

                    let cast_body = cast
                        .get("data")
                        .and_then(|d| d.get("castAddBody"))
                        .or_else(|| cast.get("data").and_then(|d| d.get("castBody")));

                    let text = cast_body
                        .and_then(|cb| cb.get("text"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("");

                    let hash = cast
                        .get("hash")
                        .and_then(|h| h.as_str())
                        .unwrap_or("unknown");

                    let signer = cast
                        .get("signer")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");

                    // Format timestamp (convert Farcaster epoch to Unix timestamp)
                    // Farcaster epoch starts at 2021-01-01 00:00:00 UTC
                    const FARCASTER_EPOCH: u64 = 1609459200; // January 1, 2021 UTC in seconds
                    let unix_timestamp = timestamp + FARCASTER_EPOCH;
                    let date_time = chrono::DateTime::from_timestamp(unix_timestamp as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    // Extract embeds if available
                    let embeds = cast_body
                        .and_then(|cb| cb.get("embeds"))
                        .and_then(|e| e.as_array());

                    let embed_count = embeds.map(|e| e.len()).unwrap_or(0);

                    // Extract mentions if available
                    let mentions = cast_body
                        .and_then(|cb| cb.get("mentions"))
                        .and_then(|m| m.as_array());

                    let mention_count = mentions.map(|m| m.len()).unwrap_or(0);

                    // Extract client info if available (some Hubs/APIs may include this)
                    let client_info =
                        cast.get("via")
                            .or_else(|| cast.get("client"))
                            .and_then(|c| c.as_str())
                            .or_else(|| {
                                // Check for client info in embeds
                                embeds.and_then(|e| {
                                    e.iter().find_map(|embed| {
                                        embed.get("url").and_then(|u| u.as_str()).filter(|url| {
                                            url.contains("client") || url.contains("via")
                                        })
                                    })
                                })
                            });

                    // Display cast
                    println!("\n{}. Cast at {}", i + 1, date_time);
                    println!("   Hash: {}", hash);
                    println!("   Signer: {}", signer);
                    if let Some(client) = client_info {
                        println!("   📱 Client: {}", client);
                    }

                    if !text.is_empty() {
                        // Truncate long texts for readability
                        let display_text = if text.len() > 200 {
                            format!("{}...", &text[..200])
                        } else {
                            text.to_string()
                        };
                        println!("   Text: {}", display_text);
                    } else {
                        println!("   Text: (empty)");
                    }

                    if embed_count > 0 {
                        println!("   📎 Embeds: {}", embed_count);
                    }

                    if mention_count > 0 {
                        println!("   👥 Mentions: {}", mention_count);
                    }
                }

                println!("{}", "─".repeat(80));
                println!("📊 Total: {} cast(s)", casts.len());
            }
        }
        Err(e) => println!("❌ Failed to get casts: {e}"),
    }

    Ok(())
}

async fn handle_submit_cast(
    hub_client: &crate::core::client::hub_client::FarcasterClient,
    fid: u64,
    text: String,
    parent_cast_fid: Option<u64>,
    parent_cast_hash: Option<String>,
    parent_url: Option<String>,
    embed_urls: Vec<String>,
) -> Result<()> {
    let text = text.trim().to_string();
    if text.is_empty() {
        println!("❌ Cast text cannot be empty");
        return Ok(());
    }

    let parent_cast_id = match (parent_cast_fid, parent_cast_hash) {
        (Some(fid), Some(hash)) => Some(crate::core::client::hub_client::CastId { fid, hash }),
        (None, None) => None,
        _ => {
            println!("❌ Both --parent-cast-fid and --parent-cast-hash are required");
            return Ok(());
        }
    };

    println!("📣 Submitting cast for FID: {fid}");
    let result = hub_client
        .submit_cast(fid, text, parent_cast_id, parent_url, embed_urls)
        .await;

    match result {
        Ok(response) => {
            println!("✅ Cast submitted successfully!");
            println!("📋 Response: {response:?}");
        }
        Err(e) => println!("❌ Failed to submit cast: {e}"),
    }

    Ok(())
}
