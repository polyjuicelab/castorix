use clap::Subcommand;

/// API server commands
#[derive(Subcommand)]
pub enum ApiCommands {
    /// Start REST API server
    ///
    /// Run the HTTP REST API server to expose Farcaster query capabilities via HTTP endpoints.
    /// The server provides a traditional RESTful API with /api/* routes.
    ///
    /// Example: castorix api serve --port 3000
    /// Example: castorix api serve caster --fid 12345 --host 127.0.0.1 --port 3001
    Serve {
        /// Host to bind to (default: 0.0.0.0)
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Port to bind to (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Optional serve mode (read-only by default)
        #[command(subcommand)]
        mode: Option<ApiServeMode>,
    },
}

#[derive(Subcommand)]
pub enum ApiServeMode {
    /// ✍️ Enable cast submission endpoint
    ///
    /// Starts the API server with a cast submission endpoint that accepts JSON.
    /// ⚠️  This mode uses local Ed25519 keys and should NOT be exposed publicly.
    ///
    /// Example: castorix api serve caster --fid 12345
    Caster {
        /// Farcaster ID (FID) to post as
        #[arg(long)]
        fid: u64,
        /// Host to bind to (overrides --host)
        #[arg(long)]
        host: Option<String>,
        /// Port to bind to (overrides --port)
        #[arg(long)]
        port: Option<u16>,
    },
}

/// MCP server commands
#[derive(Subcommand)]
pub enum McpCommands {
    /// Start MCP server in stdio mode
    ///
    /// Run the MCP server to expose Farcaster query tools to AI assistants.
    /// The server communicates via JSON-RPC 2.0 over stdin/stdout.
    ///
    /// Example: castorix mcp serve
    Serve,
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// 📋 Show wallet information
    ///
    /// Display detailed information about the currently loaded wallet,
    /// including address, public key, and other relevant details.
    ///
    /// Example: castorix key info
    Info,

    /// ✍️ Sign a message
    ///
    /// Sign a message with the currently loaded private key.
    /// The signature can be used to prove ownership of the wallet.
    ///
    /// Example: castorix key sign "Hello Farcaster!"
    Sign {
        /// Message to sign
        message: String,
    },

    /// 🔍 Verify a signature
    ///
    /// Verify that a signature was created by the wallet owner.
    /// Useful for validating message authenticity.
    ///
    /// Example: castorix key verify "Hello Farcaster!" 0x1234abcd...
    Verify {
        /// Message that was signed
        message: String,
        /// Signature to verify (hex string)
        signature: String,
    },

    /// 🔐 Generate a new private key (legacy mode)
    ///
    /// Generate a new private key and display it in plain text.
    /// ⚠️  WARNING: This displays the private key in plain text!
    /// For secure storage, use 'generate-encrypted' instead.
    ///
    /// Example: castorix key generate
    Generate,

    /// 🆕 Generate and encrypt a new private key
    ///
    /// Create a new private key and store it encrypted with a password.
    /// This is the recommended way to create new wallets securely.
    /// This command will prompt you for the key name and alias.
    ///
    /// Example: castorix key generate-encrypted
    GenerateEncrypted,

    /// 📥 Import and encrypt an existing private key
    ///
    /// Import an existing private key and store it encrypted with a password.
    /// Perfect for migrating from other wallet software.
    /// This command will prompt you for the private key securely.
    ///
    /// Example: castorix key import
    Import,

    /// 🔓 Load an encrypted private key
    ///
    /// Load and decrypt a previously stored private key.
    /// You'll be prompted for the password to decrypt the key.
    ///
    /// Example: castorix key load my-wallet
    Load {
        /// Name of the encrypted key to load
        key_name: String,
    },

    /// 📝 List all encrypted keys
    ///
    /// Display all your encrypted keys with their aliases, addresses,
    /// and creation dates. No passwords required for this operation.
    ///
    /// Example: castorix key list
    List,

    /// 🗑️ Delete an encrypted key
    ///
    /// Permanently delete an encrypted key from storage.
    /// You'll be prompted for the password to confirm deletion.
    /// ⚠️  WARNING: This action cannot be undone!
    ///
    /// Example: castorix key delete old-wallet
    Delete {
        /// Name of the encrypted key to delete
        key_name: String,
    },

    /// 🔄 Rename an encrypted key
    ///
    /// Change the filename/identifier of an encrypted key.
    /// The alias and other data remain unchanged.
    ///
    /// Example: castorix key rename old-name new-name
    Rename {
        /// Current key name
        old_name: String,
        /// New key name
        new_name: String,
    },

    /// 🏷️ Update key alias
    ///
    /// Change the display alias (friendly name) of an encrypted key.
    /// This doesn't affect the filename or other data.
    ///
    /// Example: castorix key update-alias my-wallet "My Updated Wallet"
    UpdateAlias {
        /// Key name
        key_name: String,
        /// New alias
        new_alias: String,
    },
}

#[derive(Subcommand)]
pub enum HubKeyCommands {
    /// 📥 Import an existing ECDSA private key
    ///
    /// Import an existing ECDSA private key for a specific FID and encrypt it with a password.
    /// This creates the custody key needed for Farcaster account management.
    /// The private key will be prompted interactively to avoid it appearing in shell history.
    ///
    /// Example: castorix hub key import 12345
    Import {
        /// FID (Farcaster ID) for this key
        fid: u64,
    },

    /// 📋 List all ECDSA keys
    ///
    /// Display all ECDSA keys stored locally with their FIDs, addresses, and creation dates.
    /// This is a read-only operation that shows all available custody keys.
    ///
    /// Example: castorix hub key list
    List,

    /// 🗑️ Delete ECDSA key for a FID
    ///
    /// Permanently delete the ECDSA key associated with a specific FID from local storage.
    /// This will remove the encrypted key file but will not affect the on-chain state.
    /// ⚠️  WARNING: This action cannot be undone!
    ///
    /// Example: castorix hub key delete 12345
    Delete {
        /// FID (Farcaster ID) of the key to delete
        fid: u64,
    },

    /// 🌱 Generate ECDSA key from recovery phrase
    ///
    /// Generate ECDSA (Custody) key from a recovery phrase (mnemonic) for a specific FID.
    /// This creates the custody key needed for Farcaster account management.
    /// The recovery phrase will be prompted interactively to avoid it appearing in shell history.
    ///
    /// Example: castorix hub key from-mnemonic 12345
    FromMnemonic {
        /// FID (Farcaster ID) for this key
        fid: u64,
    },
}

#[derive(Subcommand)]
pub enum SignersCommands {
    /// 📋 List all local Ed25519 signer keys
    ///
    /// Display all Ed25519 signer keys stored locally.
    /// Shows FID, public key, creation date, and status for each key.
    ///
    /// Example: castorix signers list
    List,

    /// 🔍 Get signers for a FID
    ///
    /// Retrieve all active signers (account keys) associated with a specific Farcaster ID.
    /// This shows the Ed25519 public keys that are authorized to sign messages for this FID.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix signers info 12345
    Info {
        /// FID (Farcaster ID) to get signers for
        fid: u64,
    },

    /// ➕ Register a signer to a FID
    ///
    /// Register a new Ed25519 signer key to a Farcaster ID (FID).
    /// This will generate a new Ed25519 key pair, encrypt and store it locally,
    /// and register it on-chain for the specified FID.
    ///
    /// The system will automatically find the custody wallet for the FID.
    /// If multiple wallets are found, you'll be prompted to choose one.
    ///
    /// ⚠️  WARNING: This triggers on-chain operations and consumes gas fees.
    /// You will be prompted for confirmation before proceeding.
    ///
    /// The generated private key will be encrypted and stored securely.
    ///
    /// Example: castorix signers register 12345
    /// Example: castorix signers register 12345 --wallet my-wallet
    /// Example: castorix signers register 12345 --payment-wallet gas-payer --dry-run
    Register {
        /// FID (Farcaster ID) to register signer to
        fid: u64,
        /// ECDSA wallet name for custody key (optional, auto-detected if not provided)
        #[arg(long)]
        wallet: Option<String>,
        /// ECDSA wallet name for gas payment (optional, defaults to custody wallet)
        #[arg(long)]
        payment_wallet: Option<String>,
        /// Simulate the transaction without sending it to the chain
        #[arg(long)]
        dry_run: bool,
        /// Automatically confirm the operation without prompting
        #[arg(long)]
        yes: bool,
    },

    /// ➖ Unregister a signer from a FID
    ///
    /// Unregister an existing Ed25519 signer key from a Farcaster ID (FID).
    /// This will remove the key from the on-chain registry.
    /// The local encrypted key will remain stored for potential future use.
    ///
    /// The system will automatically find the custody wallet for the FID.
    /// If multiple wallets are found, you'll be prompted to choose one.
    ///
    /// ⚠️  WARNING: This triggers on-chain operations and consumes gas fees.
    /// You will be prompted for confirmation before proceeding.
    ///
    /// Example: castorix signers unregister 12345
    /// Example: castorix signers unregister 12345 --wallet my-wallet
    /// Example: castorix signers unregister 12345 --payment-wallet gas-payer --dry-run
    Unregister {
        /// FID (Farcaster ID) to unregister signer from
        fid: u64,
        /// ECDSA wallet name for custody key (optional, auto-detected if not provided)
        #[arg(long)]
        wallet: Option<String>,
        /// ECDSA wallet name for gas payment (optional, defaults to custody wallet)
        #[arg(long)]
        payment_wallet: Option<String>,
        /// Simulate the transaction without sending it to the chain
        #[arg(long)]
        dry_run: bool,
    },

    /// 📥 Import an Ed25519 signer key
    ///
    /// Import an existing Ed25519 private key for a specific FID.
    /// The private key will be encrypted and stored locally.
    /// This allows you to use an existing Ed25519 key as a signer.
    ///
    /// Example: castorix signers import 12345
    #[clap(hide = true)]
    Import {
        /// FID (Farcaster ID) for this signer key
        fid: u64,
    },

    /// 📤 Export a local Ed25519 signer key
    ///
    /// Export a locally stored Ed25519 private key by its index number or public key.
    /// This allows you to backup the private key before deleting it.
    /// The private key will be displayed in hex format for secure storage.
    ///
    /// You can specify either:
    /// - An index number from 'castorix signers list' output (e.g., 1, 2, 3)
    /// - A public key (hex format, with or without 0x prefix)
    ///
    /// ⚠️  WARNING: Keep the exported private key secure and never share it.
    ///
    /// Example: castorix signers export 1
    /// Example: castorix signers export 48400d66960f2c4450e8847ad87b40274fd16d2796ece2a938219a8a737803cc
    Export {
        /// Index number or public key of the Ed25519 signer to export
        identifier: String,
    },

    /// 🗑️ Delete a local Ed25519 signer key
    ///
    /// Delete a locally stored Ed25519 private key by its public key or index number.
    /// This only removes the key from local storage and does not affect on-chain registration.
    /// The key will be permanently deleted and cannot be recovered.
    ///
    /// You can specify either:
    /// - A public key (hex format, with or without 0x prefix)
    /// - An index number from 'castorix signers list' output
    ///
    /// ⚠️  WARNING: This action cannot be undone. The private key will be permanently deleted.
    /// Make sure to export/backup the key first using 'castorix signers export <pubkey>'.
    ///
    /// Example: castorix signers delete 48400d66960f2c4450e8847ad87b40274fd16d2796ece2a938219a8a737803cc
    /// Example: castorix signers delete 1
    Delete {
        /// Public key or index number of the Ed25519 signer to delete
        identifier: String,
    },
}

#[derive(Subcommand)]
pub enum CustodyCommands {
    /// 📋 List all ECDSA keys
    ///
    /// Display all ECDSA keys associated with Farcaster IDs.
    /// Shows FID, address, creation date, and status for each key.
    ///
    /// Example: castorix custody list
    List,

    /// 📥 Import an ECDSA private key
    ///
    /// Import an existing ECDSA private key for a specific FID.
    /// The private key will be encrypted and stored securely.
    ///
    /// Example: castorix custody import 12345
    Import {
        /// FID (Farcaster ID) for this key
        fid: u64,
    },

    /// 🔑 Generate ECDSA key from mnemonic
    ///
    /// Generate an ECDSA key pair from a BIP39 mnemonic phrase for a specific FID.
    /// The recovery phrase will be prompted interactively to avoid it appearing in shell history.
    ///
    /// Example: castorix custody from-mnemonic 12345
    FromMnemonic {
        /// FID (Farcaster ID) for this key
        fid: u64,
    },

    /// 🗑️ Delete an ECDSA key
    ///
    /// Remove an ECDSA key for a specific FID from local storage.
    /// This will permanently delete the encrypted key file.
    ///
    /// Example: castorix custody delete 12345
    Delete {
        /// FID (Farcaster ID) to delete key for
        fid: u64,
    },
}

#[derive(Subcommand)]
pub enum EnsCommands {
    /// 🔍 Resolve ENS domain to address
    ///
    /// Look up the Ethereum address associated with an ENS domain.
    /// Useful for verifying domain ownership before creating proofs.
    ///
    /// Example: castorix ens resolve vitalik.eth
    Resolve {
        /// ENS domain to resolve (e.g., vitalik.eth)
        domain: String,
    },

    /// 🔗 Get ENS domains owned by an Ethereum address
    ///
    /// Query on-chain ENS registry to find all domains owned by a specific address.
    /// This requires an Ethereum RPC URL and may take some time to complete.
    ///
    /// Example: castorix ens domains 0x1234...
    Domains {
        /// Ethereum address to query
        address: String,
    },

    /// 🏗️ Get Base subdomains (*.base.eth) owned by an Ethereum address
    ///
    /// ⚠️  Note: This feature has been removed as Base chain reverse lookup
    /// is not supported. Base subdomains are not indexed by The Graph API.
    ///
    /// Example: castorix ens base-subdomains 0x1234...
    BaseSubdomains {
        /// Ethereum address to query
        address: String,
    },

    /// 🌐 Get all ENS domains owned by an Ethereum address
    ///
    /// Queries for regular ENS domains owned by the address.
    ///
    /// Example: castorix ens all-domains 0x1234...
    AllDomains {
        /// Ethereum address to query
        address: String,
    },

    /// 🔍 Check if a specific Base subdomain exists and get its owner
    ///
    /// Check if a specific Base subdomain like ryankung.base.eth exists
    /// and get its owner address.
    ///
    /// Example: castorix ens check-base-subdomain ryankung.base.eth
    CheckBaseSubdomain {
        /// Base subdomain to check (e.g., ryankung.base.eth)
        domain: String,
    },

    /// 🔗 Query Base chain ENS contract directly
    ///
    /// Query the Base chain ENS contract directly to get domain ownership.
    /// This bypasses The Graph and queries the contract on-chain.
    ///
    /// Example: castorix ens query-base-contract ryankung.base.eth
    QueryBaseContract {
        /// Base subdomain to query (e.g., ryankung.base.eth)
        domain: String,
    },

    /// ✅ Verify ENS domain ownership
    ///
    /// Check if the currently loaded wallet owns the specified ENS domain.
    /// This is required before creating username proofs.
    ///
    /// Example: castorix ens verify mydomain.eth
    Verify {
        /// ENS domain to verify
        domain: String,
    },

    /// 📝 Generate username proof for ENS domain
    ///
    /// Generate a signed proof linking your ENS domain to your Farcaster ID.
    /// This proof can be submitted to Farcaster to verify domain ownership.
    ///
    /// Example: castorix ens proof mydomain.eth 12345 --wallet-name my-wallet
    Proof {
        /// ENS domain name
        domain: String,
        /// Farcaster ID (your FID)
        fid: u64,
        /// Wallet name for encrypted key (required)
        #[arg(long)]
        wallet_name: Option<String>,
    },

    /// 🔍 Verify a username proof
    ///
    /// Verify that a username proof is valid and was signed by the domain owner.
    /// Useful for validating proofs before submission.
    ///
    /// Example: castorix ens verify-proof proof.json
    VerifyProof {
        /// Path to proof JSON file
        proof_file: String,
    },
}

#[derive(Subcommand)]
pub enum HubCommands {
    /// 👤 Get user information
    ///
    /// Retrieve detailed information about a Farcaster user by their FID.
    /// Includes profile data, verification status, and other public information.
    ///
    /// Example: castorix hub user 12345
    User {
        /// Farcaster ID (FID)
        fid: u64,
    },

    /// 📤 Submit username proof
    ///
    /// Submit a previously created username proof to Farcaster Hub.
    /// This links your ENS domain to your Farcaster identity.
    ///
    /// The system will automatically use the Ed25519 key bound to the specified FID.
    /// If no Ed25519 key exists for the FID, an error will be displayed.
    ///
    /// Example: castorix hub submit-proof proof.json 12345
    /// Example: castorix hub submit-proof proof.json 12345 --wallet-name my-wallet
    SubmitProof {
        /// Path to proof JSON file
        proof_file: String,
        /// FID (Farcaster ID) for Ed25519 key signing
        fid: u64,
        /// Wallet name for encrypted key (required)
        #[arg(long)]
        wallet_name: Option<String>,
    },

    /// 🔍 Get Ethereum addresses for a FID
    ///
    /// Retrieve all Ethereum addresses bound to a specific Farcaster ID.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub eth-addresses 12345
    EthAddresses {
        /// Farcaster ID (FID)
        fid: u64,
    },

    /// 🌐 Get ENS domains with proofs for a FID
    ///
    /// Retrieve all ENS domains that have proofs for a specific Farcaster ID.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub ens-domains 12345
    EnsDomains {
        /// Farcaster ID (FID)
        fid: u64,
    },

    /// 🏠 Get custody address for a FID
    ///
    /// Retrieve the custody address (Ethereum address) associated with a specific Farcaster ID.
    /// The custody address is the Ethereum address that registered the FID and has control over it.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub custody-address 12345
    CustodyAddress {
        /// FID (Farcaster ID) to get custody address for
        fid: u64,
    },

    /// 📊 Get Hub information and sync status
    ///
    /// Retrieve information about the Farcaster Hub including all Shards sync status.
    /// This shows the current state of data synchronization across different shards.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub info
    Info,

    /// 👥 Get followers for a FID
    ///
    /// Retrieve all users who follow the specified Farcaster ID.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub followers 12345
    /// Example: castorix hub followers 12345 --limit 0  # Get all followers
    Followers {
        /// Farcaster ID (FID) to get followers for
        fid: u64,
        /// Maximum number of followers to retrieve (0 for all, default: 1000)
        #[arg(long, default_value = "1000")]
        limit: u32,
    },

    /// 👤 Get following for a FID
    ///
    /// Retrieve all users that the specified Farcaster ID follows.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub following 12345
    /// Example: castorix hub following 12345 --limit 0  # Get all following
    Following {
        /// Farcaster ID (FID) to get following for
        fid: u64,
        /// Maximum number of following to retrieve (0 for all, default: 1000)
        #[arg(long, default_value = "1000")]
        limit: u32,
    },

    /// 👤 Get user profile for a FID
    ///
    /// Retrieve profile information for the specified Farcaster ID.
    /// By default shows only username, display name, bio, and profile picture.
    /// Use --all to show complete profile information including all user data.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub profile 12345
    /// Example: castorix hub profile 12345 --all
    Profile {
        /// Farcaster ID (FID) to get profile for
        fid: u64,
        /// Show all profile information instead of just basic info
        #[arg(long)]
        all: bool,
    },

    /// 📊 Get user statistics for a FID
    ///
    /// Retrieve statistics and storage limits for the specified Farcaster ID.
    /// This shows follower count, following count, and storage usage.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub stats 12345
    Stats {
        /// Farcaster ID (FID) to get statistics for
        fid: u64,
    },

    /// 🚫 Check spam status for FIDs
    ///
    /// Check if one or more FIDs are marked as spam in Warpcast's spam labels dataset.
    /// This uses the public spam labels from merkle-team/labels repository.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub spam 12345
    /// Example: castorix hub spam 12345 67890 11111
    Spam {
        /// Farcaster ID(s) (FID) to check for spam status
        fids: Vec<u64>,
    },

    /// 📊 Get spam statistics
    ///
    /// Display comprehensive spam statistics including total labels, spam count,
    /// non-spam count, and percentages. Combines with hub status to show total
    /// user count and provide additional context.
    ///
    /// Example: castorix hub spam-stat
    SpamStat,

    /// 📝 Get casts (posts) for a FID
    ///
    /// Retrieve recent casts posted by a specific Farcaster ID.
    /// This returns the most recent casts with their content, timestamps, and metadata.
    /// Use --limit to control how many casts to retrieve (0 for all available).
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix hub casts 12345
    /// Example: castorix hub casts 12345 --limit 10
    /// Example: castorix hub casts 12345 --limit 0  # Get all casts
    /// Example: castorix hub casts 12345 --json     # Show full JSON data
    Casts {
        /// Farcaster ID (FID) to get casts for
        fid: u64,
        /// Maximum number of casts to retrieve (0 for all, default: 20)
        #[arg(long, default_value = "20")]
        limit: u32,
        /// Show full JSON data structure instead of formatted output
        #[arg(long)]
        json: bool,
    },

    /// ✍️ Submit a new cast
    ///
    /// Post a new cast to the Farcaster Hub using your Ed25519 signer key.
    /// This requires a local Ed25519 key for the FID.
    ///
    /// Example: castorix hub cast 12345 "Hello Farcaster!"
    /// Example: castorix hub cast 12345 "Replying!" --parent-cast-fid 42 --parent-cast-hash 0xabc...
    /// Example: castorix hub cast 12345 "Sharing" --parent-url https://example.com
    /// Example: castorix hub cast 12345 "Check this" --embed-url https://example.com
    Cast {
        /// Farcaster ID (FID) to post as
        fid: u64,
        /// Cast text content
        text: String,
        /// Parent cast FID (for replies)
        #[arg(long, requires = "parent_cast_hash", conflicts_with = "parent_url")]
        parent_cast_fid: Option<u64>,
        /// Parent cast hash (hex, for replies)
        #[arg(long, requires = "parent_cast_fid", conflicts_with = "parent_url")]
        parent_cast_hash: Option<String>,
        /// Parent URL to attach (mutually exclusive with parent cast)
        #[arg(long, conflicts_with = "parent_cast_fid")]
        parent_url: Option<String>,
        /// Embed URL(s) to attach
        #[arg(long)]
        embed_url: Vec<String>,
    },
}

/// FID (Farcaster ID) registration and management commands
#[derive(Subcommand)]
pub enum FidCommands {
    /// 🆕 Register a new FID
    ///
    /// Register a new Farcaster ID (FID) on the blockchain.
    /// This requires a wallet with sufficient ETH for gas fees and registration cost.
    /// You can optionally specify extra storage units to rent during registration.
    ///
    /// ⚠️  WARNING: This triggers on-chain operations and consumes gas fees.
    /// You will be prompted for confirmation before proceeding.
    ///
    /// Example: castorix fid register
    /// Example: castorix fid register --wallet my-wallet
    /// Example: castorix fid register --extra-storage 5 --dry-run
    Register {
        /// Wallet name for registration (required)
        #[arg(long)]
        wallet: Option<String>,
        /// Number of extra storage units to rent (default: 0)
        #[arg(long, default_value = "0")]
        extra_storage: u64,
        /// Recovery address (optional, defaults to same as registration wallet)
        #[arg(long)]
        recovery: Option<String>,
        /// Simulate the transaction without sending it to the chain
        #[arg(long)]
        dry_run: bool,
        /// Automatically confirm the operation without prompting
        #[arg(long)]
        yes: bool,
    },

    /// 💰 Check registration price
    ///
    /// Check the current cost to register a new FID, including optional extra storage.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix fid price
    /// Example: castorix fid price --extra-storage 5
    Price {
        /// Number of extra storage units to include in price calculation (default: 0)
        #[arg(long, default_value = "0")]
        extra_storage: u64,
    },

    /// 📋 List FIDs owned by wallet
    ///
    /// List all FIDs owned by a specific wallet address.
    /// This is a read-only operation that queries the blockchain.
    ///
    /// Example: castorix fid list
    /// Example: castorix fid list --wallet my-wallet
    List {
        /// Wallet name to check FIDs for (required)
        #[arg(long)]
        wallet: Option<String>,
    },
}

/// Storage rental and management commands
#[derive(Subcommand)]
pub enum StorageCommands {
    /// 🏠 Rent storage units
    ///
    /// Rent additional storage units for a specific FID.
    /// This allows the FID to store more messages, casts, and other data.
    /// Requires the custody wallet for the FID to authorize the transaction.
    ///
    /// ⚠️  WARNING: This triggers on-chain operations and consumes gas fees.
    /// You will be prompted for confirmation before proceeding.
    ///
    /// Example: castorix storage rent 12345 --units 5
    /// Example: castorix storage rent 12345 --units 10 --wallet my-wallet --dry-run
    /// Example: castorix storage rent 12345 --units 5 --wallet custody-wallet --payment-wallet gas-payer
    Rent {
        /// FID (Farcaster ID) to rent storage for
        fid: u64,
        /// Number of storage units to rent
        #[arg(long)]
        units: u32,
        /// Wallet name for custody key (optional, auto-detected if not provided)
        #[arg(long)]
        wallet: Option<String>,
        /// ECDSA wallet name for gas payment (optional, defaults to custody wallet)
        #[arg(long)]
        payment_wallet: Option<String>,
        /// Simulate the transaction without sending it to the chain
        #[arg(long)]
        dry_run: bool,
        /// Automatically confirm the operation without prompting
        #[arg(long)]
        yes: bool,
    },

    /// 💰 Check storage rental price
    ///
    /// Check the current cost to rent storage units for a FID.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix storage price 12345 --units 5
    Price {
        /// FID (Farcaster ID) to check storage price for
        fid: u64,
        /// Number of storage units to check price for
        #[arg(long)]
        units: u32,
    },

    /// 📊 Check storage usage and limits
    ///
    /// Check the current storage usage and limits for a specific FID.
    /// This shows how much storage is currently used and available.
    /// This is a read-only operation that doesn't require authentication.
    ///
    /// Example: castorix storage usage 12345
    Usage {
        /// FID (Farcaster ID) to check storage usage for
        fid: u64,
    },
}
