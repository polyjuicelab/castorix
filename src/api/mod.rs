//! REST API module for Castorix
//!
//! Provides a RESTful HTTP API server for interacting with Farcaster protocol
//!
//! # Security
//!
//! This API server is designed as a **READ-ONLY** interface that **NEVER** touches private keys.
//! All operations are query-only and do not require authentication.
//!
//! The server is safe to expose to the internet as it:
//! - Does NOT have access to private keys
//! - Does NOT have access to encrypted key storage
//! - Does NOT perform any signing operations
//! - Does NOT submit any transactions
//! - Only queries public data from Farcaster Hub and contracts
//!
//! For sensitive operations (signing, key management, transactions), use the CLI tool.

pub mod handlers;
pub mod routes;
pub mod server;
pub mod types;

pub use server::ApiServer;
pub use types::ApiError;
pub use types::ApiResponse;
