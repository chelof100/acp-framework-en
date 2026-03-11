//! # ACP SDK for Rust
//!
//! Agent Control Protocol (ACP) v1.0 client SDK.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use acp_sdk::{AgentIdentity, ACPSigner, ACPClient};
//!
//! let agent = AgentIdentity::generate();
//! let signer = ACPSigner::new(&agent);
//! let client = ACPClient::new("http://localhost:8080", &agent, &signer);
//!
//! client.register().unwrap();
//! let health = client.health().unwrap();
//! println!("{}", health);
//! ```

pub mod error;
pub mod identity;
pub mod signer;
pub mod client;

pub use error::ACPError;
pub use identity::{AgentIdentity, derive_agent_id};
pub use signer::{ACPSigner, jcs_canonicalize};
pub use client::ACPClient;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
