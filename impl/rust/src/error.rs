//! ACP SDK error types.

use thiserror::Error;

/// ACP SDK errors.
#[derive(Debug, Error)]
pub enum ACPError {
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Missing signature field in capability")]
    MissingSignature,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Server returned unexpected response: {0}")]
    UnexpectedResponse(String),
}

impl ACPError {
    /// Returns the HTTP status code if this is an HTTP error.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            ACPError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }
}
