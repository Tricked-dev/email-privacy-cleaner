//! Error types for the email privacy cleaner.

use thiserror::Error;

/// Errors that can occur while cleaning a message.
///
/// The milter and CLI translate these into either a fail-open behaviour
/// (return the original message plus an `X-Privacy-Cleaner-Error` header) or a
/// tempfail, depending on configuration.
#[derive(Debug, Error)]
pub enum CleanerError {
    /// The raw message exceeded `max_message_size`.
    #[error("message too large: {size} bytes exceeds limit of {limit} bytes")]
    MessageTooLarge { size: usize, limit: usize },

    /// The MIME message could not be parsed at all.
    #[error("failed to parse MIME message")]
    MimeParse,

    /// An individual HTML part could not be processed.
    #[error("html rewrite failed: {0}")]
    Html(String),

    /// Re-encoding a modified body part failed.
    #[error("re-encoding failed: {0}")]
    Encoding(String),

    /// Configuration could not be loaded or was invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O error (CLI / milter transport).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The optional network resolver was invoked but is unavailable or refused.
    #[error("network resolver: {0}")]
    Network(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CleanerError>;
