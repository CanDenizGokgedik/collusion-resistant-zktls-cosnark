use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("recipient not found: {0}")]
    RecipientNotFound(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("send timeout")]
    Timeout,

    /// Layer 3: message authentication failure.
    ///
    /// Covers invalid signatures, unknown senders, stale/future timestamps,
    /// and any other authentication-layer rejection.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
}
