//! Transport abstraction for coordinator ↔ aux verifier communication.
//!
//! The `Transport` trait is deliberately simple: send a typed message to a
//! peer identified by `VerifierId`. Production implementations may use
//! gRPC, libp2p, or a message queue. The `InMemoryTransport` is for tests.

use crate::error::NetworkError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tls_attestation_core::ids::VerifierId;

/// Trait for sending opaque byte payloads to a named peer.
///
/// # Guarantees (production requirements)
///
/// - Messages must be authenticated (signed by sender key or over mTLS).
/// - Messages must be integrity-protected (TLS or similar).
/// - The transport must not silently drop messages (at-least-once delivery).
///
/// # Prototype
///
/// `InMemoryTransport` provides no authentication or ordering guarantees.
pub trait Transport: Send + Sync {
    /// Send a raw byte payload to the given verifier.
    fn send(&self, to: &VerifierId, payload: Vec<u8>) -> Result<(), NetworkError>;

    /// Receive pending messages for the given verifier (polling model).
    fn receive(&self, for_verifier: &VerifierId) -> Result<Vec<Vec<u8>>, NetworkError>;
}

/// In-memory transport backed by per-verifier message queues.
///
/// Thread-safe via `Mutex`. Only suitable for single-process tests.
#[derive(Default)]
pub struct InMemoryTransport {
    queues: Mutex<HashMap<VerifierId, Vec<Vec<u8>>>>,
}

impl InMemoryTransport {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a verifier so messages can be queued for it.
    pub fn register(&self, id: &VerifierId) {
        let mut q = self.queues.lock().unwrap();
        q.entry(id.clone()).or_default();
    }
}

impl Transport for InMemoryTransport {
    fn send(&self, to: &VerifierId, payload: Vec<u8>) -> Result<(), NetworkError> {
        let mut queues = self.queues.lock().unwrap();
        let queue = queues
            .get_mut(to)
            .ok_or_else(|| NetworkError::RecipientNotFound(to.to_string()))?;
        queue.push(payload);
        Ok(())
    }

    fn receive(&self, for_verifier: &VerifierId) -> Result<Vec<Vec<u8>>, NetworkError> {
        let mut queues = self.queues.lock().unwrap();
        let queue = queues
            .get_mut(for_verifier)
            .ok_or_else(|| NetworkError::RecipientNotFound(for_verifier.to_string()))?;
        let msgs = std::mem::take(queue);
        Ok(msgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::VerifierId;

    #[test]
    fn send_and_receive() {
        let t = InMemoryTransport::new();
        let v = VerifierId::from_bytes([1u8; 32]);
        t.register(&v);
        t.send(&v, b"hello".to_vec()).unwrap();
        t.send(&v, b"world".to_vec()).unwrap();
        let msgs = t.receive(&v).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], b"hello");
        assert_eq!(msgs[1], b"world");
    }

    #[test]
    fn receive_drains_queue() {
        let t = InMemoryTransport::new();
        let v = VerifierId::from_bytes([2u8; 32]);
        t.register(&v);
        t.send(&v, b"msg".to_vec()).unwrap();
        let _ = t.receive(&v).unwrap();
        let second = t.receive(&v).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn send_to_unregistered_fails() {
        let t = InMemoryTransport::new();
        let v = VerifierId::from_bytes([3u8; 32]);
        assert!(matches!(
            t.send(&v, b"data".to_vec()),
            Err(NetworkError::RecipientNotFound(_))
        ));
    }
}
