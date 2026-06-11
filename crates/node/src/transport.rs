//! Layer 2: `FrostNodeTransport` — abstraction over in-process and TCP aux nodes.
//!
//! # Why a trait?
//!
//! `CoordinatorNode::attest_frost_distributed_inner` today calls
//! `node.frost_round1()` and `node.frost_round2()` directly on
//! `FrostAuxiliaryNode` objects living in the same process.  That path remains
//! untouched for unit tests.
//!
//! `FrostNodeTransport` wraps that interface so the coordinator's distributed
//! attestation logic can call the same methods regardless of whether the node
//! is local or remote:
//!
//! ```text
//!  CoordinatorNode
//!      └── attest_frost_distributed_over_transport(&[&dyn FrostNodeTransport])
//!               ├── InProcessTransport  → direct method call (test / single-process)
//!               └── TcpNodeTransport    → length-prefixed JSON over TCP (production)
//! ```
//!
//! # TCP wire format
//!
//! Each round trip uses the codec from `tls_attestation_network::codec`:
//!
//! ```text
//! coordinator                                  aux node server
//!     ──── NodeRequest::FrostRound1(req) ────►
//!     ◄─── NodeResponse::FrostRound1(resp) ───
//!
//!     ──── NodeRequest::FrostRound2(req) ────►
//!     ◄─── NodeResponse::FrostRound2(resp) ───
//! ```
//!
//! The server opens a fresh `TcpStream` connection per request from the pool and
//! closes it after the response. This keeps the protocol stateless and avoids
//! connection multiplexing complexity for Layer 2.
//!
//! # Authentication (Layer 4 TODO)
//!
//! TCP connections are **unauthenticated** in this layer.  A future layer will
//! wrap the stream in mTLS or an ed25519-signed envelope before any application
//! data is exchanged.

use crate::error::NodeError;
use tls_attestation_core::ids::VerifierId;
use tls_attestation_core::types::UnixTimestamp;
use tls_attestation_network::messages::{
    FrostRound1Request, FrostRound1Response, FrostRound2Request, FrostRound2Response,
    HandshakeBindingRound1Request, HandshakeBindingRound1Response,
    HandshakeBindingRound2Request, HandshakeBindingRound2Response,
};
use tls_attestation_network::{
    codec::{read_frame, write_frame, NodeRequest, NodeResponse},
    NetworkError,
};

use std::io::BufWriter;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use crate::frost_aux::FrostAuxiliaryNode;

// ── FrostNodeTransport trait ──────────────────────────────────────────────────

/// Abstraction over a single remote (or local) FROST auxiliary node.
///
/// Implementations must be `Send + Sync` so the coordinator can hold a
/// `Vec<Box<dyn FrostNodeTransport>>` and call them from any thread.
pub trait FrostNodeTransport: Send + Sync {
    /// The verifier identity of the node this transport connects to.
    fn verifier_id(&self) -> &VerifierId;

    /// Send a Round-1 request and return the node's response.
    ///
    /// `now` is the coordinator's current time; the node uses it only in the
    /// in-process implementation.  The TCP implementation lets the server
    /// generate its own `now` since the request carries `round_expires_at`.
    fn frost_round1(
        &self,
        req: &FrostRound1Request,
        now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError>;

    /// Send a Round-2 request and return the node's response.
    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError>;

    /// Handshake Binding Round 1 — send `binding_input` and collect nonce commitment.
    fn handshake_binding_round1(
        &self,
        req: &HandshakeBindingRound1Request,
        now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError>;

    /// Handshake Binding Round 2 — send signing package and collect share.
    fn handshake_binding_round2(
        &self,
        req: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError>;
}

// ── InProcessTransport ────────────────────────────────────────────────────────

/// Transport that calls a `FrostAuxiliaryNode` in the same process.
///
/// Zero overhead — no serialization, no network I/O. Used in unit tests and
/// single-binary deployments where all nodes share a process.
pub struct InProcessTransport<'a> {
    node: &'a FrostAuxiliaryNode,
}

impl<'a> InProcessTransport<'a> {
    pub fn new(node: &'a FrostAuxiliaryNode) -> Self {
        Self { node }
    }
}

impl<'a> FrostNodeTransport for InProcessTransport<'a> {
    fn verifier_id(&self) -> &VerifierId {
        self.node.verifier_id()
    }

    fn frost_round1(
        &self,
        req: &FrostRound1Request,
        now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError> {
        self.node.frost_round1(req, now)
    }

    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        self.node.frost_round2(req)
    }

    fn handshake_binding_round1(
        &self,
        req: &HandshakeBindingRound1Request,
        now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError> {
        self.node.handshake_binding_round1(req, now)
    }

    fn handshake_binding_round2(
        &self,
        req: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError> {
        self.node.handshake_binding_round2(req)
    }
}

// ── TcpNodeTransport ──────────────────────────────────────────────────────────

/// Transport that sends FROST round messages to a remote aux node over TCP.
///
/// Opens a fresh TCP connection per request (stateless). The remote end must
/// be running a `TcpAuxServer`.
///
/// # Error handling
///
/// Any I/O failure is converted to `NodeError::FrostProtocol`. The coordinator
/// treats this as a per-node failure and may continue with other nodes if the
/// quorum threshold is still reachable.
pub struct TcpNodeTransport {
    verifier_id: VerifierId,
    addr: SocketAddr,
    /// TCP connect + read timeout (default: 30 seconds).
    timeout: std::time::Duration,
}

impl TcpNodeTransport {
    /// Create a transport targeting `addr` for the node identified by `verifier_id`.
    pub fn new(verifier_id: VerifierId, addr: impl ToSocketAddrs) -> Result<Self, NetworkError> {
        let addr = addr
            .to_socket_addrs()
            .map_err(|e| NetworkError::Serialization(e.to_string()))?
            .next()
            .ok_or_else(|| NetworkError::Serialization("no address resolved".into()))?;
        Ok(Self {
            verifier_id,
            addr,
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Override the default 30-second I/O timeout.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn connect(&self) -> Result<TcpStream, NodeError> {
        let stream = TcpStream::connect_timeout(&self.addr, self.timeout)
            .map_err(|e| NodeError::FrostProtocol(format!("TCP connect to {}: {e}", self.addr)))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| NodeError::FrostProtocol(format!("set_read_timeout: {e}")))?;
        Ok(stream)
    }
}

impl FrostNodeTransport for TcpNodeTransport {
    fn verifier_id(&self) -> &VerifierId {
        &self.verifier_id
    }

    fn frost_round1(
        &self,
        req: &FrostRound1Request,
        _now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError> {
        let mut stream = self.connect()?;
        let mut writer = BufWriter::new(stream.try_clone().map_err(|e| {
            NodeError::FrostProtocol(format!("stream clone for write: {e}"))
        })?);

        write_frame(&mut writer, &NodeRequest::FrostRound1(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("write round-1 request: {e}")))?;

        let resp: NodeResponse = read_frame(&mut stream)
            .map_err(|e| NodeError::FrostProtocol(format!("read round-1 response: {e}")))?;

        match resp {
            NodeResponse::FrostRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "aux node rejected round-1: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected response type for round-1: {other:?}"
            ))),
        }
    }

    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        let mut stream = self.connect()?;
        let mut writer = BufWriter::new(stream.try_clone().map_err(|e| {
            NodeError::FrostProtocol(format!("stream clone for write: {e}"))
        })?);

        write_frame(&mut writer, &NodeRequest::FrostRound2(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("write round-2 request: {e}")))?;

        let resp: NodeResponse = read_frame(&mut stream)
            .map_err(|e| NodeError::FrostProtocol(format!("read round-2 response: {e}")))?;

        match resp {
            NodeResponse::FrostRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "aux node rejected round-2: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected response type for round-2: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round1(
        &self,
        req: &HandshakeBindingRound1Request,
        _now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError> {
        let mut stream = self.connect()?;
        let mut writer = BufWriter::new(stream.try_clone().map_err(|e| {
            NodeError::FrostProtocol(format!("stream clone: {e}"))
        })?);
        write_frame(&mut writer, &NodeRequest::HandshakeBindingRound1(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("write hb-round1 req: {e}")))?;
        let resp: NodeResponse = read_frame(&mut stream)
            .map_err(|e| NodeError::FrostProtocol(format!("read hb-round1 resp: {e}")))?;
        match resp {
            NodeResponse::HandshakeBindingRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "aux node rejected hb-round1: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected hb-round1 response: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round2(
        &self,
        req: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError> {
        let mut stream = self.connect()?;
        let mut writer = BufWriter::new(stream.try_clone().map_err(|e| {
            NodeError::FrostProtocol(format!("stream clone: {e}"))
        })?);
        write_frame(&mut writer, &NodeRequest::HandshakeBindingRound2(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("write hb-round2 req: {e}")))?;
        let resp: NodeResponse = read_frame(&mut stream)
            .map_err(|e| NodeError::FrostProtocol(format!("read hb-round2 resp: {e}")))?;
        match resp {
            NodeResponse::HandshakeBindingRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "aux node rejected hb-round2: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected hb-round2 response: {other:?}"
            ))),
        }
    }
}

// ── TcpAuxServer ─────────────────────────────────────────────────────────────

/// TCP server that exposes a `FrostAuxiliaryNode` to remote coordinators.
///
/// Each incoming connection is handled in its own thread. The server processes
/// **one request per connection** then closes the socket — keeping the protocol
/// simple and stateless.
///
/// # Usage
///
/// ```rust,ignore
/// use tls_attestation_node::transport::TcpAuxServer;
///
/// let server = TcpAuxServer::bind("127.0.0.1:0", Arc::clone(&node)).unwrap();
/// println!("listening on {}", server.local_addr());
/// // ... run tests ...
/// server.shutdown();
/// ```
pub struct TcpAuxServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl TcpAuxServer {
    /// Bind to `addr` and start serving `node` in a background thread.
    ///
    /// Pass `"127.0.0.1:0"` to let the OS pick an ephemeral port, then read
    /// the actual address with [`local_addr`].
    pub fn bind(
        addr: impl ToSocketAddrs,
        node: Arc<FrostAuxiliaryNode>,
    ) -> Result<Self, NetworkError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| NetworkError::Serialization(format!("bind failed: {e}")))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| NetworkError::Serialization(format!("local_addr: {e}")))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = Arc::clone(&shutdown);

        thread::spawn(move || {
            Self::accept_loop(listener, node, shutdown_flag);
        });

        Ok(Self { addr: local_addr, shutdown })
    }

    /// Return the address the server is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Signal the server to stop accepting new connections.
    ///
    /// Already-running connections will complete normally. The background
    /// thread exits after the next `accept()` call unblocks (which happens
    /// when a new connection arrives or a brief timeout fires).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Poke the listener to unblock `accept()`.
        let _ = TcpStream::connect(self.addr);
    }

    fn accept_loop(
        listener: TcpListener,
        node: Arc<FrostAuxiliaryNode>,
        shutdown: Arc<AtomicBool>,
    ) {
        for result in listener.incoming() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match result {
                Ok(stream) => {
                    let node = Arc::clone(&node);
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, &node) {
                            // Log but don't crash the accept loop.
                            tracing::warn!("TcpAuxServer connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    if !shutdown.load(Ordering::Relaxed) {
                        tracing::warn!("TcpAuxServer accept error: {e}");
                    }
                }
            }
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        node: &FrostAuxiliaryNode,
    ) -> Result<(), NetworkError> {
        // Read exactly one request, dispatch, write one response.
        let request: NodeRequest = match read_frame(&mut stream) {
            Ok(r) => r,
            Err(NetworkError::ChannelClosed) => return Ok(()), // clean shutdown poke
            Err(e) => return Err(e),
        };

        let now = UnixTimestamp::now();
        let response: NodeResponse = match request {
            NodeRequest::FrostRound1(req) => match node.frost_round1(&req, now) {
                Ok(resp) => NodeResponse::FrostRound1(resp),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::FrostRound2(req) => match node.frost_round2(&req) {
                Ok(resp) => NodeResponse::FrostRound2(resp),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::HandshakeBindingRound1(req) => {
                match node.handshake_binding_round1(&req, now) {
                    Ok(resp) => NodeResponse::HandshakeBindingRound1(resp),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
            NodeRequest::HandshakeBindingRound2(req) => {
                match node.handshake_binding_round2(&req) {
                    Ok(resp) => NodeResponse::HandshakeBindingRound2(resp),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
        };

        let mut writer = BufWriter::new(&mut stream);
        write_frame(&mut writer, &response)
    }
}

// ── Layer 3: Authenticated transport ─────────────────────────────────────────
//
// `AuthTcpNodeTransport` and `AuthTcpAuxServer` wrap the plain TCP path with
// ed25519-signed `SignedEnvelope` frames.
//
// Wire protocol (per connection):
//
//   coordinator                           aux node
//     ──── SignedEnvelope<NodeRequest> ────►
//     ◄─── SignedEnvelope<NodeResponse> ───
//
// Both sides sign outgoing envelopes with their own `NodeIdentity` and verify
// incoming envelopes against a `NodeKeyRegistry`.

#[cfg(feature = "auth")]
use crate::auth::{NodeIdentity, NodeKeyRegistry};
#[cfg(feature = "auth")]
use tls_attestation_network::signed_envelope::SignedEnvelope;

#[cfg(feature = "auth")]
/// Authenticated TCP transport — coordinator side.
///
/// Signs every outgoing `NodeRequest` with the coordinator's `NodeIdentity`
/// and verifies every response against the `NodeKeyRegistry`.
pub struct AuthTcpNodeTransport {
    inner: TcpNodeTransport,
    identity: Arc<NodeIdentity>,
    registry: NodeKeyRegistry,
}

#[cfg(feature = "auth")]
impl AuthTcpNodeTransport {
    pub fn new(
        inner: TcpNodeTransport,
        identity: Arc<NodeIdentity>,
        registry: NodeKeyRegistry,
    ) -> Self {
        Self { inner, identity, registry }
    }

    fn send_recv<Req, Resp>(&self, request: &Req) -> Result<Resp, NodeError>
    where
        Req: serde::Serialize,
        Resp: for<'de> serde::Deserialize<'de>,
    {
        // Sign the request.
        let envelope = SignedEnvelope::seal(
            &self.identity.verifier_id,
            &self.identity.signing_key,
            request,
        )
        .map_err(|e| NodeError::FrostProtocol(format!("sign request: {e}")))?;

        // Open a TCP connection, send envelope, read response envelope.
        let mut stream = self.inner.connect()?;
        let mut writer = BufWriter::new(stream.try_clone().map_err(|e| {
            NodeError::FrostProtocol(format!("stream clone: {e}"))
        })?);

        write_frame(&mut writer, &envelope)
            .map_err(|e| NodeError::FrostProtocol(format!("write envelope: {e}")))?;

        let resp_env: SignedEnvelope = read_frame(&mut stream)
            .map_err(|e| NodeError::FrostProtocol(format!("read response envelope: {e}")))?;

        // Verify the response.
        let now = tls_attestation_core::types::UnixTimestamp::now().0;
        resp_env
            .open::<Resp>(self.registry.as_envelope_registry(), now)
            .map_err(|e| NodeError::FrostProtocol(format!("verify response: {e}")))
    }
}

#[cfg(feature = "auth")]
impl FrostNodeTransport for AuthTcpNodeTransport {
    fn verifier_id(&self) -> &VerifierId {
        self.inner.verifier_id()
    }

    fn frost_round1(
        &self,
        req: &FrostRound1Request,
        _now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError> {
        let node_req = NodeRequest::FrostRound1(req.clone());
        let resp: NodeResponse = self.send_recv(&node_req)?;
        match resp {
            NodeResponse::FrostRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "auth aux node rejected round-1: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected response for round-1: {other:?}"
            ))),
        }
    }

    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        let node_req = NodeRequest::FrostRound2(req.clone());
        let resp: NodeResponse = self.send_recv(&node_req)?;
        match resp {
            NodeResponse::FrostRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "auth aux node rejected round-2: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected response for round-2: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round1(
        &self,
        req: &HandshakeBindingRound1Request,
        _now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError> {
        let node_req = NodeRequest::HandshakeBindingRound1(req.clone());
        let resp: NodeResponse = self.send_recv(&node_req)?;
        match resp {
            NodeResponse::HandshakeBindingRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "auth aux node rejected hb-round1: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected auth response for hb-round1: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round2(
        &self,
        req: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError> {
        let node_req = NodeRequest::HandshakeBindingRound2(req.clone());
        let resp: NodeResponse = self.send_recv(&node_req)?;
        match resp {
            NodeResponse::HandshakeBindingRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(format!(
                "auth aux node rejected hb-round2: {reason}"
            ))),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected auth response for hb-round2: {other:?}"
            ))),
        }
    }
}

#[cfg(feature = "auth")]
/// Authenticated TCP server — auxiliary node side.
///
/// Verifies every incoming `SignedEnvelope<NodeRequest>` against the
/// `NodeKeyRegistry` and signs every response with the node's `NodeIdentity`.
pub struct AuthTcpAuxServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

#[cfg(feature = "auth")]
impl AuthTcpAuxServer {
    /// Bind to `addr` and start serving.
    pub fn bind(
        addr: impl ToSocketAddrs,
        node: Arc<FrostAuxiliaryNode>,
        identity: Arc<NodeIdentity>,
        registry: NodeKeyRegistry,
    ) -> Result<Self, NetworkError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| NetworkError::Serialization(format!("bind failed: {e}")))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| NetworkError::Serialization(format!("local_addr: {e}")))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);

        thread::spawn(move || {
            Self::accept_loop(listener, node, identity, registry, flag);
        });

        Ok(Self { addr: local_addr, shutdown })
    }

    pub fn local_addr(&self) -> SocketAddr { self.addr }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
    }

    fn accept_loop(
        listener: TcpListener,
        node: Arc<FrostAuxiliaryNode>,
        identity: Arc<NodeIdentity>,
        registry: NodeKeyRegistry,
        shutdown: Arc<AtomicBool>,
    ) {
        for result in listener.incoming() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match result {
                Ok(stream) => {
                    let node = Arc::clone(&node);
                    let identity = Arc::clone(&identity);
                    let registry = registry.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, &node, &identity, &registry) {
                            tracing::warn!("AuthTcpAuxServer error: {e}");
                        }
                    });
                }
                Err(e) if !shutdown.load(Ordering::Relaxed) => {
                    tracing::warn!("AuthTcpAuxServer accept error: {e}");
                }
                _ => {}
            }
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        node: &FrostAuxiliaryNode,
        identity: &NodeIdentity,
        registry: &NodeKeyRegistry,
    ) -> Result<(), NetworkError> {
        // Read the signed request envelope.
        let req_env: SignedEnvelope = match read_frame(&mut stream) {
            Ok(e) => e,
            Err(NetworkError::ChannelClosed) => return Ok(()),
            Err(e) => return Err(e),
        };

        // Verify the request envelope.
        let now = tls_attestation_core::types::UnixTimestamp::now().0;
        let request: NodeRequest = req_env
            .open(registry.as_envelope_registry(), now)
            .map_err(|e| NetworkError::AuthFailed(format!("request auth failed: {e}")))?;

        // Dispatch to the node.
        let ts = UnixTimestamp::now();
        let inner_response: NodeResponse = match request {
            NodeRequest::FrostRound1(req) => match node.frost_round1(&req, ts) {
                Ok(r) => NodeResponse::FrostRound1(r),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::FrostRound2(req) => match node.frost_round2(&req) {
                Ok(r) => NodeResponse::FrostRound2(r),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::HandshakeBindingRound1(req) => {
                match node.handshake_binding_round1(&req, ts) {
                    Ok(r) => NodeResponse::HandshakeBindingRound1(r),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
            NodeRequest::HandshakeBindingRound2(req) => {
                match node.handshake_binding_round2(&req) {
                    Ok(r) => NodeResponse::HandshakeBindingRound2(r),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
        };

        // Sign the response.
        let resp_env = SignedEnvelope::seal(
            &identity.verifier_id,
            &identity.signing_key,
            &inner_response,
        )?;

        let mut writer = BufWriter::new(&mut stream);
        write_frame(&mut writer, &resp_env)
    }
}

// ── Layer 4: mTLS transport ───────────────────────────────────────────────────
//
// `MtlsTcpNodeTransport` and `MtlsTcpAuxServer` wrap the plain TCP path with
// mutual TLS (rustls). Every TCP connection is:
//   - Encrypted (TLS 1.3)
//   - Server-authenticated (client verifies server cert against cluster CA)
//   - Client-authenticated (server verifies client cert against cluster CA)
//
// Wire protocol (per connection):
//
//   coordinator (client)                      aux node (server)
//     ──── TLS handshake (mTLS) ─────────────────────────────
//     ──── NodeRequest frame ────────────────►
//     ◄─── NodeResponse frame ───────────────
//
// Combine with `AuthTcpNodeTransport` for both transport-level (TLS) and
// application-level (SignedEnvelope) authentication.

use rustls::{ClientConnection, ServerConnection, StreamOwned};
use tls_attestation_network::mtls::MtlsNodeBundle;

/// mTLS transport — coordinator side.
///
/// Establishes a mutually-authenticated TLS connection to the aux node for
/// each FROST round.  Both sides present and verify certificates issued by
/// the shared cluster CA.
pub struct MtlsTcpNodeTransport {
    /// The FROST verifier identity this transport connects to.
    verifier_id: VerifierId,
    /// TCP address of the `MtlsTcpAuxServer`.
    addr: SocketAddr,
    /// rustls client config (includes cluster CA trust anchor + client cert).
    tls_config: std::sync::Arc<rustls::ClientConfig>,
    /// I/O timeout for connect + read.
    timeout: std::time::Duration,
}

impl MtlsTcpNodeTransport {
    /// Create a transport to `addr` for the FROST node identified by `verifier_id`.
    ///
    /// `bundle` is the coordinator's own `MtlsNodeBundle` — it supplies the
    /// client certificate for mutual TLS and the CA trust anchor.
    pub fn new(
        verifier_id: VerifierId,
        addr: impl ToSocketAddrs,
        bundle: &MtlsNodeBundle,
    ) -> Result<Self, NetworkError> {
        let addr = addr
            .to_socket_addrs()
            .map_err(|e| NetworkError::Serialization(e.to_string()))?
            .next()
            .ok_or_else(|| NetworkError::Serialization("no address resolved".into()))?;

        let tls_config = bundle.client_config()?;

        Ok(Self {
            verifier_id,
            addr,
            tls_config,
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Override the default 30-second I/O timeout.
    pub fn with_timeout(mut self, t: std::time::Duration) -> Self {
        self.timeout = t;
        self
    }

    fn connect_tls(
        &self,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, NodeError> {
        let tcp = TcpStream::connect_timeout(&self.addr, self.timeout)
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS TCP connect to {}: {e}", self.addr)))?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|e| NodeError::FrostProtocol(format!("set_read_timeout: {e}")))?;

        let server_name = MtlsNodeBundle::server_name();
        let conn = ClientConnection::new(std::sync::Arc::clone(&self.tls_config), server_name)
            .map_err(|e| NodeError::FrostProtocol(format!("TLS client init: {e}")))?;

        Ok(StreamOwned::new(conn, tcp))
    }
}

impl FrostNodeTransport for MtlsTcpNodeTransport {
    fn verifier_id(&self) -> &VerifierId {
        &self.verifier_id
    }

    fn frost_round1(
        &self,
        req: &FrostRound1Request,
        _now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError> {
        let mut tls = self.connect_tls()?;
        write_frame(&mut tls, &NodeRequest::FrostRound1(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS write round-1: {e}")))?;
        let resp: NodeResponse = read_frame(&mut tls)
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS read round-1: {e}")))?;
        match resp {
            NodeResponse::FrostRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(
                format!("mTLS aux node rejected round-1: {reason}"),
            )),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected mTLS response for round-1: {other:?}"
            ))),
        }
    }

    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        let mut tls = self.connect_tls()?;
        write_frame(&mut tls, &NodeRequest::FrostRound2(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS write round-2: {e}")))?;
        let resp: NodeResponse = read_frame(&mut tls)
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS read round-2: {e}")))?;
        match resp {
            NodeResponse::FrostRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(
                format!("mTLS aux node rejected round-2: {reason}"),
            )),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected mTLS response for round-2: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round1(
        &self,
        req: &HandshakeBindingRound1Request,
        _now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError> {
        let mut tls = self.connect_tls()?;
        write_frame(&mut tls, &NodeRequest::HandshakeBindingRound1(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS write hb-round1: {e}")))?;
        let resp: NodeResponse = read_frame(&mut tls)
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS read hb-round1: {e}")))?;
        match resp {
            NodeResponse::HandshakeBindingRound1(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(
                format!("mTLS aux node rejected hb-round1: {reason}"),
            )),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected mTLS hb-round1 response: {other:?}"
            ))),
        }
    }

    fn handshake_binding_round2(
        &self,
        req: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError> {
        let mut tls = self.connect_tls()?;
        write_frame(&mut tls, &NodeRequest::HandshakeBindingRound2(req.clone()))
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS write hb-round2: {e}")))?;
        let resp: NodeResponse = read_frame(&mut tls)
            .map_err(|e| NodeError::FrostProtocol(format!("mTLS read hb-round2: {e}")))?;
        match resp {
            NodeResponse::HandshakeBindingRound2(r) => Ok(r),
            NodeResponse::Error { reason } => Err(NodeError::FrostProtocol(
                format!("mTLS aux node rejected hb-round2: {reason}"),
            )),
            other => Err(NodeError::FrostProtocol(format!(
                "unexpected mTLS hb-round2 response: {other:?}"
            ))),
        }
    }
}

/// mTLS server — auxiliary node side.
///
/// Wraps each accepted TCP connection in a TLS server handshake, requiring
/// the coordinator to present a certificate issued by the cluster CA.
pub struct MtlsTcpAuxServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl MtlsTcpAuxServer {
    /// Bind to `addr` and start serving `node` over mTLS.
    ///
    /// `bundle` provides the server certificate + client verifier config.
    pub fn bind(
        addr: impl ToSocketAddrs,
        node: Arc<FrostAuxiliaryNode>,
        bundle: MtlsNodeBundle,
    ) -> Result<Self, NetworkError> {
        let tls_config = bundle.server_config()?;

        let listener = TcpListener::bind(addr)
            .map_err(|e| NetworkError::Serialization(format!("mTLS bind: {e}")))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| NetworkError::Serialization(format!("local_addr: {e}")))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);

        thread::spawn(move || {
            Self::accept_loop(listener, node, tls_config, flag);
        });

        Ok(Self { addr: local_addr, shutdown })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
    }

    fn accept_loop(
        listener: TcpListener,
        node: Arc<FrostAuxiliaryNode>,
        tls_config: Arc<rustls::ServerConfig>,
        shutdown: Arc<AtomicBool>,
    ) {
        for result in listener.incoming() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match result {
                Ok(tcp) => {
                    let node = Arc::clone(&node);
                    let tls_config = Arc::clone(&tls_config);
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(tcp, &node, tls_config) {
                            tracing::warn!("MtlsTcpAuxServer error: {e}");
                        }
                    });
                }
                Err(e) if !shutdown.load(Ordering::Relaxed) => {
                    tracing::warn!("MtlsTcpAuxServer accept error: {e}");
                }
                _ => {}
            }
        }
    }

    fn handle_connection(
        tcp: TcpStream,
        node: &FrostAuxiliaryNode,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(), NetworkError> {
        let conn = ServerConnection::new(tls_config)
            .map_err(|e| NetworkError::Serialization(format!("TLS server init: {e}")))?;
        let mut tls = StreamOwned::new(conn, tcp);

        let request: NodeRequest = match read_frame(&mut tls) {
            Ok(r) => r,
            Err(NetworkError::ChannelClosed) => return Ok(()),
            Err(e) => return Err(e),
        };

        let now = UnixTimestamp::now();
        let response: NodeResponse = match request {
            NodeRequest::FrostRound1(req) => match node.frost_round1(&req, now) {
                Ok(r) => NodeResponse::FrostRound1(r),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::FrostRound2(req) => match node.frost_round2(&req) {
                Ok(r) => NodeResponse::FrostRound2(r),
                Err(e) => NodeResponse::Error { reason: e.to_string() },
            },
            NodeRequest::HandshakeBindingRound1(req) => {
                match node.handshake_binding_round1(&req, now) {
                    Ok(r) => NodeResponse::HandshakeBindingRound1(r),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
            NodeRequest::HandshakeBindingRound2(req) => {
                match node.handshake_binding_round2(&req) {
                    Ok(r) => NodeResponse::HandshakeBindingRound2(r),
                    Err(e) => NodeResponse::Error { reason: e.to_string() },
                }
            }
        };

        write_frame(&mut tls, &response)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_transport_connect_timeout_fires() {
        // Use a non-routable address to trigger a quick timeout.
        let vid = VerifierId::from_bytes([0u8; 32]);
        let transport = TcpNodeTransport::new(vid, "192.0.2.1:9999")
            .unwrap()
            .with_timeout(std::time::Duration::from_millis(100));

        // Try to connect — should fail quickly.
        let result = transport.connect();
        assert!(result.is_err(), "expected connection error");
    }
}