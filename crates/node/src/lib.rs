pub mod auxiliary;
pub mod coordinator;
pub mod error;

#[cfg(feature = "frost")]
pub mod frost_aux;

#[cfg(feature = "frost")]
pub mod dkg_node;

#[cfg(feature = "tcp")]
pub mod transport;

#[cfg(all(feature = "frost", feature = "tcp"))]
pub mod handshake_binding;

#[cfg(feature = "auth")]
pub mod auth;

pub use auxiliary::AuxiliaryVerifierNode;
pub use coordinator::CoordinatorNode;
pub use error::NodeError;

#[cfg(feature = "frost")]
pub use frost_aux::{assemble_signing_package_from_responses, FrostAuxiliaryNode};

#[cfg(feature = "frost")]
pub use dkg_node::{
    run_dkg_ceremony, run_dkg_ceremony_encrypted, run_dkg_ceremony_with_authenticated_keys,
    run_dkg_ceremony_with_registry, FrostDkgNode,
};

#[cfg(feature = "tcp")]
pub use transport::{FrostNodeTransport, InProcessTransport, TcpAuxServer, TcpNodeTransport};

#[cfg(all(feature = "frost", feature = "tcp"))]
pub use handshake_binding::{
    run_handshake_binding,
    compute_2pc_binding_input,
    derive_2pc_dvrf_exporter,
    TlsSessionParams,
};

#[cfg(feature = "frost")]
pub use frost_aux::assemble_hb_signing_package_from_responses;

#[cfg(feature = "auth")]
pub use auth::{NodeIdentity, NodeKeyRegistry};
#[cfg(feature = "auth")]
pub use transport::{AuthTcpAuxServer, AuthTcpNodeTransport};

#[cfg(feature = "mtls")]
pub use transport::{MtlsTcpAuxServer, MtlsTcpNodeTransport};
