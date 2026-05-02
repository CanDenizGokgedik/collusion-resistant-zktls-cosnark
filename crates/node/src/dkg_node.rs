//! Type-safe DKG state machine for Pedersen DKG ceremonies.
//!
//! `FrostDkgNode` drives one participant through a three-part Pedersen DKG
//! ceremony. It enforces correct sequencing via an explicit enum state machine
//! and produces a signing-ready `FrostAuxiliaryNode` on completion.
//!
//! # Lifecycle
//!
//! ```text
//! FrostDkgNode::new(verifier_id, all_participant_ids, min_signers)
//!   │
//!   ├─ part1() → DkgRound1Package  (broadcast to all others)
//!   │      state: Initial → AfterPart1
//!   │
//!   ├─ part2(round1_pkgs_from_others) → HashMap<VerifierId, DkgRound2Package>
//!   │      state: AfterPart1 → AfterPart2  [FROST library success]
//!   │             AfterPart1 → Failed       [FROST library rejects inputs;
//!   │                                        round1_state consumed — restart required]
//!   │
//!   └─ part3(round2_pkgs_addressed_to_me) → (FrostAuxiliaryNode, FrostGroupKey)
//!          state: AfterPart2 → Completed   [success]
//!                 AfterPart2 → AfterPart2  [FROST library error — retryable if
//!                                           e.g. a package was temporarily missing]
//! ```
//!
//! # Invalid sequences
//!
//! | Call | State | Result |
//! |------|-------|--------|
//! | `part1` (again) | not `Initial` | `DkgProtocol("part1 already completed…")` |
//! | `part2` | `Initial` | `DkgProtocol("part2 called before part1")` |
//! | `part2` (again) | `AfterPart2` | `DkgProtocol("part2 already completed")` |
//! | `part3` | `Initial` | `DkgProtocol("part3 called before part1 and part2")` |
//! | `part3` | `AfterPart1` | `DkgProtocol("part3 called before part2")` |
//! | any | `Completed` | `DkgProtocol("ceremony already completed")` |
//! | any | `Failed` | `DkgProtocol("ceremony failed — …")` |
//!
//! # Round-2 confidentiality
//!
//! `part2` returns per-recipient `DkgRound2Package`s. In the in-process
//! orchestration (`run_dkg_ceremony`) these pass through memory only.
//! Before adding real network transport, callers MUST encrypt each package
//! to the recipient's long-term public key — see `DkgRound2Package` docs.

use std::collections::{BTreeMap, HashMap, HashSet};

use tls_attestation_core::ids::VerifierId;
use tls_attestation_crypto::dkg::{
    dkg_part1, dkg_part2, dkg_part3, DkgParticipantOutput, DkgRound1Package, DkgRound1State,
    DkgRound2Package, DkgRound2State, Identifier,
};
use tls_attestation_crypto::dkg_announce::{
    DkgParticipantRegistry, SignedDkgKeyAnnouncement,
};
use tls_attestation_crypto::participant_registry::{ParticipantRegistry, RegistryEpoch};
use tls_attestation_crypto::dkg_encrypt::{
    decrypt_round2_package, encrypt_round2_package, DkgCeremonyId, DkgEncryptionKeyPair,
    DkgEncryptionPublicKey,
};
use tls_attestation_crypto::frost_adapter::FrostGroupKey;
use tracing::{info, warn};

use crate::error::NodeError;
use crate::frost_aux::FrostAuxiliaryNode;

// ── DKG node internal state ───────────────────────────────────────────────────

enum DkgNodeState {
    /// Initial — `part1` has not been called.
    Initial,

    /// Part 1 complete. Secret polynomial state retained; waiting for others'
    /// Round-1 broadcast packages before `part2` can run.
    AfterPart1 { round1_state: DkgRound1State },

    /// Part 2 complete. Round-2 secret state retained. Also keeps the received
    /// Round-1 packages because `dkg_part3` requires them.
    AfterPart2 {
        round2_state: DkgRound2State,
        /// Round-1 packages received from all other participants — needed by `part3`.
        round1_packages: BTreeMap<Identifier, DkgRound1Package>,
    },

    /// Terminal success — `part3` completed; auxiliary node and group key emitted.
    Completed,

    /// Terminal failure — a FROST library call consumed secret state and rejected
    /// the inputs. The ceremony MUST restart from Part 1 (new `FrostDkgNode`).
    Failed { reason: String },
}

// ── FrostDkgNode ──────────────────────────────────────────────────────────────

/// One participant's state machine for a Pedersen DKG ceremony.
///
/// Created before the ceremony starts; driven through `part1`, `part2`, and
/// `part3`. On successful `part3`, produces:
/// - `FrostAuxiliaryNode` — signing-ready node with this participant's key share.
/// - `FrostGroupKey` — the shared group public key (must match across all participants).
///
/// # Thread safety
///
/// `FrostDkgNode` is `!Send`. All DKG operations must run in a single
/// thread/task. Concurrent access would require an external mutex.
pub struct FrostDkgNode {
    verifier_id: VerifierId,
    identifier: Identifier,
    /// Complete ordered participant list — the same for all nodes in the ceremony.
    /// `all_participant_ids[i]` maps to FROST identifier `i + 1`.
    all_participant_ids: Vec<VerifierId>,
    max_signers: u16,
    min_signers: u16,
    state: DkgNodeState,
}

impl FrostDkgNode {
    /// Create a new DKG node for this participant.
    ///
    /// `all_participant_ids` is the complete ordered list of ALL ceremony
    /// participants (including this node). The position of `verifier_id` in
    /// this list determines the FROST identifier: index `i` → identifier `i + 1`.
    ///
    /// All nodes in the same ceremony MUST use the same ordered list. The
    /// ceremony coordinator announces this list before Part 1 begins.
    ///
    /// `min_signers` is the signing threshold that will apply after the ceremony
    /// (must satisfy: `2 ≤ min_signers ≤ all_participant_ids.len()`).
    ///
    /// # Errors
    ///
    /// - `DkgProtocol` if `all_participant_ids` has fewer than 2 entries.
    /// - `DkgProtocol` if `all_participant_ids` contains duplicate entries.
    /// - `DkgProtocol` if `verifier_id` is not in `all_participant_ids`.
    /// - `DkgProtocol` if threshold constraints are violated.
    pub fn new(
        verifier_id: VerifierId,
        all_participant_ids: Vec<VerifierId>,
        min_signers: u16,
    ) -> Result<Self, NodeError> {
        let n = all_participant_ids.len();

        if n < 2 {
            return Err(NodeError::DkgProtocol(format!(
                "FROST DKG requires at least 2 participants (got {n})"
            )));
        }

        // Duplicates in the participant list are a configuration error that
        // would cause Identifier collisions.
        let unique: HashSet<&VerifierId> = all_participant_ids.iter().collect();
        if unique.len() != n {
            return Err(NodeError::DkgProtocol(
                "all_participant_ids must not contain duplicates".into(),
            ));
        }

        if min_signers < 2 {
            return Err(NodeError::DkgProtocol(format!(
                "FROST requires min_signers >= 2 (got {min_signers})"
            )));
        }
        if min_signers as usize > n {
            return Err(NodeError::DkgProtocol(format!(
                "min_signers ({min_signers}) exceeds participant count ({n})"
            )));
        }

        let position = all_participant_ids
            .iter()
            .position(|v| v == &verifier_id)
            .ok_or_else(|| {
                NodeError::DkgProtocol(format!(
                    "verifier {verifier_id} not found in all_participant_ids"
                ))
            })?;

        // Identifier is 1-indexed (FROST constraint: non-zero).
        let identifier = Identifier::try_from((position + 1) as u16).map_err(|e| {
            NodeError::DkgProtocol(format!(
                "FROST identifier assignment for position {position}: {e}"
            ))
        })?;

        Ok(Self {
            verifier_id,
            identifier,
            all_participant_ids,
            max_signers: n as u16,
            min_signers,
            state: DkgNodeState::Initial,
        })
    }

    /// This participant's protocol identity.
    pub fn verifier_id(&self) -> &VerifierId {
        &self.verifier_id
    }

    /// Whether the ceremony has completed successfully on this node.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DkgNodeState::Completed)
    }

    // ── Part 1 ──────────────────────────────────────────────────────────────

    /// Execute DKG Part 1.
    ///
    /// Generates a secret polynomial and zero-knowledge proof. Must be the
    /// first call; may only be called once.
    ///
    /// Returns the **broadcast** `DkgRound1Package` — send this to every other
    /// participant. The secret state is retained internally.
    ///
    /// # Errors
    ///
    /// - `DkgProtocol` if called in any state other than `Initial`.
    /// - `Crypto` if the FROST library rejects the parameters.
    pub fn part1(&mut self) -> Result<DkgRound1Package, NodeError> {
        match &self.state {
            DkgNodeState::Initial => {}
            DkgNodeState::AfterPart1 { .. }
            | DkgNodeState::AfterPart2 { .. }
            | DkgNodeState::Completed => {
                return Err(NodeError::DkgProtocol(
                    "part1 already completed for this ceremony".into(),
                ));
            }
            DkgNodeState::Failed { reason } => {
                return Err(NodeError::DkgProtocol(format!(
                    "ceremony failed — cannot continue: {reason}"
                )));
            }
        }

        let (round1_state, round1_pkg) =
            dkg_part1(self.identifier, self.max_signers, self.min_signers)
                .map_err(NodeError::Crypto)?;

        info!(
            verifier = %self.verifier_id,
            "DKG: part1 complete — broadcast package generated"
        );

        self.state = DkgNodeState::AfterPart1 { round1_state };
        Ok(round1_pkg)
    }

    // ── Part 2 ──────────────────────────────────────────────────────────────

    /// Execute DKG Part 2.
    ///
    /// Processes Round-1 broadcast packages from all other participants.
    /// `round1_packages_from_others` must contain exactly one entry per other
    /// participant (NOT this node's own package), keyed by sender `VerifierId`.
    ///
    /// **Consumes** the Round-1 secret state regardless of outcome — if this
    /// call fails, the ceremony cannot continue and a new `FrostDkgNode` must
    /// be created.
    ///
    /// Returns per-recipient Round-2 packages, keyed by recipient `VerifierId`.
    /// **Each package MUST be delivered on a confidential + authenticated channel.**
    ///
    /// # Errors
    ///
    /// - `DkgProtocol("part2 called before part1")` if `part1` was not called.
    /// - `DkgProtocol("part2 already completed")` if `part2` was already called.
    /// - `DkgProtocol` if a sender `VerifierId` is not in the participant list.
    /// - `Crypto` if the FROST library rejects a Round-1 package.
    ///   State transitions to `Failed` — ceremony must restart.
    pub fn part2(
        &mut self,
        round1_packages_from_others: HashMap<VerifierId, DkgRound1Package>,
    ) -> Result<HashMap<VerifierId, DkgRound2Package>, NodeError> {
        // Check state before consuming anything.
        match &self.state {
            DkgNodeState::AfterPart1 { .. } => {} // correct state
            DkgNodeState::Initial => {
                return Err(NodeError::DkgProtocol("part2 called before part1".into()));
            }
            DkgNodeState::AfterPart2 { .. } => {
                return Err(NodeError::DkgProtocol("part2 already completed".into()));
            }
            DkgNodeState::Completed => {
                return Err(NodeError::DkgProtocol("ceremony already completed".into()));
            }
            DkgNodeState::Failed { reason } => {
                return Err(NodeError::DkgProtocol(format!(
                    "ceremony failed — cannot continue: {reason}"
                )));
            }
        }

        // Translate VerifierId → Identifier for the FROST library.
        let mut btree_r1: BTreeMap<Identifier, DkgRound1Package> = BTreeMap::new();
        for (vid, pkg) in &round1_packages_from_others {
            let id = self.vid_to_identifier(vid)?;
            btree_r1.insert(id, pkg.clone());
        }

        // Take ownership of the state, setting a `Failed` sentinel as a poison
        // value. If `dkg_part2` fails (consuming round1_state), the sentinel
        // remains — the ceremony is dead.
        let old_state = std::mem::replace(
            &mut self.state,
            DkgNodeState::Failed {
                reason: "part2 did not complete successfully — round1_state consumed".into(),
            },
        );
        let DkgNodeState::AfterPart1 { round1_state } = old_state else {
            unreachable!("state was verified as AfterPart1 above");
        };

        let (round2_state, btree_out) = dkg_part2(round1_state, &btree_r1).map_err(|e| {
            // round1_state was consumed by the failing call; state stays as Failed.
            warn!(
                verifier = %self.verifier_id,
                error = %e,
                "DKG: part2 failed — ceremony must restart"
            );
            NodeError::Crypto(e)
        })?;

        // Translate FROST Identifier keys back to VerifierId for callers.
        let mut out: HashMap<VerifierId, DkgRound2Package> =
            HashMap::with_capacity(btree_out.len());
        for (id, pkg) in btree_out {
            let vid = self.identifier_to_vid(&id).ok_or_else(|| {
                NodeError::DkgProtocol(format!(
                    "DKG part2 produced package for unknown FROST identifier — \
                     all_participant_ids may be inconsistent"
                ))
            })?;
            out.insert(vid, pkg);
        }

        info!(
            verifier = %self.verifier_id,
            n_outbound = out.len(),
            "DKG: part2 complete — round-2 packages generated"
        );

        self.state = DkgNodeState::AfterPart2 {
            round2_state,
            round1_packages: btree_r1,
        };

        Ok(out)
    }

    // ── Part 3 ──────────────────────────────────────────────────────────────

    /// Execute DKG Part 3 (final).
    ///
    /// Derives this participant's long-term key share and the shared group
    /// public key. `round2_packages_for_me` must contain one entry per other
    /// participant (those addressed TO this node), keyed by sender `VerifierId`.
    ///
    /// On success: transitions to `Completed` and returns
    /// `(FrostAuxiliaryNode, FrostGroupKey)`.
    ///
    /// On failure (e.g., a missing package): stays in `AfterPart2` — the call
    /// is retryable once the missing input is available.
    ///
    /// # Errors
    ///
    /// - `DkgProtocol` if called in wrong state.
    /// - `DkgProtocol` if a sender `VerifierId` is unknown.
    /// - `Crypto` if the FROST library rejects the inputs. The node stays in
    ///   `AfterPart2` so the call can be retried.
    pub fn part3(
        &mut self,
        round2_packages_for_me: HashMap<VerifierId, DkgRound2Package>,
    ) -> Result<(FrostAuxiliaryNode, FrostGroupKey), NodeError> {
        // Borrow the state — dkg_part3 borrows round2_state so retry is possible.
        match &self.state {
            DkgNodeState::AfterPart2 { .. } => {} // correct state
            DkgNodeState::Initial => {
                return Err(NodeError::DkgProtocol(
                    "part3 called before part1 and part2".into(),
                ));
            }
            DkgNodeState::AfterPart1 { .. } => {
                return Err(NodeError::DkgProtocol("part3 called before part2".into()));
            }
            DkgNodeState::Completed => {
                return Err(NodeError::DkgProtocol("ceremony already completed".into()));
            }
            DkgNodeState::Failed { reason } => {
                return Err(NodeError::DkgProtocol(format!(
                    "ceremony failed — cannot retry part3: {reason}"
                )));
            }
        }

        // Translate VerifierId → Identifier.
        let mut btree_r2: BTreeMap<Identifier, DkgRound2Package> = BTreeMap::new();
        for (vid, pkg) in &round2_packages_for_me {
            let id = self.vid_to_identifier(vid)?;
            btree_r2.insert(id, pkg.clone());
        }

        // Borrow the inner state for the FROST call.
        let DkgNodeState::AfterPart2 { round2_state, round1_packages } = &self.state else {
            unreachable!("verified above");
        };

        // dkg_part3 borrows round2_state — does not consume it — so failure
        // leaves us in AfterPart2 and the call is retryable.
        let output: DkgParticipantOutput =
            dkg_part3(
                &self.verifier_id,
                self.identifier,
                round2_state,
                round1_packages,
                &btree_r2,
                &self.all_participant_ids,
            )
            .map_err(NodeError::Crypto)?;

        // Success — emit the signing node and group key, then mark done.
        let group_key = output.group_key;
        let aux_node = FrostAuxiliaryNode::new(output.participant);

        info!(
            verifier = %self.verifier_id,
            "DKG: part3 complete — signing node ready"
        );

        self.state = DkgNodeState::Completed;
        Ok((aux_node, group_key))
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Look up the FROST identifier for a given VerifierId.
    /// Returns an error if the VerifierId is not in `all_participant_ids`.
    fn vid_to_identifier(&self, vid: &VerifierId) -> Result<Identifier, NodeError> {
        self.all_participant_ids
            .iter()
            .position(|v| v == vid)
            .map(|pos| {
                Identifier::try_from((pos + 1) as u16)
                    .expect("position + 1 is always a valid nonzero u16 for n <= 65535")
            })
            .ok_or_else(|| {
                NodeError::DkgProtocol(format!(
                    "verifier {vid} is not in the ceremony participant list"
                ))
            })
    }

    /// Reverse lookup: FROST identifier → VerifierId.
    /// Returns `None` if the identifier is not in the participant list.
    fn identifier_to_vid(&self, id: &Identifier) -> Option<VerifierId> {
        for (pos, vid) in self.all_participant_ids.iter().enumerate() {
            let frost_id = Identifier::try_from((pos + 1) as u16)
                .expect("position + 1 is valid");
            if &frost_id == id {
                return Some(vid.clone());
            }
        }
        None
    }
}

// ── In-process ceremony orchestration ────────────────────────────────────────

/// Run a complete in-process Pedersen DKG ceremony across all provided nodes.
///
/// Drives `part1`, `part2`, and `part3` for each node, routing packages between
/// them in memory. Returns the `FrostAuxiliaryNode` for each input node (same
/// order) and the shared `FrostGroupKey`.
///
/// All nodes must have been created with the same ordered `all_participant_ids`
/// list. The function validates group-key consistency across all participants.
///
/// # Round-2 confidentiality
///
/// In this in-process implementation, Round-2 packages pass through memory
/// only — no network transmission occurs. RFC 9591's confidentiality requirement
/// is trivially satisfied: no coordinator or third party can intercept an
/// in-memory transfer.
///
/// **Before adding real network transport**: Round-2 packages MUST be encrypted
/// to each recipient's long-term public key (e.g., NaCl box / ECIES) before
/// being handed to any routing layer. See `DkgRound2Package` documentation.
///
/// # Errors
///
/// Returns an error if any `part1`, `part2`, or `part3` call fails, or if the
/// ceremony produces inconsistent group public keys across participants (which
/// would indicate a protocol violation such as inconsistent Round-1 broadcasts).
pub fn run_dkg_ceremony(
    nodes: &mut [FrostDkgNode],
) -> Result<(Vec<FrostAuxiliaryNode>, FrostGroupKey), NodeError> {
    if nodes.is_empty() {
        return Err(NodeError::DkgProtocol(
            "run_dkg_ceremony requires at least one node".into(),
        ));
    }

    // ── Part 1 ────────────────────────────────────────────────────────────────
    // Each node generates its broadcast package independently.
    let mut round1_broadcasts: HashMap<VerifierId, DkgRound1Package> =
        HashMap::with_capacity(nodes.len());
    for node in nodes.iter_mut() {
        let pkg = node.part1()?;
        round1_broadcasts.insert(node.verifier_id().clone(), pkg);
    }

    // ── Part 2 ────────────────────────────────────────────────────────────────
    // Each node receives all OTHER nodes' Round-1 packages.
    // The coordinator routes broadcast → all others (never inspects content).
    let mut round2_unicasts: HashMap<VerifierId, HashMap<VerifierId, DkgRound2Package>> =
        HashMap::with_capacity(nodes.len());

    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let others: HashMap<VerifierId, DkgRound1Package> = round1_broadcasts
            .iter()
            .filter(|(vid, _)| *vid != &my_id)
            .map(|(vid, pkg)| (vid.clone(), pkg.clone()))
            .collect();

        let outbound = node.part2(others)?;

        // Route each per-recipient package to its destination.
        for (to_vid, pkg) in outbound {
            round2_unicasts
                .entry(to_vid)
                .or_default()
                .insert(my_id.clone(), pkg);
        }
    }

    // ── Part 3 ────────────────────────────────────────────────────────────────
    // Each node processes the Round-2 packages addressed to it.
    let mut aux_nodes: Vec<FrostAuxiliaryNode> = Vec::with_capacity(nodes.len());
    let mut group_keys: Vec<FrostGroupKey> = Vec::with_capacity(nodes.len());

    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let my_r2_pkgs = round2_unicasts.remove(&my_id).unwrap_or_default();
        let (aux_node, group_key) = node.part3(my_r2_pkgs)?;
        aux_nodes.push(aux_node);
        group_keys.push(group_key);
    }

    // ── Consistency check ─────────────────────────────────────────────────────
    // All participants must derive the same group public key.
    // A mismatch means inconsistent Round-1 broadcasts — a protocol violation.
    let first_key_bytes = group_keys[0].verifying_key_bytes();
    for (i, gk) in group_keys.iter().enumerate().skip(1) {
        if gk.verifying_key_bytes() != first_key_bytes {
            return Err(NodeError::DkgProtocol(format!(
                "group key mismatch: node 0 and node {i} derived different group \
                 verifying keys — possible inconsistent Round-1 broadcast"
            )));
        }
    }

    // Return first group key (all are equal).
    let group_key = group_keys.remove(0);

    info!(
        n_participants = nodes.len(),
        "DKG ceremony complete — all nodes produced consistent group key"
    );

    Ok((aux_nodes, group_key))
}

// ── Encrypted in-process ceremony ─────────────────────────────────────────────

/// Run a Pedersen DKG ceremony with encrypted Round-2 package routing.
///
/// Identical to `run_dkg_ceremony` except that every Round-2 unicast package
/// is encrypted before being handed to the routing layer and decrypted by the
/// recipient before `part3`. This satisfies RFC 9591 §5.3: the coordinator
/// routing `EncryptedDkgRound2Package` structs can read `ceremony_id`,
/// `sender_id`, and `recipient_id` (routing metadata), but **cannot decrypt
/// the ciphertext** — it has no private key.
///
/// # Arguments
///
/// - `nodes` — mutable slice of `FrostDkgNode`s, all in `Initial` state.
/// - `ceremony_id` — a fresh `DkgCeremonyId` generated by the ceremony
///   coordinator before Part 1. Binds all packages to this specific ceremony.
/// - `encryption_keys` — one `DkgEncryptionKeyPair` per node, **in the same
///   order** as `nodes`. Each participant's public key must have been
///   distributed to all other participants before the ceremony starts.
///
/// # Encryption scheme
///
/// For each sender→recipient pair, `encrypt_round2_package` derives a
/// per-direction key via X25519 static-static ECDH + HKDF-SHA256 and encrypts
/// with XChaCha20-Poly1305, binding `ceremony_id + sender_id + recipient_id`
/// into the AEAD AAD. See `crates/crypto/src/dkg_encrypt.rs` for the full spec.
///
/// # Errors
///
/// Returns an error if `encryption_keys.len() != nodes.len()`, if any DKG
/// step fails, if encryption/decryption fails, or if the resulting group keys
/// are inconsistent across participants.
pub fn run_dkg_ceremony_encrypted(
    nodes: &mut [FrostDkgNode],
    ceremony_id: &DkgCeremonyId,
    encryption_keys: &[DkgEncryptionKeyPair],
) -> Result<(Vec<FrostAuxiliaryNode>, FrostGroupKey), NodeError> {
    if nodes.is_empty() {
        return Err(NodeError::DkgProtocol(
            "run_dkg_ceremony_encrypted requires at least one node".into(),
        ));
    }
    if encryption_keys.len() != nodes.len() {
        return Err(NodeError::DkgProtocol(format!(
            "encryption_keys.len() ({}) must equal nodes.len() ({})",
            encryption_keys.len(),
            nodes.len()
        )));
    }

    // Build VerifierId → encryption public key map (distributed to all participants).
    let enc_pub_map: HashMap<VerifierId, DkgEncryptionPublicKey> = nodes
        .iter()
        .zip(encryption_keys.iter())
        .map(|(node, kp)| (node.verifier_id().clone(), kp.public_key().clone()))
        .collect();

    // ── Part 1 ────────────────────────────────────────────────────────────────
    let mut round1_broadcasts: HashMap<VerifierId, DkgRound1Package> =
        HashMap::with_capacity(nodes.len());
    for node in nodes.iter_mut() {
        let pkg = node.part1()?;
        round1_broadcasts.insert(node.verifier_id().clone(), pkg);
    }

    // ── Part 2 — encrypt outbound Round-2 packages ────────────────────────────
    //
    // For each sender node:
    //   1. Collect all other nodes' Round-1 broadcast packages.
    //   2. Call part2() to get plaintext per-recipient Round-2 packages.
    //   3. Encrypt each package to the recipient's X25519 public key.
    //   4. Accumulate encrypted packages keyed by recipient VerifierId.
    //
    // The coordinator role is simulated by the accumulator: it sees
    // EncryptedDkgRound2Package structs with routing metadata but cannot
    // read plaintext package contents.
    let mut encrypted_round2: HashMap<VerifierId, Vec<(VerifierId, _)>> =
        HashMap::with_capacity(nodes.len());

    for (node, sender_enc_key) in nodes.iter_mut().zip(encryption_keys.iter()) {
        let my_id = node.verifier_id().clone();
        let others: HashMap<VerifierId, DkgRound1Package> = round1_broadcasts
            .iter()
            .filter(|(vid, _)| *vid != &my_id)
            .map(|(vid, pkg)| (vid.clone(), pkg.clone()))
            .collect();

        let outbound = node.part2(others)?;

        for (to_vid, pkg) in outbound {
            let recipient_pub = enc_pub_map.get(&to_vid).ok_or_else(|| {
                NodeError::DkgProtocol(format!(
                    "no encryption public key for recipient {to_vid}"
                ))
            })?;
            let enc_pkg = encrypt_round2_package(
                &pkg,
                ceremony_id,
                sender_enc_key,
                &my_id,
                recipient_pub,
                &to_vid,
            )
            .map_err(NodeError::Crypto)?;

            encrypted_round2
                .entry(to_vid)
                .or_default()
                .push((my_id.clone(), enc_pkg));
        }
    }

    // ── Part 3 — decrypt inbound Round-2 packages ────────────────────────────
    //
    // Each node decrypts the packages addressed to it, then calls part3 with
    // the plaintext packages. Decryption authenticates both the sender (via
    // static-static ECDH) and the routing metadata (via AEAD AAD).
    let mut aux_nodes: Vec<FrostAuxiliaryNode> = Vec::with_capacity(nodes.len());
    let mut group_keys: Vec<FrostGroupKey> = Vec::with_capacity(nodes.len());

    for (node, recipient_enc_key) in nodes.iter_mut().zip(encryption_keys.iter()) {
        let my_id = node.verifier_id().clone();
        let enc_pkgs = encrypted_round2.remove(&my_id).unwrap_or_default();

        let mut plaintext_r2: HashMap<VerifierId, DkgRound2Package> =
            HashMap::with_capacity(enc_pkgs.len());

        for (sender_id, enc_pkg) in enc_pkgs {
            let sender_pub = enc_pub_map.get(&sender_id).ok_or_else(|| {
                NodeError::DkgProtocol(format!(
                    "no encryption public key for sender {sender_id}"
                ))
            })?;
            let pkg = decrypt_round2_package(
                &enc_pkg,
                recipient_enc_key,
                sender_pub,
                ceremony_id,
                &sender_id,
                &my_id,
            )
            .map_err(NodeError::Crypto)?;
            plaintext_r2.insert(sender_id, pkg);
        }

        let (aux_node, group_key) = node.part3(plaintext_r2)?;
        aux_nodes.push(aux_node);
        group_keys.push(group_key);
    }

    // ── Consistency check ─────────────────────────────────────────────────────
    let first_key_bytes = group_keys[0].verifying_key_bytes();
    for (i, gk) in group_keys.iter().enumerate().skip(1) {
        if gk.verifying_key_bytes() != first_key_bytes {
            return Err(NodeError::DkgProtocol(format!(
                "group key mismatch: node 0 and node {i} derived different group \
                 verifying keys — possible inconsistent Round-1 broadcast"
            )));
        }
    }

    let group_key = group_keys.remove(0);

    info!(
        n_participants = nodes.len(),
        "DKG ceremony (encrypted) complete — all nodes produced consistent group key"
    );

    Ok((aux_nodes, group_key))
}

// ── Authenticated key-distribution ceremony ───────────────────────────────────

/// Run a Pedersen DKG ceremony with **authenticated** Round-2 key distribution.
///
/// This is the highest-assurance in-process orchestration variant.  It layers
/// signed announcement verification on top of `run_dkg_ceremony_encrypted`:
///
/// 1. All `announcements` are verified against `registry` (coordinator cannot
///    substitute a participant's `DkgEncryptionPublicKey` without forging an
///    Ed25519 signature).
/// 2. The verified public key map is consistency-checked against each node's own
///    `enc_keys` (detects callers providing enc keys that don't match their own
///    announcements — e.g., an in-process simulation of a split-brain scenario).
/// 3. The ceremony proceeds with `run_dkg_ceremony_encrypted` using the verified
///    key map instead of a positional assumption.
///
/// # Arguments
///
/// - `nodes` — DKG nodes in `Initial` state.
/// - `ceremony_id` — fresh random ceremony identifier (same one used when
///   creating announcements via `create_dkg_key_announcement`).
/// - `enc_keys` — each node's own `DkgEncryptionKeyPair` (private, same index
///   order as `nodes`).
/// - `announcements` — signed announcements from **all** participants (including
///   self), collected before the ceremony starts.
/// - `registry` — pre-distributed `DkgParticipantRegistry` mapping each
///   participant's `VerifierId` to their long-term Ed25519 verifying key.
///   Must NOT come from the coordinator channel being secured.
///
/// # Security invariant
///
/// The coordinator routing `announcements` cannot forge them without the
/// participants' private Ed25519 keys. An adversary who drops a participant's
/// announcement prevents ceremony start (liveness threat) but cannot cause
/// an incorrect key to be accepted (confidentiality threat removed).
///
/// # Errors
///
/// - `NodeError::DkgKeyAnnouncement` — if any announcement fails verification,
///   is from an unexpected participant, is a duplicate, is missing, or if an
///   enc key doesn't match the verified announcement for that participant.
/// - `NodeError::DkgProtocol` — if `enc_keys.len() != nodes.len()`.
/// - Other `NodeError` variants from the underlying `run_dkg_ceremony_encrypted`.
pub fn run_dkg_ceremony_with_authenticated_keys(
    nodes: &mut [FrostDkgNode],
    ceremony_id: &DkgCeremonyId,
    enc_keys: &[DkgEncryptionKeyPair],
    announcements: &[SignedDkgKeyAnnouncement],
    registry: &DkgParticipantRegistry,
) -> Result<(Vec<FrostAuxiliaryNode>, FrostGroupKey), NodeError> {
    if nodes.is_empty() {
        return Err(NodeError::DkgProtocol(
            "run_dkg_ceremony_with_authenticated_keys requires at least one node".into(),
        ));
    }
    if enc_keys.len() != nodes.len() {
        return Err(NodeError::DkgProtocol(format!(
            "enc_keys.len() ({}) must equal nodes.len() ({})",
            enc_keys.len(),
            nodes.len()
        )));
    }

    // ── Step 1: Verify all announcements against the registry ─────────────────
    //
    // `collect_verified_enc_keys` enforces:
    //   - Valid Ed25519 signature from each participant's identity key
    //   - Correct ceremony_id binding (no cross-ceremony replay)
    //   - All expected participants have announced (none missing)
    //   - No duplicate announcements (no ambiguity)
    //   - No outsider announcements (no injection)
    let participant_ids: Vec<VerifierId> =
        nodes.iter().map(|n| n.verifier_id().clone()).collect();

    let verified_enc_pub_map = registry
        .collect_verified_enc_keys(announcements, ceremony_id, &participant_ids)
        .map_err(|e| NodeError::DkgKeyAnnouncement(e.to_string()))?;

    // ── Step 2: Self-consistency check ────────────────────────────────────────
    //
    // Each node's actual enc key (private) must match what its own signed
    // announcement claimed (the public half). A mismatch means either:
    //   (a) The caller passed the wrong enc_keys (programming error).
    //   (b) An announcement was substituted and somehow passed verification
    //       (would require a forged signature — should be impossible here).
    //
    // This check catches (a) with a clear error and acts as a defence-in-depth
    // tripwire for (b).
    for (node, enc_key) in nodes.iter().zip(enc_keys.iter()) {
        let announced_pub = verified_enc_pub_map
            .get(node.verifier_id())
            .expect("all participants verified above");
        if announced_pub != enc_key.public_key() {
            return Err(NodeError::DkgKeyAnnouncement(format!(
                "enc key for {} does not match its own verified announcement — \
                 possible inconsistent state or key substitution",
                node.verifier_id()
            )));
        }
    }

    info!(
        n_participants = nodes.len(),
        "DKG: all key announcements verified — proceeding with authenticated encrypted ceremony"
    );

    // ── Step 3: Run the encrypted ceremony with verified keys ─────────────────
    //
    // `run_dkg_ceremony_encrypted` builds its enc_pub_map from the provided
    // enc_keys (their public halves). Because we've verified those public halves
    // match the signed announcements, the result is equivalent to using the
    // verified_enc_pub_map directly.
    run_dkg_ceremony_encrypted(nodes, ceremony_id, enc_keys)
}

/// Run a DKG ceremony with full registry-backed participant admission control.
///
/// This is the **recommended production entry point** for DKG ceremonies. It
/// strengthens `run_dkg_ceremony_with_authenticated_keys` by adding two
/// registry-level checks that close the remaining implicit trust gaps:
///
/// 1. **Epoch binding** — the ceremony must bind to a specific `RegistryEpoch`.
///    If `expected_epoch` does not match the registry snapshot's epoch, the
///    ceremony is rejected before any cryptographic work begins.
///
/// 2. **Revocation and status check** — every ceremony participant must be
///    `Active` in the registry. `Revoked` or `Retired` participants are
///    rejected even if they produce a valid signed announcement.
///
/// After these two checks pass, the function delegates to
/// `run_dkg_ceremony_with_authenticated_keys` (which verifies ed25519
/// announcement signatures, ceremony-ID binding, self-consistency, and runs
/// the encrypted DKG ceremony).
///
/// # Parameters
///
/// - `nodes` — DKG nodes, one per participant.
/// - `ceremony_id` — fresh random ceremony identifier (anti-replay in announcements).
/// - `enc_keys` — X25519 encryption key pairs, one per node (same order).
/// - `announcements` — signed key announcements from all participants.
/// - `registry` — versioned participant registry; must be from a trusted,
///   coordinator-independent source.
/// - `expected_epoch` — the epoch this ceremony is bound to. Must equal
///   `registry.epoch()`.
///
/// # Errors
///
/// - `NodeError::DkgKeyAnnouncement("registry epoch mismatch …")` if
///   `expected_epoch != registry.epoch()`.
/// - `NodeError::DkgKeyAnnouncement("participant … revoked …")` if any
///   node's participant is not `Active` in the registry.
/// - All errors from `run_dkg_ceremony_with_authenticated_keys` (signature
///   verification, ceremony binding, self-consistency, DKG protocol).
pub fn run_dkg_ceremony_with_registry(
    nodes: &mut [FrostDkgNode],
    ceremony_id: &DkgCeremonyId,
    enc_keys: &[DkgEncryptionKeyPair],
    announcements: &[SignedDkgKeyAnnouncement],
    registry: &ParticipantRegistry,
    expected_epoch: RegistryEpoch,
) -> Result<(Vec<FrostAuxiliaryNode>, FrostGroupKey), NodeError> {
    // ── Step 1: Registry epoch + participant admission check ──────────────────
    //
    // Enforces:
    // - The ceremony binds to the correct registry epoch (no stale snapshot use).
    // - Every participant node has `Active` status (no revoked/retired participants).
    let participant_ids: Vec<VerifierId> =
        nodes.iter().map(|n| n.verifier_id().clone()).collect();
    registry
        .check_ceremony_admission(expected_epoch, &participant_ids)
        .map_err(|e| NodeError::DkgKeyAnnouncement(e.to_string()))?;

    info!(
        n_participants = nodes.len(),
        epoch = expected_epoch.0,
        "DKG: registry admission check passed — all participants active at expected epoch"
    );

    // ── Step 2: Build the DKG announcement registry from active participants ──
    //
    // `to_dkg_registry()` filters to Active participants only. Revoked or retired
    // participants whose verifier IDs somehow appear in announcements will fail
    // the DkgParticipantRegistry lookup in `collect_verified_enc_keys`.
    let dkg_registry = registry.to_dkg_registry();

    // ── Step 3: Delegate to the authenticated-key path ────────────────────────
    //
    // This verifies ed25519 announcement signatures, ceremony-ID binding,
    // enc key self-consistency, and then runs the encrypted DKG ceremony.
    run_dkg_ceremony_with_authenticated_keys(
        nodes,
        ceremony_id,
        enc_keys,
        announcements,
        &dkg_registry,
    )
}

// ── Network-level DKG ceremony orchestrator ───────────────────────────────────

/// Run a Pedersen DKG ceremony using serialized network wire messages.
///
/// This is the **network transport layer** for Pedersen DKG.  It provides the
/// same security guarantees as `run_dkg_ceremony_with_authenticated_keys` but
/// works via message-passing rather than shared memory — making it suitable
/// for deployment over TCP, gRPC, or any other framing transport.
///
/// # Protocol
///
/// ```text
/// Coordinator                  Each Participant
/// -----------                  ----------------
/// DkgCeremonyAnnouncement  →   announce()  ←
///                          ←   DkgRound1Response
/// DkgRound2Delivery        →   deliver_round2()
///                          ←   DkgPart3Response
/// ```
///
/// All Round-2 packages are encrypted with X25519 + XChaCha20-Poly1305 (via
/// `encrypt_round2_package`) before serialization.  The coordinator sees only
/// ciphertexts and routing metadata.
///
/// # Arguments
///
/// - `nodes`       — DKG nodes in `Initial` state, one per local participant.
/// - `ceremony_id` — Fresh random ceremony identifier (from `DkgCeremonyId::new()`).
/// - `enc_keys`    — X25519 key pairs, one per node (same order as `nodes`).
/// - `announcements` — Signed key announcements from ALL participants.
/// - `registry`    — Pre-distributed `DkgParticipantRegistry`.
///
/// # Returns
///
/// `(aux_nodes, group_key, messages)` where `messages` is a
/// `DkgNetworkMessages` bundle carrying the serialized ceremony messages that
/// the transport layer must deliver to remote participants.
///
/// Remote participants call `run_dkg_ceremony_network_participant` with these
/// messages.
pub struct DkgNetworkMessages {
    /// Announcement to broadcast to all participants.
    pub announcement: tls_attestation_network::messages::DkgCeremonyAnnouncement,
    /// Round-1 response collected from each local participant.
    pub round1_responses: Vec<tls_attestation_network::messages::DkgRound1Response>,
    /// Encrypted Round-2 delivery envelopes, keyed by recipient VerifierId.
    pub round2_deliveries: std::collections::HashMap<
        VerifierId,
        tls_attestation_network::messages::DkgRound2Delivery,
    >,
}

/// Assemble the network ceremony messages for a set of local nodes.
///
/// Returns serialized `DkgNetworkMessages` that the transport layer can route
/// to remote participants.  This function does NOT perform Part 3 — each
/// remote participant must call `dkg_part3_from_delivery` after receiving its
/// `DkgRound2Delivery`.
pub fn build_dkg_network_messages(
    nodes: &mut [FrostDkgNode],
    ceremony_id: &DkgCeremonyId,
    enc_keys: &[DkgEncryptionKeyPair],
    announcements: &[SignedDkgKeyAnnouncement],
    registry: &DkgParticipantRegistry,
) -> Result<DkgNetworkMessages, NodeError> {
    use tls_attestation_network::messages::{
        DkgCeremonyAnnouncement, DkgRound1Response, DkgRound2Delivery,
    };

    if enc_keys.len() != nodes.len() {
        return Err(NodeError::DkgProtocol(format!(
            "enc_keys.len() ({}) must equal nodes.len() ({})",
            enc_keys.len(),
            nodes.len()
        )));
    }

    // Verify all announcements and collect the verified enc-public-key map.
    let participant_ids: Vec<VerifierId> =
        nodes.iter().map(|n| n.verifier_id().clone()).collect();
    let verified_enc_pub_map = registry
        .collect_verified_enc_keys(announcements, ceremony_id, &participant_ids)
        .map_err(|e| NodeError::DkgKeyAnnouncement(e.to_string()))?;

    // Build the ceremony announcement message.
    // Encryption public keys are serialized in the same order as all_participant_ids.
    let enc_pub_bytes: Vec<Vec<u8>> = participant_ids
        .iter()
        .map(|vid| {
            let pk = verified_enc_pub_map.get(vid).expect("verified above");
            serde_json::to_vec(pk)
                .map_err(|e| NodeError::DkgProtocol(format!("enc key serialize: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let announcement = DkgCeremonyAnnouncement {
        ceremony_id: ceremony_id.as_bytes().to_vec(),
        all_participant_ids: participant_ids.clone(),
        min_signers: nodes[0].min_signers,
        encryption_public_keys: enc_pub_bytes,
    };

    // Part 1: collect Round-1 broadcast packages.
    let mut round1_responses = Vec::with_capacity(nodes.len());
    let mut round1_broadcasts: HashMap<VerifierId, DkgRound1Package> =
        HashMap::with_capacity(nodes.len());

    for node in nodes.iter_mut() {
        let pkg = node.part1()?;
        let pkg_bytes = pkg.to_bytes();
        round1_responses.push(DkgRound1Response {
            ceremony_id: ceremony_id.as_bytes().to_vec(),
            participant_id: node.verifier_id().clone(),
            round1_package_bytes: pkg_bytes,
        });
        round1_broadcasts.insert(node.verifier_id().clone(), pkg);
    }

    // Part 2: generate and encrypt Round-2 unicast packages.
    let mut round2_deliveries: std::collections::HashMap<
        VerifierId,
        Vec<(VerifierId, Vec<u8>)>,
    > = std::collections::HashMap::new();

    for (node, sender_enc_key) in nodes.iter_mut().zip(enc_keys.iter()) {
        let my_id = node.verifier_id().clone();
        let others: HashMap<VerifierId, DkgRound1Package> = round1_broadcasts
            .iter()
            .filter(|(vid, _)| *vid != &my_id)
            .map(|(vid, pkg)| (vid.clone(), pkg.clone()))
            .collect();

        let outbound = node.part2(others)?;

        for (to_vid, pkg) in outbound {
            let recipient_pub = verified_enc_pub_map.get(&to_vid).ok_or_else(|| {
                NodeError::DkgProtocol(format!("no enc public key for {to_vid}"))
            })?;
            let enc_pkg = encrypt_round2_package(
                &pkg,
                ceremony_id,
                sender_enc_key,
                &my_id,
                recipient_pub,
                &to_vid,
            )
            .map_err(NodeError::Crypto)?;

            let enc_bytes = serde_json::to_vec(&enc_pkg)
                .map_err(|e| NodeError::DkgProtocol(format!("enc pkg serialize: {e}")))?;
            round2_deliveries
                .entry(to_vid)
                .or_default()
                .push((my_id.clone(), enc_bytes));
        }
    }

    // Convert to DkgRound2Delivery messages.
    let round2_delivery_map = round2_deliveries
        .into_iter()
        .map(|(recipient_id, pkgs)| {
            let delivery = DkgRound2Delivery {
                ceremony_id: ceremony_id.as_bytes().to_vec(),
                recipient_id: recipient_id.clone(),
                encrypted_packages: pkgs,
            };
            (recipient_id, delivery)
        })
        .collect();

    info!(
        n_participants = nodes.len(),
        "DKG network messages built — ready for transport delivery"
    );

    Ok(DkgNetworkMessages {
        announcement,
        round1_responses,
        round2_deliveries: round2_delivery_map,
    })
}

/// Complete Part 3 for a single node from a `DkgRound2Delivery` message.
///
/// Called by each remote participant after receiving its `DkgRound2Delivery`
/// from the coordinator.  Decrypts all inbound encrypted packages and runs
/// `dkg_part3`.
///
/// # Returns
///
/// `(FrostAuxiliaryNode, FrostGroupKey)` on success.
pub fn dkg_part3_from_delivery(
    node: &mut FrostDkgNode,
    enc_key: &DkgEncryptionKeyPair,
    delivery: &tls_attestation_network::messages::DkgRound2Delivery,
    enc_pub_map: &HashMap<VerifierId, DkgEncryptionPublicKey>,
    ceremony_id: &DkgCeremonyId,
) -> Result<(FrostAuxiliaryNode, FrostGroupKey), NodeError> {
    let my_id = node.verifier_id().clone();

    let mut plaintext_r2: HashMap<VerifierId, DkgRound2Package> =
        HashMap::with_capacity(delivery.encrypted_packages.len());

    for (sender_id, enc_bytes) in &delivery.encrypted_packages {
        let enc_pkg = serde_json::from_slice(enc_bytes).map_err(|e| {
            NodeError::DkgProtocol(format!("encrypted package deserialize: {e}"))
        })?;
        let sender_pub = enc_pub_map.get(sender_id).ok_or_else(|| {
            NodeError::DkgProtocol(format!("no enc public key for sender {sender_id}"))
        })?;
        let pkg = decrypt_round2_package(
            &enc_pkg,
            enc_key,
            sender_pub,
            ceremony_id,
            sender_id,
            &my_id,
        )
        .map_err(NodeError::Crypto)?;
        plaintext_r2.insert(sender_id.clone(), pkg);
    }

    node.part3(plaintext_r2)
}
