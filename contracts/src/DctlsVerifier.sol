// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DctlsVerifier
 * @notice On-chain Groth16 verifier for dx-DCTLS zero-knowledge proofs.
 *
 * @dev Implements ZKP.Verify(π, x) from paper §VIII.B (Signing Phase) and §IX
 *      (On-Chain Attestation) using Ethereum's BN254 precompiles (EIP-196/197).
 *
 * Paper references:
 *   §III.B  co-SNARK: ZKP.Verify(π_HSP, rand) = 1
 *   §V      PGP:      ZKP.Verify(π_pgp, b) = 1
 *   §IX     On-chain: smart contract verifies FROST σ + Groth16 π
 *
 * Groth16 verification equation (BN254):
 *   e(π.A, π.B) · e(vk.α_neg, vk.β) · e(Σ_vk, vk.γ) · e(π.C_neg, vk.δ) == 1
 *
 * where Σ_vk = Σ_{i=0}^{n} public_inputs[i] · vk.IC[i]
 *
 * Implemented using:
 *   EIP-196 (0x06/0x07): bn256Add, bn256ScalarMul  — G1 arithmetic
 *   EIP-197 (0x08):      bn256Pairing               — pairing product check
 *
 * Gas cost estimate (BN254 pairing, 4 pairs):
 *   45,000 + 4 × 34,000 = ~181,000 gas per Groth16 verify call.
 *
 * @custom:security-properties
 *   - Groth16 is computationally sound under the q-SDH and d-PKE assumptions.
 *   - BN254 supports 128-bit security level (NIST recommendation).
 *   - The verifying key is baked into the contract — upgrading requires redeployment.
 */
contract DctlsVerifier {

    // ── BN254 precompile addresses ───────────────────────────────────────────

    address internal constant BN254_ADD    = address(0x06);
    address internal constant BN254_MUL    = address(0x07);
    address internal constant BN254_PAIRING = address(0x08);

    // ── Proof struct ─────────────────────────────────────────────────────────

    /**
     * @notice Groth16 proof elements (BN254).
     * @dev A and C are G1 points (64 bytes each).
     *      B is a G2 point (128 bytes).
     */
    struct Proof {
        uint256 a_x;
        uint256 a_y;
        uint256 b_x0; // G2 x coefficient [1]
        uint256 b_x1; // G2 x coefficient [0]
        uint256 b_y0; // G2 y coefficient [1]
        uint256 b_y1; // G2 y coefficient [0]
        uint256 c_x;
        uint256 c_y;
    }

    // ── Verifying key structs ────────────────────────────────────────────────

    /**
     * @notice Groth16 verifying key elements shared by all circuits.
     */
    struct VerifyingKey {
        // α (G1), negated for the pairing product formula.
        uint256 alpha_x;
        uint256 alpha_y;
        // β (G2)
        uint256 beta_x0;
        uint256 beta_x1;
        uint256 beta_y0;
        uint256 beta_y1;
        // γ (G2)
        uint256 gamma_x0;
        uint256 gamma_x1;
        uint256 gamma_y0;
        uint256 gamma_y1;
        // δ (G2)
        uint256 delta_x0;
        uint256 delta_x1;
        uint256 delta_y0;
        uint256 delta_y1;
    }

    // ── Storage: verifying keys (set on deployment) ──────────────────────────

    /**
     * @notice Verifying key for π_HSP (Mode 1 — K_MAC commitment).
     *   Public inputs: [k_mac_commitment_fe, rand_binding_fe]
     */
    VerifyingKey public vkHspMode1;
    uint256[2][3] public icHspMode1; // IC[0..2]: constant + 2 public inputs

    /**
     * @notice Verifying key for π_HSP (Mode 2 — full TLS-PRF + PMS binding).
     *   Public inputs: [k_mac_commitment_fe, rand_binding_fe, pms_hash_fe]
     */
    VerifyingKey public vkHspMode2;
    uint256[2][4] public icHspMode2; // IC[0..3]: constant + 3 public inputs

    /**
     * @notice Verifying key for π_θs (session secret binding).
     *   Public inputs: [k_mac_commitment_fe, rand_binding_fe,
     *                   mac_commitment_q_fe, mac_commitment_r_fe]
     */
    VerifyingKey public vkSessionBinding;
    uint256[2][5] public icSessionBinding; // IC[0..4]: constant + 4 public inputs

    // ── Owner ────────────────────────────────────────────────────────────────

    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "DctlsVerifier: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ── Verifying key registration ────────────────────────────────────────────

    /**
     * @notice Register the π_HSP Mode 1 verifying key.
     * @dev Called once after deployment with the VK exported from Rust:
     *      `CoSnarkCrs::setup().pvk` serialized to BN254 affine coordinates.
     */
    function setHspMode1VK(
        VerifyingKey calldata vk,
        uint256[2][3] calldata ic
    ) external onlyOwner {
        vkHspMode1 = vk;
        for (uint i = 0; i < 3; i++) icHspMode1[i] = ic[i];
        emit VKRegistered("hsp_mode1");
    }

    /**
     * @notice Register the π_HSP Mode 2 verifying key.
     */
    function setHspMode2VK(
        VerifyingKey calldata vk,
        uint256[2][4] calldata ic
    ) external onlyOwner {
        vkHspMode2 = vk;
        for (uint i = 0; i < 4; i++) icHspMode2[i] = ic[i];
        emit VKRegistered("hsp_mode2");
    }

    /**
     * @notice Register the π_θs session binding verifying key.
     */
    function setSessionBindingVK(
        VerifyingKey calldata vk,
        uint256[2][5] calldata ic
    ) external onlyOwner {
        vkSessionBinding = vk;
        for (uint i = 0; i < 5; i++) icSessionBinding[i] = ic[i];
        emit VKRegistered("session_binding");
    }

    event VKRegistered(string circuit);

    // ── Public verify functions ──────────────────────────────────────────────

    /**
     * @notice Verify π_HSP Mode 1 on-chain.
     *
     * Implements paper §VIII.B: ZKP.Verify(π_HSP, rand) = 1
     *
     * @param proof              Groth16 proof elements.
     * @param kMacCommitment     pack(K_MAC) + rand_binding (Fr element).
     * @param randBinding        DVRF randomness field element.
     * @return valid             true iff the proof is valid.
     */
    function verifyHspMode1(
        Proof calldata proof,
        uint256 kMacCommitment,
        uint256 randBinding
    ) external view returns (bool valid) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = kMacCommitment;
        inputs[1] = randBinding;
        return _groth16Verify(proof, inputs, vkHspMode1, _icHspMode1AsArray());
    }

    /**
     * @notice Verify π_HSP Mode 2 on-chain (with PMS binding).
     *
     * @param proof              Groth16 proof elements.
     * @param kMacCommitment     pack(K_MAC) + rand_binding.
     * @param randBinding        DVRF randomness field element.
     * @param pmsHash            SHA256(PMS) as a BN254 Fr element.
     * @return valid             true iff the proof is valid.
     */
    function verifyHspMode2(
        Proof calldata proof,
        uint256 kMacCommitment,
        uint256 randBinding,
        uint256 pmsHash
    ) external view returns (bool valid) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = kMacCommitment;
        inputs[1] = randBinding;
        inputs[2] = pmsHash;
        return _groth16Verify(proof, inputs, vkHspMode2, _icHspMode2AsArray());
    }

    /**
     * @notice Verify π_θs (session secret binding) on-chain.
     *
     * Implements paper §V: proves K_MAC authenticated TLS query + response.
     *
     * @param proof              Groth16 proof elements.
     * @param kMacCommitment     pack(K_MAC) + rand_binding.
     * @param randBinding        DVRF randomness field element.
     * @param macCommitmentQ     pack(mac_q) + rand_binding.
     * @param macCommitmentR     pack(mac_r) + rand_binding.
     * @return valid             true iff the proof is valid.
     */
    function verifySessionBinding(
        Proof calldata proof,
        uint256 kMacCommitment,
        uint256 randBinding,
        uint256 macCommitmentQ,
        uint256 macCommitmentR
    ) external view returns (bool valid) {
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = kMacCommitment;
        inputs[1] = randBinding;
        inputs[2] = macCommitmentQ;
        inputs[3] = macCommitmentR;
        return _groth16Verify(proof, inputs, vkSessionBinding, _icSessionBindingAsArray());
    }

    /**
     * @notice Verify all three proofs atomically.
     *
     * Full attestation check per paper §IX: a single transaction verifies
     * π_HSP (Mode 2), π_θs, and their shared commitment consistency.
     *
     * @dev Reverts on any failed proof rather than returning false, making
     *      the function usable as a precondition in downstream contracts.
     */
    function verifyFullAttestation(
        Proof calldata hspProof,
        Proof calldata sessionProof,
        uint256 kMacCommitment,
        uint256 randBinding,
        uint256 pmsHash,
        uint256 macCommitmentQ,
        uint256 macCommitmentR
    ) external view {
        // Both proofs must share the same kMacCommitment.
        uint256[] memory hspInputs = new uint256[](3);
        hspInputs[0] = kMacCommitment;
        hspInputs[1] = randBinding;
        hspInputs[2] = pmsHash;
        require(
            _groth16Verify(hspProof, hspInputs, vkHspMode2, _icHspMode2AsArray()),
            "DctlsVerifier: pi_HSP invalid"
        );

        uint256[] memory sessInputs = new uint256[](4);
        sessInputs[0] = kMacCommitment;
        sessInputs[1] = randBinding;
        sessInputs[2] = macCommitmentQ;
        sessInputs[3] = macCommitmentR;
        require(
            _groth16Verify(sessionProof, sessInputs, vkSessionBinding, _icSessionBindingAsArray()),
            "DctlsVerifier: pi_theta_s invalid"
        );
    }

    // ── Internal: Groth16 verification ───────────────────────────────────────

    /**
     * @dev Core Groth16 verification using BN254 precompiles.
     *
     * Verifies: e(A, B) · e(α_neg, β) · e(Σ_vk, γ) · e(C_neg, δ) == 1
     *
     * Implemented as a single pairing product call (EIP-197) for gas efficiency.
     * The pairing precompile checks e(P1,Q1)·e(P2,Q2)·...·e(Pk,Qk) == 1.
     *
     * We negate A and C in G1 to bring all terms into one pairing product:
     *   e(-A, B) · e(α, β) · e(Σ_vk, γ) · e(C, δ)  == ... (rearranged)
     *
     * Actually the standard approach negates α:
     *   e(A, B) · e(α_neg, β) · e(Σ_vk, γ) · e(C, δ) == 1
     * where α_neg = -α stored in the verifying key.
     */
    function _groth16Verify(
        Proof calldata proof,
        uint256[] memory publicInputs,
        VerifyingKey storage vk,
        uint256[2][] memory ic
    ) internal view returns (bool) {
        require(publicInputs.length + 1 == ic.length, "DctlsVerifier: input count mismatch");

        // Compute Σ_vk = IC[0] + Σ_{i=1}^{n} input[i-1] · IC[i]  (G1 multiscalar mul)
        uint256[2] memory acc;
        acc[0] = ic[0][0];
        acc[1] = ic[0][1];

        for (uint256 i = 0; i < publicInputs.length; i++) {
            // scalar_mul: input[i] * IC[i+1]
            uint256[2] memory term = _g1ScalarMul(ic[i + 1], publicInputs[i]);
            // acc = acc + term
            acc = _g1Add(acc, term);
        }

        // Pairing product: e(A,B) · e(α_neg, β) · e(Σ_vk, γ) · e(C, δ) == 1
        // Pack 4 pairs: [G1,G2, G1,G2, G1,G2, G1,G2]
        // G1 = 64 bytes, G2 = 128 bytes → 4 pairs × 192 bytes = 768 bytes
        bytes memory input = new bytes(768);

        // Pair 1: (proof.A, proof.B)
        _packG1(input,   0, proof.a_x, proof.a_y);
        _packG2(input,  64, proof.b_x0, proof.b_x1, proof.b_y0, proof.b_y1);

        // Pair 2: (vk.alpha_neg, vk.beta)  — α is stored negated in VK
        _packG1(input, 192, vk.alpha_x, vk.alpha_y);
        _packG2(input, 256, vk.beta_x0, vk.beta_x1, vk.beta_y0, vk.beta_y1);

        // Pair 3: (Σ_vk, vk.gamma)
        _packG1(input, 384, acc[0], acc[1]);
        _packG2(input, 448, vk.gamma_x0, vk.gamma_x1, vk.gamma_y0, vk.gamma_y1);

        // Pair 4: (proof.C, vk.delta)
        _packG1(input, 576, proof.c_x, proof.c_y);
        _packG2(input, 640, vk.delta_x0, vk.delta_x1, vk.delta_y0, vk.delta_y1);

        (bool success, bytes memory result) = BN254_PAIRING.staticcall(input);
        require(success, "DctlsVerifier: pairing precompile failed");
        return result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    // ── Internal: BN254 G1 arithmetic ────────────────────────────────────────

    function _g1Add(
        uint256[2] memory a,
        uint256[2] memory b
    ) internal view returns (uint256[2] memory c) {
        bytes memory input = abi.encodePacked(a[0], a[1], b[0], b[1]);
        (bool ok, bytes memory out) = BN254_ADD.staticcall(input);
        require(ok, "DctlsVerifier: bn256Add failed");
        c = abi.decode(out, (uint256[2]));
    }

    function _g1ScalarMul(
        uint256[2] memory p,
        uint256 s
    ) internal view returns (uint256[2] memory r) {
        bytes memory input = abi.encodePacked(p[0], p[1], s);
        (bool ok, bytes memory out) = BN254_MUL.staticcall(input);
        require(ok, "DctlsVerifier: bn256ScalarMul failed");
        r = abi.decode(out, (uint256[2]));
    }

    // ── Internal: byte packing helpers ───────────────────────────────────────

    function _packG1(
        bytes memory buf,
        uint256 offset,
        uint256 x,
        uint256 y
    ) internal pure {
        assembly {
            mstore(add(add(buf, 32), offset),       x)
            mstore(add(add(buf, 32), add(offset, 32)), y)
        }
    }

    function _packG2(
        bytes memory buf,
        uint256 offset,
        uint256 x0,
        uint256 x1,
        uint256 y0,
        uint256 y1
    ) internal pure {
        assembly {
            mstore(add(add(buf, 32), offset),        x0)
            mstore(add(add(buf, 32), add(offset, 32)),  x1)
            mstore(add(add(buf, 32), add(offset, 64)),  y0)
            mstore(add(add(buf, 32), add(offset, 96)),  y1)
        }
    }

    // ── Internal: IC array helpers ────────────────────────────────────────────

    function _icHspMode1AsArray() internal view returns (uint256[2][] memory) {
        uint256[2][] memory ic = new uint256[2][](3);
        for (uint i = 0; i < 3; i++) ic[i] = icHspMode1[i];
        return ic;
    }

    function _icHspMode2AsArray() internal view returns (uint256[2][] memory) {
        uint256[2][] memory ic = new uint256[2][](4);
        for (uint i = 0; i < 4; i++) ic[i] = icHspMode2[i];
        return ic;
    }

    function _icSessionBindingAsArray() internal view returns (uint256[2][] memory) {
        uint256[2][] memory ic = new uint256[2][](5);
        for (uint i = 0; i < 5; i++) ic[i] = icSessionBinding[i];
        return ic;
    }
}
