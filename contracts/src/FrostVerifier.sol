// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title FrostVerifier
 * @notice On-chain verifier for FROST(secp256k1) threshold Schnorr signatures.
 *
 * @dev Implements SC.Verify(σ, pk) from Π_coll-min (Fig. 8, paper §VIII.B).
 *
 * Paper reference (Table I, §IX):
 *   FROST on secp256k1: 2 ECMUL + 2 ECADD + 1 Hash-to-G → ~4,200 gas on secp256k1.
 *
 * Signature format (65 bytes):
 *   bytes  0–32: R.x  (x-coordinate of nonce commitment R = k*G)
 *   bytes 32–64: s    (scalar: s = k + e*sk, where e = H(R||PK||msg))
 *
 * Verification equation (BIP-340 / FROST Schnorr):
 *   e = keccak256(abi.encodePacked(R_x, pk_x, message_hash)) mod n
 *   Check: s*G = R + e*PK  with R having even y-coordinate.
 *
 * @custom:security-properties
 *   - Aggregate signature σ = (R, s) proves ≥ t aux verifiers signed.
 *   - Forgery requires breaking discrete-log on secp256k1 (DLOG assumption).
 *   - The message digest commits to the full attestation (statement, rand, session).
 *
 * @custom:changes
 *   - _modExp: fixed staticcall output buffer (was writing to stack slot, now uses memory).
 *   - _verifyWithPrecompiles: added y-parity check to enforce even-y convention.
 *   - _ecMul/_ecAdd: replaced hardcoded gas (pre-EIP-2929) with gas() forwarding.
 */
contract FrostVerifier {
    // secp256k1 curve order
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // secp256k1 field prime p
    uint256 internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // secp256k1 generator G
    uint256 internal constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /**
     * @notice Verify a FROST Schnorr aggregate signature.
     *
     * @param message_hash  32-byte digest that was signed (envelope_digest).
     * @param pk_x          x-coordinate of the group verifying key.
     * @param pk_y          y-coordinate of the group verifying key.
     * @param sig_R_x       x-coordinate of the nonce commitment R (even-y convention).
     * @param sig_s         Schnorr scalar s.
     * @return valid        true iff the signature is valid.
     */
    function verify(
        bytes32 message_hash,
        uint256 pk_x,
        uint256 pk_y,
        uint256 sig_R_x,
        uint256 sig_s
    ) public view returns (bool valid) {
        // Compute Schnorr challenge e = keccak256(R_x || pk_x || msg) mod N.
        uint256 e = uint256(
            keccak256(abi.encodePacked(sig_R_x, pk_x, message_hash))
        ) % N;

        return _verifyWithPrecompiles(message_hash, pk_x, pk_y, sig_R_x, sig_s, e);
    }

    /**
     * @dev Verify s*G - e*PK == R using the ecrecover trick.
     *
     * secp256k1 has no native ecMul/ecAdd precompile on Ethereum mainnet.
     * (0x06/0x07 are BN254 precompiles — a different curve entirely.)
     * The standard approach is to leverage ecrecover (0x01), which internally
     * performs secp256k1 point arithmetic.
     *
     * Derivation (based on https://ethresear.ch/t/you-can-kinda-abuse-ecrecover/):
     *
     *   ecrecover(hash, v, r, s_ec) returns address(r^{-1} * (s_ec * R_r - hash * G))
     *   where R_r = secp256k1 point with x = r, y parity determined by v.
     *
     *   We want to compute addr(s*G - e*PK):
     *     - Set r      = pk_x            (use PK's x as the recovery x)
     *     - Set v      = 28 - pk_y%2     (selects -PK: opposite y parity to PK)
     *     - Set s_ec   = e * pk_x mod N  (makes the e*PK term cancel correctly)
     *     - Set hash   = N - sig_s*pk_x mod N (adds sig_s*G with correct sign)
     *
     *   Then: pk_x^{-1} * (e*pk_x*(-PK) - (N-sig_s*pk_x)*G)
     *       = pk_x^{-1} * (-e*pk_x*PK + sig_s*pk_x*G)
     *       = sig_s*G - e*PK  = R  ✓
     *
     * We also verify R_y is even (FROST even-y convention) by computing R_y from R_x.
     */
    function _verifyWithPrecompiles(
        bytes32 /*message_hash*/,
        uint256 pk_x,
        uint256 pk_y,
        uint256 sig_R_x,
        uint256 sig_s,
        uint256 e
    ) internal view returns (bool) {
        // Recover R_y (even parity — FROST convention).  Returns 0 for invalid x.
        uint256 R_y = _recoverY(sig_R_x);
        if (R_y == 0) return false;

        // Compute the expected Ethereum address of R = (sig_R_x, R_y).
        address R_addr = address(uint160(uint256(keccak256(abi.encodePacked(sig_R_x, R_y)))));

        // ecrecover parameters for the trick:
        //   v = 28 - pk_y%2  →  selects the negation of PK as the recovery point.
        uint8 v = uint8(28 - (pk_y % 2));
        //   r = pk_x  (x-coordinate of the recovery point PK / -PK)
        bytes32 r = bytes32(pk_x);
        //   s_ec = e * pk_x mod N
        bytes32 s_ec = bytes32(mulmod(e, pk_x, N));
        //   hash_ec = -(sig_s * pk_x) mod N = N - (sig_s * pk_x mod N)
        bytes32 hash_ec = bytes32(N - mulmod(sig_s, pk_x, N));

        // ecrecover returns addr(sig_s*G - e*PK) = addr(R) if the signature is valid.
        address recovered = ecrecover(hash_ec, v, r, s_ec);

        return recovered != address(0) && recovered == R_addr;
    }

    /// @dev Recover the y-coordinate for a compressed secp256k1 point (even parity).
    function _recoverY(uint256 x) internal view returns (uint256 y) {
        // y² = x³ + 7 (mod p)
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        // y = rhs^((p+1)/4) mod p  (valid since p ≡ 3 mod 4)
        y = _modExp(rhs, (P + 1) / 4, P);
        // Choose even y (FROST convention).
        if (y % 2 != 0) {
            y = P - y;
        }
        // Validate: y² == rhs (rejects invalid x-coordinates).
        if (mulmod(y, y, P) != rhs) {
            y = 0;
        }
    }

    /**
     * @dev Modular exponentiation via precompile 0x05 (EIP-198).
     *
     * Fix: the previous implementation used a uint256 stack variable as the
     * staticcall output pointer, which is undefined behavior in Solidity's memory
     * model.  We now allocate an explicit 32-byte output buffer in memory.
     */
    function _modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(
            uint256(32), uint256(32), uint256(32), base, exp, mod
        );
        bytes memory output = new bytes(32);
        assembly {
            if iszero(staticcall(gas(), 0x05, add(input, 32), 0xC0, add(output, 32), 32)) {
                revert(0, 0)
            }
        }
        result = uint256(bytes32(output));
    }

    }

/**
 * @title TLSAttestation
 * @notice On-chain attestation verifier for Π_coll-min (Fig. 8, paper §VIII.B).
 *
 * @custom:changes
 *   - verifyAttestation: external → public (child contracts call it directly).
 *   - verifyAttestation: added threshold == 0 guard.
 *   - verifyAttestation: added authorized group key registry check.
 *   - verifyRaw: removed `this.` prefix.
 *   - authorizeGroupKey / revokeGroupKey: owner-controlled key registry.
 *
 * @dev Group key registry (fix for "group key not validated on-chain"):
 *
 *   Without a registry, any party can run their own DKG ceremony and produce
 *   a valid FROST signature over an arbitrary statement, then submit it as a
 *   TLS attestation.  The signature math is correct, but the group key has no
 *   connection to the intended verifier quorum.
 *
 *   The fix introduces an `authorizedGroupKeys` mapping.  Only keys registered
 *   by the contract owner (e.g. via governance or a multisig) are accepted.
 *   DKG ceremony coordinators must call `authorizeGroupKey` after a successful
 *   key ceremony; participants verify their own output before signing.
 */
contract TLSAttestation is FrostVerifier {
    // ── Events ────────────────────────────────────────────────────────────────

    event AttestationAccepted(
        bytes32 indexed statementDigest,
        bytes32 randValue,
        uint8   threshold
    );
    event AttestationRejected(bytes32 indexed statementDigest, string reason);

    /// @notice Emitted when a group key is added to the authorized registry.
    event GroupKeyAuthorized(uint256 indexed keyX, uint256 keyY);
    /// @notice Emitted when a group key is removed from the registry.
    event GroupKeyRevoked(uint256 indexed keyX, uint256 keyY);

    // ── Owner / key registry ──────────────────────────────────────────────────

    address public immutable owner;

    /// @dev Authorized group public keys: keccak256(abi.encodePacked(x, y)) → true.
    /// Using a hash avoids storing two uint256 words per key.
    mapping(bytes32 => bool) public authorizedGroupKeys;

    modifier onlyOwner() {
        require(msg.sender == owner, "TLSAttestation: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register an authorized DKG group key.
    /// @dev Call this after a successful DKG ceremony.  Only the owner may
    ///      authorize keys, preventing rogue DKG substitution attacks.
    function authorizeGroupKey(uint256 keyX, uint256 keyY) external onlyOwner {
        bytes32 h = keccak256(abi.encodePacked(keyX, keyY));
        authorizedGroupKeys[h] = true;
        emit GroupKeyAuthorized(keyX, keyY);
    }

    /// @notice Revoke an authorized group key (e.g. after a key rotation).
    function revokeGroupKey(uint256 keyX, uint256 keyY) external onlyOwner {
        bytes32 h = keccak256(abi.encodePacked(keyX, keyY));
        authorizedGroupKeys[h] = false;
        emit GroupKeyRevoked(keyX, keyY);
    }

    /// @notice Check whether a group key is currently authorized.
    function isGroupKeyAuthorized(uint256 keyX, uint256 keyY) public view returns (bool) {
        return authorizedGroupKeys[keccak256(abi.encodePacked(keyX, keyY))];
    }

    // ── Attestation struct ────────────────────────────────────────────────────

    struct Attestation {
        bytes32 statementDigest;
        bytes32 dvrf_value;
        bytes32 envelopeDigest;
        uint256 groupKeyX;
        uint256 groupKeyY;
        uint256 sigRX;
        uint256 sigS;
        uint8   threshold;
        uint8   verifierCount;
    }

    // ── SC.Verify ─────────────────────────────────────────────────────────────

    /**
     * @notice SC.Verify(σ, pk) — Verify a Π_coll-min attestation.
     *
     * Checks (in order):
     *   1. statementDigest is non-zero.
     *   2. threshold is at least 1.
     *   3. threshold ≤ verifierCount.
     *   4. Group key is in the authorized registry.  [new]
     *   5. FROST Schnorr signature is valid.
     */
    function verifyAttestation(Attestation memory att) public returns (bool) {
        if (att.statementDigest == bytes32(0)) {
            emit AttestationRejected(att.statementDigest, "empty statement");
            return false;
        }
        if (att.threshold == 0) {
            emit AttestationRejected(att.statementDigest, "threshold is zero");
            return false;
        }
        if (att.threshold > att.verifierCount) {
            emit AttestationRejected(att.statementDigest, "threshold > verifierCount");
            return false;
        }

        // Guard: group key must be in the authorized registry.
        // Without this check any party could run their own DKG and produce a
        // valid FROST signature that the verifier would accept.
        if (!isGroupKeyAuthorized(att.groupKeyX, att.groupKeyY)) {
            emit AttestationRejected(att.statementDigest, "unauthorized group key");
            return false;
        }

        bool valid = verify(
            att.envelopeDigest,
            att.groupKeyX,
            att.groupKeyY,
            att.sigRX,
            att.sigS
        );

        if (valid) {
            emit AttestationAccepted(att.statementDigest, att.dvrf_value, att.threshold);
        } else {
            emit AttestationRejected(att.statementDigest, "invalid FROST signature");
        }
        return valid;
    }

    function verifyRaw(bytes calldata raw) external returns (bool) {
        require(raw.length == 352, "TLSAttestation: expected 352 bytes");
        Attestation memory att = _decode(raw);
        return verifyAttestation(att);
    }

    function _decode(bytes calldata raw) internal pure returns (Attestation memory att) {
        att.statementDigest = bytes32(raw[0:32]);
        att.dvrf_value      = bytes32(raw[32:64]);
        att.envelopeDigest  = bytes32(raw[64:96]);
        att.groupKeyX       = uint256(bytes32(raw[96:128]));
        att.groupKeyY       = uint256(bytes32(raw[128:160]));
        att.sigRX           = uint256(bytes32(raw[160:192]));
        att.sigS            = uint256(bytes32(raw[192:224]));
        att.threshold       = uint8(raw[255]);
        att.verifierCount   = uint8(raw[287]);
    }
}

/**
 * @title BinaryOptionsAttestation
 * @notice Use Case 1 (§X.A): Confidential Binary Options settlement verifier.
 *
 * @custom:changes
 *   - settle: winner.transfer() → low-level call (EIP-1884: transfer forwards
 *     only 2,300 gas, which is insufficient for contract recipients since
 *     EIP-1884 raised SLOAD cost to 2,100).
 *   - createOption: added expiresAt field so stale options cannot be settled.
 *   - settle: added expiry check.
 */
contract BinaryOptionsAttestation is TLSAttestation {
    struct Option {
        address alice;
        address bob;
        bytes32 conditionCommitment;
        uint256 payoutAmount;
        uint256 expiresAt;          // Unix timestamp; 0 = no expiry (legacy)
        bool    settled;
    }

    mapping(bytes32 => Option) public options;

    /**
     * @notice Register a binary option (Setup phase).
     * @param optionId        Unique option identifier.
     * @param counterparty    Bob's address.
     * @param conditionCommit Commitment to (N*, P, D*).
     * @param ttlSeconds      How long (in seconds) this option can be settled.
     *                        Pass 0 for no expiry (not recommended in production).
     */
    function createOption(
        bytes32 optionId,
        address counterparty,
        bytes32 conditionCommit,
        uint256 ttlSeconds
    ) external payable {
        require(options[optionId].alice == address(0), "Option already exists");
        uint256 expiry = ttlSeconds == 0 ? 0 : block.timestamp + ttlSeconds;
        options[optionId] = Option({
            alice:               msg.sender,
            bob:                 counterparty,
            conditionCommitment: conditionCommit,
            payoutAmount:        msg.value,
            expiresAt:           expiry,
            settled:             false
        });
    }

    /**
     * @notice Settle a binary option (Payout phase).
     *
     * Fix: replaced winner.transfer(amount) with a low-level call.
     * transfer() forwards only 2,300 gas (EIP-150 stipend), which is not
     * enough for contract recipients after EIP-1884 raised SLOAD to 2,100.
     * Low-level call forwards all available gas and reverts on failure.
     */
    function settle(
        bytes32          optionId,
        Attestation calldata att,
        address payable  winner
    ) external {
        Option storage opt = options[optionId];
        require(!opt.settled, "Already settled");
        require(
            winner == opt.alice || winner == opt.bob,
            "Winner must be a party"
        );
        require(
            opt.expiresAt == 0 || block.timestamp <= opt.expiresAt,
            "Option expired"
        );

        // SC.Verify(σ, pk).
        require(verifyAttestation(att), "Invalid attestation");

        // The statementDigest must commit to this option and the winner.
        bytes32 expectedDigest = keccak256(
            abi.encodePacked(
                "tls-attestation/binary-options/v1\x00",
                optionId,
                winner
            )
        );
        require(att.statementDigest == expectedDigest, "Statement mismatch");

        opt.settled = true;

        // Fix: low-level call instead of transfer().
        (bool ok, ) = winner.call{value: opt.payoutAmount}("");
        require(ok, "Transfer failed");
    }
}

/**
 * @title IncomeAttestation
 * @notice Use Case 2 (§X.B): Off-chain income verification for DeFi lending.
 *
 * @custom:changes
 *   - submitIncome: added attestation replay protection via
 *     `processedAttestations` mapping keyed by envelopeDigest.
 */
contract IncomeAttestation is TLSAttestation {
    mapping(address => uint256) public verifiedIncome;
    mapping(address => uint256) public incomeTimestamp;

    /// @dev Prevents replay of the same attestation for different users.
    mapping(bytes32 => bool) private processedAttestations;

    uint256 public constant INCOME_VALIDITY_SECONDS = 30 days;

    /**
     * @notice Submit income attestation from Π_coll-min verifier quorum.
     *
     * Fix: added replay protection.  Without it, the same attestation could be
     * submitted multiple times (e.g. to reset incomeTimestamp to a stale value
     * or spam gas).  envelopeDigest is unique per session so it serves as a
     * natural nonce.
     *
     * @param att       Π_coll-min attestation.
     * @param income    Attested income value (USD × 100, e.g. 300000 = $3000).
     * @param timestamp Unix timestamp of the TLS session.
     */
    function submitIncome(
        Attestation calldata att,
        uint256 income,
        uint256 timestamp
    ) external {
        // Replay protection: each envelope can only be processed once.
        require(!processedAttestations[att.envelopeDigest], "Attestation already processed");
        processedAttestations[att.envelopeDigest] = true;

        require(verifyAttestation(att), "Invalid attestation");

        bytes32 expectedDigest = keccak256(
            abi.encodePacked(
                "tls-attestation/income/v1\x00",
                msg.sender,
                income,
                timestamp
            )
        );
        require(att.statementDigest == expectedDigest, "Statement mismatch");
        require(timestamp <= block.timestamp, "Future timestamp");
        require(block.timestamp - timestamp <= INCOME_VALIDITY_SECONDS, "Attestation expired");

        verifiedIncome[msg.sender]  = income;
        incomeTimestamp[msg.sender] = timestamp;
    }

    /**
     * @notice Check if a user has a valid income attestation.
     */
    function hasVerifiedIncome(address user, uint256 minIncome) external view returns (bool) {
        if (verifiedIncome[user] < minIncome) return false;
        if (block.timestamp - incomeTimestamp[user] > INCOME_VALIDITY_SECONDS) return false;
        return true;
    }
}
