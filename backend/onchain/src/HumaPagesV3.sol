// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @notice The interface every verifier bb generates (`bb write_solidity_verifier -t evm --optimized`) implements.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title HumaPagesV3
/// @notice Public record of Huma pages (assurance-long-v3) whose every zero-knowledge proof verified on-chain.
/// @dev A long3 page is several proofs of Huma's EXISTING circuits (backend/integrations/noir/long3/prover.nr), made with
/// bb's `evm` target (keccak transcript, ZK): one `chunk<T>` proof per part of the writing session and one `final<T>`
/// proof, where T is the page's text tier (1024, 4096 or 10000 characters). Each part's public inputs are
/// [start_root, end_root, genesis]; the final proof's 44 public inputs are the page's statement, in the order of
/// `struct Final` (reader.mjs FINAL: nonce[2], state_root, ..., text_capacity at 14, ..., event_digest).
///
/// This contract routes by the statement's text_capacity to that tier's pair of generated verifiers, checks every part
/// proof and the final proof, enforces the part linkage the reader enforces (genesis first and only first, each part
/// starts where the previous ended, the final state is where the last part ended), and records
/// keccak256(statement) => (block, parts, tier, submitter). Anyone may submit; a statement is recorded once.
///
/// A page of up to MAX_PARTS_PER_TX parts goes in one transaction (`submit`). A longer one is sent in batches
/// (`submitParts`, which keeps the verified end root per submitter and session) and closed with `submitFinal`.
///
/// NOT checked here (Huma's reader checks them off-chain): the P-256 signatures over the checkpoint and presence roots,
/// the nonce <-> capture-key binding and the event digest (Poseidon2), passkey assertions, the statement's sanity
/// rules, and the text itself (its commitment is part of the recorded statement).
contract HumaPagesV3 {
    /// @notice Public inputs of a final proof: the page's statement.
    uint256 public constant FINAL_INPUTS = 44;
    /// @notice Parts one transaction may verify, so a transaction stays under a 2^24 gas cap (EIP-7825) at every tier.
    uint256 public constant MAX_PARTS_PER_TX = 12;
    uint256 internal constant STATE_ROOT = 2; // after the two nonce fields
    uint256 internal constant TEXT_CAPACITY = 14;

    struct Page {
        uint64 blockNumber;
        uint32 parts;
        uint32 tier;
        address submitter;
    }

    /// @dev A long page's parts verified so far: where the last one ended, how many, and at which tier.
    struct Progress {
        bytes32 end;
        uint32 next;
        uint32 tier;
    }

    IHonkVerifier public immutable chunk1024;
    IHonkVerifier public immutable final1024;
    IHonkVerifier public immutable chunk4096;
    IHonkVerifier public immutable final4096;
    IHonkVerifier public immutable chunk10000;
    IHonkVerifier public immutable final10000;

    /// @notice keccak256 of a page's 44 statement fields => when and by whom its proofs were verified.
    mapping(bytes32 => Page) public pages;
    /// @notice keccak256(submitter, the first part's start root) => a long page's parts verified so far.
    mapping(bytes32 => Progress) public progress;

    event PageVerified(bytes32 indexed statement, address indexed submitter, uint256 tier, uint256 parts);
    event PartsVerified(bytes32 indexed session, address indexed submitter, uint256 tier, uint256 next);

    error AlreadyVerified();
    error NoParts();
    error TooManyParts(uint256 parts);
    error UnsupportedTier(uint256 tier);
    error InvalidStatement();
    error BrokenLinkage(uint256 part);
    error InvalidPartProof(uint256 part);
    error InvalidFinalProof();
    error UnknownSession();

    constructor(
        IHonkVerifier chunk1024_,
        IHonkVerifier final1024_,
        IHonkVerifier chunk4096_,
        IHonkVerifier final4096_,
        IHonkVerifier chunk10000_,
        IHonkVerifier final10000_
    ) {
        (chunk1024, final1024) = (chunk1024_, final1024_);
        (chunk4096, final4096) = (chunk4096_, final4096_);
        (chunk10000, final10000) = (chunk10000_, final10000_);
    }

    /// @notice Verifies a whole page (up to MAX_PARTS_PER_TX parts) and records it.
    /// @return statement keccak256 of the 44 statement fields, the page's key in `pages`.
    function submit(
        bytes[] calldata partProofs,
        bytes32[3][] calldata partInputs,
        bytes calldata finalProof,
        bytes32[] calldata finalInputs
    ) external returns (bytes32 statement) {
        uint256 parts = partProofs.length;
        if (parts == 0) revert NoParts();
        if (parts > MAX_PARTS_PER_TX) revert TooManyParts(parts);
        if (partInputs.length != parts) revert InvalidStatement();
        uint256 tier = _tier(finalInputs);
        statement = keccak256(abi.encodePacked(finalInputs));
        if (pages[statement].blockNumber != 0) revert AlreadyVerified();
        bytes32 end = _verifyParts(_chunk(tier), 0, bytes32(0), partProofs, partInputs);
        _verifyFinal(tier, end, parts, finalProof, finalInputs, statement);
    }

    /// @notice Verifies a batch of a long page's parts. The first batch starts at part 0 (the genesis part); each next
    /// batch must start where the previous one ended. Sessions are per submitter.
    /// @param genesisRoot the first part's start root, which names the session.
    /// @param tier the page's text tier (its final statement must say the same).
    /// @param startIndex the index of this batch's first part.
    /// @return session keccak256(msg.sender, genesisRoot), the key in `progress`.
    function submitParts(
        bytes32 genesisRoot,
        uint256 tier,
        uint256 startIndex,
        bytes[] calldata partProofs,
        bytes32[3][] calldata partInputs
    ) external returns (bytes32 session) {
        uint256 parts = partProofs.length;
        if (parts == 0) revert NoParts();
        if (parts > MAX_PARTS_PER_TX) revert TooManyParts(parts);
        if (partInputs.length != parts) revert InvalidStatement();
        IHonkVerifier verifier = _chunk(tier);
        session = keccak256(abi.encodePacked(msg.sender, genesisRoot));
        bytes32 previousEnd;
        if (startIndex == 0) {
            if (partInputs[0][0] != genesisRoot) revert BrokenLinkage(0);
        } else {
            Progress storage p = progress[session];
            if (p.next == 0) revert UnknownSession();
            if (p.next != startIndex || p.tier != tier) revert BrokenLinkage(startIndex);
            previousEnd = p.end;
        }
        bytes32 end = _verifyParts(verifier, startIndex, previousEnd, partProofs, partInputs);
        uint256 next = startIndex + parts;
        progress[session] = Progress(end, uint32(next), uint32(tier));
        emit PartsVerified(session, msg.sender, tier, next);
    }

    /// @notice Closes a long page sent with `submitParts`: verifies its final proof against the parts verified so far
    /// and records it.
    function submitFinal(bytes32 genesisRoot, bytes calldata finalProof, bytes32[] calldata finalInputs)
        external
        returns (bytes32 statement)
    {
        bytes32 session = keccak256(abi.encodePacked(msg.sender, genesisRoot));
        Progress memory p = progress[session];
        if (p.next == 0) revert UnknownSession();
        uint256 tier = _tier(finalInputs);
        if (tier != p.tier) revert InvalidStatement();
        statement = keccak256(abi.encodePacked(finalInputs));
        if (pages[statement].blockNumber != 0) revert AlreadyVerified();
        delete progress[session];
        _verifyFinal(tier, p.end, p.next, finalProof, finalInputs, statement);
    }

    /// @notice Whether a page with this statement hash has verified on-chain.
    function verified(bytes32 statement) external view returns (bool) {
        return pages[statement].blockNumber != 0;
    }

    /// @dev The statement's tier, after checking it has 44 fields and a tier this contract has verifiers for.
    function _tier(bytes32[] calldata finalInputs) internal pure returns (uint256 tier) {
        if (finalInputs.length != FINAL_INPUTS) revert InvalidStatement();
        tier = uint256(finalInputs[TEXT_CAPACITY]);
        if (tier != 1024 && tier != 4096 && tier != 10000) revert UnsupportedTier(tier);
    }

    function _chunk(uint256 tier) internal view returns (IHonkVerifier) {
        if (tier == 1024) return chunk1024;
        if (tier == 4096) return chunk4096;
        if (tier == 10000) return chunk10000;
        revert UnsupportedTier(tier);
    }

    function _final(uint256 tier) internal view returns (IHonkVerifier) {
        return tier == 1024 ? final1024 : tier == 4096 ? final4096 : final10000; // tier checked by _tier
    }

    /// @dev Checks a run of parts starting at `firstIndex`: linkage (part 0 is the genesis part; every other part is not,
    /// and starts where the one before it ended, `previousEnd` for the run's first) and each proof. Returns the last end.
    function _verifyParts(
        IHonkVerifier verifier,
        uint256 firstIndex,
        bytes32 previousEnd,
        bytes[] calldata partProofs,
        bytes32[3][] calldata partInputs
    ) internal view returns (bytes32) {
        bytes32[] memory inputs = new bytes32[](3);
        for (uint256 i; i < partProofs.length; ++i) {
            uint256 index = firstIndex + i;
            bytes32 start = partInputs[i][0];
            uint256 genesis = uint256(partInputs[i][2]);
            if (index == 0 ? genesis != 1 : (genesis != 0 || start != (i == 0 ? previousEnd : partInputs[i - 1][1]))) {
                revert BrokenLinkage(index);
            }
            (inputs[0], inputs[1], inputs[2]) = (start, partInputs[i][1], partInputs[i][2]);
            if (!_verify(verifier, partProofs[i], inputs)) revert InvalidPartProof(index);
        }
        return partInputs[partProofs.length - 1][1];
    }

    function _verifyFinal(
        uint256 tier,
        bytes32 end,
        uint256 parts,
        bytes calldata finalProof,
        bytes32[] calldata finalInputs,
        bytes32 statement
    ) internal {
        if (finalInputs[STATE_ROOT] != end) revert BrokenLinkage(parts);
        if (!_verifyCalldata(_final(tier), finalProof, finalInputs)) revert InvalidFinalProof();
        pages[statement] = Page(uint64(block.number), uint32(parts), uint32(tier), msg.sender);
        emit PageVerified(statement, msg.sender, tier, parts);
    }

    // The generated verifiers revert (SumcheckFailed, ShpleminiFailed, ...) on a bad proof; either way it is invalid.
    function _verify(IHonkVerifier verifier, bytes calldata proof, bytes32[] memory inputs) internal view returns (bool) {
        try verifier.verify(proof, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    function _verifyCalldata(IHonkVerifier verifier, bytes calldata proof, bytes32[] calldata inputs)
        internal
        view
        returns (bool)
    {
        try verifier.verify(proof, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
